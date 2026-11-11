"""Local desktop workflow: immutable snapshots, human approval, durable proofs."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import sys
import tempfile
import uuid
import zipfile

from drive_agent.sky_witness import JMAHimawariWitness
from verifier.skyseal_verify import VerificationError, canonical_json, encode_base64url
from . import proof
from .ots import TimestampClient


class EngineError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_data_dir() -> Path:
    override = os.environ.get("SKYSEAL_DESKTOP_DATA_DIR")
    if override:
        path = Path(override).expanduser()
        if sys.platform == "linux" and not path.is_absolute():
            raise EngineError("invalid_data_dir", "SKYSEAL_DESKTOP_DATA_DIR must be an absolute path")
        return path.absolute()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "SkySeal"
    if sys.platform == "linux":
        xdg = os.environ.get("XDG_DATA_HOME", "")
        # The XDG base-directory specification requires absolute paths; ignore
        # relative settings rather than writing secrets under the working dir.
        base = Path(xdg) if xdg and Path(xdg).is_absolute() else Path.home() / ".local" / "share"
        return base / "SkySeal"
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local" / "share")))
    return base / "SkySeal"


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _unsafe_file(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _safe_source(path: Path) -> os.stat_result:
    # Do not resolve first: that would erase the evidence of a junction/symlink.
    for current in (path, *path.parents):
        info = current.lstat()
        if _unsafe_file(info):
            raise EngineError("unsafe_source", "Symbolic links and Windows reparse points are not accepted")
    return path.stat()


def _hash_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


class Engine:
    def __init__(self, data_dir: Path | None = None, *, signer=None, auth=None,
                 witness=None, timestamps=None):
        self.root = Path(os.path.abspath(data_dir or default_data_dir()))
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        _safe_source(self.root)
        self.db = sqlite3.connect(self.root / "state.sqlite3", timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, state TEXT NOT NULL, record TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.commit()
        if signer is None:
            if sys.platform == "darwin":
                from . import macos_auth
                signer = macos_auth
            elif sys.platform == "linux":
                from .linux_auth import LinuxSigner
                signer = LinuxSigner(self.root)
            else:
                from . import windows_auth
                signer = windows_auth
        if auth is None:
            from . import orcid_auth
            auth = orcid_auth
        self.signer, self.auth = signer, auth
        self.profile = getattr(signer, "PROFILE", proof.PROFILE)
        proof.schema(self.profile, "genesis")
        self.witness = witness or JMAHimawariWitness()
        self.timestamps = timestamps or TimestampClient()

    def close(self):
        self.db.close()

    @contextmanager
    def mutation(self):
        lock = (self.root / "engine.lock").open("a+b")
        lock.seek(0)
        lock.write(b"\0")
        lock.flush()
        lock.seek(0)
        try:
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise EngineError("busy", "Another SkySeal operation is running") from exc
            yield
        finally:
            lock.close()

    def _setting(self, name: str, default: str = "") -> str:
        row = self.db.execute("SELECT value FROM settings WHERE key=?", (name,)).fetchone()
        return row[0] if row else default

    def _identity(self) -> dict | None:
        path = self.root / "identity" / "private.json"
        return proof.read_json(path) if path.is_file() else None

    def _save_job(self, record: dict) -> dict:
        with self.db:
            self.db.execute("INSERT INTO jobs VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,record=excluded.record",
                (record["job_id"], record["created_at"], record["state"], json.dumps(record, ensure_ascii=False)))
        return record

    def _job(self, job_id: str) -> dict:
        if not isinstance(job_id, str) or re.fullmatch(r"[0-9a-f]{32}", job_id) is None:
            raise EngineError("invalid_job", "Invalid job ID")
        row = self.db.execute("SELECT record FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise EngineError("job_not_found", "Job does not exist")
        return json.loads(row[0])

    def _jobdir(self, job_id: str) -> Path:
        return self.root / "jobs" / job_id

    def _recover_ots_update(self, job_id: str) -> None:
        """Finish only an explicitly journaled OTS/manifest pair replacement."""
        folder = self._jobdir(job_id)
        journal = folder / ".ots-update.json"
        if not journal.exists():
            return
        record = proof.read_json(journal)
        if set(record) != {"name", "old_manifest", "new_manifest", "new_proof"}:
            raise EngineError("invalid_journal", "Invalid timestamp recovery journal")
        name = record["name"]
        if name not in {target + ".ots" for target in proof.OTS_TARGETS}:
            raise EngineError("invalid_journal", "Invalid timestamp recovery target")
        old, new = record["old_manifest"], record["new_manifest"]
        for manifest in (old, new):
            if not isinstance(manifest, dict) or set(manifest) != {"schema", "profile", "seal_id", "artifacts"} or manifest["profile"] not in proof.SUPPORTED_PROFILES or manifest["schema"] != proof.schema(manifest["profile"], "manifest") or manifest["seal_id"] != job_id:
                raise EngineError("invalid_journal", "Invalid timestamp recovery manifest")
        if old["profile"] != new["profile"]:
            raise EngineError("invalid_journal", "Timestamp recovery cannot change the evidence profile")
        before, after = dict(old["artifacts"]), dict(new["artifacts"])
        old_hash = before.pop(name, None)
        new_hash = after.pop(name, None)
        if before != after or not proof.BASE_ARTIFACTS <= set(before) or set(before) - (proof.PUBLIC_ARTIFACTS - {"manifest.json"}):
            raise EngineError("invalid_journal", "Recovery may only change one timestamp proof")
        from verifier.skyseal_verify import decode_base64url
        new_bytes = decode_base64url(record["new_proof"], "timestamp update proof")
        if len(new_bytes) > proof.MAX_PUBLIC_FILE or proof.digest(new_bytes) != new_hash:
            raise EngineError("invalid_journal", "Timestamp recovery proof does not match")
        directory = folder / "evidence"
        current = proof.read_json(directory / "manifest.json")
        if current != old and current != new:
            raise EngineError("invalid_journal", "Evidence changed outside timestamp recovery")
        for artifact, expected in before.items():
            if proof.digest((directory / artifact).read_bytes()) != expected:
                raise EngineError("invalid_journal", "Immutable evidence changed during recovery")
        timestamp = directory / name
        actual = proof.digest(timestamp.read_bytes()) if timestamp.exists() else None
        if actual not in {old_hash, new_hash}:
            raise EngineError("invalid_journal", "Timestamp evidence changed outside recovery")
        atomic_write(timestamp, new_bytes)
        atomic_write(directory / "manifest.json", proof.json_bytes(new))
        journal.unlink()

    def _update_timestamp(self, job_id: str, name: str, data: bytes) -> None:
        self._recover_ots_update(job_id)
        directory = self._jobdir(job_id) / "evidence"
        old = proof.read_json(directory / "manifest.json")
        new = json.loads(json.dumps(old))
        new["artifacts"][name] = proof.digest(data)
        atomic_write(self._jobdir(job_id) / ".ots-update.json", proof.json_bytes({
            "name": name, "old_manifest": old, "new_manifest": new,
            "new_proof": encode_base64url(data)}))
        self._recover_ots_update(job_id)

    def status(self, **_) -> dict:
        identity = self._identity()
        return {"data_dir": str(self.root), "platform": self.signer.availability(),
            "host_platform": sys.platform,
            "orcid_client_id": self._setting("orcid_client_id"),
            "configured": bool(self._setting("orcid_client_id")), "profile": self.profile,
            "identity": None if identity is None else {**{key: identity["genesis"][key]
                for key in ("identity_id", "display_name", "created_at")},
                "profile": identity["genesis"]["profile"],
                "signing_compatible": identity["genesis"]["profile"] == self.profile}}

    def configure(self, orcid_client_id: str = "", **_) -> dict:
        if not isinstance(orcid_client_id, str) or re.fullmatch(r"APP-[A-Z0-9]{8,80}", orcid_client_id) is None:
            raise EngineError("invalid_client_id", "Enter the registered ORCID production Public API client ID (APP-…)")
        identity = self._identity()
        if identity and identity["genesis"]["orcid_client_id"] != orcid_client_id:
            raise EngineError("identity_exists", "Changing the client ID requires a separately designed identity migration")
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO settings VALUES ('orcid_client_id',?)", (orcid_client_id,))
        return self.status()

    def tls_status(self, **_) -> dict:
        return self.auth.ensure_certificate(self.root)

    def trust_local_certificate(self, expected_sha256=None, **_) -> dict:
        if expected_sha256 is not None:
            return self.auth.trust_certificate(self.root, expected_sha256=expected_sha256)
        return self.auth.trust_certificate(self.root)

    def identity_enroll(self, **_) -> dict:
        if self._identity():
            raise EngineError("identity_exists", "A local identity is already enrolled")
        client_id = self._setting("orcid_client_id")
        if not client_id:
            raise EngineError("configuration_required", "Set the ORCID client ID before enrollment")
        credential = self.signer.register(proof.RP_ID, proof.ORIGIN, secrets.token_bytes(32), "SkySeal researcher")
        seed = encode_base64url(secrets.token_bytes(32))
        nonce = proof.enrollment_nonce(credential["public_key"], credential["algorithm"], seed, self.profile)
        result = self.auth.login(client_id, nonce, self.root)
        # Validate again at the engine boundary; do not trust callback fields.
        claims = self.auth.verify_id_token(result["id_token"], client_id, nonce)
        genesis = {"schema": proof.schema(self.profile, "genesis"), "profile": self.profile,
            "identity_id": "https://orcid.org/" + claims["sub"],
            "display_name": str(claims.get("name") or claims["sub"])[:200],
            "created_at": utcnow(),
            "algorithm": credential["algorithm"], "public_key": credential["public_key"],
            "enrollment_seed": seed, "orcid_client_id": client_id, "orcid_id_token": result["id_token"]}
        genesis.update(proof.approval_context(self.profile))
        payload = {"profile": self.profile, "genesis_digest": proof.object_digest(genesis),
            "created_at": utcnow(), "nonce": encode_base64url(secrets.token_bytes(32))}
        activation = {"schema": proof.schema(self.profile, "activation"), "payload": payload,
            "assertion": proof.public_assertion(self.signer.sign(credential, proof.challenge("identity", payload), proof.RP_ID, proof.ORIGIN), self.profile)}
        proof.verify_identity(genesis, activation, client_id, self.auth.verify_id_token)
        atomic_write(self.root / "identity" / "private.json", proof.json_bytes({
            "credential": credential, "genesis": genesis, "activation": activation}))
        return self.status()

    def _sources(self, paths: list[str]) -> list[Path]:
        if not isinstance(paths, list) or not paths or len(paths) > 10000 or not all(isinstance(path, str) for path in paths):
            raise EngineError("invalid_paths", "Choose one or more files or folders")
        files: dict[str, Path] = {}
        for value in paths:
            root = Path(os.path.abspath(Path(value).expanduser()))
            info = _safe_source(root)
            if root == self.root or root in self.root.parents or self.root in root.parents:
                raise EngineError("unsafe_source", "Do not include the SkySeal data directory in a snapshot")
            if stat.S_ISREG(info.st_mode):
                candidates = [root]
            elif stat.S_ISDIR(info.st_mode):
                def fail_walk(error):
                    raise EngineError("unreadable_source", "A selected folder could not be read completely") from error
                def walk_files():
                    for current, dirs, names in os.walk(root, followlinks=False, onerror=fail_walk):
                        for name in dirs:
                            _safe_source(Path(current) / name)
                        for name in names:
                            yield Path(current) / name
                candidates = walk_files()
            else:
                raise EngineError("unsafe_source", "Only regular files and directories are accepted")
            for candidate in candidates:
                if not stat.S_ISREG(_safe_source(candidate).st_mode):
                    raise EngineError("unsafe_source", "Only regular files are accepted")
                files[os.path.normcase(str(candidate))] = candidate
                if len(files) > 100000:
                    raise EngineError("too_many_files", "A snapshot may contain at most 100,000 files")
        if not files:
            raise EngineError("empty_input", "Selected folders contain no regular files")
        return [files[key] for key in sorted(files)]

    def _copy_snapshot(self, source: Path, target: Path) -> tuple[int, str]:
        before = _safe_source(source)
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        sha = hashlib.sha256()
        size = 0
        with os.fdopen(descriptor, "rb") as original, target.open("xb") as output:
            opened = os.fstat(original.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
                raise EngineError("source_changed", "A selected file changed while opening it")
            for chunk in iter(lambda: original.read(1024 * 1024), b""):
                output.write(chunk)
                sha.update(chunk)
                size += len(chunk)
            output.flush()
            os.fsync(output.fileno())
            after = os.fstat(original.fileno())
        final = _safe_source(source)
        signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        # Windows path stat and descriptor fstat can report different timestamp
        # precision. Compare each observation channel with itself, while binding
        # the channels by file identity/size above. Changes within either channel
        # still invalidate the snapshot.
        if signature(opened) != signature(after) or signature(before) != signature(final) or size != before.st_size:
            raise EngineError("source_changed", "A selected file changed during copying; prepare a fresh snapshot")
        return size, sha.hexdigest()

    def prepare(self, paths: list[str], **_) -> dict:
        sources = self._sources(paths)
        needed = sum(path.stat().st_size for path in sources)
        if shutil.disk_usage(self.root).free < needed + 16 * 1024 * 1024:
            raise EngineError("disk_space", "Insufficient free space for the fixed local snapshot")
        job_id = uuid.uuid4().hex
        folder = self._jobdir(job_id)
        snapshots = folder / "originals"
        snapshots.mkdir(parents=True, mode=0o700)
        record = {"job_id": job_id, "created_at": utcnow(), "state": "preparing", "entry_count": 0,
            "items": [], "ots_state": "not_requested", "identity_id": None, "error": None}
        self._save_job(record)
        try:
            for index, source in enumerate(sources):
                name = f"{index:08d}.bin"
                size, sha = self._copy_snapshot(source, snapshots / name)
                record["items"].append({"name": source.name, "source": str(source), "size": size, "sha256": sha, "snapshot": name})
            hashes = sorted({item["sha256"] for item in record["items"]})
            atomic_write(folder / "hashes.txt", ("\n".join(hashes) + "\n").encode("ascii"))
            record["entry_count"] = len(hashes)
            record["state"] = "prepared"
            record["snapshot_completed_at"] = utcnow()
            return self._save_job(record)
        except Exception as exc:
            record["state"], record["error"] = "interrupted", "Snapshot preparation did not complete"
            self._save_job(record)
            raise exc

    def get(self, job_id: str, **_) -> dict:
        record = self._job(job_id)
        directory = self._jobdir(job_id) / "evidence"
        if directory.is_dir() and record["state"] in {"prepared", "sealing", "interrupted"}:
            # The public directory rename is the commit point. DB updates may
            # follow after a power loss; never repeat a committed approval.
            bundle = proof.read_json(directory / "seal.skyseal.json")
            record.update(state="sealed", identity_id=bundle["payload"]["identity_id"], ots_state="pending")
        elif record["state"] in {"preparing", "sealing"}:
            # No automatic re-signing. A new explicit seal action is required.
            record["recovery_available"] = True
        return record

    def list(self, **_) -> dict:
        ids = self.db.execute("SELECT id FROM jobs ORDER BY created_at DESC,id DESC").fetchall()
        return {"jobs": [self.get(row[0]) for row in ids]}

    def seal(self, job_id: str, **_) -> dict:
        record = self.get(job_id)
        folder = self._jobdir(job_id)
        if (folder / "evidence").is_dir():
            return self.resume(job_id)
        if record["state"] not in {"prepared", "sealing"}:
            raise EngineError("invalid_state", "This snapshot is not ready for approval")
        identity = self._identity()
        if not identity:
            raise EngineError("identity_required", "Enroll an ORCID-bound local identity first")
        if identity["genesis"].get("profile") != self.profile:
            raise EngineError("incompatible_identity", "This identity belongs to a different platform signer; enroll a native identity in a separate data directory")
        # Recheck snapshots against the already shown preview before signing.
        for item in record["items"]:
            path = folder / "originals" / item["snapshot"]
            _safe_source(path)
            if path.stat().st_size != item["size"] or _hash_file(path) != item["sha256"]:
                raise EngineError("snapshot_changed", "Saved snapshot was changed; prepare a new snapshot")
        hashes_data = ("\n".join(sorted({item["sha256"] for item in record["items"]})) + "\n").encode("ascii")
        if (folder / "hashes.txt").read_bytes() != hashes_data:
            raise EngineError("snapshot_changed", "Saved hash list was changed; prepare a new snapshot")
        record["state"], record["error"] = "sealing", None
        self._save_job(record)
        staging = Path(tempfile.mkdtemp(prefix=".evidence-", dir=folder))
        try:
            witness = self.witness.capture()
            payload = {"profile": self.profile, "seal_id": job_id, "subject_digest": proof.digest(hashes_data),
                "identity_id": identity["genesis"]["identity_id"], "identity_digest": proof.object_digest(identity["activation"]),
                "created_at": utcnow(), "nonce": encode_base64url(secrets.token_bytes(32)), "sky_witness": witness.metadata}
            assertion = proof.public_assertion(self.signer.sign(identity["credential"], proof.challenge("seal", payload), proof.RP_ID, proof.ORIGIN), self.profile)
            proof.verify_assertion(assertion, proof.challenge("seal", payload), identity["genesis"])
            files = {"hashes.txt": hashes_data, "seal.skyseal.json": proof.json_bytes({"schema": proof.schema(self.profile, "seal"), "payload": payload, "assertion": assertion}),
                "identity-genesis.json": proof.json_bytes(identity["genesis"]), "identity-activation.json": proof.json_bytes(identity["activation"]),
                "sky-witness.json": proof.json_bytes(witness.metadata), "sky-witness.jpg": witness.image}
            for name, content in files.items():
                atomic_write(staging / name, content)
            atomic_write(staging / "manifest.json", proof.json_bytes(proof.create_manifest(staging, job_id, self.profile)))
            # Revalidate the cryptographic layers before committing this directory.
            proof.verify_directory(staging, client_id=self._setting("orcid_client_id"), token_verifier=self.auth.verify_id_token)
            os.rename(staging, folder / "evidence")
            if os.name == "posix":
                descriptor = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            record.update(state="sealed", ots_state="pending", identity_id=payload["identity_id"])
            self._save_job(record)
        except Exception:
            if not (folder / "evidence").is_dir():
                record.update(state="prepared", error="Approval or sealing did not complete; no seal was committed")
                self._save_job(record)
            raise
        finally:
            if staging.exists():
                shutil.rmtree(staging)
        return self.resume(job_id)

    def resume(self, job_id: str | None = None, **_) -> dict:
        if job_id is None:
            records = []
            for record in self.list()["jobs"]:
                if record["state"] == "sealed" and record["ots_state"] != "confirmed":
                    records.append(self.resume(record["job_id"]))
            return {"jobs": records}
        record = self.get(job_id)
        directory = self._jobdir(job_id) / "evidence"
        if not directory.is_dir():
            raise EngineError("approval_required", "Resume does not approve or sign a new seal")
        self._recover_ots_update(job_id)
        errors, statuses, details = [], {}, {}
        # Verify before making outgoing requests, using the signed fixed bytes.
        proof.verify_directory(directory, client_id=self._setting("orcid_client_id"), token_verifier=self.auth.verify_id_token)
        for name in proof.OTS_TARGETS:
            target, timestamp = directory / name, directory / (name + ".ots")
            try:
                old = timestamp.read_bytes() if timestamp.exists() else None
                new = self.timestamps.upgrade(target, timestamp) if old is not None else self.timestamps.stamp(target)
                if old != new:
                    if old is not None:
                        archive = self._jobdir(job_id) / "ots-history" / (name + "." + hashlib.sha256(old).hexdigest() + ".ots")
                        if not archive.exists():
                            atomic_write(archive, old)
                    self._update_timestamp(job_id, timestamp.name, new)
                detail = self.timestamps.verify(target, timestamp)
                confirmed = detail.get("status") == "confirmed" if isinstance(detail, dict) else detail is True
                details[name] = detail
                statuses[name] = "confirmed" if confirmed else "pending_or_unverified"
            except Exception as exc:
                statuses[name] = "pending_or_unverified"
                errors.append(f"{name}: {type(exc).__name__}; retry from history")
                if (self._jobdir(job_id) / ".ots-update.json").exists():
                    break
        for name in proof.OTS_TARGETS:
            statuses.setdefault(name, "pending_or_unverified")
        record.update(state="sealed", ots_state="confirmed" if all(v == "confirmed" for v in statuses.values()) else "pending",
            timestamp_status=statuses, timestamp_details=details, error="; ".join(errors) or None)
        return self._save_job(record)

    def export(self, job_id: str, destination: str, **_) -> dict:
        record = self.get(job_id)
        directory = self._jobdir(job_id) / "evidence"
        if not directory.is_dir():
            raise EngineError("not_sealed", "Only committed evidence can be exported")
        self._recover_ots_update(job_id)
        # Local export does not depend on an external issuer being reachable.
        # Full identity verification remains available via the Verify screen.
        manifest = proof.read_json(directory / "manifest.json")
        names = set(manifest["artifacts"]) | {"manifest.json"}
        if names - proof.PUBLIC_ARTIFACTS or not proof.BASE_ARTIFACTS <= names:
            raise EngineError("invalid_evidence", "Invalid artifact set")
        for name, expected in manifest["artifacts"].items():
            if proof.digest((directory / name).read_bytes()) != expected:
                raise EngineError("invalid_evidence", "Evidence has changed; export refused")
        target = Path(destination).expanduser().absolute()
        if target.suffix.lower() != ".zip" or target.exists():
            raise EngineError("invalid_destination", "Choose a new .zip filename; existing files are not overwritten")
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".skyseal-export-", dir=target.parent)
        os.close(descriptor)
        try:
            with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
                for name in sorted(names):
                    archive.write(directory / name, name)
            # Windows _commit/fsync requires a writable descriptor.
            with open(temporary, "r+b") as stream:
                os.fsync(stream.fileno())
            # Publish the completed archive atomically without replacing an
            # existing destination. No partial final ZIP is ever visible.
            if os.name == "nt":
                os.rename(temporary, target)  # Windows rename refuses existing targets.
            else:
                os.link(temporary, target)
                descriptor = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return {"path": str(target), "job_id": record["job_id"]}

    def verify(self, path: str, candidate: str | None = None, trusted_rp_id: str | None = None,
               trusted_origin: str | None = None, trusted_client_id: str | None = None, **_) -> dict:
        source = Path(path).expanduser().absolute()
        if source.is_dir():
            return self._verify_directory(source, candidate, trusted_rp_id, trusted_origin, trusted_client_id)
        if not source.is_file() or not zipfile.is_zipfile(source):
            raise EngineError("invalid_evidence", "Choose an evidence directory or .zip file")
        with tempfile.TemporaryDirectory(prefix="skyseal-verify-") as temporary:
            target = Path(temporary)
            with zipfile.ZipFile(source) as archive:
                infos = archive.infolist()
                if len(infos) > 20 or len({info.filename for info in infos}) != len(infos):
                    raise EngineError("invalid_archive", "Duplicate or excessive evidence archive entries")
                if sum(info.file_size for info in infos) > 32 * 1024 * 1024:
                    raise EngineError("invalid_archive", "Evidence archive is too large")
                for info in infos:
                    if info.filename not in proof.PUBLIC_ARTIFACTS or info.file_size > proof.MAX_PUBLIC_FILE or info.is_dir() or stat.S_ISLNK(info.external_attr >> 16):
                        raise EngineError("invalid_archive", "Unexpected or unsafe evidence archive entry")
                    atomic_write(target / info.filename, archive.read(info))
            return self._verify_directory(target, candidate, trusted_rp_id, trusted_origin, trusted_client_id)

    def _verify_directory(self, path: Path, candidate, trusted_rp_id, trusted_origin, trusted_client_id=None):
        manifest = proof.read_json(path / "manifest.json")
        if manifest.get("schema") in proof.MANIFEST_SCHEMAS:
            return proof.verify_directory(path, client_id=trusted_client_id or self._setting("orcid_client_id"),
                token_verifier=self.auth.verify_id_token, ots_verify=self.timestamps.verify,
                candidate=Path(candidate) if candidate else None)
        # Historical server evidence requires independently chosen RP/origin.
        if not trusted_rp_id or not trusted_origin:
            raise EngineError("trust_configuration_required", "Legacy evidence requires explicit trusted RP ID and origin")
        from verifier.skyseal_publication_verify import verify_publication, ARTIFACT_NAMES, SKY_WITNESS_ARTIFACT_NAMES
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, dict) or set(artifacts) - (ARTIFACT_NAMES | SKY_WITNESS_ARTIFACT_NAMES):
            raise EngineError("invalid_evidence", "Invalid legacy artifact set")
        for name in artifacts:
            artifact = path / name
            info = _safe_source(artifact)
            if not stat.S_ISREG(info.st_mode) or info.st_size > proof.MAX_PUBLIC_FILE:
                raise EngineError("invalid_evidence", "Legacy evidence artifact is unsafe or oversized")
        timestamp_details = {}
        def check(directory, proof_name, executable):
            detail = self.timestamps.verify(directory / proof_name[:-4], directory / proof_name)
            timestamp_details[proof_name[:-4]] = detail
            return detail.get("status") == "confirmed" if isinstance(detail, dict) else detail is True
        report = verify_publication(path, trusted_rp_id=trusted_rp_id, trusted_origin=trusted_origin,
            ots_verify=check, allow_pending_ots=True)
        report.update(profile="skyseal-v1.2", signature_valid=True, user_verified=True,
            time_confirmed=all(value == "confirmed" for value in report["opentimestamps"].values()), candidate_match=None,
            timestamp_details=timestamp_details)
        if candidate:
            from verifier.skyseal_verify import parse_hash_list
            hashes, _ = parse_hash_list(path / "hashes.txt")
            if _hash_file(Path(candidate)) not in hashes:
                raise VerificationError("candidate file is not a member of this seal")
            report["candidate_match"] = True
        return report

    def dispatch(self, request: dict) -> object:
        operation = request.get("op", request.get("method", request.get("operation")))
        allowed = {"status", "configure", "tls_status", "trust_local_certificate", "identity_enroll",
            "prepare", "seal", "list", "get", "resume", "export", "verify"}
        if operation not in allowed:
            raise EngineError("invalid_operation", "Unknown desktop operation")
        params = request.get("params", {})
        if not isinstance(params, dict):
            raise EngineError("invalid_request", "Request parameters must be an object")
        if operation in {"configure", "tls_status", "trust_local_certificate", "identity_enroll", "prepare", "seal", "resume", "export"}:
            with self.mutation():
                return getattr(self, operation)(**params)
        return getattr(self, operation)(**params)
