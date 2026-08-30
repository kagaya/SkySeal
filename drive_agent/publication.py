from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from verifier.skyseal_verify import (
    canonical_json,
    parse_json_bytes,
    verify_bundle,
    verify_identity_activation,
)


class PublicationError(RuntimeError):
    pass


PUBLIC_INDEX_SCHEMA = "urn:skyseal:public-evidence-index:v1"
PUBLIC_COMPONENT_RE = re.compile(r"[A-Za-z0-9._-]+")


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(path, 0o700)


class LocalEvidencePublisher:
    """Persist complete public packages locally before any remote mirroring."""

    def __init__(self, root: Path):
        self.root = root.resolve()

    @staticmethod
    def _components(prefix: str) -> tuple[str, ...]:
        components = tuple(prefix.split("/"))
        if not components or any(
            not component or PUBLIC_COMPONENT_RE.fullmatch(component) is None
            for component in components
        ):
            raise PublicationError("invalid local publication prefix")
        return components

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name != "posix":
            return
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _write_new(path: Path, content: bytes) -> None:
        with path.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o644)

    @classmethod
    def _replace(cls, path: Path, content: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o644)
            os.replace(temporary, path)
            cls._fsync_directory(path.parent)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _target(self, prefix: str) -> Path:
        components = self._components(prefix)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o755)
        os.chmod(self.root, 0o755)
        current = self.root
        for component in components[:-1]:
            current = current / component
            if current.is_symlink():
                raise PublicationError("local publication parent is a symlink")
            current.mkdir(exist_ok=True, mode=0o755)
            if not current.is_dir():
                raise PublicationError("local publication parent is not a directory")
            os.chmod(current, 0o755)
        return current / components[-1]

    @property
    def index_path(self) -> Path:
        return self.root / "index.json"

    def _read_index(self) -> list[dict[str, object]]:
        if not self.index_path.exists():
            return []
        try:
            document = json.loads(self.index_path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise PublicationError("local publication index is unreadable") from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"schema", "publications"}
            or document.get("schema") != PUBLIC_INDEX_SCHEMA
            or not isinstance(document.get("publications"), list)
        ):
            raise PublicationError("local publication index is invalid")
        return list(document["publications"])

    def _write_index(self, records: list[dict[str, object]]) -> None:
        document = {
            "schema": PUBLIC_INDEX_SCHEMA,
            "publications": sorted(
                records,
                key=lambda record: (str(record["created_at"]), str(record["seal_id"])),
                reverse=True,
            ),
        }
        self._replace(self.index_path, canonical_json(document) + b"\n")

    def _update_index(
        self,
        summary: Mapping[str, object],
        github_mirror: str,
    ) -> None:
        if github_mirror not in {"pending", "synced"}:
            raise PublicationError("invalid GitHub mirror state")
        required = {"seal_id", "created_at", "entry_count", "identity_id", "relative_path"}
        if set(summary) != required:
            raise PublicationError("local publication summary is invalid")
        records = self._read_index()
        replacement = dict(summary)
        replacement["github_mirror"] = github_mirror
        found = False
        for index, existing in enumerate(records):
            if not isinstance(existing, dict) or "seal_id" not in existing:
                raise PublicationError("local publication index record is invalid")
            if existing["seal_id"] != summary["seal_id"]:
                continue
            immutable = {key: existing.get(key) for key in required}
            if immutable != dict(summary):
                raise PublicationError("refusing to replace local publication metadata")
            records[index] = replacement
            found = True
            break
        if not found:
            records.append(replacement)
        self._write_index(records)

    def publish(
        self,
        prefix: str,
        artifacts: Mapping[str, bytes],
        manifest: bytes,
        summary: Mapping[str, object],
        *,
        updating: bool,
    ) -> None:
        package = dict(artifacts)
        package["manifest.json"] = manifest
        target = self._target(prefix)
        if target.is_symlink():
            raise PublicationError("local publication target is a symlink")
        if not target.exists():
            staging = Path(tempfile.mkdtemp(prefix=".skyseal-package-", dir=target.parent))
            try:
                for name, content in sorted(package.items()):
                    if PUBLIC_COMPONENT_RE.fullmatch(name) is None:
                        raise PublicationError("invalid local artifact name")
                    self._write_new(staging / name, content)
                self._fsync_directory(staging)
                os.chmod(staging, 0o755)
                os.rename(staging, target)
                self._fsync_directory(target.parent)
            finally:
                if staging.exists():
                    shutil.rmtree(staging)
        else:
            if not target.is_dir():
                raise PublicationError("local publication target is not a directory")
            immutable_names = {
                name for name in package if not name.endswith(".ots") and name != "manifest.json"
            }
            for name in immutable_names:
                path = target / name
                if not path.is_file() or path.read_bytes() != package[name]:
                    raise PublicationError("refusing to replace immutable local evidence")
            if not updating:
                for name, content in package.items():
                    path = target / name
                    if not path.is_file() or path.read_bytes() != content:
                        raise PublicationError("refusing to replace different local evidence")
            else:
                for name in sorted(name for name in package if name.endswith(".ots")):
                    self._replace(target / name, package[name])
                self._replace(target / "manifest.json", manifest)
        self._update_index(summary, "pending")

    def set_github_mirror(self, summary: Mapping[str, object], status: str) -> None:
        self._update_index(summary, status)


class OpenTimestampsClient:
    def __init__(self, executable: str = "ots"):
        self.executable = executable

    def _run(self, arguments: list[str], working_directory: Path) -> None:
        try:
            completed = subprocess.run(
                [self.executable, *arguments],
                cwd=working_directory,
                check=False,
                capture_output=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PublicationError("OpenTimestamps client could not run") from exc
        if completed.returncode != 0:
            raise PublicationError("OpenTimestamps operation failed")

    def stamp(self, target_name: str, target: bytes, work_directory: Path) -> bytes:
        ensure_private_directory(work_directory)
        with tempfile.TemporaryDirectory(prefix="ots-stamp-", dir=work_directory) as directory:
            root = Path(directory)
            target_path = root / target_name
            target_path.write_bytes(target)
            self._run(["stamp", target_path.name], root)
            proof_path = target_path.with_name(target_path.name + ".ots")
            if not proof_path.is_file():
                raise PublicationError("OpenTimestamps did not produce a proof")
            return proof_path.read_bytes()

    def upgrade(
        self,
        target_name: str,
        target: bytes,
        proof: bytes,
        work_directory: Path,
    ) -> bytes:
        ensure_private_directory(work_directory)
        with tempfile.TemporaryDirectory(prefix="ots-upgrade-", dir=work_directory) as directory:
            root = Path(directory)
            target_path = root / target_name
            proof_path = root / (target_name + ".ots")
            target_path.write_bytes(target)
            proof_path.write_bytes(proof)
            self._run(["upgrade", proof_path.name], root)
            return proof_path.read_bytes()


class GitHubPublisher:
    def __init__(
        self,
        *,
        owner: str,
        repository: str,
        branch: str,
        token: str,
        timeout: float = 20.0,
        api_root: str = "https://api.github.com",
    ):
        self.owner = owner
        self.repository = repository
        self.branch = branch
        self.token = token
        self.timeout = timeout
        self.api_root = api_root.rstrip("/")

    def _request(
        self, method: str, path: str, payload: object | None = None
    ) -> tuple[int, bytes]:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "SkySeal-Publisher/1.0",
        }
        data = None
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.api_root + path, data=data, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, response.read(4 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            body = exc.read(4 * 1024 * 1024)
            if exc.code == 404:
                return exc.code, body
            raise PublicationError(f"GitHub API returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise PublicationError(f"GitHub request failed: {type(exc).__name__}") from exc

    def _contents_path(self, repository_path: str) -> str:
        encoded = "/".join(
            urllib.parse.quote(component, safe="")
            for component in repository_path.split("/")
        )
        return f"/repos/{urllib.parse.quote(self.owner, safe='')}/{urllib.parse.quote(self.repository, safe='')}/contents/{encoded}"

    def put(self, repository_path: str, content: bytes, *, allow_update: bool = False) -> str:
        endpoint = self._contents_path(repository_path)
        status, existing_data = self._request(
            "GET", endpoint + "?" + urllib.parse.urlencode({"ref": self.branch})
        )
        existing_sha: str | None = None
        if status == 200:
            try:
                existing = json.loads(existing_data)
                encoded = "".join(str(existing["content"]).split())
                existing_bytes = base64.b64decode(encoded, validate=True)
                existing_sha = existing["sha"]
            except Exception as exc:
                raise PublicationError("GitHub returned invalid existing content") from exc
            if existing_bytes == content:
                return str(existing.get("html_url", ""))
            if not allow_update:
                raise PublicationError("refusing to replace different published evidence")
        elif status != 404:
            raise PublicationError(f"unexpected GitHub content status: {status}")
        payload: dict[str, object] = {
            "message": f"Publish SkySeal evidence {repository_path.rsplit('/', 2)[-2]}",
            "content": base64.b64encode(content).decode("ascii"),
            "branch": self.branch,
        }
        if existing_sha is not None:
            payload["sha"] = existing_sha
        put_status, result_data = self._request("PUT", endpoint, payload)
        if put_status not in {200, 201}:
            raise PublicationError(f"GitHub publication returned HTTP {put_status}")
        try:
            result = json.loads(result_data)
            return str(result["content"]["html_url"])
        except Exception as exc:
            raise PublicationError("GitHub publication response is incomplete") from exc


@dataclass(frozen=True)
class PublicationResult:
    prefix: str
    bundle_ots: bytes
    activation_ots: bytes


class PublicationWorker:
    def __init__(
        self,
        *,
        trusted_rp_id: str,
        trusted_origin: str,
        work_directory: Path,
        github_prefix: str,
        ots: OpenTimestampsClient,
        local: LocalEvidencePublisher,
        github: GitHubPublisher,
    ):
        self.trusted_rp_id = trusted_rp_id
        self.trusted_origin = trusted_origin
        self.work_directory = work_directory
        self.github_prefix = github_prefix.strip("/")
        self.ots = ots
        self.local = local
        self.github = github

    def _verified_base(self, job: Mapping[str, object]) -> tuple[str, dict[str, bytes]]:
        required = {
            "hash_list": job["hash_list"],
            "bundle_json": job["bundle_json"],
            "genesis_json": job["genesis_json"],
            "identity_activation": job["identity_activation"],
        }
        if any(value is None for value in required.values()):
            raise PublicationError("approved job is missing public artifacts")
        artifacts = {
            "hashes.txt": bytes(required["hash_list"]),
            "seal.skyseal.json": bytes(required["bundle_json"]),
            "identity-genesis.json": bytes(required["genesis_json"]),
            "identity-activation.json": bytes(required["identity_activation"]),
        }
        bundle_object = parse_json_bytes(artifacts["seal.skyseal.json"], "approved bundle")
        try:
            payload = bundle_object["seal_payload"]
            created_at = payload["created_at"]
            seal_id = payload["seal_id"]
        except (KeyError, TypeError) as exc:
            raise PublicationError("approved bundle is missing publication coordinates") from exc
        if not isinstance(created_at, str) or len(created_at) < 7:
            raise PublicationError("approved bundle has an invalid creation timestamp")
        if seal_id != job["seal_id"]:
            raise PublicationError("approved bundle seal ID does not match the job")
        year, month = created_at[:4], created_at[5:7]
        if not year.isdigit() or not month.isdigit():
            raise PublicationError("approved bundle has an invalid creation timestamp")
        prefix = f"{self.github_prefix}/{year}/{month}/{seal_id}"
        ensure_private_directory(self.work_directory)
        with tempfile.TemporaryDirectory(prefix="publish-verify-", dir=self.work_directory) as directory:
            root = Path(directory)
            hash_path = root / "hashes.txt"
            bundle_path = root / "seal.skyseal.json"
            genesis_path = root / "identity-genesis.json"
            activation_path = root / "identity-activation.json"
            hash_path.write_bytes(artifacts["hashes.txt"])
            bundle_path.write_bytes(artifacts["seal.skyseal.json"])
            genesis_path.write_bytes(artifacts["identity-genesis.json"])
            activation_path.write_bytes(artifacts["identity-activation.json"])
            verify_bundle(
                hash_path,
                bundle_path,
                genesis_path,
                self.trusted_rp_id,
                self.trusted_origin,
                activation_path,
            )
            verify_identity_activation(
                genesis_path,
                activation_path,
                self.trusted_rp_id,
                self.trusted_origin,
            )
        return prefix, artifacts

    @staticmethod
    def _manifest(seal_id: str, artifacts: Mapping[str, bytes]) -> bytes:
        manifest = {
            "schema": "urn:skyseal:publication-manifest:v2",
            "seal_id": seal_id,
            "artifacts": {
                name: {"sha256": sha256_prefixed(content)}
                for name, content in sorted(artifacts.items())
            },
            "timestamp_targets": [
                {
                    "proof": "seal.skyseal.json.ots",
                    "target": "seal.skyseal.json",
                },
                {
                    "proof": "identity-activation.json.ots",
                    "target": "identity-activation.json",
                },
            ],
        }
        return canonical_json(manifest) + b"\n"

    def _upload(self, prefix: str, artifacts: dict[str, bytes], *, updating: bool) -> None:
        manifest = self._manifest(prefix.rsplit("/", 1)[-1], artifacts)
        for name, content in sorted(artifacts.items()):
            self.github.put(
                f"{prefix}/{name}",
                content,
                allow_update=updating and name.endswith(".ots"),
            )
        self.github.put(f"{prefix}/manifest.json", manifest, allow_update=updating)

    @staticmethod
    def _summary(prefix: str, artifacts: Mapping[str, bytes]) -> dict[str, object]:
        bundle = parse_json_bytes(artifacts["seal.skyseal.json"], "approved bundle")
        try:
            payload = bundle["seal_payload"]
            identity_id = payload["identity_id"]
            created_at = payload["created_at"]
            seal_id = payload["seal_id"]
        except (KeyError, TypeError) as exc:
            raise PublicationError("approved bundle is missing public summary fields") from exc
        if not all(isinstance(value, str) and value for value in (identity_id, created_at, seal_id)):
            raise PublicationError("approved bundle has invalid public summary fields")
        if prefix.rsplit("/", 1)[-1] != seal_id:
            raise PublicationError("publication prefix does not match the seal ID")
        return {
            "seal_id": seal_id,
            "created_at": created_at,
            "entry_count": artifacts["hashes.txt"].count(b"\n"),
            "identity_id": identity_id,
            "relative_path": prefix,
        }

    def _complete_artifacts(
        self, job: Mapping[str, object]
    ) -> tuple[str, dict[str, bytes], bytes, dict[str, object]]:
        prefix, artifacts = self._verified_base(job)
        if job["ots_proof"] is None or job["identity_ots_proof"] is None:
            raise PublicationError("approved job has not stored its timestamp proofs")
        artifacts["seal.skyseal.json.ots"] = bytes(job["ots_proof"])
        artifacts["identity-activation.json.ots"] = bytes(job["identity_ots_proof"])
        manifest = self._manifest(prefix.rsplit("/", 1)[-1], artifacts)
        return prefix, artifacts, manifest, self._summary(prefix, artifacts)

    def stamp(self, job: Mapping[str, object]) -> PublicationResult:
        prefix, artifacts = self._verified_base(job)
        bundle_ots = self.ots.stamp(
            "seal.skyseal.json", artifacts["seal.skyseal.json"], self.work_directory
        )
        activation_ots = self.ots.stamp(
            "identity-activation.json",
            artifacts["identity-activation.json"],
            self.work_directory,
        )
        return PublicationResult(prefix, bundle_ots, activation_ots)

    def publish(self, job: Mapping[str, object]) -> PublicationResult:
        prefix, artifacts, manifest, summary = self._complete_artifacts(job)
        self.local.publish(prefix, artifacts, manifest, summary, updating=False)
        return PublicationResult(
            prefix,
            artifacts["seal.skyseal.json.ots"],
            artifacts["identity-activation.json.ots"],
        )

    def mirror(self, job: Mapping[str, object], *, updating: bool) -> PublicationResult:
        prefix, artifacts, _, summary = self._complete_artifacts(job)
        self._upload(prefix, artifacts, updating=updating)
        self.local.set_github_mirror(summary, "synced")
        return PublicationResult(
            prefix,
            artifacts["seal.skyseal.json.ots"],
            artifacts["identity-activation.json.ots"],
        )

    def ensure_local(self, job: Mapping[str, object], github_status: str) -> PublicationResult:
        prefix, artifacts, manifest, summary = self._complete_artifacts(job)
        self.local.publish(prefix, artifacts, manifest, summary, updating=True)
        self.local.set_github_mirror(
            summary, "synced" if github_status == "synced" else "pending"
        )
        return PublicationResult(
            prefix,
            artifacts["seal.skyseal.json.ots"],
            artifacts["identity-activation.json.ots"],
        )

    def upgrade(self, job: Mapping[str, object]) -> PublicationResult:
        prefix, artifacts = self._verified_base(job)
        if job["ots_proof"] is None or job["identity_ots_proof"] is None:
            raise PublicationError("published job is missing timestamp proofs")
        bundle_ots = self.ots.upgrade(
            "seal.skyseal.json",
            artifacts["seal.skyseal.json"],
            bytes(job["ots_proof"]),
            self.work_directory,
        )
        activation_ots = self.ots.upgrade(
            "identity-activation.json",
            artifacts["identity-activation.json"],
            bytes(job["identity_ots_proof"]),
            self.work_directory,
        )
        artifacts["seal.skyseal.json.ots"] = bundle_ots
        artifacts["identity-activation.json.ots"] = activation_ots
        manifest = self._manifest(prefix.rsplit("/", 1)[-1], artifacts)
        summary = self._summary(prefix, artifacts)
        self.local.publish(prefix, artifacts, manifest, summary, updating=True)
        return PublicationResult(prefix, bundle_ots, activation_ots)
