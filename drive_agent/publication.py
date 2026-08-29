from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from service.bootstrap_identity import verify_signature
from service.config import PINNED_OPENPGP_FINGERPRINT
from verifier.skyseal_verify import canonical_json, parse_json_bytes, verify_bundle


class PublicationError(RuntimeError):
    pass


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(path, 0o700)


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
    genesis_ots: bytes


class PublicationWorker:
    def __init__(
        self,
        *,
        trusted_rp_id: str,
        trusted_origin: str,
        openpgp_public_key: Path,
        work_directory: Path,
        github_prefix: str,
        ots: OpenTimestampsClient,
        github: GitHubPublisher,
        openpgp_fingerprint: str = PINNED_OPENPGP_FINGERPRINT,
    ):
        self.trusted_rp_id = trusted_rp_id
        self.trusted_origin = trusted_origin
        self.openpgp_public_key = openpgp_public_key
        self.work_directory = work_directory
        self.github_prefix = github_prefix.strip("/")
        self.ots = ots
        self.github = github
        self.openpgp_fingerprint = openpgp_fingerprint

    def _verified_base(self, job: Mapping[str, object]) -> tuple[str, dict[str, bytes]]:
        required = {
            "hash_list": job["hash_list"],
            "bundle_json": job["bundle_json"],
            "genesis_json": job["genesis_json"],
            "genesis_signature": job["genesis_signature"],
        }
        if any(value is None for value in required.values()):
            raise PublicationError("approved job is missing public artifacts")
        artifacts = {
            "hashes.txt": bytes(required["hash_list"]),
            "seal.skyseal.json": bytes(required["bundle_json"]),
            "identity-genesis.json": bytes(required["genesis_json"]),
            "identity-genesis.json.asc": bytes(required["genesis_signature"]),
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
            signature_path = root / "identity-genesis.json.asc"
            hash_path.write_bytes(artifacts["hashes.txt"])
            bundle_path.write_bytes(artifacts["seal.skyseal.json"])
            genesis_path.write_bytes(artifacts["identity-genesis.json"])
            signature_path.write_bytes(artifacts["identity-genesis.json.asc"])
            verify_bundle(
                hash_path,
                bundle_path,
                genesis_path,
                self.trusted_rp_id,
                self.trusted_origin,
            )
            verify_signature(
                artifacts["identity-genesis.json"],
                signature_path,
                self.openpgp_public_key,
                self.openpgp_fingerprint,
            )
        return prefix, artifacts

    @staticmethod
    def _manifest(seal_id: str, artifacts: Mapping[str, bytes]) -> bytes:
        manifest = {
            "schema": "urn:skyseal:publication-manifest:v1",
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
                    "proof": "identity-genesis.json.asc.ots",
                    "target": "identity-genesis.json.asc",
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

    def stamp(self, job: Mapping[str, object]) -> PublicationResult:
        prefix, artifacts = self._verified_base(job)
        bundle_ots = self.ots.stamp(
            "seal.skyseal.json", artifacts["seal.skyseal.json"], self.work_directory
        )
        genesis_ots = self.ots.stamp(
            "identity-genesis.json.asc",
            artifacts["identity-genesis.json.asc"],
            self.work_directory,
        )
        return PublicationResult(prefix, bundle_ots, genesis_ots)

    def publish(self, job: Mapping[str, object]) -> PublicationResult:
        prefix, artifacts = self._verified_base(job)
        if job["ots_proof"] is None or job["genesis_ots_proof"] is None:
            raise PublicationError("approved job has not stored its timestamp proofs")
        bundle_ots = bytes(job["ots_proof"])
        genesis_ots = bytes(job["genesis_ots_proof"])
        artifacts["seal.skyseal.json.ots"] = bundle_ots
        artifacts["identity-genesis.json.asc.ots"] = genesis_ots
        self._upload(prefix, artifacts, updating=False)
        return PublicationResult(prefix, bundle_ots, genesis_ots)

    def upgrade(self, job: Mapping[str, object]) -> PublicationResult:
        prefix, artifacts = self._verified_base(job)
        if job["ots_proof"] is None or job["genesis_ots_proof"] is None:
            raise PublicationError("published job is missing timestamp proofs")
        bundle_ots = self.ots.upgrade(
            "seal.skyseal.json",
            artifacts["seal.skyseal.json"],
            bytes(job["ots_proof"]),
            self.work_directory,
        )
        genesis_ots = self.ots.upgrade(
            "identity-genesis.json.asc",
            artifacts["identity-genesis.json.asc"],
            bytes(job["genesis_ots_proof"]),
            self.work_directory,
        )
        artifacts["seal.skyseal.json.ots"] = bundle_ots
        artifacts["identity-genesis.json.asc.ots"] = genesis_ots
        self._upload(prefix, artifacts, updating=True)
        return PublicationResult(prefix, bundle_ots, genesis_ots)
