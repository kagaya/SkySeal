from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from drive_agent.agent import AgentRuntime
from drive_agent.config import AgentConfig
from drive_agent.google_drive import (
    DriveAPIError,
    DriveFile,
    FOLDER_MIME,
    hash_unit,
    inventory_unit,
)
from drive_agent.publication import (
    GitHubPublisher,
    PublicationError,
    PublicationResult,
    PublicationWorker,
)
from drive_agent.skyseal import SealTransaction
from drive_agent.state import AgentStore


def binary_file(file_id: str, content: bytes, modified: str = "2026-08-29T00:00:00Z") -> DriveFile:
    return DriveFile(
        file_id=file_id,
        mime_type="application/octet-stream",
        modified_time=modified,
        size=len(content),
        sha256_checksum=hashlib.sha256(content).hexdigest(),
        head_revision_id="revision-" + modified,
        parents=("private-folder-id",),
        can_download=True,
    )


def folder(file_id: str) -> DriveFile:
    return DriveFile(
        file_id=file_id,
        mime_type=FOLDER_MIME,
        modified_time="2026-08-29T00:00:00Z",
        size=None,
        sha256_checksum=None,
        head_revision_id=None,
        parents=("private-inbox-id",),
        can_download=False,
    )


class FakeDrive:
    def __init__(self):
        self.inbox = folder("private-unit-id")
        self.contents = {
            "private-file-a": b"same private research bytes",
            "private-file-b": b"same private research bytes",
        }
        self.modified = "2026-08-29T00:00:00Z"

    def list_children(self, folder_id: str) -> list[DriveFile]:
        if folder_id == "private-inbox-id":
            return [self.inbox]
        if folder_id == "private-unit-id":
            return [
                binary_file(file_id, content, self.modified)
                for file_id, content in sorted(self.contents.items())
            ]
        return []

    def iter_content(self, item: DriveFile):
        yield self.contents[item.file_id]


class FakeSkySeal:
    def __init__(self):
        self.hash_lists: list[bytes] = []

    def create(self, hash_list: bytes) -> SealTransaction:
        self.hash_lists.append(hash_list)
        number = len(self.hash_lists)
        return SealTransaction(
            seal_id=f"018f0000-0000-7000-8000-{number:012d}",
            bearer_token="private-bearer-token",
            approval_url="https://seal.example.org/",
            expires_at=2_000_000_000,
        )


class FakePublisher:
    def publish(self, job):  # pragma: no cover - scan test never publishes
        raise AssertionError("unexpected publication")


class DriveHashingTests(unittest.TestCase):
    def test_folder_hashing_sorts_and_deduplicates_without_names(self) -> None:
        drive = FakeDrive()
        unit = inventory_unit(drive, drive.inbox)
        hash_list = hash_unit(drive, unit)
        expected = hashlib.sha256(b"same private research bytes").hexdigest().encode() + b"\n"
        self.assertEqual(hash_list, expected)
        self.assertFalse(hasattr(unit.files[0], "name"))
        self.assertNotIn(b"private-file", hash_list)

    def test_download_must_match_drive_sha256(self) -> None:
        drive = FakeDrive()
        unit = inventory_unit(drive, drive.inbox)
        drive.contents["private-file-a"] = b"changed after metadata"
        with self.assertRaisesRegex(DriveAPIError, "does not match"):
            hash_unit(drive, unit)


class AgentScanTests(unittest.TestCase):
    def test_stable_private_unit_creates_one_hash_only_identity_inbox_job(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AgentConfig(
                database_path=root / "agent.sqlite3",
                work_directory=root / "work",
                google_service_account_file=root / "unused-google.json",
                drive_folder_id="private-inbox-id",
                skyseal_server="https://seal.example.org",
                skyseal_rp_id="seal.example.org",
                skyseal_agent_token_file=root / "unused-agent-token",
                openpgp_public_key=root / "unused-public-key",
                github_owner="kagaya",
                github_repository="SkySeal",
                github_token_file=root / "unused-github-token",
                settle_seconds=10,
            )
            store = AgentStore(config.database_path)
            store.initialize()
            drive = FakeDrive()
            skyseal = FakeSkySeal()
            runtime = AgentRuntime(config, drive, skyseal, FakePublisher(), store)

            self.assertEqual(runtime.scan(now=100), [])
            submitted = runtime.scan(now=111)
            self.assertEqual(len(submitted), 1)
            self.assertEqual(len(skyseal.hash_lists), 1)
            self.assertEqual(submitted[0]["entry_count"], 1)
            public_event = json.dumps(submitted)
            self.assertNotIn("private-unit-id", public_event)
            self.assertNotIn("private-file", public_event)
            self.assertEqual(os.stat(config.database_path).st_mode & 0o777, 0o600)

            with store.connect() as connection:
                unit = connection.execute("SELECT * FROM units").fetchone()
                job = connection.execute("SELECT * FROM jobs").fetchone()
            self.assertEqual(unit["drive_unit_id"], "private-unit-id")
            self.assertEqual(job["status"], "pending_approval")
            self.assertNotIn("private-file", bytes(job["hash_list"]).decode())

            drive.contents["private-file-b"] = b"new private revision"
            drive.modified = "2026-08-29T00:01:00Z"
            self.assertEqual(runtime.scan(now=112), [])
            second = runtime.scan(now=123)
            self.assertEqual(len(second), 1)
            self.assertEqual(len(skyseal.hash_lists), 2)
            self.assertEqual(second[0]["entry_count"], 2)


class FakeOTS:
    def stamp(self, target_name: str, target: bytes, work_directory: Path) -> bytes:
        return b"OTS-STAMP\x00" + hashlib.sha256(target).digest()

    def upgrade(
        self, target_name: str, target: bytes, proof: bytes, work_directory: Path
    ) -> bytes:
        return proof if proof.endswith(b"-UPGRADED") else proof + b"-UPGRADED"


class FakeGitHub:
    def __init__(self):
        self.files: dict[str, bytes] = {}

    def put(self, path: str, content: bytes, *, allow_update: bool = False) -> str:
        if path in self.files and self.files[path] != content and not allow_update:
            raise AssertionError("unexpected evidence replacement")
        self.files[path] = content
        return "https://github.example/" + path


class PublicationTests(unittest.TestCase):
    def test_publication_uses_opaque_paths_and_updates_only_timestamp_proofs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seal_id = "018f0000-0000-7000-8000-000000000001"
            bundle = json.dumps(
                {
                    "seal_payload": {
                        "seal_id": seal_id,
                        "created_at": "2026-08-29T00:00:00Z",
                    }
                },
                separators=(",", ":"),
            ).encode()
            job = {
                "seal_id": seal_id,
                "hash_list": hashlib.sha256(b"secret paper").hexdigest().encode() + b"\n",
                "bundle_json": bundle,
                "genesis_json": b'{"identity":"public"}\n',
                "genesis_signature": b"PUBLIC OPENPGP SIGNATURE",
                "ots_proof": None,
                "genesis_ots_proof": None,
            }
            github = FakeGitHub()
            worker = PublicationWorker(
                trusted_rp_id="seal.example.org",
                trusted_origin="https://seal.example.org",
                openpgp_public_key=root / "unused.asc",
                work_directory=root / "work",
                github_prefix="evidence",
                ots=FakeOTS(),
                github=github,
            )
            with patch("drive_agent.publication.verify_bundle"), patch(
                "drive_agent.publication.verify_signature"
            ):
                stamped = worker.stamp(job)
                job["ots_proof"] = stamped.bundle_ots
                job["genesis_ots_proof"] = stamped.genesis_ots
                result = worker.publish(job)
            prefix = f"evidence/2026/08/{seal_id}"
            self.assertEqual(result.prefix, prefix)
            self.assertEqual(
                set(github.files),
                {
                    f"{prefix}/hashes.txt",
                    f"{prefix}/seal.skyseal.json",
                    f"{prefix}/identity-genesis.json",
                    f"{prefix}/identity-genesis.json.asc",
                    f"{prefix}/seal.skyseal.json.ots",
                    f"{prefix}/identity-genesis.json.asc.ots",
                    f"{prefix}/manifest.json",
                },
            )
            all_public_bytes = b"".join(github.files.values())
            self.assertNotIn(b"revealing-paper-name", all_public_bytes)
            self.assertNotIn(b"private-drive-file-id", all_public_bytes)
            manifest = json.loads(github.files[f"{prefix}/manifest.json"])
            self.assertEqual(manifest["seal_id"], seal_id)
            self.assertEqual(len(manifest["timestamp_targets"]), 2)

            job["ots_proof"] = result.bundle_ots
            job["genesis_ots_proof"] = result.genesis_ots
            with patch("drive_agent.publication.verify_bundle"), patch(
                "drive_agent.publication.verify_signature"
            ):
                upgraded = worker.upgrade(job)
            self.assertTrue(upgraded.bundle_ots.endswith(b"-UPGRADED"))
            self.assertEqual(
                github.files[f"{prefix}/seal.skyseal.json"], bundle
            )

    def test_timestamp_proofs_survive_partial_publication_for_retry(self) -> None:
        class RetryPublisher:
            def __init__(self):
                self.stamp_count = 0
                self.publish_count = 0

            def stamp(self, job):
                self.stamp_count += 1
                return PublicationResult("evidence/2026/08/seal", b"bundle-ots", b"genesis-ots")

            def publish(self, job):
                self.publish_count += 1
                if self.publish_count == 1:
                    raise PublicationError("simulated partial GitHub failure")
                return PublicationResult(
                    "evidence/2026/08/seal",
                    bytes(job["ots_proof"]),
                    bytes(job["genesis_ots_proof"]),
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AgentConfig(
                database_path=root / "agent.sqlite3",
                work_directory=root / "work",
                google_service_account_file=root / "unused-google.json",
                drive_folder_id="private-inbox-id",
                skyseal_server="https://seal.example.org",
                skyseal_rp_id="seal.example.org",
                skyseal_agent_token_file=root / "unused-agent-token",
                openpgp_public_key=root / "unused-public-key",
                github_owner="kagaya",
                github_repository="SkySeal",
                github_token_file=root / "unused-github-token",
                settle_seconds=0,
            )
            store = AgentStore(config.database_path)
            store.initialize()
            drive = FakeDrive()
            unit = inventory_unit(drive, drive.inbox)
            reference = store.observe(unit, now=100)
            hash_list = hash_unit(drive, unit)
            store.add_job(
                unit_ref=reference,
                snapshot_digest=unit.snapshot_digest,
                hash_list=hash_list,
                seal_id="018f0000-0000-7000-8000-000000000099",
                bearer_token="private-bearer",
                approval_url="https://seal.example.org/",
                now=100,
            )
            store.store_approved_artifacts(
                "018f0000-0000-7000-8000-000000000099",
                bundle_json=b"bundle",
                genesis_json=b"genesis",
                genesis_signature=b"signature",
            )
            publisher = RetryPublisher()
            runtime = AgentRuntime(config, drive, FakeSkySeal(), publisher, store)
            with self.assertRaises(PublicationError):
                runtime.collect()
            preserved = store.get_job("018f0000-0000-7000-8000-000000000099")
            self.assertEqual(bytes(preserved["ots_proof"]), b"bundle-ots")
            self.assertEqual(bytes(preserved["genesis_ots_proof"]), b"genesis-ots")
            self.assertEqual(publisher.stamp_count, 1)

            events = runtime.collect()
            self.assertEqual(events[-1]["event"], "published")
            self.assertEqual(publisher.stamp_count, 1)
            published = store.get_job("018f0000-0000-7000-8000-000000000099")
            self.assertEqual(published["status"], "published")

    def test_github_contents_are_idempotent_and_evidence_is_immutable(self) -> None:
        class MemoryGitHub(GitHubPublisher):
            def __init__(self):
                super().__init__(
                    owner="kagaya",
                    repository="SkySeal",
                    branch="main",
                    token="private-token",
                )
                self.remote: dict[str, tuple[bytes, str]] = {}

            def _request(self, method, path, payload=None):
                endpoint = path.split("?", 1)[0]
                if method == "GET":
                    if endpoint not in self.remote:
                        return 404, b'{}'
                    content, sha = self.remote[endpoint]
                    encoded = base64_with_line_break(content)
                    return 200, json.dumps(
                        {"content": encoded, "sha": sha, "html_url": "https://example/item"}
                    ).encode()
                content = __import__("base64").b64decode(payload["content"])
                sha = hashlib.sha1(content).hexdigest()
                self.remote[endpoint] = (content, sha)
                return 201 if "sha" not in payload else 200, json.dumps(
                    {"content": {"html_url": "https://example/item"}}
                ).encode()

        def base64_with_line_break(data: bytes) -> str:
            encoded = __import__("base64").b64encode(data).decode()
            return "\n".join(encoded[index : index + 8] for index in range(0, len(encoded), 8))

        publisher = MemoryGitHub()
        path = "evidence/2026/08/seal/hashes.txt"
        publisher.put(path, b"first bytes")
        publisher.put(path, b"first bytes")
        with self.assertRaisesRegex(PublicationError, "refusing"):
            publisher.put(path, b"different evidence")
        publisher.put(path, b"updated proof", allow_update=True)
        self.assertEqual(next(iter(publisher.remote.values()))[0], b"updated proof")


if __name__ == "__main__":
    unittest.main()
