from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from email.message import Message
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
    LocalEvidencePublisher,
    PublicationError,
    PublicationResult,
    PublicationWorker,
)
from drive_agent.private_ledger import GoogleSheetsPrivateLedger, build_receipt
from drive_agent.skyseal import SealTransaction
from drive_agent.sky_witness import JMAHimawariWitness, SkyWitnessError, SkyWitnessRecord
from drive_agent.state import JOBS_TABLE, AgentStore


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
        self.content_reads = 0

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
        self.content_reads += 1
        yield self.contents[item.file_id]

    def get_private_display_name(self, file_id: str) -> str:
        return "Owner-only research folder"


class FakeSkySeal:
    def __init__(self):
        self.hash_lists: list[bytes] = []
        self.ledger_commitments: list[str | None] = []
        self.sky_witnesses: list[dict[str, object] | None] = []
        self.private_display_names: list[str | None] = []

    def create(
        self,
        hash_list: bytes,
        ledger_commitment: str | None = None,
        sky_witness: dict[str, object] | None = None,
        private_display_name: str | None = None,
    ) -> SealTransaction:
        self.hash_lists.append(hash_list)
        self.ledger_commitments.append(ledger_commitment)
        self.sky_witnesses.append(sky_witness)
        self.private_display_names.append(private_display_name)
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
                public_root=root / "public",
                google_service_account_file=root / "unused-google.json",
                drive_folder_id="private-inbox-id",
                skyseal_server="https://seal.example.org",
                skyseal_rp_id="seal.example.org",
                skyseal_agent_token_file=root / "unused-agent-token",
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
            self.assertEqual(
                skyseal.private_display_names, ["Owner-only research folder"]
            )
            public_event = json.dumps(submitted)
            self.assertNotIn("private-unit-id", public_event)
            self.assertNotIn("private-file", public_event)
            self.assertNotIn("Owner-only research folder", public_event)
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

    def test_expired_job_retries_from_verified_cache_without_redownload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AgentConfig(
                database_path=root / "agent.sqlite3",
                work_directory=root / "work",
                public_root=root / "public",
                google_service_account_file=root / "unused-google.json",
                drive_folder_id="private-inbox-id",
                skyseal_server="https://seal.example.org",
                skyseal_rp_id="seal.example.org",
                skyseal_agent_token_file=root / "unused-agent-token",
                github_owner="kagaya",
                github_repository="SkySeal",
                github_token_file=root / "unused-github-token",
                settle_seconds=0,
            )
            store = AgentStore(config.database_path)
            store.initialize()
            drive = FakeDrive()
            skyseal = FakeSkySeal()
            runtime = AgentRuntime(config, drive, skyseal, FakePublisher(), store)

            first = runtime.scan(now=100)
            reads_after_first = drive.content_reads
            store.mark_error(
                first[0]["seal_id"], "seal_expired", retryable=True
            )
            second = runtime.scan(now=101)

            self.assertEqual(len(second), 1)
            self.assertEqual(second[0]["hash_source"], "cached_expired")
            self.assertEqual(drive.content_reads, reads_after_first)
            self.assertEqual(skyseal.hash_lists[0], skyseal.hash_lists[1])
            with store.connect() as connection:
                jobs = connection.execute(
                    "SELECT status, error_code FROM jobs ORDER BY job_id"
                ).fetchall()
            self.assertEqual(len(jobs), 2)
            self.assertEqual(
                (jobs[0]["status"], jobs[0]["error_code"]),
                ("error", "seal_expired"),
            )
            self.assertEqual(jobs[1]["status"], "pending_approval")

    def test_pre_update_expired_job_can_be_explicitly_requeued(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AgentConfig(
                database_path=root / "agent.sqlite3",
                work_directory=root / "work",
                public_root=root / "public",
                google_service_account_file=root / "unused-google.json",
                drive_folder_id="private-inbox-id",
                skyseal_server="https://seal.example.org",
                skyseal_rp_id="seal.example.org",
                skyseal_agent_token_file=root / "unused-agent-token",
                github_owner="kagaya",
                github_repository="SkySeal",
                github_token_file=root / "unused-github-token",
                settle_seconds=0,
            )
            store = AgentStore(config.database_path)
            store.initialize()
            runtime = AgentRuntime(
                config, FakeDrive(), FakeSkySeal(), FakePublisher(), store
            )
            first = runtime.scan(now=100)
            store.mark_error(first[0]["seal_id"], "seal_expired")
            self.assertEqual(store.ready_units(0, now=101), [])

            store.requeue_expired(first[0]["seal_id"])
            self.assertEqual(len(store.ready_units(0, now=101)), 1)

    def test_rejected_job_is_not_automatically_retried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AgentConfig(
                database_path=root / "agent.sqlite3",
                work_directory=root / "work",
                public_root=root / "public",
                google_service_account_file=root / "unused-google.json",
                drive_folder_id="private-inbox-id",
                skyseal_server="https://seal.example.org",
                skyseal_rp_id="seal.example.org",
                skyseal_agent_token_file=root / "unused-agent-token",
                github_owner="kagaya",
                github_repository="SkySeal",
                github_token_file=root / "unused-github-token",
                settle_seconds=0,
            )
            store = AgentStore(config.database_path)
            store.initialize()
            runtime = AgentRuntime(
                config, FakeDrive(), FakeSkySeal(), FakePublisher(), store
            )
            first = runtime.scan(now=100)
            store.mark_error(first[0]["seal_id"], "seal_rejected")
            self.assertEqual(runtime.scan(now=101), [])

    def test_legacy_unique_snapshot_schema_migrates_without_losing_job(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = AgentStore(root / "agent.sqlite3")
            store.initialize()
            drive = FakeDrive()
            unit = inventory_unit(drive, drive.inbox)
            reference = store.observe(unit, now=100)
            legacy_jobs = JOBS_TABLE.replace(
                "updated_at INTEGER NOT NULL\n);",
                "updated_at INTEGER NOT NULL,\n    UNIQUE(unit_ref, snapshot_digest)\n);",
            )
            with store.connect() as connection:
                connection.execute("DROP TABLE jobs")
                connection.executescript(legacy_jobs)
            first = store.add_job(
                unit_ref=reference,
                snapshot_digest=unit.snapshot_digest,
                hash_list=hash_unit(drive, unit),
                seal_id="018f0000-0000-7000-8000-000000000001",
                bearer_token="private-bearer-1",
                approval_url="https://seal.example.org/",
                now=100,
            )

            store.initialize()
            store.mark_error(first["seal_id"], "seal_expired", retryable=True)
            second = store.add_job(
                unit_ref=reference,
                snapshot_digest=unit.snapshot_digest,
                hash_list=bytes(first["hash_list"]),
                seal_id="018f0000-0000-7000-8000-000000000002",
                bearer_token="private-bearer-2",
                approval_url="https://seal.example.org/",
                now=101,
            )
            self.assertEqual(second["status"], "pending_approval")
            with store.connect() as connection:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 2
                )

    def test_sky_witness_is_sent_for_signing_and_kept_for_publication(self) -> None:
        metadata = {
            "schema": "urn:skyseal:sky-witness:v1",
            "provider": "Japan Meteorological Agency (JMA)",
            "platform": "Himawari-8/9",
            "product": "Full Disk Band 13 infrared",
            "observation_time": "2026-08-30T01:20:00Z",
            "retrieved_at": "2026-08-30T01:43:21Z",
            "source_url": "https://www.data.jma.go.jp/mscweb/data/himawari/img/fd_/fd__b13_0120.jpg",
            "media_type": "image/jpeg",
            "image_digest": "sha256:" + "c" * 64,
            "attribution": "Japan Meteorological Agency (JMA)",
        }

        class FakeWitness:
            def capture(self, now=None):
                return SkyWitnessRecord(metadata, b"private-test-image")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AgentConfig(
                database_path=root / "agent.sqlite3",
                work_directory=root / "work",
                public_root=root / "public",
                google_service_account_file=root / "unused-google.json",
                drive_folder_id="private-inbox-id",
                skyseal_server="https://seal.example.org",
                skyseal_rp_id="seal.example.org",
                skyseal_agent_token_file=root / "unused-agent-token",
                github_owner="kagaya",
                github_repository="SkySeal",
                github_token_file=root / "unused-github-token",
                settle_seconds=0,
            )
            store = AgentStore(config.database_path)
            store.initialize()
            skyseal = FakeSkySeal()
            runtime = AgentRuntime(
                config, FakeDrive(), skyseal, FakePublisher(), store, None, FakeWitness()
            )
            submitted = runtime.scan(now=1_788_073_600)
            job = store.get_job(submitted[0]["seal_id"])
            self.assertEqual(skyseal.sky_witnesses, [metadata])
            self.assertEqual(json.loads(bytes(job["sky_witness_json"])), metadata)
            self.assertEqual(bytes(job["sky_witness_image"]), b"private-test-image")


class SkyWitnessCaptureTests(unittest.TestCase):
    class Response:
        def __init__(self, image: bytes, last_modified: str):
            self.image = image
            self.headers = Message()
            self.headers["Content-Type"] = "image/jpeg"
            self.headers["Last-Modified"] = last_modified

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit: int) -> bytes:
            return self.image

    def test_capture_accepts_current_slot_and_hashes_exact_jpeg(self) -> None:
        image = b"\xff\xd8" + b"x" * 2048 + b"\xff\xd9"
        response = self.Response(image, "Sun, 30 Aug 2026 01:23:00 GMT")
        witness = JMAHimawariWitness(opener=lambda request, timeout: response, attempts=1)
        result = witness.capture(datetime(2026, 8, 30, 1, 43, 21, tzinfo=timezone.utc))
        self.assertEqual(result.image, image)
        self.assertEqual(result.metadata["observation_time"], "2026-08-30T01:20:00Z")
        self.assertEqual(
            result.metadata["image_digest"], "sha256:" + hashlib.sha256(image).hexdigest()
        )

    def test_capture_rejects_reused_url_from_previous_day(self) -> None:
        image = b"\xff\xd8" + b"x" * 2048 + b"\xff\xd9"
        response = self.Response(image, "Sat, 29 Aug 2026 01:23:00 GMT")
        witness = JMAHimawariWitness(opener=lambda request, timeout: response, attempts=1)
        with self.assertRaisesRegex(SkyWitnessError, "does not match"):
            witness.capture(datetime(2026, 8, 30, 1, 43, 21, tzinfo=timezone.utc))

    def test_private_ledger_receipt_is_committed_without_leaking_into_events(self) -> None:
        class FakeLedger:
            pass

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AgentConfig(
                database_path=root / "agent.sqlite3",
                work_directory=root / "work",
                public_root=root / "public",
                google_service_account_file=root / "unused-google.json",
                drive_folder_id="private-inbox-id",
                skyseal_server="https://seal.example.org",
                skyseal_rp_id="seal.example.org",
                skyseal_agent_token_file=root / "unused-agent-token",
                github_owner="kagaya",
                github_repository="SkySeal",
                github_token_file=root / "unused-github-token",
                private_ledger_spreadsheet_id="private-sheet-id",
                settle_seconds=0,
            )
            store = AgentStore(config.database_path)
            store.initialize()
            skyseal = FakeSkySeal()
            runtime = AgentRuntime(
                config, FakeDrive(), skyseal, FakePublisher(), store, FakeLedger()
            )
            submitted = runtime.scan(now=100)
            self.assertEqual(len(submitted), 1)
            self.assertRegex(skyseal.ledger_commitments[0] or "", r"^sha256:[0-9a-f]{64}$")
            self.assertNotIn("Owner-only", json.dumps(submitted))
            job = store.get_job(submitted[0]["seal_id"])
            self.assertEqual(job["ledger_status"], "pending")
            receipt = json.loads(bytes(job["ledger_receipt"]))
            self.assertEqual(receipt["drive_item"]["name"], "Owner-only research folder")
            self.assertEqual(receipt["drive_item"]["id"], "private-unit-id")


class PrivateLedgerTests(unittest.TestCase):
    def test_sheet_append_is_idempotent_and_keeps_private_mapping_in_receipt(self) -> None:
        class MemoryLedger(GoogleSheetsPrivateLedger):
            def __init__(self):
                super().__init__(object(), "private-sheet", public_origin="https://seal.example.org")
                self.rows: list[list[str]] = []

            def _request(self, url, *, method="GET", payload=None):
                if method == "GET":
                    return {"values": self.rows}
                self.rows.extend(payload["values"])
                return {"updates": {"updatedRows": 1}}

        receipt = build_receipt(
            drive_item_id="private-drive-id",
            drive_item_name="Owner paper.pdf",
            root_mime_type="application/pdf",
            snapshot_digest="a" * 64,
            subject_digest="b" * 64,
            entry_count=1,
        )
        job = {
            "seal_id": "018f0000-0000-7000-8000-000000000001",
            "ledger_receipt": receipt.content,
            "ledger_commitment": receipt.commitment,
            "subject_digest": "b" * 64,
            "publication_prefix": "evidence/2026/08/id",
            "bundle_json": json.dumps(
                {
                    "seal_payload": {
                        "seal_id": "018f0000-0000-7000-8000-000000000001",
                        "created_at": "2026-08-30T00:00:00Z",
                        "private_ledger_commitment": receipt.commitment,
                    }
                }
            ).encode(),
        }
        ledger = MemoryLedger()
        ledger.sync(job)
        ledger.sync(job)
        self.assertEqual(len(ledger.rows), 2)
        self.assertEqual(ledger.rows[1][1], job["seal_id"])
        self.assertEqual(ledger.rows[1][3], "Owner paper.pdf")
        self.assertIn("private-drive-id", ledger.rows[1][13])


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
                        "identity_id": "https://orcid.org/0000-0000-0000-0001",
                    }
                },
                separators=(",", ":"),
            ).encode()
            job = {
                "seal_id": seal_id,
                "hash_list": hashlib.sha256(b"secret paper").hexdigest().encode() + b"\n",
                "bundle_json": bundle,
                "genesis_json": b'{"identity":"public"}\n',
                "identity_activation": b"PUBLIC PASSKEY ACTIVATION",
                "ots_proof": None,
                "identity_ots_proof": None,
            }
            github = FakeGitHub()
            worker = PublicationWorker(
                trusted_rp_id="seal.example.org",
                trusted_origin="https://seal.example.org",
                work_directory=root / "work",
                github_prefix="evidence",
                ots=FakeOTS(),
                local=LocalEvidencePublisher(root / "public"),
                github=github,
            )
            with patch("drive_agent.publication.verify_bundle"), patch(
                "drive_agent.publication.verify_identity_activation"
            ):
                stamped = worker.stamp(job)
                job["ots_proof"] = stamped.bundle_ots
                job["identity_ots_proof"] = stamped.activation_ots
                result = worker.publish(job)
            prefix = f"evidence/2026/08/{seal_id}"
            self.assertEqual(result.prefix, prefix)
            self.assertEqual(github.files, {})
            local_directory = root / "public" / prefix
            self.assertTrue((local_directory / "manifest.json").is_file())
            with patch("drive_agent.publication.verify_bundle"), patch(
                "drive_agent.publication.verify_identity_activation"
            ):
                worker.mirror(job, updating=False)
            index = json.loads((root / "public" / "index.json").read_bytes())
            self.assertEqual(index["publications"][0]["github_mirror"], "synced")
            self.assertEqual(os.stat(local_directory).st_mode & 0o777, 0o755)
            self.assertEqual(
                os.stat(local_directory / "hashes.txt").st_mode & 0o777, 0o644
            )
            self.assertEqual(
                set(github.files),
                {
                    f"{prefix}/hashes.txt",
                    f"{prefix}/seal.skyseal.json",
                    f"{prefix}/identity-genesis.json",
                    f"{prefix}/identity-activation.json",
                    f"{prefix}/seal.skyseal.json.ots",
                    f"{prefix}/identity-activation.json.ots",
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
            job["identity_ots_proof"] = result.activation_ots
            with patch("drive_agent.publication.verify_bundle"), patch(
                "drive_agent.publication.verify_identity_activation"
            ):
                upgraded = worker.upgrade(job)
            self.assertTrue(upgraded.bundle_ots.endswith(b"-UPGRADED"))
            job["ots_proof"] = upgraded.bundle_ots
            job["identity_ots_proof"] = upgraded.activation_ots
            with patch("drive_agent.publication.verify_bundle"), patch(
                "drive_agent.publication.verify_identity_activation"
            ):
                worker.mirror(job, updating=True)
            self.assertEqual(
                github.files[f"{prefix}/seal.skyseal.json"], bundle
            )

    def test_local_publication_refuses_to_replace_immutable_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = LocalEvidencePublisher(root)
            seal_id = "018f0000-0000-7000-8000-000000000001"
            prefix = f"evidence/2026/08/{seal_id}"
            artifacts = {
                "hashes.txt": b"a" * 64 + b"\n",
                "seal.skyseal.json": b"bundle\n",
                "identity-genesis.json": b"genesis\n",
                "identity-activation.json": b"activation\n",
                "seal.skyseal.json.ots": b"ots-one",
                "identity-activation.json.ots": b"ots-two",
            }
            summary = {
                "seal_id": seal_id,
                "created_at": "2026-08-29T00:00:00Z",
                "entry_count": 1,
                "identity_id": "https://orcid.org/0000-0000-0000-0001",
                "relative_path": prefix,
            }
            manifest = b"manifest-one\n"
            local.publish(prefix, artifacts, manifest, summary, updating=False)
            changed = dict(artifacts)
            changed["hashes.txt"] = b"b" * 64 + b"\n"
            with self.assertRaisesRegex(PublicationError, "immutable"):
                local.publish(prefix, changed, manifest, summary, updating=True)
            upgraded = dict(artifacts)
            upgraded["seal.skyseal.json.ots"] = b"ots-one-upgraded"
            local.publish(prefix, upgraded, b"manifest-two\n", summary, updating=True)
            self.assertEqual(
                (root / prefix / "seal.skyseal.json.ots").read_bytes(),
                b"ots-one-upgraded",
            )

    def test_timestamp_proofs_survive_partial_publication_for_retry(self) -> None:
        class RetryPublisher:
            def __init__(self):
                self.stamp_count = 0
                self.publish_count = 0
                self.mirror_count = 0

            def stamp(self, job):
                self.stamp_count += 1
                return PublicationResult(
                    "evidence/2026/08/seal", b"bundle-ots", b"activation-ots"
                )

            def publish(self, job):
                self.publish_count += 1
                return PublicationResult(
                    "evidence/2026/08/seal",
                    bytes(job["ots_proof"]),
                    bytes(job["identity_ots_proof"]),
                )

            def mirror(self, job, *, updating):
                self.mirror_count += 1
                if self.mirror_count == 1:
                    raise PublicationError("simulated partial GitHub failure")
                return PublicationResult(
                    "evidence/2026/08/seal",
                    bytes(job["ots_proof"]),
                    bytes(job["identity_ots_proof"]),
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AgentConfig(
                database_path=root / "agent.sqlite3",
                work_directory=root / "work",
                public_root=root / "public",
                google_service_account_file=root / "unused-google.json",
                drive_folder_id="private-inbox-id",
                skyseal_server="https://seal.example.org",
                skyseal_rp_id="seal.example.org",
                skyseal_agent_token_file=root / "unused-agent-token",
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
                identity_activation=b"activation",
            )
            publisher = RetryPublisher()
            runtime = AgentRuntime(config, drive, FakeSkySeal(), publisher, store)
            first_events = runtime.collect()
            self.assertEqual(first_events[-2]["event"], "published_locally")
            self.assertEqual(first_events[-1]["event"], "github_mirror_pending")
            preserved = store.get_job("018f0000-0000-7000-8000-000000000099")
            self.assertEqual(bytes(preserved["ots_proof"]), b"bundle-ots")
            self.assertEqual(bytes(preserved["identity_ots_proof"]), b"activation-ots")
            self.assertEqual(publisher.stamp_count, 1)
            self.assertEqual(publisher.publish_count, 1)
            self.assertEqual(preserved["status"], "published")
            self.assertEqual(preserved["github_status"], "pending")

            events = runtime.collect()
            self.assertEqual(events[-1]["event"], "github_mirrored")
            self.assertEqual(publisher.stamp_count, 1)
            self.assertEqual(publisher.publish_count, 1)
            published = store.get_job("018f0000-0000-7000-8000-000000000099")
            self.assertEqual(published["status"], "published")
            self.assertEqual(published["github_status"], "synced")

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
