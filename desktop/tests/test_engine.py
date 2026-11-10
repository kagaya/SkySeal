"""Offline workflow tests use injected network/Windows boundaries, real ES256."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from desktop.engine import proof
from desktop.engine.core import Engine, EngineError, atomic_write
from drive_agent.sky_witness import SkyWitnessRecord
from verifier.skyseal_verify import VerificationError, canonical_json, encode_base64url


class TestSigner:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.calls = 0
        self.cancel = False

    def availability(self):
        return {"available": True, "test_only": True}

    def register(self, rp_id, origin, user_id, user_name):
        public = self.key.public_key().public_numbers()
        return {"raw_id": encode_base64url(b"private-credential-routing-id"),
            "user_id": encode_base64url(user_id), "rp_id": rp_id, "origin": origin,
            "algorithm": -7, "public_key": {"kty": "EC", "crv": "P-256",
                "x": encode_base64url(public.x.to_bytes(32, "big")), "y": encode_base64url(public.y.to_bytes(32, "big"))}}

    def sign(self, credential, challenge, rp_id, origin):
        if self.cancel:
            raise RuntimeError("cancelled by test user")
        self.calls += 1
        client = canonical_json({"type": "webauthn.get", "challenge": encode_base64url(challenge), "origin": origin})
        auth = hashlib.sha256(rp_id.encode()).digest() + b"\x05" + self.calls.to_bytes(4, "big")
        signature = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {"client_data_json": encode_base64url(client), "authenticator_data": encode_base64url(auth), "signature": encode_base64url(signature)}


class TestAuth:
    def login(self, client_id, nonce, data_dir):
        self.nonce, self.client_id = nonce, client_id
        return {"id_token": "test-issuer-token"}

    def verify_id_token(self, token, client_id, nonce, **kwargs):
        if token != "test-issuer-token" or nonce != self.nonce or client_id != self.client_id:
            raise VerificationError("test ORCID token binding mismatch")
        return {"sub": "0000-0003-3001-7690", "name": "Researcher"}


class TestWitness:
    def capture(self):
        image = b"\xff\xd8" + b"fixed test image bytes" * 80 + b"\xff\xd9"
        return SkyWitnessRecord({"schema": "urn:skyseal:sky-witness:v1", "provider": "Japan Meteorological Agency (JMA)",
            "platform": "Himawari-8/9", "product": "Full Disk Band 13 infrared", "observation_time": "2026-11-10T00:00:00Z",
            "retrieved_at": "2026-11-10T00:25:00Z", "source_url": "https://www.data.jma.go.jp/mscweb/data/himawari/img/fd_/fd__b13_0000.jpg",
            "media_type": "image/jpeg", "image_digest": proof.digest(image), "attribution": "Japan Meteorological Agency (JMA)"}, image)


class TestTimestamps:
    def __init__(self):
        self.confirmed, self.fail = False, False
        self.stamps = 0

    def stamp(self, target):
        self.stamps += 1
        if self.fail:
            raise OSError("offline")
        return b"test-timestamp:" + hashlib.sha256(target.read_bytes()).digest()

    def upgrade(self, target, timestamp):
        if self.fail:
            raise OSError("offline")
        return timestamp.read_bytes()

    def verify(self, target, timestamp):
        return {"status": "confirmed" if self.confirmed else "pending", "trust_mode": "https_explorers", "full_chain_validated": False}


class EngineCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.signer, self.auth, self.timestamps = TestSigner(), TestAuth(), TestTimestamps()
        self.engine = self.new_engine()
        self.source = self.base / "研究 data.txt"
        self.source.write_bytes(b"\x00exact research bytes\r\n")

    def tearDown(self):
        self.engine.close()
        self.temp.cleanup()

    def new_engine(self):
        return Engine(self.base / "state", signer=self.signer, auth=self.auth,
            witness=TestWitness(), timestamps=self.timestamps)

    def enroll(self):
        self.engine.configure(orcid_client_id="APP-TESTCLIENT12345")
        self.engine.identity_enroll()

    def sealed(self):
        self.enroll()
        job = self.engine.prepare([str(self.source)])
        return self.engine.seal(job["job_id"])

    def test_prepare_is_offline_and_preserves_exact_copy(self):
        job = self.engine.prepare([str(self.source)])
        self.assertEqual(job["state"], "prepared")
        self.assertEqual(self.signer.calls, 0)
        self.source.write_bytes(b"edited original")
        snapshot = self.engine._jobdir(job["job_id"]) / "originals" / job["items"][0]["snapshot"]
        self.assertEqual(snapshot.read_bytes(), b"\x00exact research bytes\r\n")

    def test_full_roundtrip_pending_is_not_confirmed_and_export_is_private(self):
        job = self.sealed()
        self.assertEqual(job["ots_state"], "pending")
        exported = self.base / "proof.zip"
        self.engine.export(job["job_id"], str(exported))
        with zipfile.ZipFile(exported) as archive:
            self.assertEqual(set(archive.namelist()), proof.PUBLIC_ARTIFACTS)
            raw = b"".join(archive.read(name) for name in archive.namelist())
            self.assertNotIn(self.source.name.encode(), raw)
            self.assertNotIn(b"private-credential-routing-id", raw)
            self.assertNotIn(encode_base64url(b"private-credential-routing-id").encode(), raw)
        result = self.engine.verify(str(exported), str(self.source))
        self.assertTrue(result["signature_valid"])
        self.assertFalse(result["time_confirmed"])
        self.assertTrue(result["candidate_match"])
        self.assertEqual(result["timestamp_details"]["seal.skyseal.json"]["trust_mode"], "https_explorers")

    def test_restart_resume_never_resigns_and_immutable_bytes_remain(self):
        self.timestamps.fail = True
        job = self.sealed()
        directory = self.engine._jobdir(job["job_id"]) / "evidence"
        signed = (directory / "seal.skyseal.json").read_bytes()
        count = self.signer.calls
        self.engine.close()
        self.engine = self.new_engine()
        self.timestamps.fail, self.timestamps.confirmed = False, True
        result = self.engine.resume(job["job_id"])
        self.assertEqual(result["ots_state"], "confirmed")
        self.assertEqual(self.signer.calls, count)
        self.assertEqual((directory / "seal.skyseal.json").read_bytes(), signed)

    def test_cancel_cannot_create_a_seal(self):
        self.enroll()
        job = self.engine.prepare([str(self.source)])
        self.signer.cancel = True
        with self.assertRaises(RuntimeError):
            self.engine.seal(job["job_id"])
        self.assertEqual(self.engine.get(job["job_id"])["state"], "prepared")
        self.assertFalse((self.engine._jobdir(job["job_id"]) / "evidence").exists())

    def test_snapshot_tamper_rejected_before_approval(self):
        self.enroll()
        job = self.engine.prepare([str(self.source)])
        (self.engine._jobdir(job["job_id"]) / "originals" / job["items"][0]["snapshot"]).write_bytes(b"changed")
        with self.assertRaises(EngineError):
            self.engine.seal(job["job_id"])
        self.assertEqual(self.signer.calls, 1)  # Enrollment activation only.

    def test_prepared_state_requires_explicit_approval_for_resume(self):
        job = self.engine.prepare([str(self.source)])
        with self.assertRaises(EngineError):
            self.engine.resume(job["job_id"])

    def test_wrong_candidate_and_path_traversal_archive_rejected(self):
        job = self.sealed()
        wrong = self.base / "wrong.txt"
        wrong.write_bytes(b"different bytes")
        with self.assertRaises(VerificationError):
            self.engine.verify(str(self.engine._jobdir(job["job_id"]) / "evidence"), str(wrong))
        bad = self.base / "bad.zip"
        with zipfile.ZipFile(bad, "w") as archive:
            archive.writestr("../escape", b"bad")
        with self.assertRaises(EngineError):
            self.engine.verify(str(bad))
        self.assertFalse((self.base / "escape").exists())

    def test_duplicate_content_hashes_deduplicated_without_losing_private_items(self):
        second = self.base / "second.txt"
        second.write_bytes(self.source.read_bytes())
        job = self.engine.prepare([str(self.source), str(second)])
        self.assertEqual(job["entry_count"], 1)
        self.assertEqual(len(job["items"]), 2)

    def test_symlink_rejected(self):
        link = self.base / "link"
        try:
            link.symlink_to(self.source)
        except OSError:
            self.skipTest("symlink privilege unavailable")
        with self.assertRaises(EngineError):
            self.engine.prepare([str(link)])

    def test_committed_directory_recovers_after_stale_database_state(self):
        job = self.sealed()
        job["state"] = "sealing"
        self.engine._save_job(job)
        self.assertEqual(self.engine.get(job["job_id"])["state"], "sealed")
        count = self.signer.calls
        self.engine.seal(job["job_id"])
        self.assertEqual(self.signer.calls, count)

    def test_power_loss_between_timestamp_and_manifest_is_recoverable(self):
        job = self.sealed()
        directory = self.engine._jobdir(job["job_id"]) / "evidence"
        signed = (directory / "seal.skyseal.json").read_bytes()
        original_write = atomic_write
        def crash_on_manifest(path, data):
            if path.name == "manifest.json":
                raise OSError("simulated power loss")
            original_write(path, data)
        with mock.patch("desktop.engine.core.atomic_write", side_effect=crash_on_manifest):
            with self.assertRaises(OSError):
                self.engine._update_timestamp(job["job_id"], "seal.skyseal.json.ots", b"updated test proof")
        self.assertTrue((self.engine._jobdir(job["job_id"]) / ".ots-update.json").exists())
        self.engine.close()
        self.engine = self.new_engine()
        self.engine.resume(job["job_id"])
        self.assertFalse((self.engine._jobdir(job["job_id"]) / ".ots-update.json").exists())
        self.assertEqual((directory / "seal.skyseal.json").read_bytes(), signed)
        self.assertTrue(self.engine.verify(str(directory))["signature_valid"])

    def test_second_process_cannot_mutate_while_lock_is_held(self):
        other = self.new_engine()
        try:
            with self.engine.mutation():
                with self.assertRaisesRegex(EngineError, "Another SkySeal"):
                    other.dispatch({"op": "prepare", "params": {"paths": [str(self.source)]}})
        finally:
            other.close()


if __name__ == "__main__":
    unittest.main()
