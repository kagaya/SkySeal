"""Offline workflow tests use injected network/Windows boundaries, real ES256."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from desktop.engine import proof
from desktop.engine.core import Engine, EngineError, atomic_write, default_data_dir
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


class TestMacSigner(TestSigner):
    """Test-only boundary: a real ES256 signature, not a Keychain ceremony."""
    PROFILE = proof.MAC_PROFILE

    def sign(self, credential, challenge, rp_id, origin):
        if self.cancel:
            raise RuntimeError("cancelled by test user")
        self.calls += 1
        signature = self.key.sign(challenge, ec.ECDSA(hashes.SHA256()))
        return {"method": proof.MAC_METHOD, "signature": encode_base64url(signature),
                "key_tag": "private-mac-key-routing-tag"}


class TestLinuxSigner(TestSigner):
    """Real ES256 test boundary; this fixture does not claim a Pinentry prompt."""
    PROFILE = proof.LINUX_PROFILE

    def register(self, rp_id, origin, user_id, user_name):
        generated = super().register(rp_id, origin, user_id, user_name)
        return {"key_id": "private-linux-key-routing-id", "algorithm": -7,
                "public_key": generated["public_key"], "method": proof.LINUX_METHOD,
                "key_storage": "encrypted-local-pkcs8", "approval_policy": "passphrase-per-signature",
                "hardware_attested": False, "private_key_extractable": True}

    def sign(self, credential, challenge, rp_id, origin):
        if self.cancel:
            raise RuntimeError("cancelled by test user")
        self.calls += 1
        signature = self.key.sign(challenge, ec.ECDSA(hashes.SHA256()))
        return {"method": proof.LINUX_METHOD, "signature": encode_base64url(signature),
                "key_path": "private-linux-key-file-path"}


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

    def test_stable_file_allows_path_and_handle_timestamp_precision_difference(self):
        info = self.source.stat()
        path_info = SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_size=info.st_size,
            st_mtime_ns=1234567890123456789, st_ctime_ns=1234567890123456789)
        handle_info = SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_size=info.st_size,
            st_mtime_ns=1234567890000000000, st_ctime_ns=1234567890000000000)
        destination = self.base / "precision-copy.bin"
        with mock.patch("desktop.engine.core._safe_source", return_value=path_info), \
                mock.patch("desktop.engine.core.os.fstat", return_value=handle_info):
            size, digest = self.engine._copy_snapshot(self.source, destination)
        self.assertEqual(size, info.st_size)
        self.assertEqual(digest, hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertEqual(destination.read_bytes(), self.source.read_bytes())

    def test_handle_timestamp_change_still_rejects_snapshot(self):
        info = self.source.stat()
        def handle_info(timestamp):
            return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_size=info.st_size,
                st_mtime_ns=timestamp, st_ctime_ns=timestamp)
        with mock.patch("desktop.engine.core.os.fstat", side_effect=[handle_info(100), handle_info(200)]):
            with self.assertRaisesRegex(EngineError, "changed during copying"):
                self.engine._copy_snapshot(self.source, self.base / "changed-copy.bin")

    def test_path_timestamp_change_still_rejects_snapshot(self):
        info = self.source.stat()
        def path_info(timestamp):
            return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino, st_size=info.st_size,
                st_mtime_ns=timestamp, st_ctime_ns=timestamp)
        with mock.patch("desktop.engine.core._safe_source", side_effect=[path_info(100), path_info(200)]):
            with self.assertRaisesRegex(EngineError, "changed during copying"):
                self.engine._copy_snapshot(self.source, self.base / "changed-path-copy.bin")

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


class MacEngineCase(unittest.TestCase):
    new_engine = EngineCase.new_engine
    enroll = EngineCase.enroll
    sealed = EngineCase.sealed
    tearDown = EngineCase.tearDown

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.signer, self.auth, self.timestamps = TestMacSigner(), TestAuth(), TestTimestamps()
        self.engine = self.new_engine()
        self.source = self.base / "研究 data.txt"
        self.source.write_bytes(b"\x00exact research bytes\r\n")

    test_cancel_cannot_create_a_seal = EngineCase.test_cancel_cannot_create_a_seal
    test_restart_resume_never_resigns_and_immutable_bytes_remain = EngineCase.test_restart_resume_never_resigns_and_immutable_bytes_remain
    test_power_loss_between_timestamp_and_manifest_is_recoverable = EngineCase.test_power_loss_between_timestamp_and_manifest_is_recoverable

    def test_mac_roundtrip_does_not_claim_portable_user_verification(self):
        job = self.sealed()
        archive_path = self.base / "mac-proof.zip"
        self.engine.export(job["job_id"], str(archive_path))
        with zipfile.ZipFile(archive_path) as archive:
            genesis = json.loads(archive.read("identity-genesis.json"))
            seal = json.loads(archive.read("seal.skyseal.json"))
            self.assertEqual(genesis["profile"], proof.MAC_PROFILE)
            self.assertEqual(genesis["approval_method"], proof.MAC_METHOD)
            self.assertNotIn("rp_id", genesis)
            self.assertNotIn("origin", genesis)
            self.assertEqual(set(seal["assertion"]), {"method", "signature"})
            self.assertNotIn(b"private-mac-key-routing-tag", b"".join(archive.read(n) for n in archive.namelist()))
        report = self.engine.verify(str(archive_path), str(self.source))
        self.assertTrue(report["signature_valid"])
        self.assertTrue(report["candidate_match"])
        self.assertIsNone(report["user_verified"])
        self.assertIsNone(report["user_present"])
        self.assertEqual(report["authentication_assurance"], "local_user_presence_not_attested")

    def test_windows_signer_host_can_independently_verify_mac_evidence(self):
        job = self.sealed()
        windows_signer = TestSigner()
        other = Engine(self.base / "windows-verifier", signer=windows_signer,
                       auth=self.auth, timestamps=self.timestamps)
        try:
            # No local identity is enrolled, and verification must not use the
            # host's signer or the identity's private Keychain routing data.
            report = other.verify(str(self.engine._jobdir(job["job_id"]) / "evidence"),
                                  trusted_client_id="APP-TESTCLIENT12345")
            self.assertEqual(report["profile"], proof.MAC_PROFILE)
            self.assertTrue(report["signature_valid"])
            self.assertEqual(windows_signer.calls, 0)
        finally:
            other.close()

    def test_copied_identity_cannot_silently_change_platform_signer(self):
        self.enroll()
        job = self.engine.prepare([str(self.source)])
        windows_signer = TestSigner()
        other = Engine(self.base / "state", signer=windows_signer, auth=self.auth,
                       witness=TestWitness(), timestamps=self.timestamps)
        try:
            self.assertFalse(other.status()["identity"]["signing_compatible"])
            with self.assertRaisesRegex(EngineError, "different platform signer"):
                other.seal(job["job_id"])
            self.assertEqual(windows_signer.calls, 0)
            self.assertEqual(other.get(job["job_id"])["state"], "prepared")
        finally:
            other.close()


class LinuxEngineCase(unittest.TestCase):
    new_engine = EngineCase.new_engine
    enroll = EngineCase.enroll
    sealed = EngineCase.sealed
    tearDown = EngineCase.tearDown

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.signer, self.auth, self.timestamps = TestLinuxSigner(), TestAuth(), TestTimestamps()
        self.engine = self.new_engine()
        self.source = self.base / "研究 data.txt"
        self.source.write_bytes(b"\x00exact research bytes\r\n")

    test_cancel_cannot_create_a_seal = EngineCase.test_cancel_cannot_create_a_seal
    test_restart_resume_never_resigns_and_immutable_bytes_remain = EngineCase.test_restart_resume_never_resigns_and_immutable_bytes_remain
    test_power_loss_between_timestamp_and_manifest_is_recoverable = EngineCase.test_power_loss_between_timestamp_and_manifest_is_recoverable

    def test_linux_export_is_independent_of_private_key_storage_and_prompt_claims(self):
        job = self.sealed()
        archive_path = self.base / "linux-proof.zip"
        self.engine.export(job["job_id"], str(archive_path))
        with zipfile.ZipFile(archive_path) as archive:
            genesis = json.loads(archive.read("identity-genesis.json"))
            seal = json.loads(archive.read("seal.skyseal.json"))
            self.assertEqual(genesis["profile"], proof.LINUX_PROFILE)
            self.assertEqual(genesis["approval_method"], proof.LINUX_METHOD)
            self.assertEqual(genesis["key_namespace"], proof.LINUX_NAMESPACE)
            self.assertNotIn("rp_id", genesis)
            self.assertNotIn("origin", genesis)
            self.assertNotIn("key_storage", genesis)
            self.assertEqual(set(seal["assertion"]), {"method", "signature"})
            exported = b"".join(archive.read(n) for n in archive.namelist())
            self.assertNotIn(b"private-linux-key-routing-id", exported)
            self.assertNotIn(b"private-linux-key-file-path", exported)
            self.assertNotIn(self.source.name.encode(), exported)
        report = self.engine.verify(str(archive_path), str(self.source))
        self.assertTrue(report["signature_valid"])
        self.assertTrue(report["candidate_match"])
        self.assertIsNone(report["user_verified"])
        self.assertIsNone(report["user_present"])
        self.assertEqual(report["approval_method"], proof.LINUX_METHOD)
        self.assertEqual(report["authentication_assurance"], "local_user_presence_not_attested")
        self.assertTrue(any("key storage protection" in warning for warning in report["warnings"]))

    def test_windows_and_mac_hosts_verify_linux_without_private_credentials(self):
        job = self.sealed()
        for index, signer in enumerate((TestSigner(), TestMacSigner())):
            with self.subTest(profile=getattr(signer, "PROFILE", proof.PROFILE)):
                other = Engine(self.base / f"external-verifier-{index}", signer=signer,
                               auth=self.auth, timestamps=self.timestamps)
                try:
                    report = other.verify(str(self.engine._jobdir(job["job_id"]) / "evidence"),
                                          trusted_client_id="APP-TESTCLIENT12345")
                    self.assertEqual(report["profile"], proof.LINUX_PROFILE)
                    self.assertTrue(report["signature_valid"])
                    self.assertEqual(signer.calls, 0)
                finally:
                    other.close()

    def test_linux_host_verifies_existing_windows_and_mac_profiles(self):
        for index, signer in enumerate((TestSigner(), TestMacSigner())):
            with self.subTest(profile=getattr(signer, "PROFILE", proof.PROFILE)):
                other = Engine(self.base / f"other-platform-{index}", signer=signer,
                               auth=self.auth, witness=TestWitness(), timestamps=self.timestamps)
                try:
                    other.configure(orcid_client_id="APP-TESTCLIENT12345")
                    other.identity_enroll()
                    job = other.prepare([str(self.source)])
                    other.seal(job["job_id"])
                    report = self.engine.verify(str(other._jobdir(job["job_id"]) / "evidence"),
                                                trusted_client_id="APP-TESTCLIENT12345")
                    self.assertEqual(report["profile"], getattr(signer, "PROFILE", proof.PROFILE))
                    self.assertTrue(report["signature_valid"])
                    self.assertEqual(self.signer.calls, 0)
                finally:
                    other.close()

    def test_copied_linux_identity_cannot_be_signed_by_windows_or_mac(self):
        self.enroll()
        job = self.engine.prepare([str(self.source)])
        for signer in (TestSigner(), TestMacSigner()):
            other = Engine(self.base / "state", signer=signer, auth=self.auth,
                           witness=TestWitness(), timestamps=self.timestamps)
            try:
                self.assertFalse(other.status()["identity"]["signing_compatible"])
                with self.assertRaisesRegex(EngineError, "different platform signer"):
                    other.seal(job["job_id"])
                self.assertEqual(signer.calls, 0)
                self.assertEqual(other.get(job["job_id"])["state"], "prepared")
            finally:
                other.close()

    def test_linux_default_signer_is_bound_to_engine_data_directory(self):
        constructor = mock.Mock(return_value=self.signer)
        with mock.patch("desktop.engine.core.sys.platform", "linux"), mock.patch.dict(
                "sys.modules", {"desktop.engine.linux_auth": SimpleNamespace(LinuxSigner=constructor)}):
            other = Engine(self.base / "native-linux", auth=self.auth,
                           witness=TestWitness(), timestamps=self.timestamps)
            try:
                constructor.assert_called_once_with(other.root)
                self.assertEqual(other.profile, proof.LINUX_PROFILE)
            finally:
                other.close()

    def test_linux_data_location_obeys_xdg_and_rejects_relative_explicit_override(self):
        with mock.patch("desktop.engine.core.sys.platform", "linux"), \
                mock.patch("desktop.engine.core.Path.home", return_value=self.base):
            with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(self.base / "custom-data")}, clear=True):
                self.assertEqual(default_data_dir(), self.base / "custom-data" / "SkySeal")
            with mock.patch.dict(os.environ, {"XDG_DATA_HOME": "relative-data"}, clear=True):
                self.assertEqual(default_data_dir(), self.base / ".local" / "share" / "SkySeal")
            with mock.patch.dict(os.environ, {"SKYSEAL_DESKTOP_DATA_DIR": "relative-data"}, clear=True):
                with self.assertRaisesRegex(EngineError, "absolute path"):
                    default_data_dir()

    def test_certificate_confirmation_forwards_the_reviewed_fingerprint(self):
        trust = mock.Mock(return_value={"trusted": False, "browser_verified": True})
        self.engine.auth = SimpleNamespace(trust_certificate=trust)
        fingerprint = "ab" * 32
        result = self.engine.trust_local_certificate(expected_sha256=fingerprint)
        self.assertTrue(result["browser_verified"])
        trust.assert_called_once_with(self.engine.root, expected_sha256=fingerprint)
        trust.reset_mock()
        self.engine.trust_local_certificate()
        trust.assert_called_once_with(self.engine.root)
        self.assertEqual(self.signer.calls, 0)


if __name__ == "__main__":
    unittest.main()
