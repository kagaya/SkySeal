import json
import unittest

from desktop.engine import proof
from desktop.engine.core import atomic_write
from desktop.tests import test_engine as fixtures
from verifier.skyseal_verify import VerificationError, decode_base64url, encode_base64url


class ProofChecks(unittest.TestCase):
    setUp = fixtures.EngineCase.setUp
    tearDown = fixtures.EngineCase.tearDown
    new_engine = fixtures.EngineCase.new_engine
    enroll = fixtures.EngineCase.enroll
    sealed = fixtures.EngineCase.sealed
    def test_signature_change_is_rejected_even_if_manifest_is_recomputed(self):
        job = self.sealed()
        directory = self.engine._jobdir(job["job_id"]) / "evidence"
        seal = proof.read_json(directory / "seal.skyseal.json")
        signature = bytearray(decode_base64url(seal["assertion"]["signature"], "signature"))
        signature[-1] ^= 1
        seal["assertion"]["signature"] = encode_base64url(signature)
        atomic_write(directory / "seal.skyseal.json", proof.json_bytes(seal))
        atomic_write(directory / "manifest.json", proof.json_bytes(proof.create_manifest(directory, job["job_id"])))
        with self.assertRaises(VerificationError):
            self.engine.verify(str(directory))

    def test_missing_uv_rejected_even_with_well_formed_json(self):
        job = self.sealed()
        directory = self.engine._jobdir(job["job_id"]) / "evidence"
        seal = proof.read_json(directory / "seal.skyseal.json")
        auth = bytearray(decode_base64url(seal["assertion"]["authenticator_data"], "auth"))
        auth[32] &= ~4
        seal["assertion"]["authenticator_data"] = encode_base64url(auth)
        atomic_write(directory / "seal.skyseal.json", proof.json_bytes(seal))
        atomic_write(directory / "manifest.json", proof.json_bytes(proof.create_manifest(directory, job["job_id"])))
        with self.assertRaisesRegex(VerificationError, "User Verified"):
            self.engine.verify(str(directory))

    def test_unlisted_timestamp_never_establishes_time(self):
        job = self.sealed()
        directory = self.engine._jobdir(job["job_id"]) / "evidence"
        manifest = proof.read_json(directory / "manifest.json")
        for name in proof.OTS_TARGETS:
            manifest["artifacts"].pop(name + ".ots")
        atomic_write(directory / "manifest.json", proof.json_bytes(manifest))
        self.timestamps.confirmed = True
        self.assertFalse(self.engine.verify(str(directory))["time_confirmed"])

    def test_identity_nonce_key_binding_cannot_be_rewritten(self):
        job = self.sealed()
        directory = self.engine._jobdir(job["job_id"]) / "evidence"
        genesis = proof.read_json(directory / "identity-genesis.json")
        genesis["enrollment_seed"] = encode_base64url(b"x" * 32)
        atomic_write(directory / "identity-genesis.json", proof.json_bytes(genesis))
        atomic_write(directory / "manifest.json", proof.json_bytes(proof.create_manifest(directory, job["job_id"])))
        with self.assertRaisesRegex(VerificationError, "token binding"):
            self.engine.verify(str(directory))


if __name__ == "__main__":
    unittest.main()
