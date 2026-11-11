import json
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

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


class MacProofChecks(unittest.TestCase):
    setUp = fixtures.MacEngineCase.setUp
    tearDown = fixtures.MacEngineCase.tearDown
    new_engine = fixtures.MacEngineCase.new_engine
    enroll = fixtures.MacEngineCase.enroll
    sealed = fixtures.MacEngineCase.sealed

    def rewrite_manifest(self, directory, job):
        atomic_write(directory / "manifest.json", proof.json_bytes(
            proof.create_manifest(directory, job["job_id"], proof.MAC_PROFILE)))

    def test_mac_payload_tamper_rejected_even_if_manifest_is_recomputed(self):
        job = self.sealed()
        directory = self.engine._jobdir(job["job_id"]) / "evidence"
        seal = proof.read_json(directory / "seal.skyseal.json")
        seal["payload"]["nonce"] = encode_base64url(b"q" * 32)
        atomic_write(directory / "seal.skyseal.json", proof.json_bytes(seal))
        self.rewrite_manifest(directory, job)
        with self.assertRaisesRegex(VerificationError, "signature verification"):
            self.engine.verify(str(directory))

    def test_mac_unknown_approval_method_is_not_accepted(self):
        job = self.sealed()
        directory = self.engine._jobdir(job["job_id"]) / "evidence"
        seal = proof.read_json(directory / "seal.skyseal.json")
        seal["assertion"]["method"] = "software-key-with-password-screen"
        atomic_write(directory / "seal.skyseal.json", proof.json_bytes(seal))
        self.rewrite_manifest(directory, job)
        with self.assertRaisesRegex(VerificationError, "approval method"):
            self.engine.verify(str(directory))

    def test_manifest_profile_cannot_reinterpret_mac_evidence_as_windows(self):
        job = self.sealed()
        directory = self.engine._jobdir(job["job_id"]) / "evidence"
        # The file digests are valid, but the outer profile is not the signed
        # genesis profile. Verification must not choose the host's algorithm.
        atomic_write(directory / "manifest.json", proof.json_bytes(
            proof.create_manifest(directory, job["job_id"], proof.PROFILE)))
        with self.assertRaisesRegex(VerificationError, "profiles do not match"):
            self.engine.verify(str(directory))

    def test_orcid_nonce_is_bound_to_mac_approval_profile(self):
        self.enroll()
        identity = self.engine._identity()
        genesis = identity["genesis"]
        mac_nonce = proof.enrollment_nonce(genesis["public_key"], -7, genesis["enrollment_seed"], proof.MAC_PROFILE)
        windows_nonce = proof.enrollment_nonce(genesis["public_key"], -7, genesis["enrollment_seed"], proof.PROFILE)
        self.assertNotEqual(mac_nonce, windows_nonce)
        self.assertEqual(mac_nonce, self.auth.nonce)
        rewritten = dict(genesis)
        rewritten.pop("approval_method")
        rewritten.pop("key_namespace")
        rewritten.update(profile=proof.PROFILE, schema=proof.GENESIS_SCHEMA,
                         rp_id=proof.RP_ID, origin=proof.ORIGIN)
        with self.assertRaisesRegex(VerificationError, "token binding"):
            proof.verify_identity(rewritten, identity["activation"], self.auth.client_id, self.auth.verify_id_token)

    def test_windows_and_mac_nonce_and_challenge_bytes_remain_compatible(self):
        key = {"kty": "EC", "crv": "P-256", "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
               "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}
        seed = encode_base64url(b"n" * 32)
        payload = {"profile": proof.PROFILE, "genesis_digest": "sha256:" + "a" * 64,
                   "created_at": "2026-11-10T00:00:00Z", "nonce": seed}
        self.assertEqual(proof.enrollment_nonce(key, -7, seed),
                         "X5aqy5RjZPHsABmOmBr4Ww4qXbKIAEM3ppLK3LHujWk")
        self.assertEqual(proof.challenge("identity", payload).hex(),
                         "b902d5aadfd5986124bc0e680df0076cefc1ffb40ae20ec8593e59ad20e0fd0b")
        self.assertEqual(proof.enrollment_nonce(key, -7, seed, proof.MAC_PROFILE),
                         "c0VabSMR-A44BSZJOybr4fmza8-I8zJBrVrO83oXZKw")
        payload["profile"] = proof.MAC_PROFILE
        self.assertEqual(proof.challenge("identity", payload).hex(),
                         "180e66c3f6c34110f5b8278b8eba9ceff001493a352e153b0287281716e63ad0")


class LinuxProofChecks(unittest.TestCase):
    setUp = fixtures.LinuxEngineCase.setUp
    tearDown = fixtures.LinuxEngineCase.tearDown
    new_engine = fixtures.LinuxEngineCase.new_engine
    enroll = fixtures.LinuxEngineCase.enroll
    sealed = fixtures.LinuxEngineCase.sealed

    def rewrite_manifest(self, directory, job):
        atomic_write(directory / "manifest.json", proof.json_bytes(
            proof.create_manifest(directory, job["job_id"], proof.LINUX_PROFILE)))

    def test_linux_signed_payload_tamper_rejected_with_recomputed_manifest(self):
        job = self.sealed()
        directory = self.engine._jobdir(job["job_id"]) / "evidence"
        seal = proof.read_json(directory / "seal.skyseal.json")
        seal["payload"]["nonce"] = encode_base64url(b"l" * 32)
        atomic_write(directory / "seal.skyseal.json", proof.json_bytes(seal))
        self.rewrite_manifest(directory, job)
        with self.assertRaisesRegex(VerificationError, "signature verification"):
            self.engine.verify(str(directory))

    def test_linux_assertion_cannot_claim_mac_method_or_webauthn_user_verification(self):
        job = self.sealed()
        directory = self.engine._jobdir(job["job_id"]) / "evidence"
        original = proof.read_json(directory / "seal.skyseal.json")
        for mutation, error in (({"method": proof.MAC_METHOD}, "approval method"),
                                ({"user_verified": True}, "invalid members")):
            with self.subTest(mutation=mutation):
                seal = json.loads(json.dumps(original))
                seal["assertion"].update(mutation)
                atomic_write(directory / "seal.skyseal.json", proof.json_bytes(seal))
                self.rewrite_manifest(directory, job)
                with self.assertRaisesRegex(VerificationError, error):
                    self.engine.verify(str(directory))

    def test_linux_namespace_is_fixed_before_issuer_or_signature_verification(self):
        self.enroll()
        identity = self.engine._identity()
        genesis = dict(identity["genesis"], key_namespace=proof.MAC_NAMESPACE)
        with self.assertRaisesRegex(VerificationError, "key namespace"):
            proof.verify_identity(genesis, identity["activation"], self.auth.client_id, self.auth.verify_id_token)

    def test_manifest_cannot_reinterpret_linux_proof_as_another_platform(self):
        job = self.sealed()
        directory = self.engine._jobdir(job["job_id"]) / "evidence"
        for profile in (proof.PROFILE, proof.MAC_PROFILE):
            with self.subTest(profile=profile):
                atomic_write(directory / "manifest.json", proof.json_bytes(
                    proof.create_manifest(directory, job["job_id"], profile)))
                with self.assertRaisesRegex(VerificationError, "profiles do not match"):
                    self.engine.verify(str(directory))

    def test_orcid_nonce_binds_linux_profile_and_cannot_be_relabelled_as_mac(self):
        self.enroll()
        identity = self.engine._identity()
        genesis = identity["genesis"]
        nonces = {profile: proof.enrollment_nonce(genesis["public_key"], -7,
                    genesis["enrollment_seed"], profile) for profile in proof.SUPPORTED_PROFILES}
        self.assertEqual(len(set(nonces.values())), 3)
        self.assertEqual(nonces[proof.LINUX_PROFILE], self.auth.nonce)
        rewritten = dict(genesis, profile=proof.MAC_PROFILE,
                         schema=proof.schema(proof.MAC_PROFILE, "genesis"),
                         **proof.approval_context(proof.MAC_PROFILE))
        with self.assertRaisesRegex(VerificationError, "token binding"):
            proof.verify_identity(rewritten, identity["activation"], self.auth.client_id, self.auth.verify_id_token)

    def test_mac_signature_cannot_be_replayed_with_linux_method_and_same_key(self):
        self.enroll()
        genesis = self.engine._identity()["genesis"]
        linux_payload = {"profile": proof.LINUX_PROFILE,
                         "genesis_digest": "sha256:" + "c" * 64,
                         "created_at": "2026-11-10T00:00:00Z",
                         "nonce": encode_base64url(b"n" * 32)}
        mac_payload = dict(linux_payload, profile=proof.MAC_PROFILE)
        signature = self.signer.key.sign(proof.challenge("identity", mac_payload), ec.ECDSA(hashes.SHA256()))
        forged = {"method": proof.LINUX_METHOD, "signature": encode_base64url(signature)}
        with self.assertRaisesRegex(VerificationError, "signature verification"):
            proof.verify_assertion(forged, proof.challenge("identity", linux_payload), genesis)


if __name__ == "__main__":
    unittest.main()
