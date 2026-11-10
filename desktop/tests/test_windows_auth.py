"""Native adapter contract tests. No test key can be selected by the application.

These exercise ctypes buffers and real signature verification using a fake
Windows DLL boundary. Windows Hello UI/hardware still needs manual acceptance.
"""
from __future__ import annotations

import ctypes as C
import hashlib
import os
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from desktop.engine import windows_auth as w
from verifier.skyseal_verify import VerificationError, decode_base64url, encode_base64url, parse_json_bytes


RP = "skyseal.localhost"
ORIGIN = "https://skyseal.localhost:34817"
USER = b"private-user-handle"
CREDENTIAL = b"private-credential-id"


def cbor(value):
    def head(major, n):
        if n < 24:
            return bytes([major * 32 + n])
        if n < 256:
            return bytes([major * 32 + 24, n])
        return bytes([major * 32 + 25]) + n.to_bytes(2, "big")
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -value - 1)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode()
        return head(3, len(data)) + data
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(value)


class FakeNative:
    """Return correctly allocated v1-prefix outputs with a real ES256 signature."""
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        numbers = self.key.public_key().public_numbers()
        self.x, self.y = numbers.x.to_bytes(32, "big"), numbers.y.to_bytes(32, "big")
        self.jwk = {"kty": "EC", "crv": "P-256", "x": encode_base64url(self.x),
                    "y": encode_base64url(self.y)}
        self.keep = []
        self.freed_attestation = self.freed_assertion = 0
        self.flags = 0x05
        self.raw_id = CREDENTIAL
        self.handle = USER
        self.bad_signature = False
        self.error = 0

    def buffer(self, data):
        result = w._buffer(data)
        self.keep.append(result)
        return result

    def WebAuthNGetErrorName(self, result):
        return "NotAllowedError"

    def WebAuthNAuthenticatorMakeCredential(self, hwnd, rp, user, params, client, options, output):
        self.make_options = w.MakeCredentialOptionsV1.from_buffer_copy(C.string_at(options, C.sizeof(w.MakeCredentialOptionsV1)))
        self.client = C.cast(client, C.POINTER(w.ClientData)).contents
        self.make_client = C.string_at(self.client.pbClientDataJSON, self.client.cbClientDataJSON)
        cose = cbor({1: 2, 3: -7, -1: 1, -2: self.x, -3: self.y})
        auth = (hashlib.sha256(RP.encode()).digest() + bytes([self.flags | 0x40]) + b"\x00" * 4
                + b"\x00" * 16 + len(self.raw_id).to_bytes(2, "big") + self.raw_id + cose)
        attestation = cbor({"fmt": "none", "attStmt": {}, "authData": auth})
        result = w.CredentialAttestationV1()
        result.dwVersion = 1
        result.cbCredentialId, result.pbCredentialId = len(self.raw_id), self.buffer(self.raw_id)
        result.cbAttestationObject, result.pbAttestationObject = len(attestation), self.buffer(attestation)
        self.keep.append(result)
        C.cast(output, C.POINTER(C.POINTER(w.CredentialAttestationV1)))[0] = C.pointer(result)
        return self.error

    def WebAuthNAuthenticatorGetAssertion(self, hwnd, rp_id, client, options, output):
        self.get_options = w.GetAssertionOptionsV1.from_buffer_copy(C.string_at(options, C.sizeof(w.GetAssertionOptionsV1)))
        data = C.cast(client, C.POINTER(w.ClientData)).contents
        self.get_client = C.string_at(data.pbClientDataJSON, data.cbClientDataJSON)
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([self.flags]) + (1).to_bytes(4, "big")
        signature = self.key.sign(auth + hashlib.sha256(self.get_client).digest(), ec.ECDSA(hashes.SHA256()))
        if self.bad_signature:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        result = w.AssertionV1()
        result.dwVersion = 1
        result.cbAuthenticatorData, result.pbAuthenticatorData = len(auth), self.buffer(auth)
        result.cbSignature, result.pbSignature = len(signature), self.buffer(signature)
        result.Credential = w.Credential(1, len(self.raw_id), self.buffer(self.raw_id), "public-key")
        result.cbUserId, result.pbUserId = len(self.handle), self.buffer(self.handle)
        self.keep.append(result)
        C.cast(output, C.POINTER(C.POINTER(w.AssertionV1)))[0] = C.pointer(result)
        return self.error

    def WebAuthNFreeCredentialAttestation(self, pointer):
        self.freed_attestation += 1

    def WebAuthNFreeAssertion(self, pointer):
        self.freed_assertion += 1

    def record(self):
        return {"raw_id": encode_base64url(CREDENTIAL), "user_id": encode_base64url(USER),
                "public_key": self.jwk, "algorithm": -7, "rp_id": RP, "origin": ORIGIN}


class WindowsAdapterTests(unittest.TestCase):
    def setUp(self):
        self.native = FakeNative()
        self.patches = [patch.object(w, "_api", return_value=self.native),
                        patch.object(w, "_window", return_value=1)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_registration_requires_uv_and_validates_cbor_public_key(self):
        result = w.register(RP, ORIGIN, USER, "SkySeal user")
        self.assertEqual(result["public_key"], self.native.jwk)
        self.assertEqual(result["raw_id"], encode_base64url(CREDENTIAL))
        self.assertEqual(self.native.make_options.dwUserVerificationRequirement, 1)
        self.assertEqual(self.native.make_options.dwAttestationConveyancePreference, 1)
        self.assertEqual(self.native.freed_attestation, 1)
        data = parse_json_bytes(self.native.make_client, "client")
        self.assertEqual(data["origin"], ORIGIN)
        self.assertEqual(len(decode_base64url(data["challenge"], "challenge")), 32)

    def test_registration_rejects_missing_uv_and_frees_output(self):
        self.native.flags = 0x01
        with self.assertRaisesRegex(VerificationError, "User Verified"):
            w.register(RP, ORIGIN, USER, "SkySeal user")
        self.assertEqual(self.native.freed_attestation, 1)

    def test_assertion_is_signature_verified_and_excludes_private_routing(self):
        challenge = b"C" * 32
        result = w.sign(self.native.record(), challenge, RP, ORIGIN)
        self.assertEqual(set(result), {"client_data_json", "authenticator_data", "signature", "sign_count"})
        self.assertEqual(result["sign_count"], 1)
        self.assertEqual(self.native.get_options.dwUserVerificationRequirement, 1)
        data = parse_json_bytes(decode_base64url(result["client_data_json"], "client"), "client")
        self.assertEqual(data["challenge"], encode_base64url(challenge))
        self.assertEqual(self.native.freed_assertion, 1)

    def test_assertion_rejects_signature_tampering(self):
        self.native.bad_signature = True
        with self.assertRaises(VerificationError):
            w.sign(self.native.record(), b"C" * 32, RP, ORIGIN)
        self.assertEqual(self.native.freed_assertion, 1)

    def test_assertion_rejects_missing_up_and_uv(self):
        for flags in [0, 1, 4]:
            with self.subTest(flags=flags):
                self.native.flags = flags
                with self.assertRaises(VerificationError):
                    w.sign(self.native.record(), b"C" * 32, RP, ORIGIN)

    def test_assertion_rejects_wrong_credential(self):
        self.native.raw_id = b"different-credential"
        with self.assertRaisesRegex(VerificationError, "credential ID mismatch"):
            w.sign(self.native.record(), b"C" * 32, RP, ORIGIN)

    def test_assertion_rejects_wrong_user_handle(self):
        self.native.handle = b"different-user"
        with self.assertRaisesRegex(VerificationError, "user handle mismatch"):
            w.sign(self.native.record(), b"C" * 32, RP, ORIGIN)

    def test_cancel_is_not_success_and_allocated_response_is_freed(self):
        self.native.error = -1
        with self.assertRaises(w.WindowsAuthError) as raised:
            w.sign(self.native.record(), b"C" * 32, RP, ORIGIN)
        self.assertEqual(raised.exception.code, "approval_cancelled")
        self.assertEqual(self.native.freed_assertion, 1)

    def test_wrong_context_is_rejected_before_ceremony(self):
        with self.assertRaises(w.WindowsAuthError):
            w.sign(self.native.record(), b"C" * 32, RP, "https://skyseal.localhost:443")
        with self.assertRaises(w.WindowsAuthError):
            w.register("proof.excyberlab.net", "https://proof.excyberlab.net", USER, "user")

    def test_challenge_must_be_exact_digest_length(self):
        with self.assertRaises(w.WindowsAuthError):
            w.sign(self.native.record(), b"short", RP, ORIGIN)

    def test_output_length_is_bounded_before_reading_native_memory(self):
        pointer = C.cast(1, w.PBYTE)
        with self.assertRaises(w.WindowsAuthError):
            w._copy_bytes(pointer, 2**32 - 1, maximum=1024, label="test")


class NativeAbiTests(unittest.TestCase):
    def test_win32_scalars_are_32_bit_on_all_test_hosts(self):
        for scalar in (w.DWORD, w.LONG, w.BOOL, w.HRESULT):
            self.assertEqual(C.sizeof(scalar), 4)
        self.assertEqual(w.LONG(-7).value, -7)

    @unittest.skipUnless(C.sizeof(C.c_void_p) == 8, "Windows x64 ABI test")
    def test_v1_windows_x64_prefix_layout(self):
        sizes = {w.RPInformation: 32, w.UserInformation: 40, w.ClientData: 24,
                 w.CoseParameter: 24, w.CoseParameters: 16, w.Credential: 24,
                 w.Credentials: 16, w.Extensions: 16, w.MakeCredentialOptionsV1: 64,
                 w.GetAssertionOptionsV1: 56, w.CredentialAttestationV1: 96, w.AssertionV1: 72}
        for structure, size in sizes.items():
            with self.subTest(structure=structure.__name__):
                self.assertEqual(C.sizeof(structure), size)
        self.assertEqual(w.CredentialAttestationV1.pbAttestationObject.offset, 72)
        self.assertEqual(w.AssertionV1.Credential.offset, 32)

    @unittest.skipIf(os.name == "nt", "Non-Windows rejection test")
    def test_non_windows_fails_closed(self):
        self.assertFalse(w.availability()["available"])
        with self.assertRaises(w.WindowsAuthError) as raised:
            w.register(RP, ORIGIN, USER, "user")
        self.assertEqual(raised.exception.code, "windows_required")


if __name__ == "__main__":
    unittest.main()
