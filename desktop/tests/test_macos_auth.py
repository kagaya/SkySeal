"""Native-helper contract tests; real macOS approval remains an acceptance test."""
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from desktop.engine import macos_auth as m
from verifier.skyseal_verify import encode_base64url


class MacOSAuthTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        public = self.key.public_key().public_numbers()
        self.credential = {"key_id": "skyseal-key-" + "1" * 32, "algorithm": -7,
            "public_key": {"kty": "EC", "crv": "P-256", "x": encode_base64url(public.x.to_bytes(32, "big")),
                           "y": encode_base64url(public.y.to_bytes(32, "big"))},
            "method": m.METHOD, "key_storage": "login-keychain-nonextractable",
            "approval_policy": "password-per-signature", "hardware_attested": False}

    def response(self, challenge):
        return {"method": m.METHOD, "signature": encode_base64url(self.key.sign(challenge, ec.ECDSA(hashes.SHA256())))}

    def test_registration_retains_only_public_fields_and_opaque_key_id(self):
        with patch.object(m, "_invoke", return_value={**self.credential, "unexpected": "not stored"}) as call:
            registered = m.register(m.RP_ID, m.ORIGIN, b"researcher", "name")
        self.assertEqual(registered, self.credential)
        call.assert_called_once_with({"op": "register"})

    def test_real_signature_is_verified_again_at_python_boundary(self):
        challenge = b"c" * 32
        with patch.object(m, "_invoke", return_value=self.response(challenge)) as call:
            result = m.sign(self.credential, challenge, m.RP_ID, m.ORIGIN)
        self.assertEqual(set(result), {"method", "signature"})
        call.assert_called_once_with({"op": "sign", "key_id": self.credential["key_id"], "challenge": encode_base64url(challenge)})
        self.assertNotIn("authenticator_data", result)

    def test_wrong_challenge_or_key_signature_is_rejected(self):
        with patch.object(m, "_invoke", return_value=self.response(b"a" * 32)):
            with self.assertRaises(m.MacOSAuthError) as caught:
                m.sign(self.credential, b"b" * 32, m.RP_ID, m.ORIGIN)
        self.assertEqual(caught.exception.code, "invalid_native_signature")

    def test_no_unprotected_credential_fallback(self):
        for field, value in [("approval_policy", "none"), ("key_storage", "software"), ("hardware_attested", True), ("key_id", "../../key")]:
            with self.subTest(field=field), patch.object(m, "_invoke") as call:
                with self.assertRaises(m.MacOSAuthError):
                    m.sign({**self.credential, field: value}, b"a" * 32, m.RP_ID, m.ORIGIN)
                call.assert_not_called()

    def test_context_and_challenge_are_fixed(self):
        with patch.object(m, "_invoke") as call:
            with self.assertRaises(m.MacOSAuthError):
                m.register("other.localhost", m.ORIGIN, b"user", "name")
            with self.assertRaises(m.MacOSAuthError):
                m.sign(self.credential, b"short", m.RP_ID, m.ORIGIN)
            call.assert_not_called()

    def test_webauthn_or_extra_result_fields_are_rejected(self):
        value = self.response(b"a" * 32)
        with patch.object(m, "_invoke", return_value={**value, "authenticator_data": "fake"}):
            with self.assertRaises(m.MacOSAuthError):
                m.sign(self.credential, b"a" * 32, m.RP_ID, m.ORIGIN)

    def test_native_cancellation_never_becomes_signature(self):
        result = subprocess.CompletedProcess([], 1, json.dumps({"ok": False, "error": {"code": "approval_cancelled", "message": "Cancelled"}}).encode())
        with patch.object(m, "_helper_path", return_value=Path("/native/macos-signer")), patch.object(m.subprocess, "run", return_value=result):
            with self.assertRaises(m.MacOSAuthError) as caught:
                m.sign(self.credential, b"a" * 32, m.RP_ID, m.ORIGIN)
        self.assertEqual(caught.exception.code, "approval_cancelled")

    def test_native_invocation_uses_fixed_binary_and_json_stdin(self):
        response = subprocess.CompletedProcess([], 0, b'{"ok":true,"result":{"available":true}}')
        with patch.object(m, "_helper_path", return_value=Path("/native/macos-signer")), patch.object(m.subprocess, "run", return_value=response) as call:
            self.assertEqual(m._invoke({"op": "status"}), {"available": True})
        self.assertEqual(call.call_args.args[0], ["/native/macos-signer"])
        self.assertEqual(json.loads(call.call_args.kwargs["input"]), {"op": "status"})
        self.assertNotIn("shell", call.call_args.kwargs)

    def test_timeout_and_malformed_success_fail_closed(self):
        with patch.object(m, "_helper_path", return_value=Path("/native/macos-signer")):
            with patch.object(m.subprocess, "run", side_effect=subprocess.TimeoutExpired("native", 1)):
                with self.assertRaises(m.MacOSAuthError) as caught:
                    m._invoke({"op": "status"})
                self.assertEqual(caught.exception.code, "approval_timeout")
            for raw, status in [(b"not JSON", 0), (b'{"ok":true,"result":{}}', 1), (b"x" * (m.MAX_RESPONSE + 1), 0)]:
                with self.subTest(status=status, size=len(raw)), patch.object(m.subprocess, "run", return_value=subprocess.CompletedProcess([], status, raw)):
                    with self.assertRaises(m.MacOSAuthError):
                        m._invoke({"op": "status"})

    def test_status_is_explicitly_unattested_and_nonmac_is_unavailable(self):
        with patch.object(m.sys, "platform", "linux"):
            result = m.availability()
        self.assertFalse(result["available"])
        self.assertEqual(result["error_code"], "unsupported_platform")
        self.assertEqual(result["authentication_assurance"], "local_user_presence_not_attested")


if __name__ == "__main__":
    unittest.main()
