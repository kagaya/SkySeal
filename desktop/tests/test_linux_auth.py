"""Real encrypted-key/signature tests and bounded Pinentry protocol tests.

Interactive native GTK approval is exercised separately by the Linux package
smoke test with a disposable key and synthetic passphrase, never a user's key.
"""
import copy
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from desktop.engine import linux_auth as m
from verifier.skyseal_verify import decode_base64url, encode_base64url

PASSPHRASE = "a disposable test passphrase + 日本語"


@unittest.skipUnless(sys.platform == "linux", "Linux key-store semantics")
class LinuxKeyStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            signer = m.LinuxSigner(root)
            with patch.object(m, "_prompt_passphrase", side_effect=lambda *_: bytearray(PASSPHRASE, "utf-8")):
                cls.credential = signer.register(m.RP_ID, m.ORIGIN, b"researcher", "Researcher")
            cls.filename = cls.credential["key_id"] + ".json"
            cls.encrypted = (root / "keys" / cls.filename).read_bytes()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "keys").mkdir(mode=0o700)
        self.path = self.root / "keys" / self.filename
        self.path.write_bytes(self.encrypted)
        self.path.chmod(0o600)
        self.signer = m.LinuxSigner(self.root)

    def prompt(self, value=PASSPHRASE):
        return patch.object(m, "_prompt_passphrase", side_effect=lambda *_: bytearray(value, "utf-8"))

    def verify(self, result, challenge, credential=None):
        jwk = (credential or self.credential)["public_key"]
        key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(decode_base64url(jwk["x"], "x", 32), "big"),
            int.from_bytes(decode_base64url(jwk["y"], "y", 32), "big"), ec.SECP256R1()).public_key()
        key.verify(decode_base64url(result["signature"], "signature"), challenge, ec.ECDSA(hashes.SHA256()))

    def assert_sign_error(self, code):
        with self.assertRaises(m.LinuxAuthError) as caught:
            self.signer.sign(self.credential, b"c" * 32, m.RP_ID, m.ORIGIN)
        self.assertEqual(caught.exception.code, code)

    def test_real_signature_and_exact_challenge_with_fresh_prompt_each_time(self):
        with self.prompt() as prompt:
            first = self.signer.sign(self.credential, b"a" * 32, m.RP_ID, m.ORIGIN)
            second = self.signer.sign(self.credential, b"b" * 32, m.RP_ID, m.ORIGIN)
        self.assertEqual(prompt.call_count, 2)
        self.assertEqual(set(first), {"method", "signature"})
        self.assertEqual(first["method"], m.METHOD)
        self.verify(first, b"a" * 32)
        self.verify(second, b"b" * 32)
        with self.assertRaises(InvalidSignature):
            self.verify(first, b"b" * 32)
        self.assertNotIn("authenticator_data", first)

    def test_registration_confirms_secret_and_saves_encrypted_owner_only_key(self):
        with self.prompt() as prompt:
            credential = self.signer.register(m.RP_ID, m.ORIGIN, b"other", "Another researcher")
        self.assertEqual(prompt.call_count, 2)
        path = self.root / "keys" / (credential["key_id"] + ".json")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(path.stat().st_nlink, 1)
        self.assertNotIn(PASSPHRASE.encode(), path.read_bytes())
        self.assertNotIn("passphrase", {key.lower() for key in credential})
        self.assertTrue(credential["private_key_extractable"])
        self.assertFalse(credential["hardware_attested"])
        with self.prompt():
            result = self.signer.sign(credential, b"r" * 32, m.RP_ID, m.ORIGIN)
        self.verify(result, b"r" * 32, credential)

    def test_mismatch_short_secret_or_cancel_never_publishes_key(self):
        before = set(self.path.parent.iterdir())
        scenarios = [
            ([bytearray(b"a sufficiently long secret"), bytearray(b"another sufficiently long secret")], "passphrase_mismatch"),
            ([bytearray(b"short"), bytearray(b"short")], "invalid_passphrase"),
            (m.LinuxAuthError("Cancelled", "approval_cancelled"), "approval_cancelled"),
        ]
        for response, code in scenarios:
            with self.subTest(code=code), patch.object(m, "_prompt_passphrase", side_effect=response):
                with self.assertRaises(m.LinuxAuthError) as caught:
                    self.signer.register(m.RP_ID, m.ORIGIN, b"user", "name")
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(set(self.path.parent.iterdir()), before)

    def test_wrong_secret_and_cancel_do_not_return_signature_or_change_key(self):
        with self.prompt("wrong but long enough passphrase"):
            self.assert_sign_error("approval_failed")
        with patch.object(m, "_prompt_passphrase", side_effect=m.LinuxAuthError("Cancelled", "approval_cancelled")):
            self.assert_sign_error("approval_cancelled")
        self.assertEqual(self.path.read_bytes(), self.encrypted)

    def test_ciphertext_and_authenticated_nonce_or_salt_tampering_are_rejected(self):
        original = json.loads(self.encrypted)
        for location in ("ciphertext", "nonce", "salt"):
            record = copy.deepcopy(original)
            container, name = (record, location) if location == "ciphertext" else (record["cipher" if location == "nonce" else "kdf"], location)
            value = bytearray(decode_base64url(container[name], name))
            value[0] ^= 1
            container[name] = encode_base64url(value)
            self.path.write_bytes(m._json_bytes(record))
            with self.subTest(location=location), self.prompt():
                self.assert_sign_error("approval_failed")

    def test_kdf_bounds_and_profile_or_public_key_tampering_fail_before_prompt(self):
        mutations = [lambda r: r["kdf"].update(n=2**30), lambda r: r["kdf"].update(p=True),
                     lambda r: r.update(profile="windows"), lambda r: r.update(key_id="skyseal-key-" + "0" * 32),
                     lambda r: r["public_key"].update(x="wrong")]
        for mutate in mutations:
            record = json.loads(self.encrypted)
            mutate(record)
            self.path.write_bytes(m._json_bytes(record))
            with patch.object(m, "_prompt_passphrase") as prompt:
                self.assert_sign_error("invalid_key_record")
                prompt.assert_not_called()

    def test_authenticated_wrong_private_key_still_fails_registered_public_key_check(self):
        record = json.loads(self.encrypted)
        header, salt, nonce, _ = m._validate_record(self.encrypted, self.credential)
        other = ec.generate_private_key(ec.SECP256R1())
        clear = other.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        derived = m._derive(bytearray(PASSPHRASE, "utf-8"), salt)
        record["ciphertext"] = encode_base64url(AESGCM(derived).encrypt(nonce, clear, m._json_bytes(header)))
        self.path.write_bytes(m._json_bytes(record))
        with self.prompt():
            self.assert_sign_error("invalid_private_key")

    def test_file_changed_while_approval_dialog_is_open_is_rejected(self):
        def approve(*_):
            self.path.write_bytes(self.encrypted + b"\n")
            return bytearray(PASSPHRASE, "utf-8")
        with patch.object(m, "_prompt_passphrase", side_effect=approve):
            self.assert_sign_error("key_changed")

    def test_unsafe_permissions_hardlink_and_oversized_key_are_rejected_before_prompt(self):
        with patch.object(m, "_prompt_passphrase") as prompt:
            self.path.chmod(0o644)
            self.assert_sign_error("unsafe_key_file")
            self.path.chmod(0o600)
            link = self.root / "also-the-key"
            os.link(self.path, link)
            self.assert_sign_error("unsafe_key_file")
            link.unlink()
            self.path.write_bytes(b"x" * (m.MAX_KEY_BYTES + 1))
            self.assert_sign_error("unsafe_key_file")
            prompt.assert_not_called()

    def test_symlinks_in_key_file_store_or_caller_root_are_rejected(self):
        target = self.root / "actual-key"
        self.path.rename(target)
        self.path.symlink_to(target)
        with patch.object(m, "_prompt_passphrase") as prompt:
            self.assert_sign_error("unsafe_key_store")
            prompt.assert_not_called()
        self.path.unlink()
        target.rename(self.path)
        real = self.root / "real-keys"
        self.path.parent.rename(real)
        (self.root / "keys").symlink_to(real, target_is_directory=True)
        with patch.object(m, "_prompt_passphrase") as prompt:
            self.assert_sign_error("unsafe_key_store")
            prompt.assert_not_called()
        root_link = self.root / "root-link"
        root_link.symlink_to(self.root, target_is_directory=True)
        linked_signer = m.LinuxSigner(root_link)
        with self.assertRaises(m.LinuxAuthError) as caught:
            linked_signer._read_key(self.credential["key_id"])
        self.assertEqual(caught.exception.code, "unsafe_key_store")

    def test_shared_root_and_key_directory_permissions_are_not_silently_changed(self):
        self.root.chmod(0o777)
        with patch.object(m, "_prompt_passphrase") as prompt:
            self.assert_sign_error("unsafe_key_store")
            prompt.assert_not_called()
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o777)
        self.root.chmod(0o700)
        self.path.parent.chmod(0o755)
        with patch.object(m, "_prompt_passphrase") as prompt:
            self.assert_sign_error("unsafe_key_store")
            prompt.assert_not_called()
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o755)

    def test_publication_never_overwrites_an_existing_identity(self):
        with self.assertRaises(m.LinuxAuthError):
            self.signer._write_key(self.credential["key_id"], b"replacement")
        self.assertEqual(self.path.read_bytes(), self.encrypted)
        self.assertFalse(list(self.path.parent.glob(".key-*.tmp")))

    def test_no_unsigned_fallback_for_invalid_context_challenge_or_credential(self):
        with patch.object(m, "_prompt_passphrase") as prompt:
            for field, value in [("approval_policy", "cached"), ("private_key_extractable", False),
                                 ("hardware_attested", True), ("key_id", "../../key")]:
                with self.subTest(field=field), self.assertRaises(m.LinuxAuthError):
                    self.signer.sign({**self.credential, field: value}, b"c" * 32, m.RP_ID, m.ORIGIN)
            with self.assertRaises(m.LinuxAuthError):
                self.signer.sign(self.credential, b"short", m.RP_ID, m.ORIGIN)
            with self.assertRaises(m.LinuxAuthError):
                self.signer.sign(self.credential, b"c" * 32, "other", m.ORIGIN)
            prompt.assert_not_called()

    def test_availability_does_not_prompt_or_require_an_existing_identity(self):
        self.path.unlink()
        self.path.parent.rmdir()
        with patch.object(m, "_pinentry_path", return_value=m.PINENTRY_PATH), patch.object(m, "_prompt_passphrase") as prompt:
            status = self.signer.availability()
        self.assertTrue(status["available"])
        self.assertEqual(status["authentication_assurance"], "local_user_presence_not_attested")
        self.assertTrue(status["private_key_extractable"])
        self.assertFalse(status["hardware_attested"])
        self.assertFalse((self.root / "keys").exists())
        prompt.assert_not_called()


@unittest.skipUnless(sys.platform == "linux", "Linux Pinentry pipe semantics")
class PinentryProtocolTests(unittest.TestCase):
    def protocol(self, response, timeout=0.5, *, open_writer=False):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, response)
        if not open_writer:
            os.close(write_fd)
        else:
            self.addCleanup(os.close, write_fd)
        output = os.fdopen(read_fd, "rb", buffering=0)
        self.addCleanup(output.close)
        protocol = m._Assuan(types.SimpleNamespace(stdout=output, stdin=io.BytesIO()), timeout)
        self.addCleanup(protocol.close)
        return protocol

    def test_percent_decoding_preserves_plus_unicode_and_multiple_data_lines(self):
        protocol = self.protocol(b"D abc+%25%0A\nD \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\nOK\n")
        self.assertEqual(protocol.response(secret=True), "abc+%\n日本語".encode())
        with self.assertRaises(m.LinuxAuthError):
            m._decode_assuan(b"wrong%2X")

    def test_cached_password_cancellation_eof_and_inquiry_fail_closed(self):
        values = [(b"S PASSWORD_FROM_CACHE\nD must-not-accept\nOK\n", "cached_approval_rejected"),
                  (b"ERR 83886179 Operation cancelled\n", "approval_cancelled"),
                  (b"D unapproved-password\n", "approval_failed"),
                  (b"INQUIRE QUALITY secret\n", "invalid_pinentry_response")]
        for response, code in values:
            with self.subTest(code=code), self.assertRaises(m.LinuxAuthError) as caught:
                self.protocol(response).response(secret=True)
            self.assertEqual(caught.exception.code, code)

    def test_lines_total_data_and_timeout_are_bounded(self):
        with self.assertRaises(m.LinuxAuthError) as caught:
            self.protocol(b"D " + b"x" * m.MAX_ASSUAN_LINE + b"\nOK\n").response(secret=True)
        self.assertEqual(caught.exception.code, "invalid_pinentry_response")
        with self.assertRaises(m.LinuxAuthError) as caught:
            self.protocol((b"D " + b"x" * 600 + b"\n") * 2 + b"OK\n").response(secret=True)
        self.assertEqual(caught.exception.code, "invalid_passphrase")
        with self.assertRaises(m.LinuxAuthError) as caught:
            self.protocol(b"", timeout=0.01, open_writer=True).response(secret=True)
        self.assertEqual(caught.exception.code, "approval_timeout")

    def test_commands_escape_untrusted_text_instead_of_injecting_assuan_commands(self):
        protocol = self.protocol(b"OK\n")
        protocol.command(b"SETDESC", "line1\nGETPIN\rpercent%value")
        self.assertEqual(protocol.process.stdin.getvalue(), b"SETDESC line1%0AGETPIN%0Dpercent%25value\n")

    def test_child_environment_uses_system_libraries_and_no_pinentry_overrides(self):
        with patch.dict(os.environ, {"LD_LIBRARY_PATH": "/frozen/libs", "LD_LIBRARY_PATH_ORIG": "/system/custom", "LD_PRELOAD": "/evil.so", "GPG_TTY": "/dev/tty1", "PINENTRY_USER_DATA": "USE_CURSES=1", "INSIDE_EMACS": "yes"}, clear=True), patch.object(m.sys, "frozen", True, create=True):
            environment = m._pinentry_environment()
        self.assertEqual(environment["LD_LIBRARY_PATH"], "/system/custom")
        for key in ("LD_PRELOAD", "GPG_TTY", "PINENTRY_USER_DATA", "INSIDE_EMACS"):
            self.assertNotIn(key, environment)
        with patch.dict(os.environ, {"LD_LIBRARY_PATH": "/frozen/libs"}, clear=True), patch.object(m.sys, "frozen", True, create=True):
            self.assertNotIn("LD_LIBRARY_PATH", m._pinentry_environment())

    def test_no_terminal_or_environment_passphrase_fallback(self):
        with patch.dict(os.environ, {"SKYSEAL_PASSPHRASE": PASSPHRASE, "GPG_TTY": "/dev/tty"}, clear=True), patch.object(m.subprocess, "Popen") as spawn:
            with self.assertRaises(m.LinuxAuthError) as caught:
                m._prompt_passphrase("Approve")
        self.assertEqual(caught.exception.code, "graphical_session_required")
        spawn.assert_not_called()

    def test_minimum_counts_unicode_characters_without_composition_rules(self):
        m._validate_passphrase(bytearray("あいうえおかきくけこさし", "utf-8"))
        m._validate_passphrase(bytearray("abcdefghijkl", "utf-8"))
        with self.assertRaises(m.LinuxAuthError):
            m._validate_passphrase(bytearray("あいうえおかきくけこさ", "utf-8"))


if __name__ == "__main__":
    unittest.main()
