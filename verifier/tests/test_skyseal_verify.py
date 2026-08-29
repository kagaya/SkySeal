from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from verifier.skyseal_verify import (
    VerificationError,
    canonical_json,
    parse_hash_list,
    parse_json_bytes,
    validate_orcid,
    verify_bundle,
)


REPOSITORY = Path(__file__).resolve().parents[2]
VECTORS = REPOSITORY / "spec" / "test-vectors" / "v1"
VERIFIER = REPOSITORY / "verifier" / "skyseal_verify.py"
HASH_LIST_CREATOR = REPOSITORY / "make_public_hashlist_v1.sh"
RP_ID = "seal.example.org"
ORIGIN = "https://seal.example.org"


class CanonicalJSONTests(unittest.TestCase):
    def test_restricted_jcs_member_order_and_escaping(self) -> None:
        value = {"😀": "last", "b": 1, "€": "middle", "a": "<\n"}
        self.assertEqual(
            canonical_json(value),
            '{"a":"<\\n","b":1,"€":"middle","😀":"last"}'.encode("utf-8"),
        )

    def test_duplicate_json_member_is_rejected(self) -> None:
        with self.assertRaisesRegex(VerificationError, "duplicate JSON member"):
            parse_json_bytes(b'{"a":1,"a":2}', "test")

    def test_float_is_rejected(self) -> None:
        with self.assertRaisesRegex(VerificationError, "floating-point"):
            parse_json_bytes(b'{"a":1.0}', "test")


class IdentityTests(unittest.TestCase):
    def test_valid_orcid_check_digit(self) -> None:
        self.assertEqual(
            validate_orcid("https://orcid.org/0000-0000-0000-0001", "test"),
            "https://orcid.org/0000-0000-0000-0001",
        )

    def test_invalid_orcid_check_digit(self) -> None:
        with self.assertRaisesRegex(VerificationError, "check digit"):
            validate_orcid("https://orcid.org/0000-0000-0000-0002", "test")


class HashListTests(unittest.TestCase):
    def test_valid_hash_list(self) -> None:
        records, digest = parse_hash_list(VECTORS / "valid-es256" / "public.txt")
        manifest = json.loads((VECTORS / "valid-es256" / "manifest.json").read_text())
        self.assertEqual(len(records), 2)
        self.assertEqual(digest, manifest["hash_list_sha256"])

    def test_invalid_hash_lists(self) -> None:
        invalid = VECTORS / "invalid"
        cases = {
            "uppercase.txt": "lowercase",
            "unsorted.txt": "sorted",
            "duplicate.txt": "duplicate",
            "missing-final-lf.txt": "final LF",
            "blank-line.txt": "lowercase",
        }
        for filename, message in cases.items():
            with self.subTest(filename=filename):
                with self.assertRaisesRegex(VerificationError, message):
                    parse_hash_list(invalid / filename)

    def test_empty_hash_list_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.txt"
            path.write_bytes(b"")
            with self.assertRaisesRegex(VerificationError, "empty commitments"):
                parse_hash_list(path)


class HashListCreatorTests(unittest.TestCase):
    def test_creator_sorts_deduplicates_and_handles_unusual_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            payloads = [b"alpha\n", b"beta\n", b"alpha\n"]
            names = ["ordinary.bin", "space name.bin", "line\nbreak.bin"]
            for name, payload in zip(names, payloads):
                (source / name).write_bytes(payload)
            output = root / "public.txt"
            completed = subprocess.run(
                ["bash", str(HASH_LIST_CREATOR), "--output", str(output), str(source)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            records, _ = parse_hash_list(output)
            expected = sorted({hashlib.sha256(payload).hexdigest() for payload in payloads})
            self.assertEqual(records, expected)
            self.assertNotIn("ordinary.bin", output.read_text())

    def test_creator_rejects_empty_folder_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "empty"
            source.mkdir()
            output = root / "public.txt"
            completed = subprocess.run(
                ["bash", str(HASH_LIST_CREATOR), "--output", str(output), str(source)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(output.exists())

    def test_creator_refuses_to_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "data.bin").write_bytes(b"data")
            output = root / "public.txt"
            output.write_text("keep me\n")
            completed = subprocess.run(
                ["bash", str(HASH_LIST_CREATOR), "--output", str(output), str(source)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(output.read_text(), "keep me\n")


class WebAuthnVectorTests(unittest.TestCase):
    def verify_directory(self, directory: Path) -> dict[str, object]:
        return verify_bundle(
            directory / "public.txt",
            directory / "public.txt.skyseal.json",
            directory / "identity-genesis.json",
            RP_ID,
            ORIGIN,
        )

    def test_valid_es256_vector(self) -> None:
        result = self.verify_directory(VECTORS / "valid-es256")
        self.assertTrue(result["ok"])
        self.assertEqual(result["credential_algorithm"], "ES256")
        self.assertTrue(result["user_verified"])

    def test_valid_ed25519_vector(self) -> None:
        result = self.verify_directory(VECTORS / "valid-ed25519")
        self.assertTrue(result["ok"])
        self.assertEqual(result["credential_algorithm"], "Ed25519")

    def test_tampered_bundles_are_rejected_for_expected_reason(self) -> None:
        valid = VECTORS / "valid-es256"
        invalid = VECTORS / "invalid"
        cases = {
            "tampered-signature.skyseal.json": "signature verification failed",
            "wrong-origin.skyseal.json": "origin does not match",
            "missing-uv.skyseal.json": "User Verified",
            "wrong-subject.skyseal.json": "hash-list digest",
            "raw-credential-id.skyseal.json": "unknown members",
        }
        for filename, message in cases.items():
            with self.subTest(filename=filename):
                with self.assertRaisesRegex(VerificationError, message):
                    verify_bundle(
                        valid / "public.txt",
                        invalid / filename,
                        valid / "identity-genesis.json",
                        RP_ID,
                        ORIGIN,
                    )

    def test_self_declared_rp_hint_cannot_replace_trusted_input(self) -> None:
        with self.assertRaisesRegex(VerificationError, "hint does not match"):
            verify_bundle(
                VECTORS / "valid-es256" / "public.txt",
                VECTORS / "valid-es256" / "public.txt.skyseal.json",
                VECTORS / "valid-es256" / "identity-genesis.json",
                "other.example.org",
                ORIGIN,
            )

    def test_membership_cli_exit_codes(self) -> None:
        vector = VECTORS / "valid-es256"
        member = subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                "contains",
                str(vector / "public.txt"),
                str(vector / "candidate-member.bin"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        nonmember = subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                "contains",
                str(vector / "public.txt"),
                str(vector / "candidate-nonmember.bin"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(member.returncode, 0, member.stderr)
        self.assertTrue(json.loads(member.stdout)["member"])
        self.assertEqual(nonmember.returncode, 1, nonmember.stderr)
        self.assertFalse(json.loads(nonmember.stdout)["member"])


if __name__ == "__main__":
    unittest.main()
