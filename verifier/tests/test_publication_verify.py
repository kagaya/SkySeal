from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from verifier.skyseal_publication_verify import (
    ARTIFACT_NAMES,
    verify_manifest,
    verify_publication,
)
from verifier.skyseal_verify import VerificationError, canonical_json


class PublicationVerifierTests(unittest.TestCase):
    def make_package(self, root: Path) -> None:
        for name in ARTIFACT_NAMES:
            (root / name).write_bytes(("fixture:" + name + "\n").encode())
        manifest = {
            "schema": "urn:skyseal:publication-manifest:v1",
            "seal_id": "018f0000-0000-7000-8000-000000000001",
            "artifacts": {
                name: {
                    "sha256": "sha256:" + hashlib.sha256((root / name).read_bytes()).hexdigest()
                }
                for name in sorted(ARTIFACT_NAMES)
            },
            "timestamp_targets": [
                {"proof": "seal.skyseal.json.ots", "target": "seal.skyseal.json"},
                {
                    "proof": "identity-genesis.json.asc.ots",
                    "target": "identity-genesis.json.asc",
                },
            ],
        }
        (root / "manifest.json").write_bytes(canonical_json(manifest) + b"\n")

    def test_manifest_detects_any_artifact_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_package(root)
            self.assertEqual(
                verify_manifest(root)["seal_id"],
                "018f0000-0000-7000-8000-000000000001",
            )
            (root / "hashes.txt").write_bytes(b"tampered\n")
            with self.assertRaisesRegex(VerificationError, "digest mismatch"):
                verify_manifest(root)

    def test_pending_timestamps_are_explicit_and_never_claimed_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_package(root)
            bundle_report = {
                "ok": True,
                "entry_count": 2,
                "identity_id": "https://orcid.org/0000-0000-0000-0001",
                "seal_id": "018f0000-0000-7000-8000-000000000001",
            }
            pending = lambda directory, proof, executable: False
            with patch(
                "verifier.skyseal_publication_verify.verify_bundle",
                return_value=bundle_report,
            ), patch("verifier.skyseal_publication_verify.verify_signature"):
                with self.assertRaisesRegex(VerificationError, "not confirmed"):
                    verify_publication(
                        root,
                        public_key=root / "unused.asc",
                        trusted_rp_id="seal.example.org",
                        trusted_origin="https://seal.example.org",
                        ots_verify=pending,
                    )
                report = verify_publication(
                    root,
                    public_key=root / "unused.asc",
                    trusted_rp_id="seal.example.org",
                    trusted_origin="https://seal.example.org",
                    ots_verify=pending,
                    allow_pending_ots=True,
                )
            self.assertTrue(report["ok"])
            self.assertEqual(set(report["opentimestamps"].values()), {"pending_or_unverified"})


if __name__ == "__main__":
    unittest.main()
