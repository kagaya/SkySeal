from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from verifier.skyseal_private_ledger_verify import verify_private_receipt
from verifier.skyseal_verify import VerificationError, canonical_json, encode_base64url


class PrivateLedgerVerifierTests(unittest.TestCase):
    def test_owner_receipt_binds_candidate_to_public_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "confidential-paper.bin"
            candidate.write_bytes(b"owner-disclosed research bytes")
            record = hashlib.sha256(candidate.read_bytes()).hexdigest()
            subject = hashlib.sha256((record + "\n").encode()).hexdigest()
            receipt = {
                "schema": "urn:skyseal:private-ledger-receipt:v1",
                "commitment_format": "skyseal-sha256-set-v1",
                "drive_item": {
                    "id": "privateDriveId_1",
                    "name": "confidential-paper.bin",
                    "url": "https://drive.google.com/open?id=privateDriveId_1",
                    "mime_type": "application/octet-stream",
                    "snapshot_digest": "b" * 64,
                },
                "subject_digest": {"algorithm": "sha256", "value": subject},
                "entry_count": 1,
                "salt": encode_base64url(b"s" * 32),
            }
            commitment = "sha256:" + hashlib.sha256(canonical_json(receipt)).hexdigest()
            bundle = {
                "schema": "urn:skyseal:webauthn-bundle:v1",
                "seal_payload": {
                    "schema": "urn:skyseal:seal-payload:v1",
                    "seal_id": "018f0000-0000-7000-8000-000000000001",
                    "commitment_format": "skyseal-sha256-set-v1",
                    "subject_digest": {"algorithm": "sha256", "value": subject},
                    "identity_id": "https://orcid.org/0000-0002-1825-0097",
                    "identity_version": 1,
                    "identity_state_digest": "sha256:" + "c" * 64,
                    "nonce": encode_base64url(b"n" * 32),
                    "created_at": "2026-08-30T00:00:00Z",
                    "private_ledger_commitment": commitment,
                },
                "webauthn": {
                    "client_data_json": "e30",
                    "authenticator_data": "AA",
                    "signature": "AA",
                },
                "identity": {
                    "orcid": "https://orcid.org/0000-0002-1825-0097",
                    "identity_genesis_digest": "sha256:" + "d" * 64,
                    "identity_state_digest": "sha256:" + "c" * 64,
                    "credential_event_digest": "sha256:" + "e" * 64,
                },
                "verification": {
                    "rp_id": "proof.excyberlab.net",
                    "allowed_origin": "https://proof.excyberlab.net",
                },
            }
            receipt_path = root / "receipt.json"
            bundle_path = root / "seal.skyseal.json"
            receipt_path.write_bytes(canonical_json(receipt) + b"\n")
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            report = verify_private_receipt(receipt_path, bundle_path, candidate)
            self.assertTrue(report["candidate_matches"])
            candidate.write_bytes(b"tampered")
            with self.assertRaisesRegex(VerificationError, "candidate bytes"):
                verify_private_receipt(receipt_path, bundle_path, candidate)


if __name__ == "__main__":
    unittest.main()
