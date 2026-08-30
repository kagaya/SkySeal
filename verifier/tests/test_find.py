from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from verifier.skyseal_find import locate


class EvidenceLocatorTests(unittest.TestCase):
    def test_locates_exact_candidate_without_private_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "published-paper.pdf"
            candidate.write_bytes(b"exact publicly disclosed bytes")
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            evidence = root / "evidence" / "2026" / "08" / "seal-id"
            evidence.mkdir(parents=True)
            (evidence / "hashes.txt").write_text(digest + "\n", encoding="ascii")
            (evidence / "manifest.json").write_text("{}", encoding="ascii")

            report = locate(candidate, root / "evidence")
            self.assertEqual(len(report["matches"]), 1)
            self.assertEqual(
                report["matches"][0]["evidence_directory"], "2026/08/seal-id"
            )
            self.assertEqual(
                report["matches"][0]["match_scope"], "single-distinct-hash seal"
            )

            candidate.write_bytes(b"different bytes")
            self.assertEqual(locate(candidate, root / "evidence")["matches"], [])


if __name__ == "__main__":
    unittest.main()
