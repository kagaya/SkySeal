import hashlib
import io
import tempfile
import unittest
from pathlib import Path

from desktop.engine.bitcoin_verify import _check_headers, verify_detached, TimestampVerificationError

try:
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.serialize import StreamSerializationContext
    HAVE_OTS = True
except ImportError:
    HAVE_OTS = False

# Bitcoin mainnet genesis block, a real PoW/header fixture.
GENESIS = ("01000000" + "00" * 32 +
           "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" +
           "29ab5f49ffff001d1dac2b7c")
BLOCK_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
MERKLE = bytes.fromhex(GENESIS[72:136])


@unittest.skipUnless(HAVE_OTS, "opentimestamps-client optional development dependency")
class BitcoinChecks(unittest.TestCase):
    def test_real_header_merkle_pow_and_provider_agreement(self):
        response = (BLOCK_HASH, GENESIS, 100)
        self.assertEqual(_check_headers(0, MERKLE, [response, response])["status"], "confirmed")
        with self.assertRaises(TimestampVerificationError):
            _check_headers(0, MERKLE, [response, ("0" * 64, GENESIS, 100)])
        with self.assertRaises(Exception):
            _check_headers(0, b"x" * 32, [response, response])

    def test_insufficient_confirmations_never_confirmed(self):
        response = (BLOCK_HASH, GENESIS, 2)
        self.assertEqual(_check_headers(0, MERKLE, [response, response])["status"], "pending")

    def test_pending_file_binding_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            proof_file = Path(tmp) / "target.ots"
            target.write_bytes(b"exact research bytes")
            ts = Timestamp(hashlib.sha256(target.read_bytes()).digest())
            ts.attestations.add(PendingAttestation("https://a.pool.opentimestamps.org"))
            proof = DetachedTimestampFile(OpSHA256(), ts)
            buffer = io.BytesIO()
            proof.serialize(StreamSerializationContext(buffer))
            proof_file.write_bytes(buffer.getvalue())
            def no_network(*args):
                self.fail("Pending evidence must not call a block provider")
            self.assertEqual(verify_detached(proof_file, target, fetch_header=no_network)["status"], "pending")
            target.write_bytes(b"tampered")
            self.assertEqual(verify_detached(proof_file, target, fetch_header=no_network)["status"], "unverified")


if __name__ == "__main__":
    unittest.main()
