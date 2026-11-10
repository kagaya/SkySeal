import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from desktop.engine.ots import (TimestampClient, TimestampError, CALENDARS, MAX_RESPONSE_BYTES,
    _calendar_origin, _deserialize, _response_timestamp, self_test)
from opentimestamps.core.notary import PendingAttestation
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import Timestamp
from opentimestamps.core.op import OpSHA256


def response(commitment, origin):
    timestamp = Timestamp(commitment)
    timestamp.attestations.add(PendingAttestation(origin))
    context = BytesSerializationContext()
    timestamp.serialize(context)
    return context.getbytes()


class DirectTimestampTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.target = Path(self.temporary.name) / "target.bin"
        self.proof = Path(self.temporary.name) / "target.bin.ots"
        self.target.write_bytes(b"synthetic test bytes")

    def tearDown(self):
        self.temporary.cleanup()

    def test_stamp_blinds_digest_and_keeps_one_calendar_when_other_fails(self):
        requests = []
        def transport(origin, commitment, *, submit, timeout):
            requests.append((origin, commitment, submit, timeout))
            if origin == CALENDARS[1]:
                raise OSError("second calendar unavailable")
            return response(commitment, origin)
        client = TimestampClient(transport=transport, nonce_factory=lambda: b"n" * 32)
        raw = client.stamp(self.target)
        detached = _deserialize(raw)
        digest = hashlib.sha256(self.target.read_bytes()).digest()
        self.assertEqual(detached.file_digest, digest)
        expected = hashlib.sha256(digest + b"n" * 32).digest()
        self.assertEqual([request[1] for request in requests], [expected, expected])
        self.assertTrue(all(request[2] for request in requests))
        self.assertNotEqual(expected, digest)
        self.assertEqual(len(list(detached.timestamp.all_attestations())), 1)

    def test_all_calendars_unavailable_never_fabricates_proof(self):
        with self.assertRaises(TimestampError):
            TimestampClient(transport=mock.Mock(side_effect=OSError("offline"))).stamp(self.target)

    def test_upgrade_outage_retains_exact_pending_bytes(self):
        client = TimestampClient(transport=lambda origin, commitment, **kw: response(commitment, origin))
        raw = client.stamp(self.target)
        self.proof.write_bytes(raw)
        client.transport = mock.Mock(side_effect=OSError("offline"))
        self.assertEqual(client.upgrade(self.target, self.proof), raw)
        self.assertEqual(client.transport.call_count, 2)

    def test_upgrade_checks_file_digest_before_any_network(self):
        client = TimestampClient(transport=lambda origin, commitment, **kw: response(commitment, origin))
        self.proof.write_bytes(client.stamp(self.target))
        self.target.write_bytes(b"changed")
        client.transport = mock.Mock(side_effect=AssertionError("must not call network"))
        with self.assertRaisesRegex(TimestampError, "does not match"):
            client.upgrade(self.target, self.proof)
        client.transport.assert_not_called()

    def test_upgrade_merges_real_operations_from_partial_calendar_response(self):
        client = TimestampClient(transport=lambda origin, commitment, **kw: response(commitment, origin))
        original = client.stamp(self.target)
        self.proof.write_bytes(original)
        def transport(origin, commitment, **kw):
            if origin == CALENDARS[1]:
                raise OSError("second calendar offline")
            timestamp = Timestamp(commitment)
            child = timestamp.ops.add(OpSHA256())
            child.attestations.add(PendingAttestation(origin))
            context = BytesSerializationContext()
            timestamp.serialize(context)
            return context.getbytes()
        client.transport = transport
        updated = client.upgrade(self.target, self.proof)
        self.assertNotEqual(updated, original)
        self.assertEqual(_deserialize(updated).file_digest, hashlib.sha256(self.target.read_bytes()).digest())
        self.assertEqual(len(list(_deserialize(updated).timestamp.all_attestations())), 3)

    def test_calendar_origin_restrictions(self):
        self.assertEqual(_calendar_origin(CALENDARS[0]), CALENDARS[0])
        for uri in ["http://a.pool.opentimestamps.org", CALENDARS[0] + "/", CALENDARS[0] + "/evil",
                    CALENDARS[0] + "?q=1", CALENDARS[0] + "#frag", CALENDARS[0] + ":443",
                    "https://user@a.pool.opentimestamps.org", "https://localhost", "https://a.pool.opentimestamps.org.evil.test"]:
            with self.subTest(uri=uri), self.assertRaises(TimestampError):
                _calendar_origin(uri)

    def test_response_rejects_trailing_bytes_oversize_and_untrusted_calendar(self):
        commitment = b"x" * 32
        for raw in [response(commitment, CALENDARS[0]) + b"junk", b"x" * (MAX_RESPONSE_BYTES + 1),
                    response(commitment, "https://evil.test")]:
            with self.assertRaises(TimestampError):
                _response_timestamp(raw, commitment)

    def test_offline_self_test_does_not_import_wallet_or_rpc(self):
        import sys
        result = self_test()
        self.assertTrue(result["pending_verified"])
        self.assertTrue(result["tamper_rejected"])
        self.assertFalse(result["network_used"])
        self.assertNotIn("bitcoin.wallet", sys.modules)
        self.assertNotIn("bitcoin.rpc", sys.modules)
        self.assertNotIn("bitcoin.core.key", sys.modules)


if __name__ == "__main__":
    unittest.main()
