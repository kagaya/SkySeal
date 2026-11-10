"""Direct OpenTimestamps calendar client without wallet/RPC/OpenSSL bindings.

Only blinded commitments leave the PC. Calendar replies are bounded and
untrusted; a reply or successful upgrade never means Bitcoin confirmation.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
from pathlib import Path
import secrets
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from opentimestamps.core.notary import PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

CALENDARS = ("https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org")
ALLOWED_HOSTS = frozenset({"a.pool.opentimestamps.org", "b.pool.opentimestamps.org",
    "alice.btc.calendar.opentimestamps.org", "bob.btc.calendar.opentimestamps.org",
    "finney.calendar.eternitywall.com", "btc.calendar.catallaxy.com"})
MAX_RESPONSE_BYTES = 256 * 1024
MAX_PROOF_BYTES = 4 * 1024 * 1024
MAX_NODES = 4096
MAX_DEPTH = 128
MAX_REQUESTS = 8


class TimestampError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TimestampError("Calendar redirects are not accepted")


def _calendar_origin(uri: str | bytes) -> str:
    if isinstance(uri, bytes):
        uri = uri.decode("ascii")
    if not isinstance(uri, str):
        raise TimestampError("Invalid calendar URI")
    try:
        parsed = urlsplit(uri)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS or parsed.port is not None or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            raise TimestampError("Proof uses an untrusted calendar origin")
    except (ValueError, UnicodeError) as exc:
        raise TimestampError("Invalid calendar URI") from exc
    origin = "https://" + parsed.hostname
    if origin != uri:
        raise TimestampError("Calendar URI must be an exact approved HTTPS origin")
    return origin


def _nodes(timestamp: Timestamp):
    stack = [(timestamp, 0)]
    seen = set()
    while stack:
        node, depth = stack.pop()
        if id(node) in seen:
            raise TimestampError("Cyclic or shared timestamp nodes are not accepted")
        seen.add(id(node))
        if len(seen) > MAX_NODES or depth > MAX_DEPTH:
            raise TimestampError("Timestamp tree exceeds accepted bounds")
        if len(node.attestations) > MAX_NODES:
            raise TimestampError("Too many timestamp attestations")
        yield node
        stack.extend((child, depth + 1) for child in node.ops.values())


def _serialize(detached: DetachedTimestampFile) -> bytes:
    list(_nodes(detached.timestamp))
    context = BytesSerializationContext()
    detached.serialize(context)
    result = context.getbytes()
    if len(result) > MAX_PROOF_BYTES:
        raise TimestampError("Timestamp proof exceeds accepted size")
    return result


def _deserialize(raw: bytes) -> DetachedTimestampFile:
    if len(raw) > MAX_PROOF_BYTES:
        raise TimestampError("Timestamp proof exceeds accepted size")
    try:
        detached = DetachedTimestampFile.deserialize(BytesDeserializationContext(raw))
        if type(detached.file_hash_op) is not OpSHA256:
            raise TimestampError("Only SHA-256 detached proofs are accepted")
        list(_nodes(detached.timestamp))
        return detached
    except TimestampError:
        raise
    except Exception as exc:
        raise TimestampError("Invalid OpenTimestamps proof") from exc


def _response_timestamp(raw: bytes, commitment: bytes) -> Timestamp:
    if len(raw) > MAX_RESPONSE_BYTES:
        raise TimestampError("Calendar response exceeds accepted size")
    try:
        context = BytesDeserializationContext(raw)
        timestamp = Timestamp.deserialize(context, commitment, _recursion_limit=MAX_DEPTH)
        context.assert_eof()
        for node in _nodes(timestamp):
            for attestation in node.attestations:
                if type(attestation) is PendingAttestation:
                    _calendar_origin(attestation.uri)
        return timestamp
    except TimestampError:
        raise
    except Exception as exc:
        raise TimestampError("Invalid calendar response") from exc


def _request(origin: str, commitment: bytes, *, submit: bool, timeout: float) -> bytes:
    origin = _calendar_origin(origin)
    if not 1 <= len(commitment) <= 4096:
        raise TimestampError("Invalid calendar commitment size")
    url = origin + ("/digest" if submit else "/timestamp/" + commitment.hex())
    request = urllib.request.Request(url, data=commitment if submit else None,
        headers={"Accept": "application/vnd.opentimestamps.v1", "User-Agent": "SkySeal-Desktop/0.1",
                 "Content-Type": "application/octet-stream"})
    deadline = time.monotonic() + timeout
    with urllib.request.build_opener(_NoRedirect).open(request, timeout=min(timeout, 20)) as response:
        if response.status != 200:
            raise TimestampError("Calendar did not return a timestamp")
        chunks, total = [], 0
        read = getattr(response, "read1", response.read)
        while True:
            if time.monotonic() >= deadline:
                raise TimestampError("Calendar response exceeded the time limit")
            chunk = read(min(8192, MAX_RESPONSE_BYTES + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise TimestampError("Calendar response exceeds accepted size")


class TimestampClient:
    def __init__(self, timeout: int = 90, *, transport=None, nonce_factory=None):
        self.timeout = min(max(timeout, 1), 120)
        self.transport = transport or _request
        self.nonce_factory = nonce_factory or (lambda: secrets.token_bytes(32))

    def _fetch(self, origin, commitment, *, submit, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimestampError("Timestamp request time budget exhausted")
        return _response_timestamp(self.transport(origin, commitment, submit=submit,
            timeout=min(remaining, 25)), commitment)

    def stamp(self, target: Path) -> bytes:
        with Path(target).open("rb") as source:
            detached = DetachedTimestampFile.from_fd(OpSHA256(), source)
        nonce = self.nonce_factory()
        if not isinstance(nonce, bytes) or len(nonce) != 32:
            raise TimestampError("Timestamp blinding nonce must be 32 bytes")
        blinded = detached.timestamp.ops.add(OpAppend(nonce)).ops.add(OpSHA256())
        deadline = time.monotonic() + self.timeout
        accepted = []
        for origin in CALENDARS:
            try:
                result = self._fetch(origin, blinded.msg, submit=True, deadline=deadline)
                # Check a candidate before replacing the previous usable result.
                candidate = DetachedTimestampFile(OpSHA256(), Timestamp(detached.file_digest))
                node = candidate.timestamp.ops.add(OpAppend(nonce)).ops.add(OpSHA256())
                for reply in [*accepted, result]:
                    node.merge(reply)
                _serialize(candidate)
                detached = candidate
                accepted.append(result)
            except Exception:
                # Preserve usable responses even if another calendar is down.
                continue
        if not accepted:
            raise TimestampError("No calendar returned a usable proof; retry from history")
        return _serialize(detached)

    def upgrade(self, target: Path, proof: Path) -> bytes:
        with Path(proof).open("rb") as source:
            raw = source.read(MAX_PROOF_BYTES + 1)
        detached = _deserialize(raw)
        with Path(target).open("rb") as source:
            target_digest = OpSHA256().hash_fd(source)
        if detached.file_digest != target_digest:
            raise TimestampError("Timestamp proof does not match its target")
        pending = []
        for node in _nodes(detached.timestamp):
            for attestation in node.attestations:
                if type(attestation) is PendingAttestation:
                    origin = _calendar_origin(attestation.uri)
                    pending.append((node, origin))
        deadline = time.monotonic() + self.timeout
        current = raw
        for node, origin in pending[:MAX_REQUESTS]:
            try:
                response = self._fetch(origin, node.msg, submit=False, deadline=deadline)
                # Merge into a copy so an oversized merged response cannot
                # discard a previous successful partial upgrade.
                candidate = _deserialize(current)
                destination = next(stamp for stamp in _nodes(candidate.timestamp) if stamp.msg == node.msg)
                destination.merge(response)
                current = _serialize(candidate)
            except Exception:
                # Keeping the exact previous pending proof is a successful retry
                # outcome, but does not imply a confirmed timestamp.
                continue
        return current

    @staticmethod
    def _check_calendar_uris(raw: bytes) -> None:
        for node in _nodes(_deserialize(raw).timestamp):
            for attestation in node.attestations:
                if type(attestation) is PendingAttestation:
                    _calendar_origin(attestation.uri)

    def verify(self, target: Path, proof: Path) -> dict:
        from .bitcoin_verify import verify_detached
        return verify_detached(proof, target)


def self_test() -> dict:
    """Offline frozen-runtime check: parse/serialize and bind a pending proof."""
    from .bitcoin_verify import verify_detached
    content = b"SkySeal bundled OTS self-test\n"
    detached = DetachedTimestampFile(OpSHA256(), Timestamp(hashlib.sha256(content).digest()))
    detached.timestamp.attestations.add(PendingAttestation(CALENDARS[0]))
    raw = _serialize(detached)
    if _deserialize(raw).file_digest != hashlib.sha256(content).digest():
        raise TimestampError("OTS round-trip self-test failed")
    with tempfile.TemporaryDirectory(prefix="skyseal-ots-self-test-") as temporary:
        target = Path(temporary) / "target.bin"
        proof_path = Path(temporary) / "target.bin.ots"
        target.write_bytes(content)
        proof_path.write_bytes(raw)
        def no_network(*args):
            raise TimestampError("Pending self-test must not access the network")
        result = verify_detached(proof_path, target, fetch_header=no_network)
        target.write_bytes(b"changed self-test bytes")
        tampered = verify_detached(proof_path, target, fetch_header=no_network)
    if result.get("status") != "pending" or tampered.get("status") != "unverified":
        raise TimestampError("Bundled OTS target-binding self-test failed")
    return {"ok": True, "library": "opentimestamps", "version": importlib.metadata.version("opentimestamps"),
            "status": "pending", "network_used": False, "pending_verified": True, "tamper_rejected": True}
