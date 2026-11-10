"""Verify OTS commitments against Bitcoin headers from two HTTPS providers.

This is explicitly an explorer-assisted check, not full-chain validation. The
providers attest chain membership/height; OTS operations, file digest, block
hash, proof of work and merkle-root binding are checked locally. No source file,
filename or digest is sent to these providers (only public block heights/hashes).
"""
from __future__ import annotations

import hashlib
import io
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PROVIDERS = ("https://blockstream.info/api", "https://mempool.space/api")
MAX_PROOF_BYTES = 4 * 1024 * 1024
MIN_CONFIRMATIONS = 6


class TimestampVerificationError(ValueError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TimestampVerificationError("Block provider redirected the request")


def _get_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "SkySeal-Desktop/0.1"})
    with urllib.request.build_opener(_NoRedirect).open(request, timeout=12) as response:
        data = response.read(1025)
        if len(data) > 1024:
            raise TimestampVerificationError("Oversized block provider response")
        return data.decode("ascii").strip()


def _provider_header(provider: str, height: int) -> tuple[str, str, int]:
    block_hash = _get_text(f"{provider}/block-height/{height}")
    if re.fullmatch(r"[0-9a-f]{64}", block_hash) is None:
        raise TimestampVerificationError("Invalid Bitcoin block hash")
    header = _get_text(f"{provider}/block/{block_hash}/header")
    if re.fullmatch(r"[0-9a-fA-F]{160}", header) is None:
        raise TimestampVerificationError("Invalid Bitcoin block header")
    tip = _get_text(f"{provider}/blocks/tip/height")
    if re.fullmatch(r"[0-9]{1,9}", tip) is None:
        raise TimestampVerificationError("Invalid Bitcoin tip height")
    return block_hash, header.lower(), int(tip)


def _check_headers(height: int, leaf: bytes, responses: list[tuple[str, str, int]]) -> dict:
    from bitcoin.core import CBlockHeader, CheckProofOfWork, b2lx
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation

    if len(responses) != 2:
        raise TimestampVerificationError("Both independent providers are required")
    first, second = responses
    if first[:2] != second[:2]:
        raise TimestampVerificationError("Bitcoin providers disagree about the block")
    raw = bytes.fromhex(first[1])
    if len(raw) != 80:
        raise TimestampVerificationError("Bitcoin header must contain 80 bytes")
    header = CBlockHeader.deserialize(raw)
    if b2lx(header.GetHash()) != first[0]:
        raise TimestampVerificationError("Bitcoin header hash does not match")
    CheckProofOfWork(header.GetHash(), header.nBits)
    block_time = BitcoinBlockHeaderAttestation(height).verify_against_blockheader(leaf, header)
    confirmations = min(first[2], second[2]) - height + 1
    if confirmations < MIN_CONFIRMATIONS:
        return {"status": "pending", "reason": "insufficient_confirmations", "confirmations": max(0, confirmations)}
    return {
        "status": "confirmed", "height": height, "block_hash": first[0],
        "block_time": datetime.fromtimestamp(block_time, timezone.utc).isoformat(),
        "confirmations": confirmations,
    }


def verify_detached(proof_path: Path, target_path: Path, *, fetch_header=None) -> dict:
    """No submission or upgrade: verify an existing proof against exact bytes.

    Invalid commitments and unavailable chain information are returned as
    ``unverified``; they can never become a positive time claim. Caller should
    preserve this distinction from a valid but pending proof.
    """
    base = {"trust_mode": "https_explorers", "providers": list(PROVIDERS), "full_chain_validated": False}
    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.serialize import StreamDeserializationContext
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation

        proof_path, target_path = Path(proof_path), Path(target_path)
        if proof_path.is_symlink() or target_path.is_symlink():
            raise TimestampVerificationError("Symbolic links are not accepted")
        if proof_path.stat().st_size > MAX_PROOF_BYTES:
            raise TimestampVerificationError("OTS proof is too large")
        raw = proof_path.read_bytes()
        proof = DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(raw)))
        if type(proof.file_hash_op) is not OpSHA256:
            raise TimestampVerificationError("Only SHA-256 detached proofs are accepted")
        digest = hashlib.sha256()
        with target_path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.digest() != proof.file_digest:
            raise TimestampVerificationError("OTS proof does not match the target bytes")
        attestations = list(proof.timestamp.all_attestations())
        candidates = sorted(((leaf, att) for leaf, att in attestations
                             if type(att) is BitcoinBlockHeaderAttestation), key=lambda item: item[1].height)
        if not candidates:
            pending = any(type(att) is PendingAttestation for _, att in attestations)
            return {**base, "status": "pending" if pending else "unverified",
                    "reason": "awaiting_bitcoin_attestation" if pending else "no_bitcoin_attestation"}
        fetch = fetch_header or _provider_header
        errors = []
        # Bound network work for untrusted input containing many attestations.
        for leaf, attestation in candidates[:3]:
            try:
                height = attestation.height
                if not 0 <= height <= 100_000_000:
                    raise TimestampVerificationError("Bitcoin height is outside accepted bounds")
                result = _check_headers(height, leaf, [fetch(provider, height) for provider in PROVIDERS])
                return {**base, **result}
            except Exception as exc:
                errors.append(type(exc).__name__)
        return {**base, "status": "unverified", "reason": "block_verification_failed", "errors": errors}
    except Exception as exc:
        return {**base, "status": "unverified", "reason": "invalid_or_unavailable_proof", "error_type": type(exc).__name__}
