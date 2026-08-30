#!/usr/bin/env python3
"""Verify an owner-disclosed private receipt against public SkySeal evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from verifier.skyseal_verify import (  # noqa: E402
    BASE64URL_RE,
    DIGEST_RE,
    HASH_LIST_FORMAT,
    HEX64_RE,
    VerificationError,
    canonical_json,
    decode_base64url,
    load_json,
    validate_bundle,
)


RECEIPT_SCHEMA = "urn:skyseal:private-ledger-receipt:v1"


def _exact(value: Any, required: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{context}: expected a JSON object")
    missing = required - value.keys()
    unknown = value.keys() - required
    if missing:
        raise VerificationError(f"{context}: missing members: {', '.join(sorted(missing))}")
    if unknown:
        raise VerificationError(f"{context}: unknown members: {', '.join(sorted(unknown))}")
    return value


def validate_receipt(value: Any) -> dict[str, Any]:
    receipt = _exact(
        value,
        {"schema", "commitment_format", "drive_item", "subject_digest", "entry_count", "salt"},
        "private receipt",
    )
    if receipt["schema"] != RECEIPT_SCHEMA:
        raise VerificationError("private receipt: unsupported schema")
    if receipt["commitment_format"] != HASH_LIST_FORMAT:
        raise VerificationError("private receipt: unsupported commitment format")
    item = _exact(
        receipt["drive_item"],
        {"id", "name", "url", "mime_type", "snapshot_digest"},
        "private receipt drive item",
    )
    item_id = item["id"]
    if not isinstance(item_id, str) or BASE64URL_RE.fullmatch(item_id) is None:
        raise VerificationError("private receipt drive item ID is invalid")
    if item["url"] != "https://drive.google.com/open?id=" + quote(item_id, safe=""):
        raise VerificationError("private receipt Drive URL does not match its ID")
    if not isinstance(item["name"], str) or not item["name"] or len(item["name"].encode()) > 1024:
        raise VerificationError("private receipt drive item name is invalid")
    if not isinstance(item["mime_type"], str) or not item["mime_type"]:
        raise VerificationError("private receipt MIME type is invalid")
    if not isinstance(item["snapshot_digest"], str) or HEX64_RE.fullmatch(item["snapshot_digest"]) is None:
        raise VerificationError("private receipt snapshot digest is invalid")
    subject = _exact(
        receipt["subject_digest"], {"algorithm", "value"}, "private receipt subject"
    )
    if subject["algorithm"] != "sha256" or not isinstance(subject["value"], str) or HEX64_RE.fullmatch(subject["value"]) is None:
        raise VerificationError("private receipt subject digest is invalid")
    count = receipt["entry_count"]
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 10_000_000:
        raise VerificationError("private receipt entry count is invalid")
    decode_base64url(receipt["salt"], "private receipt salt", expected_length=32)
    return receipt


def hash_candidate(path: Path) -> tuple[bytes, int]:
    if path.is_symlink():
        raise VerificationError("candidate symlinks are forbidden")
    if path.is_file():
        candidates = [path]
    elif path.is_dir():
        candidates = sorted(item for item in path.rglob("*") if item.is_file())
        if any(item.is_symlink() for item in path.rglob("*")):
            raise VerificationError("candidate directory contains a symlink")
    else:
        raise VerificationError("candidate must be a regular file or directory")
    if not candidates:
        raise VerificationError("candidate contains no regular files")
    hashes_out: set[str] = set()
    for candidate in candidates:
        digest = hashlib.sha256()
        with candidate.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        hashes_out.add(digest.hexdigest())
    hash_list = ("\n".join(sorted(hashes_out)) + "\n").encode("ascii")
    return hash_list, len(hashes_out)


def verify_private_receipt(
    receipt_path: Path, bundle_path: Path, candidate_path: Path
) -> dict[str, Any]:
    receipt = validate_receipt(load_json(receipt_path, "private receipt"))
    bundle = validate_bundle(load_json(bundle_path, "public bundle"))
    payload = bundle["seal_payload"]
    commitment = payload.get("private_ledger_commitment")
    if not isinstance(commitment, str) or DIGEST_RE.fullmatch(commitment) is None:
        raise VerificationError("public bundle has no private-ledger commitment")
    calculated_commitment = "sha256:" + hashlib.sha256(canonical_json(receipt)).hexdigest()
    if calculated_commitment != commitment:
        raise VerificationError("private receipt does not match the signed public commitment")
    if receipt["subject_digest"] != payload["subject_digest"]:
        raise VerificationError("private receipt subject does not match the public bundle")
    hash_list, entry_count = hash_candidate(candidate_path)
    candidate_digest = hashlib.sha256(hash_list).hexdigest()
    if candidate_digest != receipt["subject_digest"]["value"]:
        raise VerificationError("candidate bytes do not match the private receipt")
    if entry_count != receipt["entry_count"]:
        raise VerificationError("candidate entry count does not match the private receipt")
    return {
        "ok": True,
        "seal_id": payload["seal_id"],
        "private_ledger_commitment": commitment,
        "entry_count": entry_count,
        "candidate_matches": True,
        "drive_item_id": receipt["drive_item"]["id"],
        "drive_item_name": receipt["drive_item"]["name"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args(argv)
    try:
        report = verify_private_receipt(args.receipt, args.bundle, args.candidate)
    except (OSError, VerificationError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
