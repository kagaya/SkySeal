#!/usr/bin/env python3
"""Locate public SkySeal evidence containing the exact candidate bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from verifier.skyseal_verify import VerificationError, parse_hash_list  # noqa: E402


def hash_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise VerificationError("candidate must be a regular, non-symlink file")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise VerificationError(f"cannot read candidate: {type(exc).__name__}") from exc
    return digest.hexdigest()


def locate(candidate: Path, evidence_root: Path) -> dict[str, object]:
    candidate_digest = hash_file(candidate)
    root = evidence_root.resolve()
    if not root.is_dir():
        raise VerificationError("evidence root is not a directory")
    matches: list[dict[str, object]] = []
    invalid: list[str] = []
    for hash_list in sorted(root.rglob("hashes.txt")):
        directory = hash_list.parent
        if not (directory / "manifest.json").is_file():
            continue
        relative = directory.relative_to(root).as_posix()
        try:
            records, subject_digest = parse_hash_list(hash_list)
        except VerificationError:
            invalid.append(relative)
            continue
        if candidate_digest in records:
            matches.append(
                {
                    "evidence_directory": relative,
                    "seal_id": directory.name,
                    "entry_count": len(records),
                    "match_scope": (
                        "single-distinct-hash seal"
                        if len(records) == 1
                        else "member of a multi-hash seal"
                    ),
                    "subject_digest": "sha256:" + subject_digest,
                }
            )
    return {
        "ok": True,
        "candidate_digest": "sha256:" + candidate_digest,
        "matches": matches,
        "invalid_evidence_directories": invalid,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("evidence_root", type=Path, nargs="?", default=Path("evidence"))
    args = parser.parse_args(argv)
    try:
        result = locate(args.candidate, args.evidence_root)
    except VerificationError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
