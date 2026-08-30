#!/usr/bin/env python3
"""Verify a complete public SkySeal evidence directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Callable

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from verifier.skyseal_verify import (  # noqa: E402
    DIGEST_RE,
    UUID7_RE,
    VerificationError,
    parse_json_bytes,
    verify_bundle,
)


SCHEMA = "urn:skyseal:publication-manifest:v2"
ARTIFACT_NAMES = {
    "hashes.txt",
    "seal.skyseal.json",
    "seal.skyseal.json.ots",
    "identity-genesis.json",
    "identity-activation.json",
    "identity-activation.json.ots",
}
SKY_WITNESS_ARTIFACT_NAMES = {"sky-witness.json", "sky-witness.jpg"}
TIMESTAMP_TARGETS = {
    ("seal.skyseal.json.ots", "seal.skyseal.json"),
    ("identity-activation.json.ots", "identity-activation.json"),
}


def sha256_prefixed(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise VerificationError(f"cannot read publication artifact: {path.name}") from exc
    return "sha256:" + digest.hexdigest()


def verify_manifest(directory: Path) -> dict[str, object]:
    try:
        manifest_bytes = (directory / "manifest.json").read_bytes()
    except OSError as exc:
        raise VerificationError("cannot read publication manifest") from exc
    manifest = parse_json_bytes(manifest_bytes, "publication manifest")
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema",
        "seal_id",
        "artifacts",
        "timestamp_targets",
    }:
        raise VerificationError("publication manifest has invalid members")
    if manifest["schema"] != SCHEMA:
        raise VerificationError("unsupported publication manifest schema")
    if not isinstance(manifest["seal_id"], str) or UUID7_RE.fullmatch(manifest["seal_id"]) is None:
        raise VerificationError("publication manifest has an invalid seal ID")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, dict) or frozenset(artifacts) not in {
        frozenset(ARTIFACT_NAMES),
        frozenset(ARTIFACT_NAMES | SKY_WITNESS_ARTIFACT_NAMES),
    }:
        raise VerificationError("publication manifest has an invalid artifact set")
    for name in sorted(artifacts):
        record = artifacts[name]
        if not isinstance(record, dict) or set(record) != {"sha256"}:
            raise VerificationError(f"invalid artifact record: {name}")
        expected = record["sha256"]
        if not isinstance(expected, str) or DIGEST_RE.fullmatch(expected) is None:
            raise VerificationError(f"invalid artifact digest: {name}")
        if sha256_prefixed(directory / name) != expected:
            raise VerificationError(f"publication artifact digest mismatch: {name}")
    raw_targets = manifest["timestamp_targets"]
    if not isinstance(raw_targets, list) or len(raw_targets) != 2:
        raise VerificationError("publication manifest has invalid timestamp targets")
    targets: set[tuple[str, str]] = set()
    for target in raw_targets:
        if not isinstance(target, dict) or set(target) != {"proof", "target"}:
            raise VerificationError("invalid timestamp target record")
        proof, subject = target["proof"], target["target"]
        if not isinstance(proof, str) or not isinstance(subject, str):
            raise VerificationError("timestamp target names must be strings")
        targets.add((proof, subject))
    if targets != TIMESTAMP_TARGETS:
        raise VerificationError("timestamp proof-to-target mapping is invalid")
    return manifest


def default_ots_verify(directory: Path, proof_name: str, executable: str) -> bool:
    try:
        completed = subprocess.run(
            [executable, "verify", proof_name],
            cwd=directory,
            check=False,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerificationError("OpenTimestamps verifier could not run") from exc
    return completed.returncode == 0


def verify_publication(
    directory: Path,
    *,
    trusted_rp_id: str,
    trusted_origin: str,
    ots_executable: str = "ots",
    ots_verify: Callable[[Path, str, str], bool] = default_ots_verify,
    allow_pending_ots: bool = False,
) -> dict[str, object]:
    directory = directory.resolve()
    if not directory.is_dir():
        raise VerificationError("publication path is not a directory")
    manifest = verify_manifest(directory)
    bundle_report = verify_bundle(
        directory / "hashes.txt",
        directory / "seal.skyseal.json",
        directory / "identity-genesis.json",
        trusted_rp_id,
        trusted_origin,
        directory / "identity-activation.json",
        directory / "sky-witness.json" if "sky-witness.json" in manifest["artifacts"] else None,
        directory / "sky-witness.jpg" if "sky-witness.jpg" in manifest["artifacts"] else None,
    )
    if bundle_report["seal_id"] != manifest["seal_id"]:
        raise VerificationError("publication manifest and bundle seal IDs differ")
    timestamp_status = {}
    for proof_name, _ in sorted(TIMESTAMP_TARGETS):
        confirmed = ots_verify(directory, proof_name, ots_executable)
        timestamp_status[proof_name] = "confirmed" if confirmed else "pending_or_unverified"
        if not confirmed and not allow_pending_ots:
            raise VerificationError(f"OpenTimestamps proof is not confirmed: {proof_name}")
    return {
        "ok": True,
        "seal_id": manifest["seal_id"],
        "entry_count": bundle_report["entry_count"],
        "identity_id": bundle_report["identity_id"],
        "identity_activation": "ORCID OAuth + User-Verified Passkey",
        "sky_witness": bundle_report.get("sky_witness"),
        "opentimestamps": timestamp_status,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--rp-id", required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--ots", default="ots", help="OpenTimestamps executable")
    parser.add_argument("--allow-pending-ots", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = verify_publication(
            args.directory,
            trusted_rp_id=args.rp_id,
            trusted_origin=args.origin,
            ots_executable=args.ots,
            allow_pending_ots=args.allow_pending_ots,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
