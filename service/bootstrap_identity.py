#!/usr/bin/env python3
"""Verify an offline OpenPGP identity-genesis signature and activate the identity."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY))

from service.config import PINNED_OPENPGP_FINGERPRINT  # noqa: E402
from service.storage import Store  # noqa: E402
from verifier.skyseal_verify import validate_orcid  # noqa: E402


def run_gpg(home: Path, arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["gpg", "--batch", "--no-options", "--homedir", str(home), *arguments],
        check=False,
        capture_output=True,
    )


def valid_signature_fingerprints(status_output: bytes) -> set[str]:
    fingerprints: set[str] = set()
    for line in status_output.decode("utf-8", errors="replace").splitlines():
        if not line.startswith("[GNUPG:] VALIDSIG "):
            continue
        fields = line.split()
        fingerprints.update(
            field for field in fields[2:] if len(field) == 40 and all(c in "0123456789ABCDEF" for c in field)
        )
    return fingerprints


def listed_key_fingerprints(colon_output: bytes) -> set[str]:
    fingerprints: set[str] = set()
    for line in colon_output.decode("utf-8", errors="replace").splitlines():
        fields = line.split(":")
        if len(fields) > 9 and fields[0] == "fpr" and len(fields[9]) == 40:
            fingerprints.add(fields[9])
    return fingerprints


def verify_signature(
    genesis: bytes,
    signature_path: Path,
    public_key_path: Path,
    expected_fingerprint: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="skyseal-gpg-") as directory:
        home = Path(directory)
        os.chmod(home, 0o700)
        genesis_path = home / "identity-genesis.json"
        genesis_path.write_bytes(genesis)
        # Some minimal systems return a nonzero import status when gpg-agent
        # cannot start even though the public key was imported. The keyring
        # contents and pinned fingerprint, not that incidental status, are the
        # authority for continuing.
        run_gpg(home, ["--import", str(public_key_path.resolve())])
        listed = run_gpg(home, ["--with-colons", "--list-keys"])
        if expected_fingerprint not in listed_key_fingerprints(listed.stdout):
            raise RuntimeError("could not import the OpenPGP public key")
        checked = run_gpg(
            home,
            [
                "--status-fd=1",
                "--verify",
                str(signature_path.resolve()),
                str(genesis_path),
            ],
        )
        if checked.returncode != 0:
            raise RuntimeError("OpenPGP identity-genesis signature is invalid")
        fingerprints = valid_signature_fingerprints(checked.stdout)
        if expected_fingerprint not in fingerprints:
            raise RuntimeError("valid signature does not resolve to the pinned primary fingerprint")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--orcid", required=True, help="compact ORCID iD or canonical URL")
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--fingerprint", default=PINNED_OPENPGP_FINGERPRINT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    identity_url = args.orcid if args.orcid.startswith("https://") else f"https://orcid.org/{args.orcid}"
    try:
        validate_orcid(identity_url, "ORCID")
        store = Store(args.database.resolve())
        store.initialize()
        identity = store.get_identity(identity_url)
        if identity is None:
            raise RuntimeError("identity not found in the database")
        signature = args.signature.read_bytes()
        verify_signature(
            bytes(identity["genesis_json"]),
            args.signature,
            args.public_key,
            args.fingerprint,
        )
        store.activate_identity(identity_url, signature)
        print(f"Activated {identity_url} with OpenPGP fingerprint {args.fingerprint}")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
