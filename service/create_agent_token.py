#!/usr/bin/env python3
"""Create a one-time-display token for a private SkySeal Drive agent."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from service.storage import Store  # noqa: E402
from verifier.skyseal_verify import validate_orcid  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--orcid", required=True, help="compact ORCID iD or canonical URL")
    parser.add_argument("--output", type=Path, help="write the token once with mode 600")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    identity_url = (
        args.orcid if args.orcid.startswith("https://") else f"https://orcid.org/{args.orcid}"
    )
    try:
        validate_orcid(identity_url, "ORCID")
        output = args.output.expanduser().resolve() if args.output is not None else None
        if output is not None and (output.exists() or not output.parent.is_dir()):
            raise RuntimeError("output must be a new file in an existing private directory")
        store = Store(args.database.resolve())
        store.initialize()
        token = store.create_agent_token(identity_url)
        if output is not None:
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
                    handle.write(token + "\n")
            except Exception:
                try:
                    output.unlink()
                except OSError:
                    pass
                raise
            print(f"Created mode-600 Drive agent token file: {output}")
        else:
            print("Store this token in the Drive agent's mode-600 configuration.")
            print("It cannot be displayed again.")
            print(token)
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
