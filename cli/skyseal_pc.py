#!/usr/bin/env python3
"""PC-local SkySeal Phase 1 client; original files and names stay local."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY))

from verifier.skyseal_verify import HASH_LIST_FORMAT, VerificationError, parse_hash_list, verify_bundle  # noqa: E402


class ClientError(RuntimeError):
    pass


def validate_server(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.path not in {"", "/"}:
        raise ClientError("server must be an exact HTTP(S) origin")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ClientError("server origin must not contain credentials, query, or fragment")
    return value.rstrip("/")


def request(
    url: str,
    *,
    method: str = "GET",
    bearer: str | None = None,
    payload: object | None = None,
) -> tuple[bytes, str]:
    headers = {"Accept": "application/json", "User-Agent": "SkySeal-PC/1.0"}
    data = None
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if payload is not None:
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.read(2 * 1024 * 1024), response.headers.get_content_type()
    except urllib.error.HTTPError as exc:
        detail = exc.read(1024 * 1024)
        try:
            message = json.loads(detail).get("message", f"HTTP {exc.code}")
        except Exception:
            message = f"HTTP {exc.code}"
        raise ClientError(message) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ClientError(f"service request failed: {type(exc).__name__}") from exc


def write_private_json(path: Path, value: object) -> None:
    if path.exists():
        raise ClientError(f"refusing to overwrite private state file: {path}")
    data = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def write_public_file(path: Path, data: bytes) -> None:
    if path.exists():
        raise ClientError(f"refusing to overwrite output: {path}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def load_state(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ClientError(f"cannot read state file: {path}") from exc
    if not isinstance(value, dict):
        raise ClientError("state file is not a JSON object")
    required = {"server", "rp_id", "seal_id", "bearer_token", "hash_list"}
    if not required.issubset(value):
        raise ClientError("state file is missing required members")
    return value


def json_from_response(data: bytes) -> dict[str, object]:
    try:
        value = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ClientError("service returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ClientError("service returned a non-object JSON value")
    return value


def create(args: argparse.Namespace) -> int:
    server = validate_server(args.server)
    records, digest = parse_hash_list(args.hash_list)
    data, _ = request(
        f"{server}/api/v1/seals",
        method="POST",
        payload={
            "commitment_format": HASH_LIST_FORMAT,
            "subject_digest": digest,
            "entry_count": len(records),
        },
    )
    response = json_from_response(data)
    state_path = args.state or args.hash_list.with_name(args.hash_list.name + ".pending.json")
    write_private_json(
        state_path,
        {
            "server": server,
            "rp_id": args.rp_id,
            "seal_id": response["seal_id"],
            "bearer_token": response["bearer_token"],
            "approval_url": response["approval_url"],
            "hash_list": str(args.hash_list.resolve()),
            "created_at": int(time.time()),
        },
    )
    print(f"Approval URL:\n{response['approval_url']}")
    print(f"Private state: {state_path}")
    print("Open the URL in the PC browser, then choose a nearby-device passkey to use iPhone/iPad.")
    return 0


def status(args: argparse.Namespace) -> int:
    state = load_state(args.state)
    data, _ = request(
        f"{state['server']}/api/v1/seals/{state['seal_id']}",
        bearer=str(state["bearer_token"]),
    )
    response = json_from_response(data)
    print(json.dumps(response, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if response.get("status") == "approved" else 1


def wait_for_bundle(args: argparse.Namespace) -> int:
    state = load_state(args.state)
    deadline = time.monotonic() + args.timeout
    last_status = None
    while True:
        data, _ = request(
            f"{state['server']}/api/v1/seals/{state['seal_id']}",
            bearer=str(state["bearer_token"]),
        )
        response = json_from_response(data)
        current = response.get("status")
        if current != last_status:
            print(f"Status: {current}")
            last_status = current
        if current == "approved":
            break
        if current in {"expired", "rejected", "invalidated"}:
            raise ClientError(f"seal ended in state: {current}")
        if time.monotonic() >= deadline:
            raise ClientError("timed out waiting for approval")
        time.sleep(args.interval)

    bundle_data, _ = request(
        f"{state['server']}/api/v1/seals/{state['seal_id']}/bundle",
        bearer=str(state["bearer_token"]),
    )
    bundle = json_from_response(bundle_data)
    hash_list = Path(str(state["hash_list"]))
    output = args.output or hash_list.with_name(hash_list.name + ".skyseal.json")
    identity = bundle.get("identity")
    if not isinstance(identity, dict) or not isinstance(identity.get("orcid"), str):
        raise ClientError("bundle does not contain an ORCID identity")
    compact = identity["orcid"].rsplit("/", 1)[-1]
    genesis_data, _ = request(f"{state['server']}/api/v1/identity/{compact}/genesis")
    genesis_output = args.genesis_output or output.with_name("identity-genesis.json")
    write_public_file(output, bundle_data)
    write_public_file(genesis_output, genesis_data)

    if str(state["server"]).startswith("https://"):
        verification = verify_bundle(
            hash_list,
            output,
            genesis_output,
            str(state["rp_id"]),
            str(state["server"]),
        )
        print(json.dumps(verification, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print("Development HTTP origin: offline production-bundle verification was skipped.")
    print(f"Bundle: {output}")
    print(f"Identity genesis: {genesis_output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create", help="create a hash-only approval transaction")
    create_parser.add_argument("hash_list", type=Path)
    create_parser.add_argument("--server", required=True)
    create_parser.add_argument("--rp-id", required=True)
    create_parser.add_argument("--state", type=Path)
    create_parser.set_defaults(function=create)

    status_parser = subparsers.add_parser("status", help="show transaction status")
    status_parser.add_argument("state", type=Path)
    status_parser.set_defaults(function=status)

    wait_parser = subparsers.add_parser("wait", help="wait for approval and download the bundle")
    wait_parser.add_argument("state", type=Path)
    wait_parser.add_argument("--output", type=Path)
    wait_parser.add_argument("--genesis-output", type=Path)
    wait_parser.add_argument("--timeout", type=float, default=900)
    wait_parser.add_argument("--interval", type=float, default=2)
    wait_parser.set_defaults(function=wait_for_bundle)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.function(args)
    except (ClientError, VerificationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
