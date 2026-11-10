"""One bounded JSON request on stdin, one JSON result on stdout."""
from __future__ import annotations
import json
import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--ots-self-test"]:
        from .ots import self_test
        print(json.dumps(self_test(), sort_keys=True))
        return 0
    if args == ["--ots", "--version"]:
        import importlib.metadata
        print("opentimestamps " + importlib.metadata.version("opentimestamps"))
        return 0
    if args and args[0] == "--ots":
        print("Use the SkySeal engine API for timestamp operations", file=sys.stderr)
        return 2
    from verifier.skyseal_verify import parse_json_bytes, VerificationError
    from .core import Engine, EngineError
    engine = None
    try:
        raw = sys.stdin.buffer.readline(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise EngineError("invalid_request", "Request is too large")
        request = parse_json_bytes(raw, "desktop request")
        if not isinstance(request, dict):
            raise EngineError("invalid_request", "Request must be a JSON object")
        engine = Engine()
        response = {"ok": True, "result": engine.dispatch(request)}
    except Exception as exc:
        # Do not send tracebacks or network/token details to the UI or logs.
        if isinstance(exc, EngineError):
            code, message = exc.code, str(exc)
        elif isinstance(exc, VerificationError):
            code, message = "verification_failed", str(exc)
        elif type(exc).__name__ in {"WindowsAuthenticationError", "WindowsAuthError", "ORCIDError", "ORCIDAuthError", "TimestampError", "SkyWitnessError"}:
            code, message = "operation_failed", str(exc)
        elif isinstance(exc, (OSError, ValueError, TypeError)):
            code, message = "operation_failed", "The operation could not complete; check configuration, selected paths, and available storage"
        else:
            code, message = "operation_failed", "The operation could not complete; the existing proof has been retained"
        response = {"ok": False, "error": {"code": code, "message": message}}
    finally:
        if engine is not None:
            engine.close()
    sys.stdout.write(json.dumps(response, ensure_ascii=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
