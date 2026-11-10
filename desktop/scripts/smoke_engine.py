"""Exercise the *packaged* engine with no external network or user profile data."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> int:
    executable = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="skyseal-package-smoke-") as temporary:
        root = Path(temporary)
        environment = dict(os.environ)
        environment["SKYSEAL_DESKTOP_DATA_DIR"] = str(root / "data")
        environment["PYTHONUTF8"] = "1"

        # Exercise the actual frozen library imports and detached proof parser,
        # not merely package metadata or an external `ots` command.
        diagnostic = subprocess.run(
            [str(executable), "--ots-self-test"],
            text=True,
            encoding="utf-8",
            capture_output=True,
            env=environment,
            timeout=90,
            check=False,
        )
        if diagnostic.returncode:
            raise RuntimeError(f"packaged timestamp self-test exited {diagnostic.returncode}: {diagnostic.stderr[:1000]}")
        timestamp_check = json.loads(diagnostic.stdout)
        if not all(timestamp_check.get(field) is True for field in ("ok", "pending_verified", "tamper_rejected")):
            raise RuntimeError("packaged timestamp serialization, pending proof, or tamper rejection did not pass")

        def request(method: str, params: dict | None = None):
            completed = subprocess.run(
                [str(executable)],
                input=json.dumps({"method": method, "params": params or {}}),
                text=True,
                encoding="utf-8",
                capture_output=True,
                env=environment,
                timeout=90,
                check=False,
            )
            if completed.returncode:
                raise RuntimeError(f"packaged engine {method} exited {completed.returncode}: {completed.stderr[:1000]}")
            result = json.loads(completed.stdout)
            if not result.get("ok"):
                raise RuntimeError(f"packaged engine {method} failed: {result.get('error')}")
            return result["result"]

        request("status")
        source = root / "日本語の研究データ.txt"
        source.write_bytes("SkySeal package smoke test\n".encode("utf-8"))
        prepared = request("prepare", {"paths": [str(source)]})
        if not prepared.get("job_id"):
            raise RuntimeError("prepare did not return a persistent job id")
        jobs = request("list")
        if prepared["job_id"] not in {entry["job_id"] for entry in jobs["jobs"]}:
            raise RuntimeError("a new engine process did not recover the saved job")
        request("get", {"job_id": prepared["job_id"]})
        print("Packaged engine: offline timestamp proof/tamper checks, status, Japanese-path snapshot, persisted history, and restart passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
