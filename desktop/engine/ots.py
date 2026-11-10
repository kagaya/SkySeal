"""Bundled OTS client orchestration. Signed targets are never modified."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


class TimestampError(RuntimeError):
    pass


class TimestampClient:
    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    def _run(self, arguments: list[str], cwd: Path) -> subprocess.CompletedProcess:
        command = [sys.executable, "--ots"] if getattr(sys, "frozen", False) else [sys.executable, "-m", "desktop.engine", "--ots"]
        environment = os.environ.copy()
        if not getattr(sys, "frozen", False):
            root = str(Path(__file__).resolve().parents[2])
            environment["PYTHONPATH"] = root + os.pathsep + environment.get("PYTHONPATH", "")
        try:
            return subprocess.run(command + arguments, cwd=cwd, env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise TimestampError("OpenTimestamps operation could not complete; retry from history") from exc

    def stamp(self, target: Path) -> bytes:
        with tempfile.TemporaryDirectory(prefix="skyseal-ots-") as temp:
            root = Path(temp)
            (root / target.name).write_bytes(target.read_bytes())
            result = self._run(["stamp", target.name], root)
            proof = root / (target.name + ".ots")
            if result.returncode != 0 or not proof.is_file():
                raise TimestampError("OpenTimestamps did not return a proof; retry from history")
            return proof.read_bytes()

    def upgrade(self, target: Path, proof: Path) -> bytes:
        # OTS proof calendars are untrusted input; the library performs its own
        # bounded parser and the adapter limits network destinations below.
        self._check_calendar_uris(proof.read_bytes())
        with tempfile.TemporaryDirectory(prefix="skyseal-ots-") as temp:
            root = Path(temp)
            (root / target.name).write_bytes(target.read_bytes())
            working = root / proof.name
            working.write_bytes(proof.read_bytes())
            result = self._run(["upgrade", proof.name], root)
            if result.returncode != 0:
                raise TimestampError("OpenTimestamps upgrade is unavailable; existing proof retained")
            return working.read_bytes()

    @staticmethod
    def _check_calendar_uris(raw: bytes) -> None:
        from urllib.parse import urlsplit
        from opentimestamps.core.serialize import BytesDeserializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.notary import PendingAttestation
        allowed = {"alice.btc.calendar.opentimestamps.org", "bob.btc.calendar.opentimestamps.org",
                   "finney.calendar.eternitywall.com", "btc.calendar.catallaxy.com",
                   "a.pool.opentimestamps.org", "b.pool.opentimestamps.org"}
        detached = DetachedTimestampFile.deserialize(BytesDeserializationContext(raw))
        for _, attestation in detached.timestamp.all_attestations():
            if isinstance(attestation, PendingAttestation):
                uri = attestation.uri.decode("ascii") if isinstance(attestation.uri, bytes) else attestation.uri
                parsed = urlsplit(uri)
                if parsed.scheme not in {"http", "https"} or parsed.hostname not in allowed or parsed.username or parsed.password or parsed.port not in {None, 80, 443}:
                    raise TimestampError("Proof uses an untrusted calendar; automatic upgrade refused")

    def verify(self, target: Path, proof: Path) -> dict:
        from .bitcoin_verify import verify_detached
        return verify_detached(proof, target)
