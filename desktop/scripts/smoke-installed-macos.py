"""Copy the actual .app, check bundled helpers, then launch an empty GUI profile.

No identity enrollment, Keychain signing prompt, certificate trust, or network
call is requested. Window metadata and optional screenshots respect macOS TCC.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import sys
import tempfile
import time


def run(command: list[str], *, timeout=60, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, capture_output=True, text=True,
                          encoding="utf-8", timeout=timeout, **kwargs)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("app", type=Path)
    parser.add_argument("--diagnostics", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise SystemExit("The installed-application test must run on macOS.")
    source = args.app.resolve(strict=True)
    diagnostics = args.diagnostics.resolve()
    diagnostics.mkdir(parents=True, exist_ok=True)
    script_root = Path(__file__).resolve().parent
    report = {"passed": False, "native_window": False, "gui_started_engine": False,
              "installed_sidecar_smoke": False, "native_signer_self_test": False,
              "bundled_public_tls_roots": False,
              "limits": ["No production ORCID login, certificate trust, or Keychain approval ceremony is performed.",
                         "No Accessibility permission is requested; native window and JavaScript-initiated engine startup are checked."]}
    failure = None
    process = None
    with tempfile.TemporaryDirectory(prefix="skyseal-installed-smoke-") as raw_root:
        root = Path(raw_root).resolve()
        installed = root / "Applications" / "SkySeal.app"
        installed.parent.mkdir()
        stdout_path = diagnostics / "application.stdout.txt"
        stderr_path = diagnostics / "application.stderr.txt"
        stdout = stdout_path.open("w", encoding="utf-8")
        stderr = stderr_path.open("w", encoding="utf-8")
        try:
            run(["/usr/bin/ditto", str(source), str(installed)])
            run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(installed)])
            info = plistlib.loads((installed / "Contents/Info.plist").read_bytes())
            binaries = installed / "Contents/MacOS"
            executable = binaries / info["CFBundleExecutable"]
            engine = binaries / "desktop-engine"
            signer = binaries / "macos-signer"
            for binary in (executable, engine, signer):
                if not binary.is_file() or not os.access(binary, os.X_OK):
                    raise RuntimeError(f"Missing installed executable: {binary.name}")
            tested_engine = run([sys.executable, str(script_root / "smoke_engine.py"), str(engine)], timeout=120)
            (diagnostics / "installed-engine.txt").write_text(tested_engine.stdout, encoding="utf-8")
            report["installed_sidecar_smoke"] = True
            default_tls_environment = {key: value for key, value in os.environ.items() if key != "SSL_CERT_FILE"}
            public_tls = json.loads(run([str(engine), "--tls-self-test"], env=default_tls_environment).stdout)
            if not (public_tls.get("ok") is True and public_tls.get("bundled_public_roots") is True
                    and public_tls.get("ca_count", 0) > 0 and public_tls.get("network_used") is False):
                raise RuntimeError("The bundled engine did not load its own public HTTPS trust roots")
            report["bundled_public_tls_roots"] = True
            self_test = json.loads(run([str(signer), "--self-test"]).stdout)
            if not all(self_test.get(key) is True for key in (
                    "ok", "acl_policy_checked", "permissive_acl_rejected", "signature_roundtrip", "changed_challenge_rejected")):
                raise RuntimeError("The bundled native signer self-test did not pass")
            report["native_signer_self_test"] = True
            report["native_signer_status"] = json.loads(run([str(signer)], input='{"op":"status"}\n').stdout)
            if report["native_signer_status"].get("ok") is not True:
                raise RuntimeError("The bundled native signer could not report its status")

            probe = root / "window-probe"
            run(["/usr/bin/xcrun", "swiftc", str(script_root / "macos-window-probe.swift"),
                 "-framework", "AppKit", "-framework", "CoreGraphics", "-o", str(probe)], timeout=90)
            gui_data = root / "gui-data"
            if gui_data.exists():
                raise RuntimeError("The GUI test profile was not fresh")
            environment = dict(os.environ)
            environment["SKYSEAL_DESKTOP_DATA_DIR"] = str(gui_data)
            environment["PYTHONUTF8"] = "1"
            process = subprocess.Popen([str(executable)], cwd=installed.parent,
                                       env=environment, stdout=stdout, stderr=stderr,
                                       start_new_session=True)
            report["process_id"] = process.pid
            deadline = time.monotonic() + 45
            window = {}
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"The installed GUI exited during startup ({process.returncode})")
                window = json.loads(run([str(probe), str(process.pid)], timeout=5).stdout)
                report["native_window"] = window.get("window_found") is True
                # This separate profile was never passed to the engine harness.
                # Its database can be created only by the real GUI startup call.
                report["gui_started_engine"] = (gui_data / "state.sqlite3").is_file()
                if report["native_window"] and report["gui_started_engine"]:
                    break
                time.sleep(0.4)
            report["window"] = window
            if not report["native_window"]:
                raise RuntimeError("No visible native application window appeared within 45 seconds")
            if not report["gui_started_engine"]:
                raise RuntimeError("The GUI did not initialize the bundled engine through JavaScript/Tauri")
            time.sleep(2)
            if process.poll() is not None:
                raise RuntimeError("The installed GUI exited immediately after initialization")

            if window.get("screen_recording_preapproved"):
                try:
                    capture = diagnostics / "installed-window.png"
                    run(["/usr/sbin/screencapture", "-x", "-o", "-l", str(window["window_id"]), str(capture)], timeout=10)
                    if capture.is_file():
                        report["screenshot"] = capture.name
                except Exception as exc:
                    report["screenshot_diagnostic"] = str(exc)
            else:
                report["limits"].append("No screenshot: Screen Recording permission was not already granted.")
            report["passed"] = True
        except Exception as exc:
            failure = exc
            report["error"] = str(exc)
        finally:
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                except ProcessLookupError:
                    pass
            stdout.close()
            stderr.close()
            (diagnostics / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if failure is not None:
        raise failure
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
