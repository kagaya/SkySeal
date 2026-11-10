"""Launch the copied portable app or the actually installed Debian binaries.

Run under an isolated Xvfb/Openbox session as a non-root user. The WebKit sandbox
remains enabled. No personal identity, ORCID session or certificate trust is used.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def run(command, *, timeout=90, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, text=True,
                          encoding='utf-8', timeout=timeout, **kwargs)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--app-dir', required=True, type=Path)
    p.add_argument('--diagnostics', required=True, type=Path)
    p.add_argument('--installed', action='store_true')
    a = p.parse_args()
    if sys.platform != 'linux' or os.geteuid() == 0 or not os.environ.get('DISPLAY'):
        raise SystemExit('Use an ordinary Linux user inside an X11 test session.')
    if os.environ.get('WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS'):
        raise SystemExit('The WebKit sandbox must remain enabled.')
    source = a.app_dir.resolve(strict=True)
    diagnostics = a.diagnostics.resolve()
    diagnostics.mkdir(parents=True, exist_ok=True)
    script_root = Path(__file__).resolve().parent
    report = {'passed': False, 'deployment': 'installed-deb' if a.installed else 'copied-portable',
              'tested_os': platform.freedesktop_os_release(), 'native_window': False,
              'gui_started_engine': False, 'installed_sidecar_smoke': False,
              'bundled_public_tls_roots': False, 'webkit_sandbox_disabled': False,
              'limits': ['X11 test session; actual Wayland desktop acceptance remains separate.',
                         'No production ORCID login or browser certificate trust ceremony is performed.']}
    failure = None
    process = None
    with tempfile.TemporaryDirectory(prefix='skyseal-linux-installed-') as temporary:
        root = Path(temporary).resolve()
        app = source if a.installed else root / 'application'
        stdout = (diagnostics/'application.stdout.txt').open('w', encoding='utf-8')
        stderr = (diagnostics/'application.stderr.txt').open('w', encoding='utf-8')
        try:
            if not a.installed:
                app.mkdir()
                for name in ('skyseal-desktop', 'desktop-engine'):
                    shutil.copy2(source/name, app/name)
            executable, engine = app/'skyseal-desktop', app/'desktop-engine'
            for binary in (executable, engine):
                if not binary.is_file() or not os.access(binary, os.X_OK):
                    raise RuntimeError(f'Missing application executable: {binary.name}')
            tested = run([sys.executable, str(script_root/'smoke_engine.py'), str(engine)], timeout=180)
            (diagnostics/'installed-engine.txt').write_text(tested.stdout, encoding='utf-8')
            report['installed_sidecar_smoke'] = True
            environment = dict(os.environ)
            for name in ('PYTHONPATH', 'PYTHONHOME', 'SSL_CERT_FILE'):
                environment.pop(name, None)
            tls = json.loads(run([str(engine), '--tls-self-test'], env=environment).stdout)
            if not (tls.get('ok') is True and tls.get('bundled_public_roots') is True
                    and tls.get('ca_count', 0) > 0 and tls.get('network_used') is False):
                raise RuntimeError('The bundled engine did not load its own public HTTPS roots')
            report['bundled_public_tls_roots'] = True
            gui_data = root/'gui-data'
            if gui_data.exists():
                raise RuntimeError('The GUI data directory was not fresh')
            environment['SKYSEAL_DESKTOP_DATA_DIR'] = str(gui_data)
            environment['XDG_DATA_HOME'] = str(root/'xdg-data')
            environment['XDG_CACHE_HOME'] = str(root/'xdg-cache')
            environment['XDG_CONFIG_HOME'] = str(root/'xdg-config')
            environment['PYTHONUTF8'] = '1'
            process = subprocess.Popen([str(executable)], cwd=root, env=environment,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            report['process_id'] = process.pid
            deadline = time.monotonic()+60
            window = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f'The installed GUI exited ({process.returncode})')
                found = subprocess.run(['/usr/bin/xdotool', 'search', '--onlyvisible', '--pid', str(process.pid)],
                                       capture_output=True, text=True, timeout=5)
                for identifier in found.stdout.split():
                    if identifier.isdecimal():
                        title = run(['/usr/bin/xdotool', 'getwindowname', identifier], timeout=5).stdout.strip()
                        if title == 'SkySeal':
                            window = identifier
                            break
                report['native_window'] = window is not None
                # Only the GUI received this directory; the earlier engine
                # harness used a different fresh temporary profile.
                report['gui_started_engine'] = (gui_data/'state.sqlite3').is_file()
                if report['native_window'] and report['gui_started_engine']:
                    break
                time.sleep(0.4)
            if not report['native_window']:
                raise RuntimeError('No visible SkySeal native window appeared within 60 seconds')
            if not report['gui_started_engine']:
                raise RuntimeError('The GUI did not initialize the bundled engine')
            time.sleep(2)
            if process.poll() is not None:
                raise RuntimeError('The GUI exited immediately after initialization')
            report['window_title'] = 'SkySeal'
            report['window_id'] = window
            capture = diagnostics/'installed-window.png'
            run(['/usr/bin/import', '-window', window, str(capture)], timeout=15)
            if not capture.is_file() or capture.stat().st_size < 1000:
                raise RuntimeError('The native window screenshot was not captured')
            report['screenshot'] = capture.name
            report['passed'] = True
        except Exception as exc:
            failure = exc
            report['error'] = str(exc)
        finally:
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                except ProcessLookupError:
                    pass
            stdout.close()
            stderr.close()
            (diagnostics/'result.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if failure is not None:
        raise failure
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
