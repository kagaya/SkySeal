"""CI-only actual Pinentry GUI exercise of the production Linux signer.

This script is never distributed. A separate CI-only frozen copy exercises the
same production adapter under PyInstaller. It creates a disposable encrypted key, supplies a
random test passphrase through X11 input, and checks fresh-process signing,
wrong-passphrase rejection, cancellation and ciphertext tampering. No production
credential bypass, password environment variable or agent cache is used.
"""
from __future__ import annotations
import argparse
import base64
import json
from functools import partial
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
import time

if not getattr(sys, 'frozen', False):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def worker(operation: str, root: Path) -> int:
    from desktop.engine.linux_auth import LinuxSigner, LinuxAuthError, RP_ID, ORIGIN
    request = json.loads(sys.stdin.read(16 * 1024))
    signer = LinuxSigner(root)
    runtime = {'frozen': bool(getattr(sys, 'frozen', False)),
               'pyinstaller_library_path_present': bool(getattr(sys, '_MEIPASS', None))
               and str(sys._MEIPASS) in os.environ.get('LD_LIBRARY_PATH', '').split(':')}
    try:
        if operation == 'register':
            result = signer.register(RP_ID, ORIGIN, b'skyseal-ci-disposable-user', 'SkySeal CI')
        else:
            result = signer.sign(request['credential'], bytes.fromhex(request['challenge']), RP_ID, ORIGIN)
        print(json.dumps({'ok': True, 'result': result, 'runtime': runtime}))
    except LinuxAuthError as exc:
        # Only a fixed error code is surfaced; never return prompt text/secrets.
        print(json.dumps({'ok': False, 'error_code': exc.code, 'runtime': runtime}))
    return 0


def pinentry_children(pid: int) -> set[int]:
    # The one-file bootloader forks the Python worker. Follow only this test
    # process's descendants, never an unrelated desktop password prompt.
    result: set[int] = set()
    pending = [pid]
    seen: set[int] = set()
    while pending:
        parent = pending.pop()
        if parent in seen:
            continue
        seen.add(parent)
        if len(seen) > 64:
            raise RuntimeError('Unexpected signing worker process tree')
        try:
            children = (Path('/proc')/str(parent)/'task'/str(parent)/'children').read_text().split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        for raw in children:
            if not raw.isdecimal():
                continue
            child = int(raw)
            pending.append(child)
            try:
                if os.readlink(f'/proc/{child}/exe') == '/usr/bin/pinentry-gtk-2':
                    result.add(child)
            except OSError:
                continue
    return result


def prompt_window(pid: int) -> str | None:
    found = subprocess.run(['/usr/bin/xdotool', 'search', '--onlyvisible', '--pid', str(pid)],
                           capture_output=True, text=True, timeout=5)
    for window in found.stdout.split():
        if not window.isdecimal():
            continue
        title = subprocess.run(['/usr/bin/xdotool', 'getwindowname', window],
                               capture_output=True, text=True, timeout=5)
        if title.returncode == 0 and title.stdout.strip() == 'SkySeal':
            return window
    return None


def exercise(operation: str, root: Path, request: dict, entries: list[str | None],
             *, worker_executable: Path | None = None) -> tuple[dict, list[int]]:
    # Secrets remain in this controller's memory and are sent only as synthetic
    # X11 keystrokes to the identified native child window, via stdin to xdotool.
    command = ([str(worker_executable)] if worker_executable else
               [sys.executable, str(Path(__file__).resolve())])
    process = subprocess.Popen([*command, '--worker', operation, '--root', str(root)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, encoding='utf-8',
                               start_new_session=True)
    process.stdin.write(json.dumps(request))
    process.stdin.close()
    process.stdin = None
    submitted: list[int] = []
    observed: set[int] = set()
    deadline = time.monotonic()+70
    try:
        while process.poll() is None and time.monotonic() < deadline:
            children = pinentry_children(process.pid)
            observed.update(children)
            for child in sorted(children):
                if child in submitted:
                    continue
                window = prompt_window(child)
                if window is None:
                    continue
                if len(submitted) >= len(entries):
                    raise RuntimeError('An unexpected extra native passphrase prompt appeared')
                subprocess.run(['/usr/bin/xdotool', 'windowfocus', '--sync', window], check=True, timeout=5)
                value = entries[len(submitted)]
                if value is None:
                    subprocess.run(['/usr/bin/xdotool', 'key', '--clearmodifiers', 'Escape'], check=True, timeout=5)
                else:
                    subprocess.run(['/usr/bin/xdotool', 'type', '--clearmodifiers', '--delay', '1', '--file', '-'],
                                   input=value.encode('utf-8'), check=True, timeout=10)
                    subprocess.run(['/usr/bin/xdotool', 'key', '--clearmodifiers', 'Return'], check=True, timeout=5)
                submitted.append(child)
            time.sleep(0.08)
        if process.poll() is None:
            raise RuntimeError('The native signing GUI test exceeded its deadline')
        stdout, _stderr = process.communicate(timeout=5)
        if process.returncode:
            raise RuntimeError(f'The native signing worker exited {process.returncode}')
        if len(submitted) != len(entries):
            raise RuntimeError(f'Expected {len(entries)} native prompt(s), observed {len(submitted)}')
        result = json.loads(stdout)
        if not isinstance(result, dict):
            raise RuntimeError('The native signer worker returned invalid JSON')
        runtime = result.pop('runtime', {})
        if worker_executable and (runtime.get('frozen') is not True
                                  or runtime.get('pyinstaller_library_path_present') is not True):
            raise RuntimeError('The CI worker did not exercise the frozen PyInstaller library environment')
        return result, submitted
    finally:
        for child in observed:
            try:
                if os.readlink(f'/proc/{child}/exe') == '/usr/bin/pinentry-gtk-2':
                    os.kill(child, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value+'='*((-len(value)) % 4))


def verify(result: dict, credential: dict, challenge: bytes) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    if result.get('ok') is not True:
        raise RuntimeError('Native approval did not yield a signature: '+str(result.get('error_code')))
    jwk = credential['public_key']
    key = ec.EllipticCurvePublicNumbers(int.from_bytes(decode(jwk['x']), 'big'),
                                      int.from_bytes(decode(jwk['y']), 'big'), ec.SECP256R1()).public_key()
    key.verify(decode(result['result']['signature']), challenge, ec.ECDSA(hashes.SHA256()))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--worker', choices=('register', 'sign'))
    p.add_argument('--root', type=Path)
    p.add_argument('--diagnostics', type=Path)
    p.add_argument('--worker-executable', type=Path, help='Trusted CI-only frozen copy of this script')
    a = p.parse_args()
    if a.worker:
        return worker(a.worker, a.root)
    if not a.diagnostics:
        p.error('--diagnostics is required')
    if sys.platform != 'linux' or os.geteuid() == 0 or not os.environ.get('DISPLAY'):
        raise SystemExit('Use an ordinary Linux user inside an isolated X11 test display.')
    if a.worker_executable:
        a.worker_executable = a.worker_executable.resolve(strict=True)
        if not a.worker_executable.is_file() or not os.access(a.worker_executable, os.X_OK):
            p.error('--worker-executable must be an executable file')
    run_worker = partial(exercise, worker_executable=a.worker_executable)
    diagnostics = a.diagnostics.resolve()
    diagnostics.mkdir(parents=True, exist_ok=True)
    report = {'passed': False,
              'test_scope': ('production LinuxSigner in CI-only PyInstaller worker with real system Pinentry GTK'
                             if a.worker_executable else 'production LinuxSigner source with real system Pinentry GTK'),
              'frozen_worker': bool(a.worker_executable),
              'pyinstaller_library_path_exercised': bool(a.worker_executable),
              'synthetic_test_key_only': True, 'production_orcid_tested': False,
              'password_in_arguments_or_environment': False}
    failure = None
    try:
        with tempfile.TemporaryDirectory(prefix='skyseal-pinentry-test-') as temporary:
            root = Path(temporary).resolve()/'data'
            root.mkdir(mode=0o700)
            secret = 'SkySeal test '+secrets.token_hex(20)
            registration, register_prompts = run_worker('register', root, {}, [secret, secret])
            if registration.get('ok') is not True:
                raise RuntimeError('Native passphrase enrollment failed: '+str(registration.get('error_code')))
            credential = registration['result']
            key_file = root/'keys'/(credential['key_id']+'.json')
            original = key_file.read_bytes()
            if secret.encode() in original or b'PRIVATE KEY' in original:
                raise RuntimeError('The key file contains plaintext sensitive material')
            assert key_file.stat().st_mode & 0o777 == 0o600
            report['native_enrollment_confirmation'] = len(register_prompts) == 2
            report['encrypted_key_owner_only'] = True
            challenge = secrets.token_bytes(32)
            request = {'credential': credential, 'challenge': challenge.hex()}
            signed, first_prompts = run_worker('sign', root, request, [secret])
            verify(signed, credential, challenge)
            signed_again, second_prompts = run_worker('sign', root, request, [secret])
            verify(signed_again, credential, challenge)
            if set(first_prompts) & set(second_prompts):
                raise RuntimeError('Signing reused the previous Pinentry process')
            report['fresh_process_signature_roundtrip'] = True
            report['new_prompt_for_every_signature'] = True
            refused, _ = run_worker('sign', root, request, ['Incorrect test '+secrets.token_hex(20)])
            if refused != {'ok': False, 'error_code': 'approval_failed'}:
                raise RuntimeError('A wrong passphrase was not refused')
            report['wrong_passphrase_rejected'] = True
            cancelled, _ = run_worker('sign', root, request, [None])
            if cancelled != {'ok': False, 'error_code': 'approval_cancelled'}:
                raise RuntimeError('Native cancellation was not refused')
            report['cancel_rejected'] = True
            record = json.loads(original)
            encrypted = bytearray(decode(record['ciphertext']))
            encrypted[0] ^= 1
            record['ciphertext'] = base64.urlsafe_b64encode(encrypted).decode().rstrip('=')
            key_file.write_text(json.dumps(record), encoding='utf-8')
            tampered, _ = run_worker('sign', root, request, [secret])
            if tampered != {'ok': False, 'error_code': 'approval_failed'}:
                raise RuntimeError('A modified encrypted key was not refused')
            key_file.write_bytes(original)
            report['ciphertext_tamper_rejected'] = True
            report['native_dialogs_observed'] = len(register_prompts)+len(first_prompts)+len(second_prompts)+3
        report['temporary_key_deleted'] = not root.exists()
        report['passed'] = True
    except Exception as exc:
        failure = exc
        report['error'] = str(exc)
    (diagnostics/'result.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if failure is not None:
        raise failure
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
