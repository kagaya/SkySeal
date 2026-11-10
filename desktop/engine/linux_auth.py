"""Linux software signer protected by a separate, per-use SkySeal passphrase.

The desktop WebView never receives the passphrase. A fresh system Pinentry GTK
process obtains it for each operation, without gpg-agent or an external cache.
The private key is encrypted on disk and briefly decrypted in this process;
this is neither hardware-backed nor independently attested user verification.
Python/cryptography do not promise complete zeroization of all temporary copies.

Assuan: https://www.gnupg.org/documentation/manuals/assuan/Server-responses.html
Pinentry cache opt-in: https://lists.gnupg.org/pipermail/gnupg-commits/2015-May/011101.html
"""
from __future__ import annotations

from contextlib import contextmanager
import hmac
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
import uuid

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from verifier.skyseal_verify import (
    VerificationError, decode_base64url, encode_base64url, parse_json_bytes,
    validate_public_key,
)

PROFILE = "skyseal-local-linux-passphrase-v0.1-draft"
METHOD = "linux-passphrase-p256-v0.1"
KEY_NAMESPACE = "net.excyberlab.skyseal.desktop.linux"
RP_ID = "skyseal.localhost"
ORIGIN = "https://skyseal.localhost"
KEY_SCHEMA = "urn:skyseal:local:linux-passphrase:encrypted-key:v0.1"
PINENTRY_PATH = Path("/usr/bin/pinentry-gtk-2")
MIN_PASSPHRASE_CHARACTERS = 12
MAX_PASSPHRASE_BYTES = 1024
MAX_KEY_BYTES = 16 * 1024
MAX_ASSUAN_BYTES = 16 * 1024
MAX_ASSUAN_LINE = 1000
SCRYPT_N = 1 << 17
SCRYPT_R = 8
SCRYPT_P = 1


class LinuxAuthError(RuntimeError):
    def __init__(self, message: str, code: str = "linux_auth_error"):
        super().__init__(message)
        self.code = code


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _wipe(value: bytearray | None) -> None:
    if value is not None:
        value[:] = b"\0" * len(value)


def _context(rp_id: str, origin: str) -> None:
    if sys.platform != "linux":
        raise LinuxAuthError("Linux signing is available only on Linux", "unsupported_platform")
    if rp_id != RP_ID or origin != ORIGIN:
        raise LinuxAuthError("The Linux signer requires the fixed SkySeal local context", "invalid_local_context")


def _pinentry_path() -> Path:
    if sys.platform != "linux":
        raise LinuxAuthError("Linux signing is available only on Linux", "unsupported_platform")
    if not os.environ.get("DISPLAY"):
        raise LinuxAuthError("A graphical desktop with X11 or XWayland is required for the passphrase dialog", "graphical_session_required")
    try:
        # The concrete package executable is deliberately not selected through
        # PATH, user configuration, or the system's generic pinentry alternative.
        for part in (PINENTRY_PATH, *PINENTRY_PATH.parents):
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise LinuxAuthError("The system Pinentry executable or its directory is not trusted", "pinentry_untrusted")
        info = PINENTRY_PATH.stat()
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
            raise LinuxAuthError("The system Pinentry executable is unavailable", "pinentry_missing")
    except OSError as exc:
        raise LinuxAuthError("Install the Ubuntu pinentry-gtk2 package to enable signing", "pinentry_missing") from exc
    return PINENTRY_PATH


def _pinentry_environment() -> dict[str, str]:
    environment = dict(os.environ)
    # Frozen Python alters this variable for its bundled libraries. System GTK
    # must load the system libraries rather than the onefile extraction tree.
    if getattr(sys, "frozen", False):
        if environment.get("LD_LIBRARY_PATH_ORIG"):
            environment["LD_LIBRARY_PATH"] = environment["LD_LIBRARY_PATH_ORIG"]
        else:
            environment.pop("LD_LIBRARY_PATH", None)
    for name in ("LD_PRELOAD", "GPG_TTY", "PINENTRY_USER_DATA", "INSIDE_EMACS"):
        environment.pop(name, None)
    return environment


def _escape_text(value: str) -> bytes:
    return value.encode("utf-8").replace(b"%", b"%25").replace(b"\r", b"%0D").replace(b"\n", b"%0A")


def _decode_assuan(value: bytes) -> bytearray:
    result = bytearray()
    position = 0
    while position < len(value):
        if value[position] == 37:  # Percent escapes are byte-oriented, not form data.
            pair = value[position + 1:position + 3]
            if len(pair) != 2 or re.fullmatch(b"[0-9A-Fa-f]{2}", pair) is None:
                raise LinuxAuthError("Invalid Pinentry data encoding", "invalid_pinentry_response")
            result.append(int(pair, 16))
            position += 3
        else:
            result.append(value[position])
            position += 1
    return result


class _Assuan:
    """A bounded request/response client; secret response bytes are never logged."""
    def __init__(self, process: subprocess.Popen, timeout: float):
        self.process = process
        self.deadline = time.monotonic() + timeout
        self.buffer = bytearray()
        self.received = 0
        self.selector = selectors.DefaultSelector()
        self.selector.register(process.stdout, selectors.EVENT_READ)

    def close(self):
        self.selector.close()
        _wipe(self.buffer)

    def _line(self) -> bytes:
        while b"\n" not in self.buffer:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise LinuxAuthError("The passphrase dialog timed out", "approval_timeout")
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                raise LinuxAuthError("The passphrase dialog closed without approval", "approval_failed")
            self.received += len(chunk)
            if self.received > MAX_ASSUAN_BYTES:
                raise LinuxAuthError("The passphrase dialog returned too much data", "invalid_pinentry_response")
            self.buffer.extend(chunk)
            if b"\n" not in self.buffer and len(self.buffer) > MAX_ASSUAN_LINE:
                raise LinuxAuthError("The passphrase dialog returned an oversized line", "invalid_pinentry_response")
        end = self.buffer.index(10)
        if end > MAX_ASSUAN_LINE:
            raise LinuxAuthError("The passphrase dialog returned an oversized line", "invalid_pinentry_response")
        line = bytes(self.buffer[:end]).removesuffix(b"\r")
        del self.buffer[:end + 1]
        return line

    def response(self, *, secret: bool = False) -> bytearray:
        data = bytearray()
        try:
            while True:
                line = self._line()
                if line == b"OK" or line.startswith(b"OK "):
                    return data
                if line.startswith(b"ERR "):
                    token = line.split(b" ", 2)[1]
                    code = int(token) & 0xFFFF if token.isdigit() else None
                    if code in {99, 198}:  # GPG_ERR_CANCELED / GPG_ERR_FULLY_CANCELED.
                        raise LinuxAuthError("Passphrase entry was cancelled", "approval_cancelled")
                    if code == 62:  # GPG_ERR_TIMEOUT.
                        raise LinuxAuthError("The passphrase dialog timed out", "approval_timeout")
                    raise LinuxAuthError("The passphrase dialog did not approve this operation", "approval_failed")
                if line.startswith(b"S "):
                    if line.split(b" ", 2)[1] == b"PASSWORD_FROM_CACHE":
                        raise LinuxAuthError("A cached passphrase is not accepted", "cached_approval_rejected")
                    continue
                if line.startswith(b"#") or not line:
                    continue
                if line.startswith(b"D ") and secret:
                    part = _decode_assuan(line[2:])
                    data.extend(part)
                    _wipe(part)
                    if len(data) > MAX_PASSPHRASE_BYTES:
                        raise LinuxAuthError("The passphrase is too long", "invalid_passphrase")
                    continue
                # No quality-bar or other INQUIRE callback is enabled; never
                # echo a supplied secret back in a status/diagnostic response.
                raise LinuxAuthError("Unexpected Pinentry response", "invalid_pinentry_response")
        except BaseException:
            _wipe(data)
            raise

    def command(self, name: bytes, value: str | None = None, *, secret=False) -> bytearray:
        request = name + (b" " + _escape_text(value) if value is not None else b"") + b"\n"
        if len(request) > MAX_ASSUAN_LINE:
            raise LinuxAuthError("The passphrase dialog request is too long", "invalid_pinentry_request")
        try:
            self.process.stdin.write(request)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise LinuxAuthError("The passphrase dialog closed without approval", "approval_failed") from exc
        return self.response(secret=secret)


def _prompt_passphrase(description: str) -> bytearray:
    helper = _pinentry_path()
    process = None
    protocol = None
    secret = None
    try:
        process = subprocess.Popen([str(helper)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/",
            env=_pinentry_environment(), close_fds=True, start_new_session=True)
        protocol = _Assuan(process, 180)
        protocol.response()
        protocol.command(b"SETTITLE", "SkySeal")
        protocol.command(b"SETDESC", description)
        protocol.command(b"SETPROMPT", "SkySeal passphrase:")
        protocol.command(b"SETOK", "Approve")
        protocol.command(b"SETCANCEL", "Cancel")
        # Do not request OPTION allow-external-password-cache or SETKEYINFO.
        # Direct Pinentry is a fresh process, with no gpg-agent cache at all.
        secret = protocol.command(b"GETPIN", secret=True)
        protocol.command(b"BYE")
        process.wait(timeout=5)
        if process.returncode != 0:
            raise LinuxAuthError("The passphrase dialog failed to finish", "approval_failed")
        _validate_passphrase(secret)
        result, secret = secret, None
        return result
    except subprocess.TimeoutExpired as exc:
        raise LinuxAuthError("The passphrase dialog timed out", "approval_timeout") from exc
    except OSError as exc:
        raise LinuxAuthError("Cannot start the system passphrase dialog", "pinentry_unavailable") from exc
    finally:
        _wipe(secret)
        if protocol is not None:
            protocol.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if process.stdin:
                process.stdin.close()
            if process.stdout:
                process.stdout.close()


def _validate_passphrase(secret: bytearray) -> None:
    try:
        value = secret.decode("utf-8")
    except (UnicodeError, AttributeError) as exc:
        raise LinuxAuthError("The passphrase must be valid Unicode text", "invalid_passphrase") from exc
    if not MIN_PASSPHRASE_CHARACTERS <= len(value) or len(secret) > MAX_PASSPHRASE_BYTES or "\0" in value:
        raise LinuxAuthError("Use a SkySeal passphrase of at least 12 characters (at most 1024 UTF-8 bytes)", "invalid_passphrase")


def _key_id(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"skyseal-key-[0-9a-f]{32}", value) is None:
        raise LinuxAuthError("Invalid Linux signing key identifier", "invalid_credential")
    return value


def _credential(value: dict) -> dict:
    fields = {"key_id", "algorithm", "public_key", "method", "key_storage",
              "approval_policy", "hardware_attested", "private_key_extractable"}
    if not isinstance(value, dict) or set(value) != fields:
        raise LinuxAuthError("Invalid Linux signing credential fields", "invalid_credential")
    _key_id(value["key_id"])
    if (type(value["algorithm"]) is not int or value["algorithm"] != -7 or value["method"] != METHOD
            or value["key_storage"] != "encrypted-local-pkcs8"
            or value["approval_policy"] != "passphrase-per-signature"
            or value["hardware_attested"] is not False or value["private_key_extractable"] is not True):
        raise LinuxAuthError("Unsupported Linux signing credential policy", "invalid_credential")
    try:
        validate_public_key({"algorithm": -7, "jwk": value["public_key"]})
    except (VerificationError, ValueError, TypeError) as exc:
        raise LinuxAuthError("Invalid Linux signing public key", "invalid_credential") from exc
    return value


def _public_jwk(key) -> dict:
    numbers = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": encode_base64url(numbers.x.to_bytes(32, "big")),
            "y": encode_base64url(numbers.y.to_bytes(32, "big"))}


def _derive(secret: bytearray, salt: bytes) -> bytearray:
    return bytearray(Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(secret))


def _validate_record(raw: bytes, credential: dict) -> tuple[dict, bytes, bytes, bytes]:
    try:
        record = parse_json_bytes(raw, "Linux encrypted key")
        fields = {"schema", "profile", "method", "key_namespace", "key_id", "algorithm", "public_key", "kdf", "cipher", "ciphertext"}
        if not isinstance(record, dict) or set(record) != fields:
            raise ValueError("unexpected record fields")
        if (record["schema"] != KEY_SCHEMA or record["profile"] != PROFILE or record["method"] != METHOD
                or record["key_namespace"] != KEY_NAMESPACE or record["key_id"] != credential["key_id"]
                or type(record["algorithm"]) is not int or record["algorithm"] != -7
                or record["public_key"] != credential["public_key"]):
            raise ValueError("credential mismatch")
        kdf, cipher = record["kdf"], record["cipher"]
        if not isinstance(kdf, dict) or set(kdf) != {"name", "n", "r", "p", "salt"} or kdf["name"] != "scrypt":
            raise ValueError("unsupported key derivation")
        if any(type(kdf[name]) is not int or kdf[name] != expected for name, expected in (("n", SCRYPT_N), ("r", SCRYPT_R), ("p", SCRYPT_P))):
            raise ValueError("unsupported derivation parameters")
        if not isinstance(cipher, dict) or set(cipher) != {"name", "nonce"} or cipher["name"] != "AES-256-GCM":
            raise ValueError("unsupported cipher")
        salt = decode_base64url(kdf["salt"], "key salt", 32)
        nonce = decode_base64url(cipher["nonce"], "key nonce", 12)
        encrypted = decode_base64url(record["ciphertext"], "encrypted private key")
        if not 32 <= len(encrypted) <= 2048:
            raise ValueError("invalid encrypted key length")
        return {name: value for name, value in record.items() if name != "ciphertext"}, salt, nonce, encrypted
    except (VerificationError, ValueError, TypeError, KeyError) as exc:
        raise LinuxAuthError("The encrypted key record does not match this identity or its protection policy", "invalid_key_record") from exc


class LinuxSigner:
    PROFILE = PROFILE
    METHOD = METHOD
    KEY_NAMESPACE = KEY_NAMESPACE

    def __init__(self, data_dir: Path):
        path = Path(data_dir)
        if not path.is_absolute() or ".." in path.parts:
            raise LinuxAuthError("The signing data directory must be an absolute, unambiguous path", "unsafe_key_store")
        # Do not resolve: doing so would hide a symlink supplied by the caller.
        self.root = path

    @contextmanager
    def _directory(self, *, create=False, missing_ok=False):
        descriptor = None
        store = None
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            descriptor = os.open("/", flags)
            for part in self.root.parts[1:]:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            root_info = os.fstat(descriptor)
            if root_info.st_uid != os.geteuid() or root_info.st_mode & 0o022:
                raise LinuxAuthError("The signing data directory must be owned by this user and not writable by others", "unsafe_key_store")
            if create:
                try:
                    os.mkdir("keys", mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            try:
                store = os.open("keys", flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not missing_ok:
                    raise LinuxAuthError("The Linux signing key store is missing", "signing_key_missing")
            if store is not None:
                info = os.fstat(store)
                if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise LinuxAuthError("The signing key directory must have owner-only permissions (0700)", "unsafe_key_store")
            yield store
        except OSError as exc:
            raise LinuxAuthError("Cannot safely access the signing key directory; links and shared permissions are not accepted", "unsafe_key_store") from exc
        finally:
            if store is not None:
                os.close(store)
            if descriptor is not None:
                os.close(descriptor)

    def _read_key(self, key_id: str) -> bytes:
        filename = _key_id(key_id) + ".json"
        with self._directory() as directory:
            try:
                descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
            except FileNotFoundError as exc:
                raise LinuxAuthError("The Linux signing key is missing", "signing_key_missing") from exc
            try:
                before = os.fstat(descriptor)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                        or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                        or not 1 <= before.st_size <= MAX_KEY_BYTES):
                    raise LinuxAuthError("The signing key must be one owner-only regular file (0600)", "unsafe_key_file")
                chunks = bytearray()
                while True:
                    chunk = os.read(descriptor, min(4096, MAX_KEY_BYTES + 1 - len(chunks)))
                    if not chunk:
                        break
                    chunks.extend(chunk)
                    if len(chunks) > MAX_KEY_BYTES:
                        raise LinuxAuthError("The signing key file is too large", "unsafe_key_file")
                after = os.fstat(descriptor)
                fingerprint = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                if fingerprint(before) != fingerprint(after) or len(chunks) != before.st_size:
                    raise LinuxAuthError("The signing key changed while it was being read", "key_changed")
                return bytes(chunks)
            finally:
                os.close(descriptor)

    def _write_key(self, key_id: str, raw: bytes) -> None:
        filename = _key_id(key_id) + ".json"
        temporary = ".key-" + uuid.uuid4().hex + ".tmp"
        with self._directory(create=True) as directory:
            try:
                descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                # link() publishes a complete file atomically without replacing
                # any existing identity; rename() alone would overwrite one.
                os.link(temporary, filename, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                os.unlink(temporary, dir_fd=directory)
                os.fsync(directory)
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
        if self._read_key(key_id) != raw:
            raise LinuxAuthError("The saved signing key failed its read-back check", "key_changed")

    def availability(self) -> dict:
        value = {"available": False, "platform": "linux", "backend": "linux-encrypted-key",
                 "profile": PROFILE, "approval_method": METHOD,
                 "authentication_assurance": "local_user_presence_not_attested",
                 "hardware_attested": False, "private_key_extractable": True,
                 "passphrase_required": True}
        try:
            _pinentry_path()
            with self._directory(missing_ok=True):
                pass
            return {**value, "available": True, "reason": "SkySeal-specific passphrase approval through the system Pinentry dialog"}
        except LinuxAuthError as exc:
            return {**value, "reason": str(exc), "error_code": exc.code}

    def register(self, rp_id: str, origin: str, user_id: bytes, user_name: str) -> dict:
        _context(rp_id, origin)
        if not isinstance(user_id, bytes) or not 1 <= len(user_id) <= 64 or not isinstance(user_name, str) or not user_name:
            raise LinuxAuthError("Invalid local researcher registration", "invalid_registration")
        with self._directory(missing_ok=True):
            pass
        first = second = derived = clear = None
        try:
            first = _prompt_passphrase("SkySeal 専用の新しいパスフレーズを入力してください（12文字以上）。\nLinux のログインパスワードとは別のものを設定します。忘れると、この署名鍵を利用できなくなります。")
            second = _prompt_passphrase("確認のため、同じ SkySeal 専用パスフレーズをもう一度入力してください。")
            _validate_passphrase(first)
            _validate_passphrase(second)
            if not hmac.compare_digest(first, second):
                raise LinuxAuthError("The two SkySeal passphrases do not match", "passphrase_mismatch")
            key = ec.generate_private_key(ec.SECP256R1())
            key_id = "skyseal-key-" + uuid.uuid4().hex
            public_key = _public_jwk(key)
            salt, nonce = os.urandom(32), os.urandom(12)
            header = {"schema": KEY_SCHEMA, "profile": PROFILE, "method": METHOD,
                "key_namespace": KEY_NAMESPACE, "key_id": key_id, "algorithm": -7,
                "public_key": public_key, "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": encode_base64url(salt)},
                "cipher": {"name": "AES-256-GCM", "nonce": encode_base64url(nonce)}}
            clear = bytearray(key.private_bytes(serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            derived = _derive(first, salt)
            encrypted = AESGCM(derived).encrypt(nonce, clear, _json_bytes(header))
            self._write_key(key_id, _json_bytes({**header, "ciphertext": encode_base64url(encrypted)}))
            return {"key_id": key_id, "algorithm": -7, "public_key": public_key, "method": METHOD,
                    "key_storage": "encrypted-local-pkcs8", "approval_policy": "passphrase-per-signature",
                    "hardware_attested": False, "private_key_extractable": True}
        finally:
            for value in (first, second, derived, clear):
                _wipe(value)

    def sign(self, credential: dict, challenge: bytes, rp_id: str, origin: str) -> dict:
        _context(rp_id, origin)
        credential = _credential(credential)
        if not isinstance(challenge, bytes) or len(challenge) != 32:
            raise LinuxAuthError("A 32-byte SkySeal signing challenge is required", "invalid_challenge")
        raw = self._read_key(credential["key_id"])
        header, salt, nonce, encrypted = _validate_record(raw, credential)
        secret = derived = clear = None
        try:
            secret = _prompt_passphrase("SkySeal に表示された本人登録または封緘の内容を確認してから、SkySeal 専用パスフレーズを入力してください。\nLinux のログインパスワードではありません。")
            _validate_passphrase(secret)
            derived = _derive(secret, salt)
            try:
                clear = bytearray(AESGCM(derived).decrypt(nonce, encrypted, _json_bytes(header)))
            except InvalidTag as exc:
                raise LinuxAuthError("The passphrase is incorrect or the encrypted key has changed", "approval_failed") from exc
            try:
                key = serialization.load_der_private_key(clear, password=None)
                if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1) or _public_jwk(key) != credential["public_key"]:
                    raise ValueError("registered key mismatch")
            except (ValueError, TypeError) as exc:
                raise LinuxAuthError("The decrypted key does not match the registered identity", "invalid_private_key") from exc
            if self._read_key(credential["key_id"]) != raw:
                raise LinuxAuthError("The signing key changed during approval", "key_changed")
            signature = key.sign(challenge, ec.ECDSA(hashes.SHA256()))
            try:
                key.public_key().verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
            except InvalidSignature as exc:
                raise LinuxAuthError("The signature did not match the exact challenge", "invalid_native_signature") from exc
            if self._read_key(credential["key_id"]) != raw:
                raise LinuxAuthError("The signing key changed during signing", "key_changed")
            return {"method": METHOD, "signature": encode_base64url(signature)}
        finally:
            for value in (secret, derived, clear):
                _wipe(value)
