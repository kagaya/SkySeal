"""Windows-native, user-verified WebAuthn ceremonies for the local profile.

Only Windows' system WebAuthn provider holds/uses the credential private key.
There is deliberately no software-key fallback. The public native outputs are
checked again by SkySeal's protocol verifier before being returned to callers.

The ctypes declarations below use the version-1 prefixes from Microsoft's
MIT-licensed SDK header: https://github.com/microsoft/webauthn/blob/master/webauthn.h
Later output versions append fields; only the stable v1 prefix is read here.
The origin is a native-client assertion, not proof of an HTTPS web server or
of the authenticity of the installed application.
"""
from __future__ import annotations

import ctypes as C
import os
import secrets
from typing import Any
from urllib.parse import urlsplit

from service.webauthn import verify_assertion, verify_registration
from verifier.skyseal_verify import (
    canonical_json,
    decode_base64url,
    encode_base64url,
    validate_origin,
    validate_public_key,
    validate_rp_id,
)


class WindowsAuthError(RuntimeError):
    def __init__(self, message: str, code: str = "windows_auth_error"):
        super().__init__(message)
        self.code = code


# Win32 is LLP64, including when this module is imported on LP64 hosts for tests.
DWORD = C.c_uint32
LONG = C.c_int32
BOOL = C.c_int32
HRESULT = C.c_int32
BYTE = C.c_ubyte
PBYTE = C.POINTER(BYTE)
PCWSTR = C.c_wchar_p
HWND = C.c_void_p


class RPInformation(C.Structure):
    _fields_ = [("dwVersion", DWORD), ("pwszId", PCWSTR),
                ("pwszName", PCWSTR), ("pwszIcon", PCWSTR)]


class UserInformation(C.Structure):
    _fields_ = [("dwVersion", DWORD), ("cbId", DWORD), ("pbId", PBYTE),
                ("pwszName", PCWSTR), ("pwszIcon", PCWSTR),
                ("pwszDisplayName", PCWSTR)]


class ClientData(C.Structure):
    _fields_ = [("dwVersion", DWORD), ("cbClientDataJSON", DWORD),
                ("pbClientDataJSON", PBYTE), ("pwszHashAlgId", PCWSTR)]


class CoseParameter(C.Structure):
    _fields_ = [("dwVersion", DWORD), ("pwszCredentialType", PCWSTR), ("lAlg", LONG)]


class CoseParameters(C.Structure):
    _fields_ = [("cCredentialParameters", DWORD),
                ("pCredentialParameters", C.POINTER(CoseParameter))]


class Credential(C.Structure):
    _fields_ = [("dwVersion", DWORD), ("cbId", DWORD), ("pbId", PBYTE),
                ("pwszCredentialType", PCWSTR)]


class Credentials(C.Structure):
    _fields_ = [("cCredentials", DWORD), ("pCredentials", C.POINTER(Credential))]


class Extension(C.Structure):
    _fields_ = [("pwszExtensionIdentifier", PCWSTR), ("cbExtension", DWORD),
                ("pvExtension", C.c_void_p)]


class Extensions(C.Structure):
    _fields_ = [("cExtensions", DWORD), ("pExtensions", C.POINTER(Extension))]


class MakeCredentialOptionsV1(C.Structure):
    _fields_ = [("dwVersion", DWORD), ("dwTimeoutMilliseconds", DWORD),
                ("CredentialList", Credentials), ("Extensions", Extensions),
                ("dwAuthenticatorAttachment", DWORD), ("bRequireResidentKey", BOOL),
                ("dwUserVerificationRequirement", DWORD),
                ("dwAttestationConveyancePreference", DWORD), ("dwFlags", DWORD)]


class GetAssertionOptionsV1(C.Structure):
    _fields_ = [("dwVersion", DWORD), ("dwTimeoutMilliseconds", DWORD),
                ("CredentialList", Credentials), ("Extensions", Extensions),
                ("dwAuthenticatorAttachment", DWORD),
                ("dwUserVerificationRequirement", DWORD), ("dwFlags", DWORD)]


class CredentialAttestationV1(C.Structure):
    _fields_ = [("dwVersion", DWORD), ("pwszFormatType", PCWSTR),
                ("cbAuthenticatorData", DWORD), ("pbAuthenticatorData", PBYTE),
                ("cbAttestation", DWORD), ("pbAttestation", PBYTE),
                ("dwAttestationDecodeType", DWORD), ("pvAttestationDecode", C.c_void_p),
                ("cbAttestationObject", DWORD), ("pbAttestationObject", PBYTE),
                ("cbCredentialId", DWORD), ("pbCredentialId", PBYTE)]


class AssertionV1(C.Structure):
    _fields_ = [("dwVersion", DWORD), ("cbAuthenticatorData", DWORD),
                ("pbAuthenticatorData", PBYTE), ("cbSignature", DWORD),
                ("pbSignature", PBYTE), ("Credential", Credential),
                ("cbUserId", DWORD), ("pbUserId", PBYTE)]


def _buffer(value: bytes) -> Any:
    return (BYTE * len(value)).from_buffer_copy(value)


def _copy_bytes(pointer: Any, count: int, *, maximum: int, label: str,
                allow_empty: bool = False) -> bytes:
    if count == 0 and allow_empty:
        return b""
    if not pointer or not 0 < count <= maximum:
        raise WindowsAuthError(f"Invalid native {label} length", "invalid_native_response")
    return C.string_at(pointer, count)


def _context(rp_id: str, origin: str) -> None:
    validate_rp_id(rp_id, "local RP ID")
    validate_origin(origin, "local origin")
    parsed = urlsplit(origin)
    if parsed.hostname != rp_id or not (rp_id == "localhost" or rp_id.endswith(".localhost")):
        raise WindowsAuthError("The desktop signer requires a matching localhost RP and HTTPS origin",
                               "invalid_local_origin")


def _client_data(kind: str, challenge: bytes, origin: str) -> tuple[bytes, Any, ClientData]:
    if not isinstance(challenge, bytes) or len(challenge) != 32:
        raise WindowsAuthError("WebAuthn challenge must contain exactly 32 bytes", "invalid_challenge")
    raw = canonical_json({"type": kind, "challenge": encode_base64url(challenge),
                          "origin": origin, "crossOrigin": False})
    buffer = _buffer(raw)
    return raw, buffer, ClientData(1, len(raw), buffer, "SHA-256")


def _api() -> Any:
    if os.name != "nt":
        raise WindowsAuthError("Windows Hello / FIDO2 requires Windows 10 version 1903 or later",
                               "windows_required")
    try:
        # LOAD_LIBRARY_SEARCH_SYSTEM32 prevents a DLL in the working directory
        # from being substituted for Windows' WebAuthn implementation.
        api = C.WinDLL("webauthn.dll", winmode=0x00000800)
        api.WebAuthNGetApiVersionNumber.argtypes = []
        api.WebAuthNGetApiVersionNumber.restype = DWORD
        api.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.argtypes = [C.POINTER(BOOL)]
        api.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.restype = HRESULT
        api.WebAuthNAuthenticatorMakeCredential.argtypes = [
            HWND, C.POINTER(RPInformation), C.POINTER(UserInformation),
            C.POINTER(CoseParameters), C.POINTER(ClientData),
            C.POINTER(MakeCredentialOptionsV1), C.POINTER(C.POINTER(CredentialAttestationV1)),
        ]
        api.WebAuthNAuthenticatorMakeCredential.restype = HRESULT
        api.WebAuthNAuthenticatorGetAssertion.argtypes = [
            HWND, PCWSTR, C.POINTER(ClientData), C.POINTER(GetAssertionOptionsV1),
            C.POINTER(C.POINTER(AssertionV1)),
        ]
        api.WebAuthNAuthenticatorGetAssertion.restype = HRESULT
        api.WebAuthNFreeCredentialAttestation.argtypes = [C.POINTER(CredentialAttestationV1)]
        api.WebAuthNFreeCredentialAttestation.restype = None
        api.WebAuthNFreeAssertion.argtypes = [C.POINTER(AssertionV1)]
        api.WebAuthNFreeAssertion.restype = None
        api.WebAuthNGetErrorName.argtypes = [HRESULT]
        api.WebAuthNGetErrorName.restype = PCWSTR
    except (OSError, AttributeError) as exc:
        raise WindowsAuthError("Windows WebAuthn API is unavailable", "webauthn_unavailable") from exc
    if api.WebAuthNGetApiVersionNumber() < 1:
        raise WindowsAuthError("Windows WebAuthn API version is unsupported", "webauthn_unavailable")
    return api


def _window() -> Any:
    user32 = C.WinDLL("user32.dll", winmode=0x00000800)
    user32.GetForegroundWindow.argtypes = []
    user32.GetForegroundWindow.restype = HWND
    user32.GetDesktopWindow.argtypes = []
    user32.GetDesktopWindow.restype = HWND
    return user32.GetForegroundWindow() or user32.GetDesktopWindow()


def _check_hresult(api: Any, result: int) -> None:
    if result == 0:
        return
    name = api.WebAuthNGetErrorName(result) or "UnknownError"
    code = "approval_cancelled" if name in {"NotAllowedError", "AbortError"} else "windows_auth_error"
    raise WindowsAuthError(f"Windows WebAuthn: {name} (0x{result & 0xffffffff:08x})", code)


def availability() -> dict[str, Any]:
    """Report API and Hello availability without displaying approval UI.

    A false Hello flag does not exclude a user-verifying external FIDO2 key.
    """
    try:
        api = _api()
        available = BOOL()
        result = api.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(C.byref(available))
        return {"available": True, "api_version": int(api.WebAuthNGetApiVersionNumber()),
                "platform_authenticator_available": bool(available.value) if result == 0 else None,
                "external_fido2_supported": True}
    except WindowsAuthError as exc:
        return {"available": False, "code": exc.code, "message": str(exc),
                "platform_authenticator_available": False, "external_fido2_supported": False}


def register(rp_id: str, origin: str, user_id: bytes, user_name: str) -> dict[str, Any]:
    """Create an ES256 credential with a fresh challenge and UV required.

    Returned routing data (raw_id and user_id) stays private. Registration is
    not ORCID authentication or identity activation; the caller performs those
    separately and obtains an assertion over the exact activated identity.
    """
    _context(rp_id, origin)
    if not isinstance(user_id, bytes) or not 1 <= len(user_id) <= 64:
        raise WindowsAuthError("User handle must contain 1 to 64 bytes", "invalid_user")
    if not isinstance(user_name, str) or not user_name.strip() or len(user_name) > 200 or "\x00" in user_name:
        raise WindowsAuthError("A user display name is required (up to 200 characters)", "invalid_user")
    api = _api()
    challenge = secrets.token_bytes(32)
    raw_client, client_buffer, client = _client_data("webauthn.create", challenge, origin)
    user_buffer = _buffer(user_id)
    rp = RPInformation(1, rp_id, "SkySeal Desktop", None)
    user = UserInformation(1, len(user_id), user_buffer, user_name, None, user_name)
    parameter = CoseParameter(1, "public-key", -7)
    parameters = CoseParameters(1, C.pointer(parameter))
    options = MakeCredentialOptionsV1()
    options.dwVersion = 1
    options.dwTimeoutMilliseconds = 120_000
    options.dwAuthenticatorAttachment = 0  # Hello or an external authenticator.
    options.bRequireResidentKey = 0
    options.dwUserVerificationRequirement = 1  # REQUIRED, never preferred.
    options.dwAttestationConveyancePreference = 1  # NONE: no attestation identity leak.
    output = C.POINTER(CredentialAttestationV1)()
    try:
        result = api.WebAuthNAuthenticatorMakeCredential(
            _window(), C.byref(rp), C.byref(user), C.byref(parameters),
            C.byref(client), C.byref(options), C.byref(output))
        _check_hresult(api, result)
        if not output or output.contents.dwVersion < 1:
            raise WindowsAuthError("Windows returned no credential", "invalid_native_response")
        value = output.contents
        raw_id = _copy_bytes(value.pbCredentialId, value.cbCredentialId, maximum=1024, label="credential ID")
        attestation = _copy_bytes(value.pbAttestationObject, value.cbAttestationObject,
                                  maximum=65536, label="attestation")
        encoded_id = encode_base64url(raw_id)
        response = {"client_data_json": encode_base64url(raw_client),
                    "attestation_object": encode_base64url(attestation)}
        registered = verify_registration(
            {"id": encoded_id, "raw_id": encoded_id, "type": "public-key",
             "response": response, "transports": [], "recovery_code_commitment": None},
            expected_challenge=challenge, rp_id=rp_id, origin=origin)
        if registered.algorithm != -7:
            raise WindowsAuthError("Authenticator returned an unrequested algorithm", "invalid_native_response")
        return {"raw_id": encoded_id, "user_id": encode_base64url(user_id),
                "public_key": registered.jwk, "algorithm": registered.algorithm,
                "sign_count": registered.sign_count, "rp_id": rp_id, "origin": origin}
    finally:
        if output:
            api.WebAuthNFreeCredentialAttestation(output)


def sign(credential: dict[str, Any], challenge: bytes, rp_id: str, origin: str) -> dict[str, Any]:
    """Obtain and independently verify an assertion over the supplied digest."""
    _context(rp_id, origin)
    if credential.get("rp_id") != rp_id or credential.get("origin") != origin:
        raise WindowsAuthError("Credential is registered for a different local profile", "credential_context_mismatch")
    if credential.get("algorithm") != -7:
        raise WindowsAuthError("The local signer requires ES256", "unsupported_algorithm")
    raw_id = decode_base64url(credential.get("raw_id"), "credential.raw_id")
    user_id = decode_base64url(credential.get("user_id"), "credential.user_id")
    if not 1 <= len(raw_id) <= 1024 or not 1 <= len(user_id) <= 64:
        raise WindowsAuthError("Invalid credential routing data", "invalid_credential")
    jwk = credential.get("public_key")
    validate_public_key({"algorithm": -7, "jwk": jwk})
    raw_client, client_buffer, client = _client_data("webauthn.get", challenge, origin)
    api = _api()
    credential_buffer = _buffer(raw_id)
    native_credential = Credential(1, len(raw_id), credential_buffer, "public-key")
    options = GetAssertionOptionsV1()
    options.dwVersion = 1
    options.dwTimeoutMilliseconds = 120_000
    options.CredentialList = Credentials(1, C.pointer(native_credential))
    options.dwAuthenticatorAttachment = 0
    options.dwUserVerificationRequirement = 1
    output = C.POINTER(AssertionV1)()
    try:
        result = api.WebAuthNAuthenticatorGetAssertion(
            _window(), rp_id, C.byref(client), C.byref(options), C.byref(output))
        _check_hresult(api, result)
        if not output or output.contents.dwVersion < 1:
            raise WindowsAuthError("Windows returned no assertion", "invalid_native_response")
        value = output.contents
        auth_data = _copy_bytes(value.pbAuthenticatorData, value.cbAuthenticatorData,
                                maximum=65536, label="authenticator data")
        signature = _copy_bytes(value.pbSignature, value.cbSignature, maximum=1024, label="signature")
        returned_id = _copy_bytes(value.Credential.pbId, value.Credential.cbId,
                                  maximum=1024, label="credential ID")
        handle = _copy_bytes(value.pbUserId, value.cbUserId, maximum=64, label="user handle", allow_empty=True)
        response = {"client_data_json": encode_base64url(raw_client),
                    "authenticator_data": encode_base64url(auth_data),
                    "signature": encode_base64url(signature),
                    "user_handle": encode_base64url(handle) if handle else None}
        checked = verify_assertion(
            {"raw_id": encode_base64url(returned_id), "type": "public-key", "response": response},
            expected_challenge=challenge, rp_id=rp_id, origin=origin, algorithm=-7,
            jwk=jwk, expected_raw_id=raw_id, expected_user_handle=user_id)
        # Raw credential IDs and user handles are deliberately not public output.
        return {"client_data_json": response["client_data_json"],
                "authenticator_data": response["authenticator_data"],
                "signature": response["signature"], "sign_count": checked.sign_count}
    finally:
        if output:
            api.WebAuthNFreeAssertion(output)
