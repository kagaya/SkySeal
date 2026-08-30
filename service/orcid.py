from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from verifier.skyseal_verify import VerificationError, validate_orcid


class ORCIDError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuthenticatedORCID:
    identity_url: str
    display_name: str


def authorization_url(
    *,
    base_url: str,
    client_id: str,
    redirect_uri: str,
    state: str,
) -> str:
    if not client_id:
        raise ORCIDError("ORCID client ID is not configured")
    query = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "scope": "/authenticate",
            "redirect_uri": redirect_uri,
            "state": state,
        }
    )
    return f"{base_url.rstrip('/')}/oauth/authorize?{query}"


def exchange_authorization_code(
    *,
    base_url: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code: str,
    timeout: float = 15.0,
) -> AuthenticatedORCID:
    if not client_id or not client_secret:
        raise ORCIDError("ORCID client credentials are not configured")
    form = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
    ).encode("ascii")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/oauth/token",
        data=form,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "SkySeal/1.1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise ORCIDError(f"ORCID token endpoint returned HTTP {response.status}")
            data = json.loads(response.read(1024 * 1024).decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ORCIDError(f"ORCID authorization-code exchange failed: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise ORCIDError("ORCID token response is not a JSON object")
    compact_orcid = data.get("orcid")
    if not isinstance(compact_orcid, str):
        raise ORCIDError("ORCID token response lacks an authenticated iD")
    identity_url = f"https://orcid.org/{compact_orcid}"
    try:
        validate_orcid(identity_url, "ORCID token response")
    except VerificationError as exc:
        raise ORCIDError(str(exc)) from exc
    display_name = data.get("name")
    if not isinstance(display_name, str) or not display_name.strip():
        display_name = identity_url.rsplit("/", 1)[-1]
    return AuthenticatedORCID(identity_url, display_name.strip()[:200])
