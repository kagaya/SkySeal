from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from drive_agent.google_drive import DriveAPIError, validate_hash_list_bytes
from verifier.skyseal_verify import HASH_LIST_FORMAT, parse_json_bytes, validate_orcid


class SkySealAPIError(RuntimeError):
    pass


@dataclass(frozen=True)
class SealTransaction:
    seal_id: str
    bearer_token: str
    approval_url: str
    expires_at: int


@dataclass(frozen=True)
class ApprovedArtifacts:
    bundle_json: bytes
    genesis_json: bytes
    identity_activation: bytes


class SkySealClient:
    def __init__(self, server: str, agent_token: str, timeout: float = 20.0):
        self.server = server.rstrip("/")
        self.agent_token = agent_token
        self.timeout = timeout

    def _request(
        self,
        path: str,
        *,
        method: str = "GET",
        authorization: str | None = None,
        payload: object | None = None,
    ) -> bytes:
        headers = {
            "Accept": "application/json",
            "User-Agent": "SkySeal-Drive-Agent/1.0",
        }
        if authorization:
            headers["Authorization"] = authorization
        body = None
        if payload is not None:
            body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.server + path, data=body, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read(4 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            detail = exc.read(1024 * 1024)
            try:
                error = json.loads(detail)
                message = error.get("message", f"HTTP {exc.code}")
            except Exception:
                message = f"HTTP {exc.code}"
            raise SkySealAPIError(str(message)) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise SkySealAPIError(f"SkySeal request failed: {type(exc).__name__}") from exc

    @staticmethod
    def _object(data: bytes, context: str) -> dict[str, object]:
        value = parse_json_bytes(data, context)
        if not isinstance(value, dict):
            raise SkySealAPIError(f"{context} is not a JSON object")
        return value

    def create(self, hash_list: bytes) -> SealTransaction:
        try:
            records = validate_hash_list_bytes(hash_list)
        except DriveAPIError as exc:
            raise SkySealAPIError(str(exc)) from exc
        response = self._object(
            self._request(
                "/api/v1/seals",
                method="POST",
                authorization=f"SkySeal-Agent {self.agent_token}",
                payload={
                    "commitment_format": HASH_LIST_FORMAT,
                    "subject_digest": hashlib.sha256(hash_list).hexdigest(),
                    "entry_count": len(records),
                },
            ),
            "seal creation response",
        )
        if response.get("delivery") != "identity_inbox":
            raise SkySealAPIError("service did not bind the transaction to the identity inbox")
        try:
            return SealTransaction(
                seal_id=str(response["seal_id"]),
                bearer_token=str(response["bearer_token"]),
                approval_url=str(response["approval_url"]),
                expires_at=int(response["expires_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise SkySealAPIError("seal creation response is incomplete") from exc

    def status(self, seal_id: str, bearer_token: str) -> str:
        response = self._object(
            self._request(
                f"/api/v1/seals/{seal_id}", authorization=f"Bearer {bearer_token}"
            ),
            "seal status response",
        )
        status = response.get("status")
        if not isinstance(status, str):
            raise SkySealAPIError("seal status response is incomplete")
        return status

    def approved_artifacts(self, seal_id: str, bearer_token: str) -> ApprovedArtifacts:
        bundle = self._request(
            f"/api/v1/seals/{seal_id}/bundle", authorization=f"Bearer {bearer_token}"
        )
        bundle_object = self._object(bundle, "approved bundle")
        identity = bundle_object.get("identity")
        if not isinstance(identity, dict):
            raise SkySealAPIError("approved bundle has no identity")
        orcid = identity.get("orcid")
        try:
            validate_orcid(orcid, "approved bundle identity")
        except ValueError as exc:
            raise SkySealAPIError(str(exc)) from exc
        compact = str(orcid).rsplit("/", 1)[-1]
        genesis = self._request(f"/api/v1/identity/{compact}/genesis")
        activation = self._request(f"/api/v1/identity/{compact}/activation")
        return ApprovedArtifacts(bundle, genesis, activation)
