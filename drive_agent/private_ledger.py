from __future__ import annotations

import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from verifier.skyseal_verify import (
    VerificationError,
    canonical_json,
    encode_base64url,
    parse_json_bytes,
)
from verifier.skyseal_private_ledger_verify import validate_receipt


RECEIPT_SCHEMA = "urn:skyseal:private-ledger-receipt:v1"
LEDGER_HEADER = (
    "schema",
    "seal_id",
    "created_at",
    "drive_item_name",
    "drive_item_url",
    "drive_item_id",
    "root_mime_type",
    "snapshot_digest",
    "subject_digest",
    "entry_count",
    "private_ledger_commitment",
    "public_proof_url",
    "ledger_mode",
    "receipt_json",
)


class PrivateLedgerError(RuntimeError):
    pass


@dataclass(frozen=True)
class PrivateLedgerReceipt:
    content: bytes
    commitment: str


def build_receipt(
    *,
    drive_item_id: str,
    drive_item_name: str,
    root_mime_type: str,
    snapshot_digest: str,
    subject_digest: str,
    entry_count: int,
) -> PrivateLedgerReceipt:
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "commitment_format": "skyseal-sha256-set-v1",
        "drive_item": {
            "id": drive_item_id,
            "name": drive_item_name,
            "url": "https://drive.google.com/open?id="
            + urllib.parse.quote(drive_item_id, safe=""),
            "mime_type": root_mime_type,
            "snapshot_digest": snapshot_digest,
        },
        "subject_digest": {"algorithm": "sha256", "value": subject_digest},
        "entry_count": entry_count,
        "salt": encode_base64url(secrets.token_bytes(32)),
    }
    content = canonical_json(receipt)
    return PrivateLedgerReceipt(
        content=content,
        commitment="sha256:" + hashlib.sha256(content).hexdigest(),
    )


class GoogleSheetsPrivateLedger:
    def __init__(
        self,
        token_provider: Any,
        spreadsheet_id: str,
        sheet: str = "Ledger",
        public_origin: str = "",
        timeout: float = 20.0,
    ):
        self.token_provider = token_provider
        self.spreadsheet_id = spreadsheet_id
        self.sheet = sheet
        self.public_origin = public_origin.rstrip("/")
        self.timeout = timeout

    @property
    def _range(self) -> str:
        return urllib.parse.quote(f"{self.sheet}!A:N", safe="")

    @property
    def _base(self) -> str:
        return "https://sheets.googleapis.com/v4/spreadsheets/" + urllib.parse.quote(
            self.spreadsheet_id, safe=""
        )

    def _request(self, url: str, *, method: str = "GET", payload: object | None = None) -> Any:
        data = None
        headers = {
            "Authorization": f"Bearer {self.token_provider.access_token()}",
            "Accept": "application/json",
            "User-Agent": "SkySeal-Drive-Agent/1.0",
        }
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(4 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            exc.read(1024 * 1024)
            raise PrivateLedgerError(
                f"Google Sheets API returned HTTP {exc.code}"
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise PrivateLedgerError(
                f"Google Sheets request failed: {type(exc).__name__}"
            ) from exc
        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            raise PrivateLedgerError("Google Sheets returned invalid JSON") from exc

    def _append(self, row: tuple[str, ...]) -> None:
        url = (
            f"{self._base}/values/{self._range}:append?"
            "valueInputOption=RAW&insertDataOption=INSERT_ROWS"
        )
        self._request(
            url,
            method="POST",
            payload={"majorDimension": "ROWS", "values": [list(row)]},
        )

    def _values(self) -> list[Any]:
        response = self._request(
            f"{self._base}/values/{self._range}?majorDimension=ROWS"
        )
        values = response.get("values", []) if isinstance(response, dict) else []
        if not isinstance(values, list):
            raise PrivateLedgerError("Google Sheets returned invalid values")
        return values

    def check(self) -> None:
        values = self._values()
        if not values:
            self._append(LEDGER_HEADER)
        elif tuple(values[0]) != LEDGER_HEADER:
            raise PrivateLedgerError("private ledger header does not match SkySeal v1")

    def sync(self, job: Any) -> None:
        if job["ledger_receipt"] is None or job["ledger_commitment"] is None:
            raise PrivateLedgerError("private ledger receipt is missing")
        receipt_bytes = bytes(job["ledger_receipt"])
        try:
            receipt = validate_receipt(
                parse_json_bytes(receipt_bytes, "private ledger receipt")
            )
            payload = parse_json_bytes(bytes(job["bundle_json"]), "approved bundle")
        except VerificationError as exc:
            raise PrivateLedgerError(str(exc)) from exc
        calculated_commitment = "sha256:" + hashlib.sha256(
            canonical_json(receipt)
        ).hexdigest()
        if calculated_commitment != job["ledger_commitment"]:
            raise PrivateLedgerError("private ledger receipt commitment does not match")
        try:
            seal_payload = payload["seal_payload"]
            created_at = str(seal_payload["created_at"])
            if seal_payload["seal_id"] != job["seal_id"]:
                raise PrivateLedgerError("private ledger seal ID does not match")
            if seal_payload.get("private_ledger_commitment") != calculated_commitment:
                raise PrivateLedgerError("signed private-ledger commitment does not match")
            item = receipt["drive_item"]
            subject = receipt["subject_digest"]
            if subject.get("value") != job["subject_digest"]:
                raise PrivateLedgerError("private ledger subject digest does not match")
            row = (
                RECEIPT_SCHEMA,
                str(job["seal_id"]),
                created_at,
                str(item["name"]),
                str(item["url"]),
                str(item["id"]),
                str(item["mime_type"]),
                str(item["snapshot_digest"]),
                str(subject["value"]),
                str(receipt["entry_count"]),
                str(job["ledger_commitment"]),
                f"{self.public_origin}/proofs/{job['seal_id']}",
                "committed",
                receipt_bytes.decode("utf-8"),
            )
        except (KeyError, TypeError) as exc:
            raise PrivateLedgerError("private ledger row cannot be constructed") from exc

        values = self._values()
        if not values:
            self._append(LEDGER_HEADER)
        else:
            if tuple(values[0]) != LEDGER_HEADER:
                raise PrivateLedgerError("private ledger header does not match SkySeal v1")
            for existing in values[1:]:
                if isinstance(existing, list) and len(existing) > 1 and existing[1] == row[1]:
                    if tuple(existing) != row:
                        raise PrivateLedgerError("private ledger already has a different row")
                    return
        self._append(row)
