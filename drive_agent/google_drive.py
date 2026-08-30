from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Protocol

from verifier.skyseal_verify import canonical_json


DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.readonly"
SHEETS_SCOPE = "https://www.googleapis.com/auth/spreadsheets"
FOLDER_MIME = "application/vnd.google-apps.folder"
SHORTCUT_MIME = "application/vnd.google-apps.shortcut"
WORKSPACE_EXPORTS = {
    "application/vnd.google-apps.document": "application/pdf",
    "application/vnd.google-apps.spreadsheet": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    ),
    "application/vnd.google-apps.presentation": "application/pdf",
    "application/vnd.google-apps.drawing": "application/pdf",
}
FILE_FIELDS = (
    "id,mimeType,modifiedTime,size,sha256Checksum,headRevisionId,parents,"
    "capabilities(canDownload)"
)


class DriveAPIError(RuntimeError):
    pass


def validate_hash_list_bytes(data: bytes) -> list[bytes]:
    if not data or not data.endswith(b"\n") or b"\r" in data:
        raise DriveAPIError("invalid strict hash list framing")
    records = data[:-1].split(b"\n")
    if any(
        len(record) != 64
        or any(byte not in b"0123456789abcdef" for byte in record)
        for record in records
    ):
        raise DriveAPIError("invalid strict SHA-256 hash-list record")
    if records != sorted(set(records)):
        raise DriveAPIError("hash-list records are not strictly sorted and unique")
    return records


@dataclass(frozen=True)
class DriveFile:
    file_id: str
    mime_type: str
    modified_time: str
    size: int | None
    sha256_checksum: str | None
    head_revision_id: str | None
    parents: tuple[str, ...]
    can_download: bool

    @property
    def is_folder(self) -> bool:
        return self.mime_type == FOLDER_MIME

    def private_snapshot_record(self) -> dict[str, object]:
        return {
            "id": self.file_id,
            "mime_type": self.mime_type,
            "modified_time": self.modified_time,
            "size": self.size,
            "sha256_checksum": self.sha256_checksum,
            "head_revision_id": self.head_revision_id,
            "parents": list(self.parents),
        }


@dataclass(frozen=True)
class DriveUnit:
    root: DriveFile
    files: tuple[DriveFile, ...]
    snapshot_digest: str


class DriveReader(Protocol):
    def list_children(self, folder_id: str) -> list[DriveFile]: ...

    def iter_content(self, item: DriveFile) -> Iterator[bytes]: ...


class GoogleServiceAccountTokenProvider:
    """Short-lived token provider backed by Google's maintained auth library."""

    def __init__(self, service_account_file: Path, scopes: tuple[str, ...] = (DRIVE_SCOPE,)):
        try:
            from google.auth.transport.requests import Request
            from google.oauth2 import service_account
        except ImportError as exc:  # pragma: no cover - deployment dependency
            raise DriveAPIError(
                "google-auth is required; install drive_agent/requirements.txt"
            ) from exc
        self._request_type = Request
        try:
            self._credentials = service_account.Credentials.from_service_account_file(
                str(service_account_file), scopes=list(scopes)
            )
        except Exception as exc:
            raise DriveAPIError("cannot load Google service-account credentials") from exc

    def access_token(self) -> str:
        if not self._credentials.valid or not self._credentials.token:
            try:
                self._credentials.refresh(self._request_type())
            except Exception as exc:
                raise DriveAPIError("Google service-account token refresh failed") from exc
        return str(self._credentials.token)


class GoogleDriveRESTClient:
    def __init__(self, token_provider, timeout: float = 30.0):
        self.token_provider = token_provider
        self.timeout = timeout

    def _open(self, url: str):
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self.token_provider.access_token()}",
                "Accept": "application/json",
                "User-Agent": "SkySeal-Drive-Agent/1.0",
            },
        )
        try:
            return urllib.request.urlopen(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            exc.read(1024 * 1024)
            raise DriveAPIError(f"Google Drive API returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise DriveAPIError(f"Google Drive request failed: {type(exc).__name__}") from exc

    def _json(self, url: str) -> dict[str, object]:
        with self._open(url) as response:
            try:
                value = json.loads(response.read(4 * 1024 * 1024))
            except json.JSONDecodeError as exc:
                raise DriveAPIError("Google Drive returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise DriveAPIError("Google Drive returned a non-object response")
        return value

    @staticmethod
    def _file(value: object) -> DriveFile:
        if not isinstance(value, dict):
            raise DriveAPIError("Google Drive returned invalid file metadata")
        file_id = value.get("id")
        mime_type = value.get("mimeType")
        modified_time = value.get("modifiedTime")
        if not all(isinstance(item, str) and item for item in (file_id, mime_type, modified_time)):
            raise DriveAPIError("Google Drive omitted required private metadata")
        size_value = value.get("size")
        size = int(size_value) if isinstance(size_value, str) and size_value.isdigit() else None
        checksum = value.get("sha256Checksum")
        revision = value.get("headRevisionId")
        parents = value.get("parents", [])
        capabilities = value.get("capabilities", {})
        return DriveFile(
            file_id=file_id,
            mime_type=mime_type,
            modified_time=modified_time,
            size=size,
            sha256_checksum=checksum if isinstance(checksum, str) else None,
            head_revision_id=revision if isinstance(revision, str) else None,
            parents=tuple(item for item in parents if isinstance(item, str))
            if isinstance(parents, list)
            else (),
            can_download=bool(capabilities.get("canDownload"))
            if isinstance(capabilities, dict)
            else False,
        )

    def list_children(self, folder_id: str) -> list[DriveFile]:
        files: list[DriveFile] = []
        page_token: str | None = None
        while True:
            query = {
                "q": f"'{folder_id}' in parents and trashed = false",
                "spaces": "drive",
                "pageSize": "1000",
                "supportsAllDrives": "true",
                "includeItemsFromAllDrives": "true",
                "fields": f"nextPageToken,files({FILE_FIELDS})",
            }
            if page_token:
                query["pageToken"] = page_token
            url = "https://www.googleapis.com/drive/v3/files?" + urllib.parse.urlencode(query)
            response = self._json(url)
            raw_files = response.get("files", [])
            if not isinstance(raw_files, list):
                raise DriveAPIError("Google Drive returned invalid file list")
            files.extend(self._file(item) for item in raw_files)
            next_token = response.get("nextPageToken")
            if not isinstance(next_token, str) or not next_token:
                break
            page_token = next_token
        return sorted(files, key=lambda item: item.file_id)

    def get_private_display_name(self, file_id: str) -> str:
        """Fetch a root display name only for the owner-only ledger."""
        query = urllib.parse.urlencode(
            {"fields": "id,name", "supportsAllDrives": "true"}
        )
        url = (
            "https://www.googleapis.com/drive/v3/files/"
            + urllib.parse.quote(file_id, safe="")
            + "?"
            + query
        )
        value = self._json(url)
        if value.get("id") != file_id or not isinstance(value.get("name"), str):
            raise DriveAPIError("Google Drive omitted the private display name")
        name = str(value["name"])
        if not name or len(name.encode("utf-8")) > 1024:
            raise DriveAPIError("Google Drive returned an invalid private display name")
        return name

    def iter_content(self, item: DriveFile) -> Iterator[bytes]:
        if item.is_folder or item.mime_type == SHORTCUT_MIME:
            raise DriveAPIError("folders and shortcuts have no directly sealable bytes")
        if not item.can_download:
            raise DriveAPIError("a monitored item cannot be downloaded")
        if item.mime_type.startswith("application/vnd.google-apps."):
            export_mime = WORKSPACE_EXPORTS.get(item.mime_type)
            if export_mime is None:
                raise DriveAPIError("unsupported Google Workspace file type")
            query = urllib.parse.urlencode({"mimeType": export_mime})
            url = (
                "https://www.googleapis.com/drive/v3/files/"
                + urllib.parse.quote(item.file_id, safe="")
                + "/export?"
                + query
            )
        else:
            url = (
                "https://www.googleapis.com/drive/v3/files/"
                + urllib.parse.quote(item.file_id, safe="")
                + "?alt=media&supportsAllDrives=true"
            )
        with self._open(url) as response:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                yield chunk


def inventory_unit(reader: DriveReader, root: DriveFile) -> DriveUnit:
    files: list[DriveFile] = []
    visited_folders: set[str] = set()

    def walk(item: DriveFile) -> None:
        if item.mime_type == SHORTCUT_MIME:
            raise DriveAPIError("shortcuts are forbidden in a sealing unit")
        if not item.is_folder:
            files.append(item)
            return
        if item.file_id in visited_folders:
            raise DriveAPIError("folder cycle detected")
        visited_folders.add(item.file_id)
        for child in reader.list_children(item.file_id):
            walk(child)

    walk(root)
    records = [item.private_snapshot_record() for item in sorted(files, key=lambda f: f.file_id)]
    snapshot = hashlib.sha256(canonical_json(records)).hexdigest()
    return DriveUnit(root=root, files=tuple(sorted(files, key=lambda f: f.file_id)), snapshot_digest=snapshot)


def hash_unit(reader: DriveReader, unit: DriveUnit) -> bytes:
    if not unit.files:
        raise DriveAPIError("empty folders cannot be sealed")
    digests: set[str] = set()
    for item in unit.files:
        digest = hashlib.sha256()
        for chunk in reader.iter_content(item):
            if not isinstance(chunk, bytes) or not chunk:
                raise DriveAPIError("Drive content stream returned an invalid chunk")
            digest.update(chunk)
        computed = digest.hexdigest()
        if item.sha256_checksum is not None and item.mime_type not in WORKSPACE_EXPORTS:
            if computed != item.sha256_checksum:
                raise DriveAPIError("downloaded content does not match Drive's SHA-256 checksum")
        digests.add(computed)
    result = ("\n".join(sorted(digests)) + "\n").encode("ascii")
    validate_hash_list_bytes(result)
    return result
