from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Callable

from verifier.skyseal_verify import validate_sky_witness


class SkyWitnessError(RuntimeError):
    pass


JMA_FULL_DISK_ROOT = "https://www.data.jma.go.jp/mscweb/data/himawari/img/fd_"
MAX_IMAGE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class SkyWitnessRecord:
    metadata: dict[str, object]
    image: bytes


class JMAHimawariWitness:
    """Capture one recent JMA Himawari full-disk infrared observation."""

    def __init__(
        self,
        *,
        timeout: float = 20.0,
        opener: Callable[..., object] = urllib.request.urlopen,
        initial_lag_minutes: int = 20,
        attempts: int = 10,
    ):
        self.timeout = timeout
        self.opener = opener
        self.initial_lag_minutes = initial_lag_minutes
        self.attempts = attempts

    @staticmethod
    def _utc(value: datetime | int | None) -> datetime:
        if value is None:
            return datetime.now(timezone.utc).replace(microsecond=0)
        if isinstance(value, int):
            return datetime.fromtimestamp(value, timezone.utc).replace(microsecond=0)
        if value.tzinfo is None:
            raise SkyWitnessError("sky witness clock must be timezone-aware")
        return value.astimezone(timezone.utc).replace(microsecond=0)

    @staticmethod
    def _candidate(now: datetime, minutes_back: int) -> datetime:
        candidate = now - timedelta(minutes=minutes_back)
        return candidate.replace(minute=(candidate.minute // 10) * 10, second=0, microsecond=0)

    @staticmethod
    def _url(observation: datetime) -> str:
        return f"{JMA_FULL_DISK_ROOT}/fd__b13_{observation:%H%M}.jpg"

    @staticmethod
    def _last_modified(response: object) -> datetime:
        raw = response.headers.get("Last-Modified")
        if not raw:
            raise SkyWitnessError("JMA response has no Last-Modified header")
        try:
            value = parsedate_to_datetime(raw)
        except (TypeError, ValueError) as exc:
            raise SkyWitnessError("JMA Last-Modified header is invalid") from exc
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @staticmethod
    def _read_image(response: object) -> bytes:
        content_type = response.headers.get_content_type().lower()
        if content_type != "image/jpeg":
            raise SkyWitnessError("JMA response is not a JPEG image")
        image = response.read(MAX_IMAGE_BYTES + 1)
        if len(image) > MAX_IMAGE_BYTES:
            raise SkyWitnessError("JMA image exceeds the accepted size")
        if len(image) < 1024 or not image.startswith(b"\xff\xd8") or not image.endswith(b"\xff\xd9"):
            raise SkyWitnessError("JMA response is not a complete JPEG image")
        return image

    def capture(self, now: datetime | int | None = None) -> SkyWitnessRecord:
        retrieved_at = self._utc(now)
        failures: list[str] = []
        for index in range(self.attempts):
            observation = self._candidate(
                retrieved_at, self.initial_lag_minutes + index * 10
            )
            source_url = self._url(observation)
            request = urllib.request.Request(
                source_url,
                headers={
                    "Accept": "image/jpeg",
                    "User-Agent": "SkySeal-Sky-Witness/1.0 (+https://proof.excyberlab.net)",
                },
            )
            try:
                with self.opener(request, timeout=self.timeout) as response:
                    last_modified = self._last_modified(response)
                    # JMA reuses the HHMM URL every day.  A dated response header is
                    # therefore required to reject a stale image from another day.
                    if not observation <= last_modified <= observation + timedelta(hours=6):
                        raise SkyWitnessError("JMA image date does not match the observation slot")
                    image = self._read_image(response)
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
                failures.append(type(exc).__name__)
                continue
            except SkyWitnessError as exc:
                failures.append(str(exc))
                continue

            metadata: dict[str, object] = {
                "schema": "urn:skyseal:sky-witness:v1",
                "provider": "Japan Meteorological Agency (JMA)",
                "platform": "Himawari-8/9",
                "product": "Full Disk Band 13 infrared",
                "observation_time": observation.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "retrieved_at": retrieved_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source_url": source_url,
                "media_type": "image/jpeg",
                "image_digest": "sha256:" + hashlib.sha256(image).hexdigest(),
                "attribution": "Japan Meteorological Agency (JMA)",
            }
            validate_sky_witness(metadata)
            return SkyWitnessRecord(metadata, image)
        detail = failures[-1] if failures else "no candidate observations"
        raise SkyWitnessError(f"no current JMA Himawari observation was accepted: {detail}")
