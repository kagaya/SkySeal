from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class CBORDecodeError(ValueError):
    pass


@dataclass
class Decoder:
    data: bytes
    offset: int = 0
    max_depth: int = 16
    max_collection_length: int = 1024

    def _read(self, length: int) -> bytes:
        if length < 0 or self.offset + length > len(self.data):
            raise CBORDecodeError("truncated CBOR input")
        value = self.data[self.offset : self.offset + length]
        self.offset += length
        return value

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        if additional == 24:
            return int.from_bytes(self._read(1), "big")
        if additional == 25:
            return int.from_bytes(self._read(2), "big")
        if additional == 26:
            return int.from_bytes(self._read(4), "big")
        if additional == 27:
            return int.from_bytes(self._read(8), "big")
        if additional == 31:
            raise CBORDecodeError("indefinite-length CBOR is forbidden")
        raise CBORDecodeError("reserved CBOR additional information")

    def decode(self, depth: int = 0) -> Any:
        if depth > self.max_depth:
            raise CBORDecodeError("CBOR nesting is too deep")
        initial = self._read(1)[0]
        major = initial >> 5
        additional = initial & 0x1F

        if major in {0, 1}:
            argument = self._argument(additional)
            return argument if major == 0 else -1 - argument
        if major in {2, 3}:
            length = self._argument(additional)
            raw = self._read(length)
            if major == 2:
                return raw
            try:
                return raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise CBORDecodeError("invalid UTF-8 CBOR text string") from exc
        if major == 4:
            length = self._argument(additional)
            if length > self.max_collection_length:
                raise CBORDecodeError("CBOR array is too large")
            return [self.decode(depth + 1) for _ in range(length)]
        if major == 5:
            length = self._argument(additional)
            if length > self.max_collection_length:
                raise CBORDecodeError("CBOR map is too large")
            result: dict[Any, Any] = {}
            for _ in range(length):
                key = self.decode(depth + 1)
                try:
                    if key in result:
                        raise CBORDecodeError("duplicate CBOR map key")
                    result[key] = self.decode(depth + 1)
                except TypeError as exc:
                    raise CBORDecodeError("unhashable CBOR map key") from exc
            return result
        if major == 6:
            raise CBORDecodeError("CBOR tags are forbidden in this profile")
        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional == 22:
                return None
            raise CBORDecodeError("unsupported CBOR simple or floating-point value")
        raise CBORDecodeError("unsupported CBOR major type")


def decode_one(data: bytes, *, require_eof: bool = True) -> tuple[Any, int]:
    decoder = Decoder(data)
    value = decoder.decode()
    if require_eof and decoder.offset != len(data):
        raise CBORDecodeError("trailing bytes after CBOR value")
    return value, decoder.offset
