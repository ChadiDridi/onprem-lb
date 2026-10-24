"""Strict HTTP/1.x message heads and body framing.

Strictness is deliberate: ambiguous framing is how request smuggling works,
so requests with both Transfer-Encoding and Content-Length, conflicting
Content-Lengths, obsolete line folding, or whitespace before the colon are
rejected with 400.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from urllib.parse import parse_qs

MAX_HEAD = 64 * 1024
MAX_CHUNK_LINE = 4096
TOKEN = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
HEX = re.compile(rb"^[0-9A-Fa-f]+$")


class HTTPError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class Headers:
    """Ordered, case-insensitive multi-map that preserves original names.
    Lowercased names are computed once per header (hot path)."""

    __slots__ = ("_h",)

    def __init__(self, items: list[tuple[str, str]] | None = None) -> None:
        self._h = [(k.lower(), k, v) for k, v in items or ()]

    @property
    def items(self) -> list[tuple[str, str]]:
        return [(k, v) for _, k, v in self._h]

    def copy(self) -> Headers:
        h = Headers()
        h._h = list(self._h)
        return h

    def get(self, name: str, default: str | None = None) -> str | None:
        n = name.lower()
        for lk, _, v in self._h:
            if lk == n:
                return v
        return default

    def get_all(self, name: str) -> list[str]:
        n = name.lower()
        return [v for lk, _, v in self._h if lk == n]

    def tokens(self, name: str) -> set[str]:
        """Comma-separated tokens across all instances, lowercased."""
        return {t.strip().lower() for v in self.get_all(name) for t in v.split(",") if t.strip()}

    def remove(self, *names: str) -> None:
        ns = {n.lower() for n in names}
        self._h = [h for h in self._h if h[0] not in ns]

    def set(self, name: str, value: str) -> None:
        self.remove(name)
        self._h.append((name.lower(), name, value))

    def add(self, name: str, value: str) -> None:
        self._h.append((name.lower(), name, value))

    def encode(self) -> bytes:
        return "".join(f"{k}: {v}\r\n" for _, k, v in self._h).encode("latin-1")


@dataclass
class Request:
    method: str
    target: str
    version: str
    headers: Headers

    @property
    def path(self) -> str:
        return self.target.split("?", 1)[0]

    @property
    def query_string(self) -> str:
        return self.target.split("?", 1)[1] if "?" in self.target else ""

    def query(self) -> dict[str, list[str]]:
        return parse_qs(self.query_string, keep_blank_values=True)


@dataclass
class Response:
    version: str
    status: int
    reason: str
    headers: Headers


async def read_head(reader: asyncio.StreamReader) -> bytes | None:
    """Read up to and including the blank line. None on clean EOF."""
    try:
        data = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as e:
        if not e.partial.strip():
            return None
        raise HTTPError(400, "incomplete request head") from None
    except asyncio.LimitOverrunError:
        raise HTTPError(431, "request head too large") from None
    # RFC 9112 2.2: ignore at least one empty line before the request line.
    return data.lstrip(b"\r\n")


def _headers(lines: list[bytes]) -> Headers:
    items = []
    for line in lines:
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            raise HTTPError(400, "obsolete line folding")
        name, sep, value = line.partition(b":")
        if not sep or not TOKEN.match(name):
            raise HTTPError(400, "malformed header")
        if b"\r" in value or b"\n" in value or b"\x00" in value:
            raise HTTPError(400, "invalid header value")
        items.append((name.decode("latin-1"), value.strip(b" \t").decode("latin-1")))
    return Headers(items)


def parse_request(head: bytes) -> Request:
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) != 3 or not TOKEN.match(parts[0]) or not parts[1]:
        raise HTTPError(400, "malformed request line")
    version = parts[2].decode("latin-1")
    if version not in ("HTTP/1.1", "HTTP/1.0"):
        raise HTTPError(505, "HTTP version not supported")
    return Request(parts[0].decode(), parts[1].decode("latin-1"), version, _headers(lines[1:]))


def parse_response(head: bytes) -> Response:
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/1.") or not parts[1].isdigit() or len(parts[1]) != 3:
        raise HTTPError(502, "malformed upstream status line")
    reason = parts[2].decode("latin-1") if len(parts) > 2 else ""
    return Response(parts[0].decode(), int(parts[1]), reason, _headers(lines[1:]))


# Framing kinds.
NONE, LENGTH, CHUNKED, CLOSE = "none", "length", "chunked", "close"


def _content_length(h: Headers) -> int | None:
    values = {v.strip() for raw in h.get_all("content-length") for v in raw.split(",")}
    if not values:
        return None
    if len(values) > 1:
        raise HTTPError(400, "conflicting Content-Length")
    v = values.pop()
    if not v.isdigit():
        raise HTTPError(400, "invalid Content-Length")
    return int(v)


def request_framing(h: Headers) -> tuple[str, int]:
    te = [t.strip().lower() for raw in h.get_all("transfer-encoding") for t in raw.split(",") if t.strip()]
    if te:
        if h.get_all("content-length"):
            raise HTTPError(400, "both Transfer-Encoding and Content-Length")
        if te != ["chunked"]:
            raise HTTPError(501, "unsupported Transfer-Encoding")
        return CHUNKED, 0
    n = _content_length(h)
    return (LENGTH, n) if n else (NONE, 0)


def response_framing(method: str, status: int, h: Headers) -> tuple[str, int]:
    if method == "HEAD" or 100 <= status < 200 or status in (204, 304):
        return NONE, 0
    te = [t.strip().lower() for raw in h.get_all("transfer-encoding") for t in raw.split(",") if t.strip()]
    if te:
        return (CHUNKED, 0) if te[-1] == "chunked" else (CLOSE, 0)
    try:
        n = _content_length(h)
    except HTTPError:
        raise HTTPError(502, "invalid upstream Content-Length") from None
    if n is None:
        return CLOSE, 0
    return (LENGTH, n) if n else (NONE, 0)


async def _read(reader: asyncio.StreamReader, n: int, timeout: float) -> bytes:
    return await asyncio.wait_for(reader.read(n), timeout)


async def copy_length(reader, writer, n: int, timeout: float) -> int:
    left = n
    while left:
        data = await _read(reader, min(left, 65536), timeout)
        if not data:
            raise asyncio.IncompleteReadError(b"", left)
        writer.write(data)
        await writer.drain()
        left -= len(data)
    return n


async def copy_chunked(reader, writer, timeout: float) -> int:
    """Forward a chunked body verbatim (sizes validated, trailers passed)."""
    total = 0
    while True:
        line = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout)
        if len(line) > MAX_CHUNK_LINE:
            raise HTTPError(400, "chunk size line too long")
        size_s = line.split(b";", 1)[0].strip(b" \t\r\n")
        # Strict hex only: int(x, 16) would also accept "0x10", "+1", "1_0".
        if not HEX.match(size_s) or len(size_s) > 16:
            raise HTTPError(400, "invalid chunk size")
        size = int(size_s, 16)
        writer.write(line)
        if size == 0:
            while True:  # trailers, then the final CRLF
                t = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout)
                writer.write(t)
                if t == b"\r\n":
                    break
            await writer.drain()
            return total
        left = size
        while left:
            data = await _read(reader, min(left, 65536), timeout)
            if not data:
                raise asyncio.IncompleteReadError(b"", left)
            writer.write(data)
            left -= len(data)
            await writer.drain()
        crlf = await asyncio.wait_for(reader.readexactly(2), timeout)
        if crlf != b"\r\n":
            raise HTTPError(400, "missing CRLF after chunk")
        writer.write(crlf)
        total += size


async def copy_until_close(reader, writer, timeout: float, chunk: bool) -> int:
    """Copy a close-delimited body, re-encoding as chunked if asked."""
    total = 0
    while True:
        data = await _read(reader, 65536, timeout)
        if not data:
            break
        total += len(data)
        writer.write(b"%x\r\n%s\r\n" % (len(data), data) if chunk else data)
        await writer.drain()
    if chunk:
        writer.write(b"0\r\n\r\n")
        await writer.drain()
    return total


async def copy_body(kind: str, n: int, reader, writer, timeout: float, rechunk: bool = False) -> int:
    if kind == LENGTH:
        return await copy_length(reader, writer, n, timeout)
    if kind == CHUNKED:
        return await copy_chunked(reader, writer, timeout)
    if kind == CLOSE:
        return await copy_until_close(reader, writer, timeout, rechunk)
    return 0
