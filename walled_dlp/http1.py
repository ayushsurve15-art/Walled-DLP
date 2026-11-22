"""Just enough HTTP/1.1 to sit between a browser and a server.

Requests are read in full (the body has to be inspected before anything is forwarded). Responses
are streamed through as they arrive, so ChatGPT's and Perplexity's streamed answers aren't delayed,
except for the few HTML pages the proxy rewrites.
"""

from __future__ import annotations

import asyncio
import zlib
from dataclasses import dataclass, field

MAX_HEAD = 64 * 1024


class HttpError(Exception):
    pass


class Headers:
    """Ordered, case-insensitive header list that keeps the original spelling."""

    def __init__(self, items: list[tuple[str, str]] | None = None) -> None:
        self.items: list[tuple[str, str]] = list(items or [])

    def get(self, name: str, default: str = "") -> str:
        name = name.lower()
        for k, v in self.items:
            if k.lower() == name:
                return v
        return default

    def get_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.items if k.lower() == name]

    def remove(self, name: str) -> None:
        name = name.lower()
        self.items = [(k, v) for k, v in self.items if k.lower() != name]

    def set(self, name: str, value: str) -> None:
        self.remove(name)
        self.items.append((name, value))

    def has_token(self, name: str, token: str) -> bool:
        return any(token in (t.strip().lower() for t in v.split(",")) for v in self.get_all(name))

    def encode(self) -> bytes:
        return b"".join(f"{k}: {v}\r\n".encode("latin-1") for k, v in self.items)


def parse_head(raw: bytes) -> tuple[str, Headers]:
    lines = raw.decode("latin-1").split("\r\n")
    start = lines[0]
    headers = Headers()
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise HttpError(f"bad header line {line[:60]!r}")
        k, v = line.split(":", 1)
        headers.items.append((k.strip(), v.strip()))
    return start, headers


async def read_head(reader: asyncio.StreamReader) -> bytes | None:
    """Bytes up to and including the blank line, or None if the peer closed cleanly first."""
    try:
        raw = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as exc:
        if not exc.partial.strip():
            return None
        raise HttpError("connection closed mid-header") from exc
    except asyncio.LimitOverrunError as exc:
        raise HttpError("header too large") from exc
    if len(raw) > MAX_HEAD:
        raise HttpError("header too large")
    return raw.lstrip(b"\r\n")


async def read_chunked(reader: asyncio.StreamReader, limit: int) -> bytes:
    body = bytearray()
    while True:
        line = await reader.readline()
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError as exc:
            raise HttpError("bad chunk size") from exc
        if size == 0:
            while (await reader.readline()).strip():  # trailers
                pass
            return bytes(body)
        if len(body) + size > limit:
            raise HttpError("body too large")
        body += await reader.readexactly(size)
        await reader.readexactly(2)


async def read_body(reader: asyncio.StreamReader, headers: Headers, limit: int) -> bytes:
    if headers.has_token("transfer-encoding", "chunked"):
        return await read_chunked(reader, limit)
    length = headers.get("content-length")
    if not length:
        return b""
    n = int(length)
    if n > limit:
        raise HttpError("body too large")
    return await reader.readexactly(n)


@dataclass
class Request:
    method: str
    target: str  # origin-form path, e.g. "/backend-api/conversation?x=1"
    version: str
    headers: Headers
    body: bytes = b""
    host: str = ""
    scheme: str = "https"

    @property
    def path(self) -> str:
        return self.target.split("?", 1)[0]

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}{self.target}"

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type").split(";")[0].strip().lower()

    @property
    def is_websocket(self) -> bool:
        return self.headers.get("upgrade").lower() == "websocket"

    def encode(self) -> bytes:
        """Serialise for the upstream server, with the (already buffered) body framed by length."""
        h = Headers(self.headers.items)
        h.remove("transfer-encoding")
        h.remove("expect")
        h.remove("proxy-connection")
        h.remove("proxy-authorization")
        if self.body or self.method in ("POST", "PUT", "PATCH"):
            h.set("content-length", str(len(self.body)))
        else:
            h.remove("content-length")
        return f"{self.method} {self.target} HTTP/1.1\r\n".encode("latin-1") + h.encode() + b"\r\n" + self.body


@dataclass
class Response:
    status: int
    reason: str
    headers: Headers = field(default_factory=Headers)
    version: str = "HTTP/1.1"

    def encode_head(self) -> bytes:
        return f"{self.version} {self.status} {self.reason}\r\n".encode("latin-1") + self.headers.encode() + b"\r\n"


def parse_response_head(raw: bytes) -> Response:
    start, headers = parse_head(raw)
    parts = start.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise HttpError(f"bad status line {start[:60]!r}")
    return Response(int(parts[1]), parts[2] if len(parts) > 2 else "", headers, parts[0])


def parse_request(raw: bytes) -> Request:
    start, headers = parse_head(raw)
    parts = start.split(" ")
    if len(parts) != 3:
        raise HttpError(f"bad request line {start[:60]!r}")
    return Request(parts[0].upper(), parts[1], parts[2], headers)


def has_body(method: str, status: int) -> bool:
    return not (method == "HEAD" or 100 <= status < 200 or status in (204, 304))


async def relay_body(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, resp: Response, method: str
) -> bool:
    """Copy a response body through as it arrives. Returns False if the connection must close."""
    if not has_body(method, resp.status):
        return True
    h = resp.headers
    if h.has_token("transfer-encoding", "chunked"):
        while True:
            line = await reader.readline()
            writer.write(line)
            size = int(line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while True:
                    trailer = await reader.readline()
                    writer.write(trailer)
                    if not trailer.strip():
                        break
                await writer.drain()
                return True
            writer.write(await reader.readexactly(size + 2))
            await writer.drain()
    length = h.get("content-length")
    if length:
        remaining = int(length)
        while remaining:
            chunk = await reader.read(min(remaining, 65536))
            if not chunk:
                raise HttpError("upstream closed mid-body")
            writer.write(chunk)
            remaining -= len(chunk)
            await writer.drain()
        return True
    while chunk := await reader.read(65536):  # body runs until the server closes
        writer.write(chunk)
        await writer.drain()
    return False


async def iter_body(reader: asyncio.StreamReader, resp: Response, method: str, state: dict):
    """Yield a response body's bytes with the transfer framing removed. Sets state["close"] when
    the body is delimited by the connection closing."""
    if not has_body(method, resp.status):
        return
    h = resp.headers
    if h.has_token("transfer-encoding", "chunked"):
        while True:
            line = await reader.readline()
            size = int(line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while (await reader.readline()).strip():
                    pass
                return
            yield await reader.readexactly(size)
            await reader.readexactly(2)
    length = h.get("content-length")
    if length:
        remaining = int(length)
        while remaining:
            chunk = await reader.read(min(remaining, 65536))
            if not chunk:
                raise HttpError("upstream closed mid-body")
            remaining -= len(chunk)
            yield chunk
        return
    state["close"] = True
    while chunk := await reader.read(65536):
        yield chunk


async def read_response_body(reader: asyncio.StreamReader, resp: Response, method: str, limit: int) -> bytes:
    if not has_body(method, resp.status):
        return b""
    if resp.headers.has_token("transfer-encoding", "chunked") or resp.headers.get("content-length"):
        return await read_body(reader, resp.headers, limit)
    data = await reader.read(-1)
    if len(data) > limit:
        raise HttpError("body too large")
    return data


def decode_content(body: bytes, encoding: str) -> bytes | None:
    """Undo gzip/deflate. None for encodings we can't undo (the caller leaves the body alone)."""
    encoding = encoding.strip().lower()
    if encoding in ("", "identity"):
        return body
    if encoding in ("gzip", "x-gzip"):
        return zlib.decompress(body, 16 + zlib.MAX_WBITS)
    if encoding == "deflate":
        try:
            return zlib.decompress(body)
        except zlib.error:
            return zlib.decompress(body, -zlib.MAX_WBITS)
    return None
