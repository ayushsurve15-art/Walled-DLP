"""Local HTTPS proxy that sits between the browser and the monitored AI sites.

The browser's proxy settings (a PAC file served by this proxy) send only the monitored hosts here.
For those hosts the proxy completes TLS itself with a certificate from the local CA, reads each
request, and asks the policy what to do: forward it, hold it while the user decides, or answer it
with a block. Any other host that reaches the proxy is tunnelled byte-for-byte without decryption.

The policy (see policy.py) holds every site-specific decision; this module only moves bytes.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Callable, Protocol

from .certs import CertificateAuthority
from .http1 import (
    Headers,
    HttpError,
    Request,
    Response,
    iter_body,
    parse_request,
    parse_response_head,
    read_body,
    read_head,
    read_response_body,
    relay_body,
)

log = logging.getLogger(__name__)

NETWORK_ERRORS = (ConnectionError, HttpError, asyncio.IncompleteReadError, ssl.SSLError, OSError, asyncio.TimeoutError)


class Reply:
    """A response the proxy writes itself instead of contacting the server."""

    def __init__(self, status: int, body: bytes = b"", content_type: str = "text/plain; charset=utf-8", reason: str = "", headers: list[tuple[str, str]] | None = None) -> None:
        self.status = status
        self.body = body
        self.reason = reason or {200: "OK", 403: "Forbidden", 404: "Not Found", 413: "Payload Too Large", 502: "Bad Gateway"}.get(status, "Blocked")
        self.headers = Headers([("content-type", content_type), *(headers or [])])
        self.close = False

    def encode(self) -> bytes:
        h = Headers(self.headers.items)
        h.set("content-length", str(len(self.body)))
        h.set("cache-control", "no-store")
        if self.close:
            h.set("connection", "close")
        return Response(self.status, self.reason, h).encode_head() + self.body


WsFilter = Callable[[int, bytes], bool]  # (opcode, unmasked payload) -> drop this message?


class Policy(Protocol):
    def intercepts(self, host: str) -> bool: ...
    async def on_request(self, req: Request) -> Reply | None: ...
    def prepare_upstream(self, req: Request) -> None: ...
    def buffer_response(self, req: Request, resp: Response) -> bool: ...
    def on_response(self, req: Request, resp: Response, body: bytes) -> bytes: ...
    def page_transform(self, req: Request, resp: Response) -> tuple[Callable[[bytes], bytes], Callable[[], bytes]] | None: ...
    def websocket_filter(self, req: Request) -> WsFilter | None: ...
    def local(self, req: Request, proxy_port: int) -> Reply | None: ...


def upstream_tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    try:  # macOS python.org builds have no system CA bundle wired up
        import certifi

        ctx.load_verify_locations(certifi.where())
    except ImportError:
        pass
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(65536):
            writer.write(chunk)
            await writer.drain()
    except NETWORK_ERRORS:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def _unmask(payload: bytes, mask: bytes) -> bytes:
    if not mask:
        return payload
    n = len(payload)
    key = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(key, "big")).to_bytes(n, "big") if n else b""


async def _filter_websocket(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, drop: WsFilter) -> None:
    """Copy browser-to-server WebSocket frames, leaving out whole messages the filter rejects."""
    dropping = False
    try:
        while True:
            head = await reader.readexactly(2)
            opcode = head[0] & 0x0F
            n = head[1] & 0x7F
            ext = b""
            if n == 126:
                ext = await reader.readexactly(2)
                n = int.from_bytes(ext, "big")
            elif n == 127:
                ext = await reader.readexactly(8)
                n = int.from_bytes(ext, "big")
            mask = await reader.readexactly(4) if head[1] & 0x80 else b""
            payload = await reader.readexactly(n)
            if opcode in (1, 2):  # first frame of a text/binary message decides for the whole message
                dropping = drop(opcode, _unmask(payload, mask))
            if opcode in (0, 1, 2) and dropping:
                continue
            writer.write(head + ext + mask + payload)
            await writer.drain()
    except NETWORK_ERRORS:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


class Proxy:
    def __init__(
        self,
        policy: Policy,
        ca: CertificateAuthority,
        host: str = "127.0.0.1",
        port: int = 8899,
        body_limit: int = 256 * 1024 * 1024,
        upstream_override: dict[str, tuple[str, int]] | None = None,
    ) -> None:
        self.policy = policy
        self.ca = ca
        self.host = host
        self.port = port
        self.body_limit = body_limit
        # Tests point monitored hosts at local plain-HTTP fixture servers.
        self.upstream_override = upstream_override or {}
        self._upstream_ctx = upstream_tls_context()
        self.server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._client, self.host, self.port, limit=1 << 20)
        self.port = self.server.sockets[0].getsockname()[1]
        log.info("proxy listening on %s:%d", self.host, self.port)

    async def serve_forever(self) -> None:
        if self.server is None:
            await self.start()
        assert self.server is not None
        async with self.server:
            await self.server.serve_forever()

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    # -- connections --------------------------------------------------------------------------
    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await read_head(reader)
            if raw is None:
                return
            req = parse_request(raw)
            if req.method == "CONNECT":
                await self._connect(req, reader, writer)
            elif req.target.startswith("/"):
                req.body = await read_body(reader, req.headers, 1 << 20)
                reply = self.policy.local(req, self.port) or Reply(404, b"not found\n")
                reply.close = True  # one request per connection here
                writer.write(reply.encode())
                await writer.drain()
            else:
                await self._plain_http(req, reader, writer)
        except NETWORK_ERRORS as exc:
            log.debug("client connection ended: %r", exc)
        except Exception:
            log.exception("proxy connection failed")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _connect(self, req: Request, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        host, _, port_s = req.target.rpartition(":")
        host = host.strip("[]").lower()
        port = int(port_s or 443)
        if not self.policy.intercepts(host):
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, port), 20)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(_pipe(reader, up_w), _pipe(up_r, writer))
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await writer.start_tls(self.ca.server_context(host))
        await self._serve_decrypted(host, port, reader, writer)

    async def _open_upstream(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if host in self.upstream_override:
            addr, oport = self.upstream_override[host]
            return await asyncio.wait_for(asyncio.open_connection(addr, oport, limit=1 << 20), 20)
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=self._upstream_ctx, server_hostname=host, limit=1 << 20), 30
        )

    async def _serve_decrypted(self, host: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
        authority = host if port == 443 else f"{host}:{port}"
        try:
            while True:
                raw = await read_head(reader)
                if raw is None:
                    return
                req = parse_request(raw)
                req.host = authority
                if req.headers.get("expect").lower() == "100-continue":
                    writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                    await writer.drain()
                req.body = await read_body(reader, req.headers, self.body_limit)

                reply = await self.policy.on_request(req)
                if reply is not None:
                    writer.write(reply.encode())
                    await writer.drain()
                    continue

                self.policy.prepare_upstream(req)
                resp = None
                for attempt in range(2):  # a kept-alive upstream connection may have gone stale
                    if upstream is None or upstream[1].is_closing():
                        upstream = await self._open_upstream(host, port)
                    up_r, up_w = upstream
                    try:
                        up_w.write(req.encode())
                        await up_w.drain()
                        resp = await self._read_final_head(up_r)
                    except NETWORK_ERRORS:
                        resp = None
                    if resp is not None:
                        break
                    up_w.close()
                    upstream = None
                if resp is None:
                    writer.write(Reply(502, f"Walled DLP could not reach {host}\n".encode()).encode())
                    await writer.drain()
                    return
                up_r, up_w = upstream
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("%s %s -> %d", req.method, req.url[:120], resp.status)

                if req.is_websocket and resp.status == 101:
                    writer.write(resp.encode_head())
                    await writer.drain()
                    drop = self.policy.websocket_filter(req)
                    client_to_server = _filter_websocket(reader, up_w, drop) if drop else _pipe(reader, up_w)
                    await asyncio.gather(client_to_server, _pipe(up_r, writer))
                    return

                framing = Response(resp.status, resp.reason, Headers(list(resp.headers.items)), resp.version)
                transform = self.policy.page_transform(req, resp)  # may rewrite resp.headers
                if transform is not None:
                    keep = await self._relay_transformed(up_r, writer, resp, framing, req.method, *transform)
                elif self.policy.buffer_response(req, resp):
                    body = await read_response_body(up_r, resp, req.method, self.body_limit)
                    body = self.policy.on_response(req, resp, body)
                    resp.headers.remove("transfer-encoding")
                    resp.headers.set("content-length", str(len(body)))
                    writer.write(resp.encode_head() + body)
                    await writer.drain()
                    keep = True
                else:
                    writer.write(resp.encode_head())
                    keep = await relay_body(up_r, writer, resp, req.method)
                if resp.headers.has_token("connection", "close") or not keep:
                    up_w.close()
                    upstream = None
                    if not keep or req.headers.has_token("connection", "close"):
                        return
        finally:
            if upstream:
                upstream[1].close()

    @staticmethod
    async def _relay_transformed(up_r, writer, resp: Response, framing: Response, method: str, feed, finish) -> bool:
        """Stream a rewritten body, re-chunked. `framing` holds the upstream headers as received."""
        resp.headers.remove("content-length")
        resp.headers.set("transfer-encoding", "chunked")
        writer.write(resp.encode_head())
        state: dict = {}

        def frame(data: bytes) -> bytes:
            return b"%x\r\n%s\r\n" % (len(data), data) if data else b""

        async for piece in iter_body(up_r, framing, method, state):
            writer.write(frame(feed(piece)))
            await writer.drain()
        writer.write(frame(finish()) + b"0\r\n\r\n")
        await writer.drain()
        return not state.get("close")

    @staticmethod
    async def _read_final_head(reader: asyncio.StreamReader) -> Response | None:
        while True:
            raw = await read_head(reader)
            if raw is None:
                return None
            resp = parse_response_head(raw)
            if resp.status == 101 or not 100 <= resp.status < 200:
                return resp

    async def _plain_http(self, req: Request, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Forward an http:// request (only reaches us if the user set a manual proxy)."""
        from urllib.parse import urlsplit

        url = urlsplit(req.target)
        host, port = url.hostname or "", url.port or 80
        req.body = await read_body(reader, req.headers, self.body_limit)
        req.target = (url.path or "/") + (f"?{url.query}" if url.query else "")
        req.headers.set("connection", "close")
        up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, port), 20)
        try:
            up_w.write(req.encode())
            await up_w.drain()
            await _pipe(up_r, writer)
        finally:
            up_w.close()

