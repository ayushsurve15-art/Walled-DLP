"""The proxy end to end over real sockets and real TLS.

A fake upstream (plain HTTP) stands in for chatgpt.com, Perplexity and the upload host and records
every request that actually reaches it. Clients connect through the proxy exactly like a browser:
CONNECT, then TLS verified against the Walled DLP CA, then HTTP/1.1 or a WebSocket.
"""

import asyncio
import base64
import gzip
import http.client
import json
import os
import socket
import ssl
import threading
import time

import pytest

from support import SAMPLES
from walled_dlp.certs import CertificateAuthority
from walled_dlp.guard import Guard
from walled_dlp.http1 import Headers, Response, parse_request, read_body, read_head
from walled_dlp.policy import DlpPolicy
from walled_dlp.proxy import Proxy

M = "WALLED_SENSITIVE"


def shutdown(loop):
    """Cancel everything still running on a background loop, then stop it."""

    async def cancel_all():
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run_coroutine_threadsafe(cancel_all(), loop).result(5)
    loop.call_soon_threadsafe(loop.stop)


class Upstream:
    """Plain-HTTP stand-in for the real sites. Records (method, host, path, body) of each request."""

    def __init__(self):
        self.seen = []
        self.ws_messages = []
        self.loop = asyncio.new_event_loop()
        self.server = self.loop.run_until_complete(asyncio.start_server(self.handle, "127.0.0.1", 0))
        self.port = self.server.sockets[0].getsockname()[1]
        threading.Thread(target=self.loop.run_forever, daemon=True).start()

    async def handle(self, reader, writer):
        try:
            while True:
                raw = await read_head(reader)
                if raw is None:
                    return
                req = parse_request(raw)
                req.body = await read_body(reader, req.headers, 1 << 26)
                host = req.headers.get("host")
                self.seen.append((req.method, host, req.path, req.body, dict((k.lower(), v) for k, v in req.headers.items)))
                if req.headers.get("upgrade").lower() == "websocket":
                    await self.websocket(req, reader, writer)
                    return
                await self.respond(req, host, writer)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    async def respond(self, req, host, writer):
        h = Headers([("content-type", "application/json")])
        body = b"{}"
        status = 200
        if req.path == "/" and req.method == "GET":
            h = Headers([("content-type", "text/html; charset=utf-8"), ("content-security-policy", "style-src 'self'")])
            body = b"<!doctype html><html><head><title>t</title></head><body>app</body></html>"
            if "gzip" in req.headers.get("accept-encoding"):
                body = gzip.compress(body)
                h.set("content-encoding", "gzip")
        elif req.path.endswith("/conversation"):
            # Streamed answer, chunked, like ChatGPT's event stream.
            h = Headers([("content-type", "text/event-stream"), ("transfer-encoding", "chunked")])
            writer.write(Response(200, "OK", h).encode_head())
            for part in (b"data: one\n\n", b"data: two\n\n"):
                writer.write(b"%x\r\n%s\r\n" % (len(part), part))
                await writer.drain()
                await asyncio.sleep(0.05)
            writer.write(b"0\r\n\r\n")
            await writer.drain()
            return
        elif req.path == "/backend-api/files":
            body = json.dumps({"file_id": "file-abc", "upload_url": "https://files07.oaiusercontent.com/file-abc?sig=1"}).encode()
            if "gzip" in req.headers.get("accept-encoding"):
                body = gzip.compress(body)
                h.set("content-encoding", "gzip")
        elif req.path == "/rest/uploads/create_upload_url":
            dest = json.loads(req.body).get("dest") or "https://api.cloudinary.com/v1_1/pplx/image/upload"
            body = json.dumps({"s3_bucket_url": dest, "fields": {"api_key": "k", "signature": "s"}, "file_uuid": "u1"}).encode()
        elif req.method == "PUT":
            status = 201
        h.set("content-length", str(len(body)))
        writer.write(Response(status, "OK", h).encode_head() + body)
        await writer.drain()

    async def websocket(self, req, reader, writer):
        import hashlib

        key = req.headers.get("sec-websocket-key")
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        writer.write(Response(101, "Switching Protocols", Headers([("upgrade", "websocket"), ("connection", "Upgrade"), ("sec-websocket-accept", accept)])).encode_head())
        await writer.drain()
        while True:
            head = await reader.readexactly(2)
            n = head[1] & 0x7F
            mask = await reader.readexactly(4)
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(await reader.readexactly(n)))
            self.ws_messages.append(data.decode())

    def close(self):
        shutdown(self.loop)


class Dialog:
    def __init__(self):
        self.answer = False
        self.alerts = []

    def __call__(self, alert):
        self.alerts.append(alert)
        return self.answer


@pytest.fixture
def env(tmp_path, cfg):
    upstream = Upstream()
    ca = CertificateAuthority(tmp_path / "ca")
    dialog = Dialog()
    events = []
    guard = Guard(cfg, ask_fn=dialog, on_event=events.append)
    hosts = ["chatgpt.com", "files07.oaiusercontent.com", "www.perplexity.ai", "suggest.perplexity.ai", "api.cloudinary.com"]
    proxy = Proxy(DlpPolicy(cfg, guard, ca), ca, port=0, upstream_override={h: ("127.0.0.1", upstream.port) for h in hosts})
    loop = asyncio.new_event_loop()
    loop.run_until_complete(proxy.start())
    threading.Thread(target=loop.run_forever, daemon=True).start()
    ctx = ssl.create_default_context(cafile=str(ca.cert_path))

    class Env:
        pass

    e = Env()
    e.upstream, e.dialog, e.proxy, e.ca, e.ctx, e.events = upstream, dialog, proxy, ca, ctx, events

    def request(host, method, path, body=b"", headers=None):
        conn = http.client.HTTPSConnection("127.0.0.1", proxy.port, context=ctx, timeout=10)
        conn.set_tunnel(host, 443)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    e.request = request
    yield e
    shutdown(loop)
    upstream.close()


def reached(env, path):
    return [s for s in env.upstream.seen if s[2] == path]


def test_clean_prompt_passes_untouched_and_streams(env):
    body = json.dumps({"messages": [{"content": {"parts": ["What is the capital of France?"]}}]}).encode()
    resp, data = env.request("chatgpt.com", "POST", "/backend-api/f/conversation", body, {"content-type": "application/json"})
    assert resp.status == 200 and data == b"data: one\n\ndata: two\n\n"
    assert reached(env, "/backend-api/f/conversation")[0][3] == body
    assert env.dialog.alerts == []


@pytest.mark.parametrize("answer", [False, True])
def test_sensitive_prompt_waits_for_the_dialog(env, answer):
    env.dialog.answer = answer
    body = json.dumps({"messages": [{"content": {"parts": [f"Summarise the {M} deck"]}}]}).encode()
    resp, data = env.request("chatgpt.com", "POST", "/backend-api/f/conversation", body, {"content-type": "application/json"})
    assert len(env.dialog.alerts) == 1 and env.dialog.alerts[0].site == "ChatGPT"
    if answer:
        assert resp.status == 200 and reached(env, "/backend-api/f/conversation")[0][3] == body  # unchanged
    else:
        assert resp.status == 403 and reached(env, "/backend-api/f/conversation") == []
        assert "Walled DLP blocked this prompt" in json.loads(data)["detail"]


def test_analytics_copy_is_withheld_silently(env):
    event = json.dumps({"event_name": "submit query", "event_data": {"queryStr": f"what is {M}"}}).encode()
    resp, _ = env.request("www.perplexity.ai", "POST", "/rest/event/analytics", event, {"content-type": "application/json"})
    assert resp.status == 204 and reached(env, "/rest/event/analytics") == [] and env.dialog.alerts == []


def test_upload_named_from_the_create_request_and_blocked(env):
    create = json.dumps({"file_name": "sensitive-screenshot.png", "file_size": 1, "use_case": "multimodal"}).encode()
    resp, data = env.request("chatgpt.com", "POST", "/backend-api/files", create, {"content-type": "application/json", "accept-encoding": "gzip, br"})
    assert resp.status == 200 and json.loads(data)["file_id"] == "file-abc"
    assert reached(env, "/backend-api/files")[0][4]["accept-encoding"] == "identity"

    png = (SAMPLES / "sensitive-report.pdf").read_bytes()
    resp, data = env.request("files07.oaiusercontent.com", "PUT", "/file-abc?sig=1", png, {"content-type": "application/pdf"})
    assert resp.status == 403 and reached(env, "/file-abc") == []
    (alert,) = env.dialog.alerts
    assert alert.source == "file" and alert.subject.startswith("sensitive-screenshot.png (PDF")


def test_upload_named_by_size_when_the_reply_does_not_match(env):
    """Signed-in ChatGPT PUTs to sdmntpr…/files/<id>/raw; the name still comes from the create call."""
    data = (SAMPLES / "sensitive-notes.txt").read_bytes()
    create = json.dumps({"file_name": "notes-q3.txt", "file_size": len(data), "use_case": "my_files"}).encode()
    env.request("chatgpt.com", "POST", "/backend-api/files/create", create, {"content-type": "application/json"})
    resp, _ = env.request("files07.oaiusercontent.com", "PUT", "/files/00000000-abcd/raw?se=1", data, {"content-type": "text/plain"})
    assert resp.status == 403
    assert env.dialog.alerts[0].subject.startswith("notes-q3.txt (TEXT")


def test_continue_upload_reaches_storage_unchanged(env):
    env.dialog.answer = True
    data = (SAMPLES / "sensitive-notes.txt").read_bytes()
    resp, _ = env.request("files07.oaiusercontent.com", "PUT", "/file-xyz?sig=1", data, {"content-type": "text/plain"})
    assert resp.status == 201 and reached(env, "/file-xyz")[0][3] == data


def test_clean_upload_no_dialog(env):
    data = (SAMPLES / "clean-report.pdf").read_bytes()
    resp, _ = env.request("files07.oaiusercontent.com", "PUT", "/file-c?sig=1", data, {"content-type": "application/pdf"})
    assert resp.status == 201 and env.dialog.alerts == []


def _multipart(name, data, mime):
    boundary = "----walledtest"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"api_key\"\r\n\r\nk\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: {mime}\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
    return body, {"content-type": f"multipart/form-data; boundary={boundary}", "origin": "https://www.perplexity.ai"}


def test_perplexity_upload_to_its_cloudinary_account_is_inspected(env):
    resp, data = env.request("www.perplexity.ai", "POST", "/rest/uploads/create_upload_url",
                             json.dumps({"filename": "sensitive-screenshot.png", "file_size": 1}).encode(), {"content-type": "application/json"})
    assert resp.status == 200 and json.loads(data)["s3_bucket_url"].startswith("https://api.cloudinary.com/v1_1/pplx/")
    body, headers = _multipart("sensitive-screenshot.png", (SAMPLES / "sensitive-screenshot.png").read_bytes(), "image/png")
    resp, data = env.request("api.cloudinary.com", "POST", "/v1_1/pplx/image/upload", body, headers)
    assert resp.status == 403 and resp.getheader("access-control-allow-origin") == "https://www.perplexity.ai"
    assert reached(env, "/v1_1/pplx/image/upload") == []
    (alert,) = env.dialog.alerts
    assert alert.site == "Perplexity" and alert.subject.startswith("sensitive-screenshot.png (IMAGE")


def test_other_websites_cloudinary_traffic_is_left_alone(env):
    body, headers = _multipart("notes.txt", f"{M}".encode(), "text/plain")
    resp, _ = env.request("api.cloudinary.com", "POST", "/v1_1/someone-else/raw/upload", body, headers)
    assert resp.status == 200 and len(reached(env, "/v1_1/someone-else/raw/upload")) == 1 and env.dialog.alerts == []


def test_upload_to_an_uninspectable_host_fails_closed(env):
    create = json.dumps({"filename": "a.pdf", "dest": "https://new-bucket.s3.amazonaws.com/"}).encode()
    resp, data = env.request("www.perplexity.ai", "POST", "/rest/uploads/create_upload_url", create, {"content-type": "application/json"})
    assert resp.status == 403 and "new-bucket.s3.amazonaws.com" in json.loads(data)["detail"]


def test_page_gets_the_colour_style(env):
    resp, data = env.request("chatgpt.com", "GET", "/", headers={"sec-fetch-dest": "document", "accept-encoding": "gzip, br"})
    assert resp.status == 200
    assert b'<head><style id="walled-dlp-response-color" nonce="' in data and data.endswith(b"<body>app</body></html>")
    assert "'nonce-" in resp.getheader("content-security-policy")
    assert reached(env, "/")[0][4]["accept-encoding"] == "identity"


def test_api_json_is_not_rewritten(env):
    resp, data = env.request("chatgpt.com", "GET", "/backend-api/me", headers={"sec-fetch-dest": "empty"})
    assert data == b"{}"


def _ws_connect(env, host, path):
    sock = socket.create_connection(("127.0.0.1", env.proxy.port), timeout=5)
    sock.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    assert sock.recv(1024).startswith(b"HTTP/1.1 200")
    tls = env.ctx.wrap_socket(sock, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    tls.sendall(
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n".encode()
    )
    assert tls.recv(4096).startswith(b"HTTP/1.1 101")
    return tls


def _ws_send(sock, text):
    data = text.encode()
    mask = os.urandom(4)
    sock.sendall(bytes([0x81, 0x80 | len(data)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def test_typeahead_frames_with_the_marker_are_dropped(env):
    ws = _ws_connect(env, "suggest.perplexity.ai", "/suggest/ws")
    for q in ("what is", f"what is {M[:8]}", f"what is {M}", f"what is {M} data", "hello"):
        _ws_send(ws, json.dumps({"q": q}))
    deadline = time.time() + 3
    while len(env.upstream.ws_messages) < 3 and time.time() < deadline:
        time.sleep(0.05)
    time.sleep(0.2)
    assert [json.loads(m)["q"] for m in env.upstream.ws_messages] == ["what is", f"what is {M[:8]}", "hello"]
    # compression was not negotiated, so frames stay readable
    ws_req = [s for s in env.upstream.seen if s[2] == "/suggest/ws"][0]
    assert "sec-websocket-extensions" not in ws_req[4]
    assert [e["outcome"] for e in env.events] == ["withheld"]  # one activity entry, not one per keystroke
    ws.close()


def test_other_hosts_are_tunnelled_not_decrypted(env):
    sock = socket.create_connection(("127.0.0.1", env.proxy.port), timeout=5)
    sock.sendall(f"CONNECT 127.0.0.1:{env.upstream.port} HTTP/1.1\r\n\r\n".encode())
    assert sock.recv(1024).startswith(b"HTTP/1.1 200")
    sock.sendall(b"GET /plain HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n")
    assert sock.recv(4096).startswith(b"HTTP/1.1 200")
    assert reached(env, "/plain")[0][1] == "example.test"
    sock.close()


def test_pac_and_ca_download(env):
    conn = http.client.HTTPConnection("127.0.0.1", env.proxy.port, timeout=5)
    conn.request("GET", "/proxy.pac")
    pac = conn.getresponse().read().decode()
    assert f'return "PROXY 127.0.0.1:{env.proxy.port}"' in pac and 'dnsDomainIs(host, ".perplexity.ai")' in pac
    conn.request("GET", "/ca.pem")
    assert conn.getresponse().read() == env.ca.pem
