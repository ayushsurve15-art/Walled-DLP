"""What the proxy does with each request to a monitored site.

    request ──► files in it? ──► inspect each (text / PDF / OCR) ──► marker? ──► dialog
            └─► text with the marker? ──► user send ──► dialog (once per content)
                                     └─► side channel ──► follow the user's decision, else withhold
    page    ──► HTML document? ──► add the response-colour <style>

Blocked requests get a 403 with a JSON body explaining why (the app shows its usual error state;
the user can edit and send again). Withheld side channels get an empty 204 so the app carries on.
"""

from __future__ import annotations

import json
import logging
import time
import zlib
from collections import OrderedDict
from urllib.parse import urlsplit

from .certs import CertificateAuthority
from .config import Config
from .content import marker_strings, split_request
from .detector import contains_marker
from .guard import Guard, Verdict
from .http1 import Request, Response, decode_content
from .pagestyle import prepare_page_response, stylesheet
from .proxy import Reply
from .sites import SITES, Site, all_hosts, site_for

log = logging.getLogger(__name__)


def pac_script(port: int, hosts: list[str] | None = None) -> str:
    """Proxy auto-config: only the monitored sites go through Walled DLP; everything else is direct."""
    checks = " ||\n      ".join(f'host === "{h}" || dnsDomainIs(host, ".{h}")' for h in (hosts or all_hosts()))
    return (
        "// Walled DLP: route ChatGPT and Perplexity through the local inspection proxy.\n"
        "function FindProxyForURL(url, host) {\n"
        "  host = host.toLowerCase();\n"
        f"  if ({checks})\n"
        f'    return "PROXY 127.0.0.1:{port}";\n'
        '  return "DIRECT";\n'
        "}\n"
    )


def pac_data_url(port: int) -> str:
    """The PAC as a data: URL. Installed this way it doesn't depend on Walled DLP running: if the app
    is stopped, the monitored sites fail to load instead of quietly going direct (fail closed)."""
    import base64

    return "data:application/x-ns-proxy-autoconfig;base64," + base64.b64encode(pac_script(port).encode()).decode()


def _blocked_body(message: str) -> bytes:
    return json.dumps({"detail": message, "error": {"message": message, "type": "walled_dlp_blocked", "code": "walled_dlp_blocked"}}).encode()


BLOCK_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Blocked by Walled DLP</title>
<style>body{{font:16px system-ui,sans-serif;max-width:40rem;margin:15vh auto;padding:0 1rem;color:#1f2937}}
h1{{font-size:1.4rem;color:#6d28d9}}</style></head><body><h1>Blocked by Walled DLP</h1><p>{message}</p>
<p><a href="javascript:history.back()">Go back</a></p></body></html>"""


def _url_fields(obj, key: str = ""):
    """(key, url) for every string in a JSON value that is an https URL, at any depth."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _url_fields(v, str(k).lower())
    elif isinstance(obj, list):
        for v in obj:
            yield from _url_fields(v, key)
    elif isinstance(obj, str) and obj.startswith("https://"):
        yield key, obj


class DlpPolicy:
    def __init__(self, cfg: Config, guard: Guard, ca: CertificateAuthority) -> None:
        self.cfg = cfg
        self.guard = guard
        self.ca = ca
        # Signed upload URL path -> file name, learned from the request that created the URL.
        self._upload_names: OrderedDict[str, str] = OrderedDict()
        # (site, size, name, when) announced by create-upload requests, for matching by size when the
        # reply can't be tied to the upload URL.
        self._announced: list[tuple[str, int, str, float]] = []

    # -- routing ------------------------------------------------------------------------------
    def intercepts(self, host: str) -> bool:
        return site_for(host) is not None

    # -- requests -----------------------------------------------------------------------------
    async def on_request(self, req: Request) -> Reply | None:
        site = site_for(req.host)
        if site is None or (not req.body and "?" not in req.target) or site.is_foreign(req.host, req.path):
            return None
        marker = self.cfg.marker
        if self._creates_upload(req):
            self._remember_announced(site, req)
        upload = site.is_upload_host(req.host)
        payload = split_request(req, marker, upload_host=upload, file_name=self._upload_name(site, req) if upload else "")
        if payload.files or payload.texts:
            log.info("%s %s: %d file(s), %d marker text(s)", req.method, req.url.split("?")[0], len(payload.files), len(payload.texts))

        for f in payload.files:
            verdict = await self.guard.check_file(site, f.name, f.mime, f.data, req.url)
            if not verdict.allow:
                why = verdict.reason or "it contains sensitive content and you chose Cancel"
                return self._block(req, f"Walled DLP blocked the upload of {f.name}: {why}.")

        if payload.texts:
            if site.is_side_channel(req.host, req.path):
                verdict = await self.guard.check_side_channel(site, payload.texts, req.url)
                if not verdict.allow:
                    return Reply(204, b"")
            else:
                verdict = await self.guard.check_text(site, payload.texts, req.url)
                if not verdict.allow:
                    why = verdict.reason or f"it contains sensitive content ({marker})"
                    return self._block(req, f"Walled DLP blocked this prompt because {why}. Edit it and send again.")
        return None

    def _block(self, req: Request, message: str) -> Reply:
        if req.headers.get("sec-fetch-dest") == "document":
            import html

            return Reply(403, BLOCK_PAGE.format(message=html.escape(message)).encode(), "text/html; charset=utf-8")
        # Cross-origin uploads (ChatGPT's page PUTs to oaiusercontent.com) need CORS headers, or the
        # browser hides the 403 from the app as a network error.
        origin = req.headers.get("origin")
        cors = [("access-control-allow-origin", origin), ("access-control-allow-credentials", "true"), ("vary", "origin")] if origin else []
        return Reply(403, _blocked_body(message), "application/json", headers=cors)

    def prepare_upstream(self, req: Request) -> None:
        site = site_for(req.host)
        if site is None:
            return
        if req.headers.get("sec-fetch-dest") == "document" and site.is_page_host(req.host.split(":")[0]):
            req.headers.set("accept-encoding", "identity")  # so the page can be rewritten as it streams
        if req.is_websocket:
            req.headers.remove("sec-websocket-extensions")  # no compression, so frames can be read
        if self._creates_upload(req):
            req.headers.set("accept-encoding", "identity")  # so the reply (with the upload URL) can be read

    # -- responses ----------------------------------------------------------------------------
    def page_transform(self, req: Request, resp: Response):
        site = site_for(req.host)
        if (
            site is None
            or req.method != "GET"
            or resp.status != 200
            or not site.is_page_host(req.host.split(":")[0])
            or req.headers.get("sec-fetch-dest") not in ("document", "iframe")
            or not resp.headers.get("content-type").lower().startswith("text/html")
        ):
            return None
        return prepare_page_response(resp.headers, stylesheet(self.cfg.response_color))

    def buffer_response(self, req: Request, resp: Response) -> bool:
        # Learn file names for direct-to-storage uploads: the request that creates the signed URL
        # carries the name, the response carries the URL.
        return (
            self._creates_upload(req)
            and resp.status < 300
            and "json" in resp.headers.get("content-type").lower()
            and resp.headers.get("content-encoding", "identity").lower() in ("identity", "gzip", "deflate")
        )

    @staticmethod
    def _creates_upload(req: Request) -> bool:
        head = req.body[:4096]
        return req.method == "POST" and (b'"file_name"' in head or b'"filename"' in head)

    def on_response(self, req: Request, resp: Response, body: bytes) -> bytes:
        """Read the reply to a create-upload request: learn the file name for the signed URL, and
        refuse destinations Walled DLP can't inspect (so a site moving its storage fails closed)."""
        try:
            request = json.loads(req.body)
            reply = json.loads(decode_content(body, resp.headers.get("content-encoding")) or b"")
        except (ValueError, zlib.error):
            return body
        site = site_for(req.host)
        name = request.get("file_name") or request.get("filename") if isinstance(request, dict) else None
        for key, url in _url_fields(reply):
            if "upload" not in key and "bucket" not in key:
                continue
            target = urlsplit(url)
            owner = site_for(target.hostname or "")
            if owner is None or owner.is_foreign(target.hostname or "", target.path):
                log.warning("%s asked the browser to upload to %s, which Walled DLP can't inspect; refused", req.host, target.hostname)
                if site is not None:
                    self.guard.emit(site, "file", f"upload to {target.hostname} (not inspectable)", "blocked")
                resp.status, resp.reason = 403, "Forbidden"
                resp.headers.remove("content-encoding")
                resp.headers.set("content-type", "application/json")
                return _blocked_body(f"Walled DLP blocked this upload: it would go to {target.hostname}, which Walled DLP can't inspect.")
            log.info("create-upload reply from %s points at %s", req.host, target.hostname)
            if name and key == "upload_url":
                self._upload_names[target.path] = str(name)
                while len(self._upload_names) > 200:
                    self._upload_names.popitem(last=False)
        return body

    def _remember_announced(self, site: Site, req: Request) -> None:
        """Note every (name, size) a create-upload request announces, at any depth (Perplexity's
        batch call nests them per file)."""
        try:
            body = json.loads(req.body)
        except ValueError:
            return
        now = time.monotonic()
        stack = [body]
        while stack:
            obj = stack.pop()
            if isinstance(obj, dict):
                name = obj.get("file_name") or obj.get("filename")
                size = obj.get("file_size", obj.get("size"))
                if isinstance(name, str) and isinstance(size, int):
                    self._announced.append((site.key, size, name, now))
                stack.extend(obj.values())
            elif isinstance(obj, list):
                stack.extend(obj)
        self._announced = [a for a in self._announced if now - a[3] < 600][-100:]

    def _upload_name(self, site: Site, req: Request) -> str:
        name = self._upload_names.get(req.path)
        if name:
            return name
        # Fall back to the most recent announced file of exactly this size.
        for i in range(len(self._announced) - 1, -1, -1):
            key, size, name, _ = self._announced[i]
            if key == site.key and size == len(req.body):
                del self._announced[i]
                return name
        return ""

    # -- websockets ---------------------------------------------------------------------------
    def websocket_filter(self, req: Request):
        site = site_for(req.host)
        if site is None:
            return None
        marker = self.cfg.marker
        reported = []

        def drop(opcode: int, payload: bytes) -> bool:
            if opcode != 1:
                return False
            text = payload.decode("utf-8", "replace")
            if not contains_marker(text, marker):
                return False
            texts = [" ".join(s.split()) for s in marker_strings(text, marker)] or [text]
            if self.guard.websocket_allows(site, texts):
                return False
            log.info("dropped a WebSocket message to %s carrying the marker", req.host)
            if not reported:  # one activity entry per socket, not one per keystroke
                reported.append(True)
                self.guard.emit(site, "background", f"typing sent to {req.host.split(':')[0]}", "withheld")
            return True

        return drop

    # -- local endpoints ----------------------------------------------------------------------
    def local(self, req: Request, proxy_port: int) -> Reply | None:
        if req.path == "/proxy.pac":
            return Reply(200, pac_script(proxy_port).encode(), "application/x-ns-proxy-autoconfig")
        if req.path in ("/ca.pem", "/walled-dlp-ca.pem"):
            return Reply(200, self.ca.pem, "application/x-pem-file", headers=[("content-disposition", 'attachment; filename="walled-dlp-ca.pem"')])
        if req.path == "/":
            sites = ", ".join(s.name for s in SITES)
            return Reply(200, f"Walled DLP is running and protecting {sites}.\n".encode())
        return None


__all__ = ["DlpPolicy", "pac_script", "Verdict", "Site"]
