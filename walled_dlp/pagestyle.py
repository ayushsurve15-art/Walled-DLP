"""Recolour AI responses by adding a <style> element to the sites' HTML pages as they pass through.

Both sites are single-page apps: the HTML document is loaded once and every answer is rendered
into it, so a stylesheet in the document's <head> applies to answers as they stream in. The style
is inserted while the page streams (nothing is buffered beyond the first few kilobytes), and if the
page has a Content-Security-Policy that restricts inline styles, a per-response nonce is added for
this one element.
"""

from __future__ import annotations

import re
import secrets
import zlib
from typing import Callable

from .http1 import Headers
from .sites import SITES

DEFAULT_LIGHT = "#6d28d9"
DEFAULT_DARK = "#c4b5fd"
HEAD_RE = re.compile(rb"<head\b[^>]*>", re.I)
SCAN_LIMIT = 256 * 1024
COLOR_RE = re.compile(r"^#[0-9a-fA-F]{3,8}$|^[a-zA-Z]{3,20}$|^rgba?\([\d\s.,%]+\)$")


def stylesheet(color: str = "") -> str:
    """CSS for every site's response selectors. An empty colour means violet, lighter on dark themes."""
    if color and not COLOR_RE.match(color):
        color = ""
    light = color or DEFAULT_LIGHT
    dark = color or DEFAULT_DARK
    selectors = ",\n".join(sel for site in SITES for sel in site.response_selectors)
    return (
        f":root{{--walled-rc:{light}}}\n"
        f":root.dark,:root[data-theme=\"dark\"],:root[data-color-scheme=\"dark\"]{{--walled-rc:{dark}}}\n"
        f"@media (prefers-color-scheme: dark){{:root:not(.light):not([data-theme=\"light\"]){{--walled-rc:{dark}}}}}\n"
        f"{selectors}{{color:var(--walled-rc)!important;-webkit-text-fill-color:var(--walled-rc)!important}}\n"
    )


def _allows_inline_style(directive_sources: list[str]) -> bool:
    lowered = [s.lower() for s in directive_sources]
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in lowered)
    return "'unsafe-inline'" in lowered and not has_nonce_or_hash


def adjust_csp(policy: str, nonce: str) -> str:
    """Let one <style nonce=…> element through a CSP, without loosening anything else.

    Adding a nonce to a directive that relies on 'unsafe-inline' would switch 'unsafe-inline' off,
    so directives that already allow inline styles are left alone.
    """
    directives = [d.strip() for d in policy.split(";") if d.strip()]
    parsed = [(d.split()[0].lower(), d.split()[1:]) for d in directives]
    names = [n for n, _ in parsed]
    out = []
    for name, sources in parsed:
        if name in ("style-src", "style-src-elem") and not _allows_inline_style(sources):
            sources = [s for s in sources if s.lower() != "'none'"] + [f"'nonce-{nonce}'"]
        out.append(" ".join([name, *sources]))
    if "style-src" not in names and "style-src-elem" not in names and "default-src" in names:
        default = dict(parsed)["default-src"]
        if not _allows_inline_style(default):
            out.append(" ".join(["style-src", *[s for s in default if s.lower() != "'none'"], f"'nonce-{nonce}'"]))
    return "; ".join(out)


class HtmlInjector:
    """Streaming transform: inserts the <style> right after <head …>, then passes bytes through."""

    def __init__(self, css: str, nonce: str = "") -> None:
        attr = f' nonce="{nonce}"' if nonce else ""
        self.tag = f'<style id="walled-dlp-response-color"{attr}>\n{css}</style>'.encode()
        self._buf = b""
        self._done = False

    def feed(self, data: bytes) -> bytes:
        if self._done:
            return data
        self._buf += data
        m = HEAD_RE.search(self._buf)
        if m:
            out = self._buf[: m.end()] + self.tag + self._buf[m.end() :]
        elif len(self._buf) > SCAN_LIMIT:
            out = self._buf  # no <head> in sight: leave the page alone
        else:
            return b""
        self._done = True
        self._buf = b""
        return out

    def finish(self) -> bytes:
        out, self._buf, self._done = self._buf, b"", True
        return out


class Decoder:
    """Incremental gzip/deflate decoder. Encodings we can't decode make the caller skip the page."""

    def __init__(self, encoding: str) -> None:
        enc = encoding.strip().lower()
        self.supported = enc in ("", "identity", "gzip", "x-gzip", "deflate")
        self._z = None
        if enc in ("gzip", "x-gzip"):
            self._z = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif enc == "deflate":
            self._z = zlib.decompressobj()

    def feed(self, data: bytes) -> bytes:
        return self._z.decompress(data) if self._z else data

    def flush(self) -> bytes:
        return self._z.flush() if self._z else b""


def prepare_page_response(headers: Headers, css: str) -> tuple[Callable[[bytes], bytes], Callable[[], bytes]] | None:
    """Set up the transform for an HTML page, adjusting its headers. None if it can't be rewritten."""
    decoder = Decoder(headers.get("content-encoding"))
    if not decoder.supported:
        return None
    nonce = ""
    for name in ("content-security-policy", "content-security-policy-report-only"):
        values = headers.get_all(name)
        if values:
            nonce = nonce or secrets.token_urlsafe(16)
            headers.remove(name)
            for v in values:
                headers.items.append((name, adjust_csp(v, nonce)))
    injector = HtmlInjector(css, nonce)
    headers.remove("content-encoding")
    headers.remove("content-length")
    headers.remove("etag")  # the body differs from what the server hashed

    def feed(chunk: bytes) -> bytes:
        return injector.feed(decoder.feed(chunk))

    def finish() -> bytes:
        return injector.feed(decoder.flush()) + injector.finish()

    return feed, finish
