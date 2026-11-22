"""Turn an outgoing HTTP request into the text and files it carries.

Sites encode prompts in different ways: ChatGPT's signed-in app posts JSON, its logged-out app
posts a URL-encoded form whose fields hold more JSON, Perplexity posts JSON and streams keystrokes
as JSON over a WebSocket, and analytics beacons nest the prompt somewhere inside an event. Rather
than knowing each format, this module unwraps whatever it finds (query string, form fields,
multipart parts, JSON at any depth, JSON inside strings) and returns every string that contains the
marker. Files are multipart parts with a filename, bodies with a non-text content type, or any body
sent to a site's upload host.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import HTTP
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from .detector import contains_marker
from .http1 import Request
from .inspector import _looks_like_text, decode_text

TEXT_TYPES = (
    "application/json", "application/x-www-form-urlencoded", "application/x-ndjson",
    "application/csp-report", "application/javascript", "application/xml", "application/graphql",
)
MAX_STRING = 8000  # longer strings are cut down to the part around the marker


@dataclass
class FilePart:
    name: str
    mime: str
    data: bytes


@dataclass
class Payload:
    texts: list[str] = field(default_factory=list)  # strings that contain the marker
    files: list[FilePart] = field(default_factory=list)


def is_text_type(content_type: str) -> bool:
    ct = content_type.lower()
    return ct.startswith("text/") or ct in TEXT_TYPES or ct.endswith("+json") or ct.endswith("+xml")


def _walk(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(k)
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def marker_strings(text: str, marker: str, form: bool = False, depth: int = 0) -> list[str]:
    """Every innermost string in `text` that contains the marker, unwrapping JSON and forms."""
    if not text or depth > 6:
        return []
    stripped = text.strip()
    if stripped[:1] in ("{", "[") or stripped[:1] == '"':
        try:
            obj = json.loads(stripped)
        except ValueError:
            obj = None
        if obj is not None and not isinstance(obj, (int, float, bool)):
            if isinstance(obj, str):
                return marker_strings(obj, marker, depth=depth + 1)
            found: list[str] = []
            for s in _walk(obj):
                found.extend(marker_strings(s, marker, depth=depth + 1))
            if found or not contains_marker(stripped, marker):
                return found
    if stripped.count("\n") and stripped.lstrip().startswith("{"):  # NDJSON
        found = [s for line in stripped.splitlines() for s in marker_strings(line, marker, depth=depth + 1)]
        if found:
            return found
    if form or ("=" in stripped and "&" in stripped and " " not in stripped):
        pairs = parse_qsl(stripped, keep_blank_values=True)
        if pairs:
            found = [s for k, v in pairs for s in marker_strings(v, marker, depth=depth + 1) + marker_strings(k, marker, depth=depth + 1)]
            if found or not contains_marker(stripped, marker):
                return found
    if contains_marker(stripped, marker):
        return [stripped]
    if "%" in stripped or "+" in stripped:
        decoded = unquote_plus(stripped)
        if decoded != stripped and contains_marker(decoded, marker):
            return marker_strings(decoded, marker, depth=depth + 1)
    return []


def _multipart(req: Request) -> tuple[list[FilePart], list[str]]:
    head = f"Content-Type: {req.headers.get('content-type')}\r\n\r\n".encode("latin-1")
    msg = BytesParser(policy=HTTP).parsebytes(head + req.body)
    files: list[FilePart] = []
    fields: list[str] = []
    if not msg.is_multipart():
        return files, fields
    for part in msg.iter_parts():
        data = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename is not None:
            files.append(FilePart(filename or "unnamed file", part.get_content_type(), data))
        else:
            fields.append(decode_text(data))
    return files, fields


def split_request(req: Request, marker: str, upload_host: bool = False, file_name: str = "") -> Payload:
    out = Payload()
    sources: list[tuple[str, bool]] = []
    query = req.target.partition("?")[2]
    if query:
        sources.append((query, True))

    if req.body:
        ct = req.content_type
        if ct == "multipart/form-data":
            files, fields = _multipart(req)
            out.files.extend(files)
            sources.extend((f, False) for f in fields)
        elif upload_host or (ct and not is_text_type(ct)) or (not ct and not _looks_like_text(req.body)):
            name = file_name or urlsplit(req.target).path.rsplit("/", 1)[-1] or "upload"
            out.files.append(FilePart(name, ct, req.body))
        else:
            sources.append((decode_text(req.body), ct == "application/x-www-form-urlencoded"))

    seen: set[str] = set()
    for text, form in sources:
        if not contains_marker(text, marker) and not ("%" in text and contains_marker(unquote_plus(text), marker)):
            continue
        for s in marker_strings(text, marker, form=form):
            s = " ".join(s.split())
            if len(s) > MAX_STRING:
                i = s.casefold().find(marker.casefold())
                s = s[max(0, i - MAX_STRING // 2) : max(0, i - MAX_STRING // 2) + MAX_STRING]
            if s not in seen:
                seen.add(s)
                out.texts.append(s)
    return out
