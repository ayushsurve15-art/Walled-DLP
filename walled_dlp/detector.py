"""Marker matching.

Typed text and text pulled out of files is matched case-insensitively. OCR output needs more slack:
engines drop underscores, split words and confuse look-alike glyphs (0/O, 1/I/l, 5/S). The fuzzy
match maps both sides onto the same canonical alphabet and drops everything that isn't a letter or
digit before comparing.
"""

from __future__ import annotations

import re

_CONFUSABLES = str.maketrans({
    "0": "O", "Q": "O",
    "1": "I", "L": "I", "|": "I", "!": "I", "J": "I",
    "5": "S", "$": "S",
    "8": "B",
    "2": "Z",
})
_NON_ALNUM = re.compile(r"[^A-Z0-9]")


def _canonical(text: str) -> str:
    return _NON_ALNUM.sub("", text.upper().translate(_CONFUSABLES))


def contains_marker(text: str, marker: str) -> bool:
    return marker.casefold() in text.casefold()


def contains_marker_fuzzy(text: str, marker: str) -> bool:
    """Match OCR output. Also catches 'WALLED SENSITIVE' and 'WALLED_SENS1TIVE'."""
    needle = _canonical(marker)
    return bool(needle) and needle in _canonical(text)


def preview(text: str, limit: int = 280) -> str:
    """Single-line excerpt for the dialog, centred on the marker so the user sees why it fired."""
    flat = " ".join(text.split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 1] + "…"


def excerpt_around(text: str, marker: str, limit: int = 280) -> str:
    flat = " ".join(text.split())
    idx = flat.casefold().find(marker.casefold())
    if idx < 0 or len(flat) <= limit:
        return preview(flat, limit)
    start = max(0, idx - (limit - len(marker)) // 2)
    end = min(len(flat), start + limit)
    start = max(0, end - limit)
    snippet = flat[start:end]
    return ("…" if start else "") + snippet + ("…" if end < len(flat) else "")
