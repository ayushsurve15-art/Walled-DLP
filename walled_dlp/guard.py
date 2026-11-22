"""Decisions: when to ask the user, and how one answer covers related requests.

Sending one prompt makes a site emit several requests that carry the same text: the prompt
itself, an analytics event, typeahead lookups, and later the conversation history on the next
turn. The user should see one dialog, and every copy should follow their answer. So decisions are
remembered by content. A remembered decision covers a text only if that text is *part of* the
decided text: typeahead prefixes and verbatim copies are covered; an edited, longer prompt is new
content and asks again.

* User sends (any request not listed as a side channel) raise a dialog unless an earlier Continue
  covers them. One dialog is on screen at a time. Requests that queued behind a dialog follow its
  answer, Cancel included: they are copies of the same send. A Cancel never silences a later
  send, so the user can always try again.
* Side channels (analytics, typeahead, telemetry) never raise a dialog. They wait briefly for the
  user's decision on matching text (the prompt is usually a few milliseconds behind) and follow
  it; with no decision they are withheld silently.
* Files are remembered by SHA-256: Continue for ten minutes, Cancel for a few seconds, which
  absorbs the automatic retries apps make after a failed upload.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .config import Config
from .detector import excerpt_around
from .dialogs import Alert, ask
from .inspector import Inspector, Report
from .sites import Site

log = logging.getLogger(__name__)

APPROVED_TTL = 12 * 3600
CANCELLED_TTL = 30.0  # a Cancel still answers requests that were queued behind its dialog
FILE_APPROVED_TTL = 600.0
FILE_CANCELLED_TTL = 5.0
SIDE_CHANNEL_WAIT = 3.0

AskFn = Callable[[Alert], "bool | None"]
EventFn = Callable[[dict], None]


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


@dataclass
class Verdict:
    allow: bool
    asked: bool = False  # a dialog was shown for this request
    reason: str = ""


@dataclass
class _Decision:
    site: str
    texts: list[str]
    allow: bool
    at: float
    expires: float


def _norm(s: str) -> str:
    return " ".join(s.split()).casefold()


class Memory:
    """Recent decisions on text, per site. Newest first wins."""

    def __init__(self, limit: int = 500) -> None:
        self._items: list[_Decision] = []
        self._limit = limit
        self._lock = threading.Lock()

    def remember(self, site: str, texts: list[str], allow: bool, ttl: float) -> None:
        now = time.monotonic()
        with self._lock:
            self._items.insert(0, _Decision(site, [_norm(t) for t in texts], allow, now, now + ttl))
            del self._items[self._limit :]

    def undecided(self, site: str, texts: list[str], cancels_since: float | None = None) -> tuple[list[str], bool | None]:
        """Texts no remembered decision covers, and the verdict for the covered ones (False if any
        covered text was cancelled). Cancels count only if made at or after `cancels_since`; None
        means every remembered Cancel counts."""
        now = time.monotonic()
        with self._lock:
            self._items = [d for d in self._items if d.expires > now]
            items = [d for d in self._items if d.site == site and (d.allow or cancels_since is None or d.at >= cancels_since)]
        left: list[str] = []
        verdict: bool | None = None
        for text in texts:
            n = _norm(text)
            hit = next((d.allow for d in items if any(n in t for t in d.texts)), None)
            if hit is None:
                left.append(text)
            else:
                verdict = hit if verdict is None else (verdict and hit)
        return left, verdict


class Audit:
    """Append-only record of every intervention. File names and decisions, never prompt text."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def write(self, **record) -> dict:
        record = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), **record}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock, self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError:
            log.exception("could not write audit log")
        return record


class Guard:
    def __init__(
        self,
        cfg: Config,
        inspector: Inspector | None = None,
        ask_fn: AskFn | None = None,
        on_event: EventFn | None = None,
    ) -> None:
        self.cfg = cfg
        self.inspector = inspector or Inspector(cfg)
        self._ask = ask_fn or (lambda alert: ask(alert, cfg.dialog_backend, cfg.dialog_timeout))
        self._on_event = on_event or (lambda e: None)
        self.memory = Memory()
        self._files: OrderedDict[str, tuple[bool, float, float]] = OrderedDict()  # digest -> (allow, at, expires)
        self._dialog = asyncio.Lock()
        self.audit = Audit(Path(cfg.log_path).with_name("events.jsonl"))

    # -- text --------------------------------------------------------------------------------
    async def check_text(self, site: Site, texts: list[str], url: str) -> Verdict:
        arrived = time.monotonic()
        left, verdict = self.memory.undecided(site.key, texts, cancels_since=arrived)
        if not left:
            return Verdict(bool(verdict))
        async with self._dialog:
            # Decided while we queued? Then we are a copy of that send and follow it.
            left, verdict = self.memory.undecided(site.key, texts, cancels_since=arrived)
            if verdict is False:
                return Verdict(False)
            if not left:
                return Verdict(bool(verdict))
            subject = excerpt_around(max(left, key=len), self.cfg.marker)
            answer = await asyncio.to_thread(self._ask, Alert("prompt", site.name, subject, "prompt text"))
            allow = bool(answer)
            self.memory.remember(site.key, texts, allow, APPROVED_TTL if allow else CANCELLED_TTL)
        reason = "no desktop dialog could be shown; blocked to be safe" if answer is None else ""
        self._record(site, "prompt", None, ["prompt text"], answer, reason, url)
        return Verdict(allow, asked=True, reason=reason)

    async def check_side_channel(self, site: Site, texts: list[str], url: str, wait: float = SIDE_CHANNEL_WAIT) -> Verdict:
        """Pass only once a Continue covers the text. A Cancel doesn't end the wait: the copy may
        belong to a new send whose dialog hasn't opened yet."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait
        while True:
            left, verdict = self.memory.undecided(site.key, texts)
            if not left and verdict:
                return Verdict(True)
            if self._dialog.locked():  # a decision is being made right now; it may cover us
                deadline = max(deadline, loop.time() + 1.0)
            elif loop.time() >= deadline:
                log.info("withheld side-channel request to %s", url.split("?")[0])
                self.emit(site, "background", url.split("?")[0].removeprefix("https://"), "withheld")
                return Verdict(False)
            await asyncio.sleep(0.1)

    def websocket_allows(self, site: Site, texts: list[str]) -> bool:
        """Typeahead frames can't wait: they pass only if the text was already approved."""
        left, verdict = self.memory.undecided(site.key, texts)
        return not left and bool(verdict)

    # -- files -------------------------------------------------------------------------------
    def _file_memory(self, digest: str, since: float) -> bool | None:
        hit = self._files.get(digest)
        if hit is None or hit[2] <= time.monotonic():
            return None
        allow, at, _ = hit
        return allow if (allow or at >= since or at + FILE_CANCELLED_TTL > time.monotonic()) else None

    async def check_file(self, site: Site, name: str, mime: str, data: bytes, url: str) -> Verdict:
        arrived = time.monotonic()
        digest = hashlib.sha256(data).hexdigest()
        known = self._file_memory(digest, arrived)
        if known is not None:
            return Verdict(known)
        if len(data) > self.cfg.max_file_bytes:
            report = Report("other", error=f"file is {human_size(len(data))}, over the {self.cfg.max_file_mb} MB inspection limit")
        else:
            report = await asyncio.to_thread(self.inspector.inspect_file, name, data, mime)
        kind = report.kind.upper() if report.kind != "other" else "file"
        subject = f"{name} ({kind}, {human_size(len(data))})"

        if not report.detected and not report.error:
            return Verdict(True)
        if not report.detected and self.cfg.on_inspection_error != "ask":
            allow = self.cfg.on_inspection_error == "allow"
            self._remember_file(digest, allow)
            self._record(site, "file", subject, [], None, report.error or "", url, verdict=allow)
            return Verdict(allow, reason=report.error or "")

        async with self._dialog:
            known = self._file_memory(digest, arrived)
            if known is not None:
                return Verdict(known)
            uninspectable = not report.detected
            detail = report.error if uninspectable else ", ".join(report.findings)
            answer = await asyncio.to_thread(self._ask, Alert("file", site.name, subject, detail or "", uninspectable))
            allow = bool(answer)
            self._remember_file(digest, allow)
        reason = "no desktop dialog could be shown; blocked to be safe" if answer is None else (report.error or "")
        self._record(site, "file", subject, report.findings, answer, reason, url)
        return Verdict(allow, asked=True, reason=reason)

    def _remember_file(self, digest: str, allow: bool) -> None:
        now = time.monotonic()
        self._files[digest] = (allow, now, now + (FILE_APPROVED_TTL if allow else FILE_CANCELLED_TTL))
        self._files.move_to_end(digest)
        while len(self._files) > 200:
            self._files.popitem(last=False)

    # -- reporting ---------------------------------------------------------------------------
    def _record(self, site: Site, source: str, subject: str | None, findings: list[str], answer: bool | None, error: str, url: str, verdict: bool | None = None) -> None:
        decision = None if answer is None else ("continue" if answer else "cancel")
        allowed = verdict if verdict is not None else bool(answer)
        self.audit.write(
            source=source, site=site.name, subject=subject, findings=findings, decision=decision,
            verdict="allow" if allowed else "block", error=error or None, endpoint=url.split("?")[0],
        )
        self.emit(site, source, subject or "text prompt", decision or ("allowed" if allowed else "blocked"))

    def emit(self, site: Site, source: str, subject: str, outcome: str) -> None:
        try:
            self._on_event({"time": time.time(), "site": site.name, "source": source, "subject": subject, "outcome": outcome})
        except Exception:
            log.exception("event listener failed")
