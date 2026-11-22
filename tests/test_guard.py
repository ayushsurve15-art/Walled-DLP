"""Decisions: one dialog per piece of content, side channels follow it, files remembered by hash."""

import asyncio
import json
import threading
import time

import pytest

from support import SAMPLES
from walled_dlp import guard as guard_mod
from walled_dlp.config import Config
from walled_dlp.guard import Guard, Memory
from walled_dlp.sites import CHATGPT, PERPLEXITY

M = "WALLED_SENSITIVE"
URL = "https://chatgpt.com/backend-api/f/conversation"


class Recorder:
    """Stands in for the native dialog: records each alert and gives a scripted answer."""

    def __init__(self, answer=True, delay=0.0):
        self.answer = answer
        self.delay = delay
        self.alerts = []

    def __call__(self, alert):
        self.alerts.append(alert)
        time.sleep(self.delay)
        return self.answer


def run(coro):
    return asyncio.run(coro)


def make(cfg, answer=True, delay=0.0, events=None):
    rec = Recorder(answer, delay)
    return Guard(cfg, ask_fn=rec, on_event=(events.append if events is not None else None)), rec


@pytest.mark.parametrize("answer", [True, False])
def test_prompt_follows_dialog(cfg, answer):
    g, rec = make(cfg, answer)
    v = run(g.check_text(CHATGPT, [f"Summarise the {M} deck"], URL))
    assert v.allow is answer and v.asked
    (a,) = rec.alerts
    assert a.source == "prompt" and a.site == "ChatGPT" and M in a.subject


def test_no_dialog_backend_blocks(cfg):
    g, _ = make(cfg, None)
    v = run(g.check_text(CHATGPT, [f"x {M}"], URL))
    assert not v.allow and "no desktop dialog" in v.reason


def test_continue_covers_copies_and_prefixes(cfg):
    g, rec = make(cfg, True)

    async def flow():
        await g.check_text(PERPLEXITY, [f"what is {M} data"], URL)
        # analytics repeats it, typeahead sends a prefix, both after approval
        a = await g.check_side_channel(PERPLEXITY, [f"what is {M} data"], URL)
        b = g.websocket_allows(PERPLEXITY, [f"what is {M} d"])
        # the next turn re-sends the approved message in the history: no second dialog
        c = await g.check_text(PERPLEXITY, [f"what is {M} data"], URL)
        return a, b, c

    a, b, c = run(flow())
    assert a.allow and b and c.allow and len(rec.alerts) == 1


def test_edited_prompt_asks_again(cfg):
    """Adding to an approved or cancelled prompt is new content: it is never covered."""
    g, rec = make(cfg, False)

    async def flow():
        await g.check_text(CHATGPT, [f"is {M} a colour?"], URL)
        rec.answer = True
        return await g.check_text(CHATGPT, [f"is {M} a colour? Answer yes or no."], URL)

    assert run(flow()).allow and len(rec.alerts) == 2


def test_cancel_covers_queued_copies_but_never_a_later_resend(cfg):
    g, rec = make(cfg, False, delay=0.2)

    async def flow():
        # Two copies of one send arrive together: one dialog, both blocked.
        a, b = await asyncio.gather(g.check_text(CHATGPT, [f"x {M}"], URL), g.check_text(CHATGPT, [f"x {M}"], URL))
        # The user tries again with the same text: they get the dialog again.
        rec.answer = True
        c = await g.check_text(CHATGPT, [f"x {M}"], URL)
        return a, b, c

    a, b, c = run(flow())
    assert not a.allow and not b.allow and c.allow and len(rec.alerts) == 2


def test_cancelled_file_absorbs_automatic_retries_only(cfg, monkeypatch):
    g, rec = make(cfg, False)
    data = (SAMPLES / "sensitive-notes.txt").read_bytes()
    assert not run(g.check_file(CHATGPT, "n.txt", "", data, URL)).allow
    assert not run(g.check_file(CHATGPT, "n.txt", "", data, URL)).allow  # app retries at once
    assert len(rec.alerts) == 1
    monkeypatch.setattr(guard_mod, "FILE_CANCELLED_TTL", 0)
    g._files.clear()
    rec.answer = True
    assert run(g.check_file(CHATGPT, "n.txt", "", data, URL)).allow  # the user picks it again later
    assert len(rec.alerts) == 2


def test_side_channel_never_asks_and_is_withheld(cfg):
    events = []
    g, rec = make(cfg, True, events=events)
    v = run(g.check_side_channel(PERPLEXITY, [f"what is {M}"], "https://suggest.perplexity.ai/x", wait=0.2))
    assert not v.allow and rec.alerts == []
    assert events and events[0]["outcome"] == "withheld"


def test_side_channel_waits_for_the_prompt_dialog(cfg):
    """Analytics fires a moment before the prompt; it waits and follows the user's answer."""
    g, rec = make(cfg, False, delay=0.5)

    async def flow():
        side = asyncio.create_task(g.check_side_channel(PERPLEXITY, [f"what is {M} data"], "https://www.perplexity.ai/rest/event/analytics", wait=0.3))
        await asyncio.sleep(0.05)
        prompt = await g.check_text(PERPLEXITY, [f"what is {M} data"], URL)
        return prompt, await side

    prompt, side = run(flow())
    assert not prompt.allow and not side.allow and len(rec.alerts) == 1


def test_one_dialog_at_a_time_and_duplicates_share_it(cfg):
    g, rec = make(cfg, True, delay=0.3)
    in_dialog = []
    lock = threading.Lock()
    active = [0]

    def ask(alert):
        with lock:
            active[0] += 1
            in_dialog.append(active[0])
        time.sleep(0.2)
        with lock:
            active[0] -= 1
        return True

    g._ask = ask

    async def flow():
        return await asyncio.gather(
            g.check_text(CHATGPT, [f"a {M}"], URL),
            g.check_text(CHATGPT, [f"a {M}"], URL),  # same content: shares the first answer
            g.check_text(CHATGPT, [f"b {M}"], URL),
        )

    results = run(flow())
    assert all(r.allow for r in results)
    assert len(in_dialog) == 2 and max(in_dialog) == 1


def test_sensitive_file_dialog_names_the_file(cfg):
    g, rec = make(cfg, False)
    data = (SAMPLES / "sensitive-report.pdf").read_bytes()
    v = run(g.check_file(CHATGPT, "sensitive-report.pdf", "application/pdf", data, URL))
    assert not v.allow
    (a,) = rec.alerts
    assert a.source == "file" and a.subject.startswith("sensitive-report.pdf (PDF,") and "page 1 text" in a.detail
    # A retry of the same bytes doesn't ask again.
    assert not run(g.check_file(CHATGPT, "renamed.pdf", "", data, URL)).allow and len(rec.alerts) == 1


def test_clean_file_no_dialog(cfg):
    g, rec = make(cfg)
    v = run(g.check_file(CHATGPT, "clean-report.pdf", "", (SAMPLES / "clean-report.pdf").read_bytes(), URL))
    assert v.allow and rec.alerts == []


@pytest.mark.parametrize("policy,allowed,dialogs", [("ask", True, 1), ("allow", True, 0), ("block", False, 0)])
def test_uninspectable_file_policy(tmp_path, policy, allowed, dialogs):
    cfg = Config(log_path=str(tmp_path / "a.log"), on_inspection_error=policy)
    g, rec = make(cfg, True)
    v = run(g.check_file(CHATGPT, "broken.pdf", "", b"%PDF-1.7 garbage", URL))
    assert v.allow is allowed and len(rec.alerts) == dialogs
    if dialogs:
        assert rec.alerts[0].uninspectable


def test_too_large_file(tmp_path):
    cfg = Config(log_path=str(tmp_path / "a.log"), max_file_mb=1)
    g, rec = make(cfg, False)
    v = run(g.check_file(CHATGPT, "big.bin", "", b"x" * (2 * 1024 * 1024), URL))
    assert not v.allow and "inspection limit" in rec.alerts[0].detail


def test_audit_log_has_no_prompt_text(cfg):
    g, _ = make(cfg, False)
    run(g.check_text(CHATGPT, [f"my salary is 123 {M}"], URL))
    rows = [json.loads(l) for l in g.audit.path.read_text().splitlines()]
    assert rows[-1]["decision"] == "cancel" and rows[-1]["site"] == "ChatGPT"
    assert "salary" not in g.audit.path.read_text()
