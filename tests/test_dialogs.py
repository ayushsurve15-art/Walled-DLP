import os
import sys

import pytest

from walled_dlp import dialogs
from walled_dlp.dialogs import Alert


def alert(**kw):
    return Alert(**{"source": "file", "site": "ChatGPT", "subject": "q3 <draft> & notes.pdf", "detail": "page 2 text", **kw})


def test_alert_text():
    a = alert()
    assert a.heading == "Sensitive content detected in a file upload"
    assert ("File", "q3 <draft> & notes.pdf") in a.lines()
    p = alert(source="prompt", subject="hello")
    assert p.heading.endswith("a text prompt") and ("Prompt", "“hello”") in p.lines()


@pytest.fixture
def fake_bin(tmp_path, monkeypatch):
    def make(name, script):
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + script)
        path.chmod(0o755)
        return path

    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    return make


@pytest.mark.skipif(sys.platform == "win32", reason="shell fakes")
@pytest.mark.parametrize("code,expected", [(0, True), (1, False), (5, False)])
def test_zenity_exit_codes(fake_bin, code, expected):
    fake_bin("zenity", f"exit {code}\n")
    assert dialogs.ask(alert(), "zenity", 10) is expected


@pytest.mark.skipif(sys.platform == "win32", reason="shell fakes")
def test_zenity_markup_is_escaped(fake_bin, tmp_path):
    fake_bin("zenity", f'printf "%s" "$@" > "{tmp_path}/args"\nexit 0\n')
    dialogs.ask(alert(), "zenity", 10)
    args = (tmp_path / "args").read_text()
    assert "q3 &lt;draft&gt; &amp; notes.pdf" in args and "<draft>" not in args


@pytest.mark.skipif(sys.platform == "win32", reason="shell fakes")
def test_broken_backend_falls_through(fake_bin, monkeypatch):
    fake_bin("zenity", "exit 255\n")  # e.g. no display
    fake_bin("kdialog", "exit 0\n")
    monkeypatch.setattr(sys, "platform", "linux")
    assert dialogs.backend_order()[:2] == ["zenity", "kdialog"]
    assert dialogs.ask(alert(), "auto", 10) is True


def test_no_backend_returns_none(monkeypatch):
    monkeypatch.setattr(dialogs, "backend_order", lambda preferred="auto": [])
    assert dialogs.ask(alert()) is None
