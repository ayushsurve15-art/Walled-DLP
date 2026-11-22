"""Native Continue / Cancel confirmation dialogs.

Every backend runs as a child process, so a dialog can't hang or crash the agent and Tk never has
to share a thread with anything else. Backends by platform:

    Linux    zenity (GTK) -> kdialog (KDE) -> Tk
    macOS    osascript (AppKit 'display dialog') -> Tk
    Windows  Tk (native Win32 widgets)

ask() returns True for Continue, False for Cancel / closed / timed out, and None when no backend
could show a dialog at all (the caller then blocks: an unseen dialog must not leak data).
"""

from __future__ import annotations

import html
import json
import logging
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass

log = logging.getLogger(__name__)

TITLE = "Walled DLP"


@dataclass
class Alert:
    source: str  # "prompt" | "file"
    site: str  # "ChatGPT" | "Perplexity"
    subject: str  # prompt excerpt, or file name
    detail: str  # where the marker was found, or why the file couldn't be inspected
    uninspectable: bool = False

    @property
    def heading(self) -> str:
        if self.uninspectable:
            return "A file could not be inspected"
        where = "a text prompt" if self.source == "prompt" else "a file upload"
        return f"Sensitive content detected in {where}"

    def lines(self) -> list[tuple[str, str]]:
        label = "Prompt" if self.source == "prompt" else "File"
        subject = f"“{self.subject}”" if self.source == "prompt" else self.subject
        return [
            ("Type", "Text prompt" if self.source == "prompt" else "File upload"),
            ("Site", self.site),
            (label, subject),
            ("Reason" if self.uninspectable else "Found in", self.detail),
        ]

    @property
    def footer(self) -> str:
        what = "prompt" if self.source == "prompt" else "file"
        return f"Continue sends the {what} unchanged. Cancel blocks it so you can edit and try again."

    def plain_text(self) -> str:
        body = "\n".join(f"{k}: {v}" for k, v in self.lines())
        return f"{self.heading}\n\n{body}\n\n{self.footer}"


# -- backends ------------------------------------------------------------------------------------
# Each returns True/False for a real answer, or raises _BackendFailed to try the next one.


class _BackendFailed(Exception):
    pass


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=(timeout + 5) if timeout else None)
    except FileNotFoundError as exc:
        raise _BackendFailed(str(exc)) from exc
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 5, "", "timed out")


def _zenity(alert: Alert, timeout: int) -> bool:
    rows = "\n".join(f"<b>{html.escape(k)}:</b> {html.escape(v)}" for k, v in alert.lines())
    text = (
        f"<span size='large' weight='bold'>{html.escape(alert.heading)}</span>\n\n{rows}\n\n"
        f"<small>{html.escape(alert.footer)}</small>"
    )
    cmd = [
        "zenity", "--question", f"--title={TITLE}", f"--text={text}", "--icon=dialog-warning",
        "--ok-label=Continue", "--cancel-label=Cancel", "--default-cancel", "--width=520", "--modal",
    ]
    if timeout:
        cmd.append(f"--timeout={timeout}")
    proc = _run(cmd, timeout)
    # 0 = Continue, 1 = Cancel or closed, 5 = timeout. Anything else means GTK couldn't start.
    if proc.returncode in (0, 1, 5):
        return proc.returncode == 0
    raise _BackendFailed(f"zenity exited {proc.returncode}: {proc.stderr.strip()[:200]}")


def _kdialog(alert: Alert, timeout: int) -> bool:
    cmd = [
        "kdialog", "--title", TITLE, "--warningcontinuecancel", alert.plain_text(),
        "--continue-label", "Continue", "--cancel-label", "Cancel",
    ]
    proc = _run(cmd, timeout)
    if proc.returncode in (0, 1, 2):
        return proc.returncode == 0
    raise _BackendFailed(f"kdialog exited {proc.returncode}: {proc.stderr.strip()[:200]}")


_APPLESCRIPT = """
on run argv
    set r to display dialog (item 1 of argv) with title (item 2 of argv) ¬
        buttons {"Cancel", "Continue"} default button "Cancel" cancel button "Cancel" ¬
        with icon caution giving up after (item 3 of argv as integer)
    if gave up of r then return "timeout"
    return button returned of r
end run
"""


def _osascript(alert: Alert, timeout: int) -> bool:
    proc = _run(["osascript", "-e", _APPLESCRIPT, alert.plain_text(), TITLE, str(timeout or 86400)], timeout)
    if proc.returncode == 0:
        return proc.stdout.strip() == "Continue"
    if "-128" in proc.stderr:  # user cancelled
        return False
    raise _BackendFailed(f"osascript exited {proc.returncode}: {proc.stderr.strip()[:200]}")


def _tk(alert: Alert, timeout: int) -> bool:
    payload = json.dumps({"alert": asdict(alert), "timeout": timeout})
    proc = _run([sys.executable, "-m", "walled_dlp.dialogs", payload], timeout)
    answer = proc.stdout.strip()
    if answer in ("continue", "cancel"):
        return answer == "continue"
    raise _BackendFailed(f"tk dialog failed ({proc.returncode}): {proc.stderr.strip()[-300:]}")


_BACKENDS = {"zenity": _zenity, "kdialog": _kdialog, "osascript": _osascript, "tk": _tk}


def backend_order(preferred: str = "auto") -> list[str]:
    if preferred != "auto":
        return [preferred]
    if sys.platform == "darwin":
        order = ["osascript", "tk"]
    elif sys.platform == "win32":
        order = ["tk"]
    else:
        order = ["zenity", "kdialog", "tk"]
    return [b for b in order if b == "tk" or shutil.which(b)]


def ask(alert: Alert, preferred: str = "auto", timeout: int = 300) -> bool | None:
    for name in backend_order(preferred):
        try:
            answer = _BACKENDS[name](alert, timeout)
            log.info("dialog via %s -> %s", name, "continue" if answer else "cancel")
            return answer
        except _BackendFailed as exc:
            log.warning("dialog backend %s failed: %s", name, exc)
    return None


# -- Tk dialog (runs in its own process: python -m walled_dlp.dialogs '<json>') -------------------


def _tk_main(payload: str) -> None:
    import tkinter as tk
    from tkinter import ttk

    spec = json.loads(payload)
    alert = Alert(**spec["alert"])
    result = {"answer": "cancel"}

    root = tk.Tk()
    root.title(TITLE)
    root.resizable(False, False)
    root.attributes("-topmost", True)
    style = ttk.Style(root)
    if sys.platform == "win32":
        style.theme_use("vista")

    frame = ttk.Frame(root, padding=18)
    frame.grid(sticky="nsew")
    icon = ttk.Label(frame, image="::tk::icons::warning")
    icon.grid(row=0, column=0, rowspan=2, sticky="n", padx=(0, 14))
    ttk.Label(frame, text=alert.heading, font=("TkDefaultFont", 12, "bold")).grid(row=0, column=1, sticky="w")

    details = ttk.Frame(frame)
    details.grid(row=1, column=1, sticky="w", pady=(10, 0))
    for row, (key, value) in enumerate(alert.lines()):
        ttk.Label(details, text=f"{key}:", font=("TkDefaultFont", 9, "bold")).grid(row=row, column=0, sticky="nw", padx=(0, 8), pady=1)
        ttk.Label(details, text=value, wraplength=380, justify="left").grid(row=row, column=1, sticky="w", pady=1)
    ttk.Label(frame, text=alert.footer, wraplength=440, foreground="#555").grid(row=2, column=1, sticky="w", pady=(12, 0))

    def finish(answer: str) -> None:
        result["answer"] = answer
        root.destroy()

    buttons = ttk.Frame(frame)
    buttons.grid(row=3, column=0, columnspan=2, sticky="e", pady=(16, 0))
    cancel = ttk.Button(buttons, text="Cancel", command=lambda: finish("cancel"))
    cont = ttk.Button(buttons, text="Continue", command=lambda: finish("continue"))
    cancel.grid(row=0, column=0, padx=(0, 8))
    cont.grid(row=0, column=1)

    root.protocol("WM_DELETE_WINDOW", lambda: finish("cancel"))
    root.bind("<Escape>", lambda _e: finish("cancel"))
    root.bind("<Return>", lambda e: e.widget.invoke() if isinstance(e.widget, ttk.Button) else None)
    if spec.get("timeout"):
        root.after(spec["timeout"] * 1000, lambda: finish("cancel"))

    root.update_idletasks()
    x = (root.winfo_screenwidth() - root.winfo_reqwidth()) // 2
    y = (root.winfo_screenheight() - root.winfo_reqheight()) // 3
    root.geometry(f"+{x}+{y}")
    root.lift()
    root.focus_force()
    cancel.focus_set()
    root.mainloop()
    print(result["answer"], flush=True)


if __name__ == "__main__":
    _tk_main(sys.argv[1])
