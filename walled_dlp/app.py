"""The Walled DLP desktop window.

Opening the app starts protection (the inspection proxy runs on a background thread). The window
shows whether protection is on, lets the user connect the browser (trust the certificate and set
the proxy auto-config) in one click, change the response colour, and see recent interventions.
Closing the window stops protection.
"""

from __future__ import annotations

import json
import logging
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from importlib import resources
from tkinter import colorchooser, messagebox, ttk
from tkinter import font as tkfont

from . import __version__, system
from .config import Config, save_setting
from .pagestyle import DEFAULT_LIGHT
from .service import Service

log = logging.getLogger(__name__)

GREEN = "#15803d"
RED = "#b91c1c"
AMBER = "#b45309"
MUTED = "#6b7280"


class App:
    def __init__(self, root: tk.Tk, cfg: Config) -> None:
        self.root = root
        self.cfg = cfg
        self.events: queue.Queue[dict] = queue.Queue()
        self.ui_calls: queue.Queue = queue.Queue()  # worker threads hand UI updates to the Tk thread
        self.service: Service | None = None
        self.start_error = ""

        root.title("Walled DLP")
        root.minsize(600, 560)
        try:
            icon = tk.PhotoImage(data=resources.files("walled_dlp.assets").joinpath("icon.png").read_bytes())
            root.iconphoto(True, icon)
            self._icon = icon.subsample(4, 4)
        except Exception:
            self._icon = None
        style = ttk.Style(root)
        if "clam" in style.theme_names() and sys.platform.startswith("linux"):
            style.theme_use("clam")
        base = tkfont.nametofont("TkDefaultFont")
        self.font_title = base.copy()
        self.font_title.configure(size=16, weight="bold")
        self.font_bold = base.copy()
        self.font_bold.configure(weight="bold")
        style.configure("Title.TLabel", font=self.font_title)
        style.configure("Section.TLabelframe.Label", font=self.font_bold)

        self._build()
        self._start_service()
        self._load_history()
        self.refresh_setup()
        root.protocol("WM_DELETE_WINDOW", self.quit)
        root.after(250, self._drain_events)

    # -- layout -------------------------------------------------------------------------------
    def _build(self) -> None:
        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)

        head = ttk.Frame(outer)
        head.pack(fill="x")
        if self._icon:
            ttk.Label(head, image=self._icon).pack(side="left", padx=(0, 10))
        titles = ttk.Frame(head)
        titles.pack(side="left", fill="x", expand=True)
        ttk.Label(titles, text="Walled DLP", style="Title.TLabel").pack(anchor="w")
        self.status = tk.Label(titles, text="Starting…", fg=MUTED, anchor="w", font=self.font_bold)
        self.status.pack(anchor="w")
        ttk.Label(
            outer,
            text=f"Prompts and uploads to ChatGPT and Perplexity are checked for “{self.cfg.marker}” before they leave "
            "this computer. Keep this window open; you can minimise it.",
            wraplength=560, foreground=MUTED, justify="left",
        ).pack(anchor="w", pady=(8, 12))

        setup = ttk.LabelFrame(outer, text="Browser connection", padding=10, style="Section.TLabelframe")
        setup.pack(fill="x")
        setup.columnconfigure(1, weight=1)
        self.proxy_value = self._row(setup, 0, "Inspection proxy")
        self.route_value = self._row(setup, 1, "Browser routing")
        self.cert_value = self._row(setup, 2, "Certificate")
        buttons = ttk.Frame(setup)
        buttons.grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self.setup_button = ttk.Button(buttons, text="Connect browser", command=self.connect_browser)
        self.setup_button.pack(side="left")
        ttk.Button(buttons, text="Disconnect", command=self.disconnect_browser).pack(side="left", padx=6)
        ttk.Button(buttons, text="Show certificate", command=self.show_certificate).pack(side="left")

        colour = ttk.LabelFrame(outer, text="AI response colour", padding=10, style="Section.TLabelframe")
        colour.pack(fill="x", pady=12)
        self.swatch = tk.Canvas(colour, width=28, height=20, highlightthickness=1, highlightbackground="#d1d5db")
        self.swatch.pack(side="left")
        self.colour_label = ttk.Label(colour, text="")
        self.colour_label.pack(side="left", padx=8)
        ttk.Button(colour, text="Change…", command=self.pick_colour).pack(side="left")
        ttk.Button(colour, text="Default", command=lambda: self.set_colour("")).pack(side="left", padx=6)
        ttk.Label(colour, text="Reload open tabs to apply.", foreground=MUTED).pack(side="left", padx=6)
        self._show_colour()

        activity = ttk.LabelFrame(outer, text="Recent activity", padding=10, style="Section.TLabelframe")
        activity.pack(fill="both", expand=True)
        cols = ("time", "site", "what", "outcome")
        self.tree = ttk.Treeview(activity, columns=cols, show="headings", height=8)
        for col, label, width in zip(cols, ("Time", "Site", "What", "Outcome"), (55, 85, 280, 135)):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w", stretch=col == "what")
        self.tree.tag_configure("cancel", foreground=RED)
        self.tree.tag_configure("continue", foreground=AMBER)
        self.tree.tag_configure("withheld", foreground=MUTED)
        self.tree.pack(fill="both", expand=True)

        foot = ttk.Frame(outer)
        foot.pack(fill="x", pady=(10, 0))
        ttk.Label(foot, text=f"Walled DLP {__version__} · marker {self.cfg.marker}", foreground=MUTED).pack(side="left")
        ttk.Button(foot, text="Quit", command=self.quit).pack(side="right")

    @staticmethod
    def _row(parent: ttk.Frame, row: int, label: str) -> tk.Label:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 16), pady=2)
        value = tk.Label(parent, text="…", anchor="w", justify="left")
        value.grid(row=row, column=1, sticky="w", pady=2)
        return value

    # -- protection ---------------------------------------------------------------------------
    def _start_service(self) -> None:
        try:
            self.service = Service(self.cfg, on_event=self.events.put)
            self.service.start_background()
        except OSError as exc:
            self.service = None
            self.start_error = f"port {self.cfg.port} is in use (is Walled DLP already running?)" if exc.errno in (98, 48, 10048) else str(exc)
        except Exception as exc:  # pragma: no cover - shown to the user
            self.service = None
            self.start_error = str(exc)
        if self.service:
            self.status.config(text="Protecting ChatGPT and Perplexity", fg=GREEN)
            self.proxy_value.config(text=f"Running on 127.0.0.1:{self.service.proxy.port}", fg=GREEN)
        else:
            self.status.config(text="Not protecting", fg=RED)
            self.proxy_value.config(text=f"Not running: {self.start_error}", fg=RED)

    def refresh_setup(self) -> None:
        if not self.service:
            self.route_value.config(text="–", fg=MUTED)
            self.cert_value.config(text="–", fg=MUTED)
            return
        port = self.service.proxy.port

        def check() -> None:
            routed = system.proxy_configured(port)
            trusted = system.ca_trusted(self.service.ca)
            self.ui_calls.put(lambda: self._show_setup(routed, trusted))

        threading.Thread(target=check, daemon=True).start()

    def _show_setup(self, routed: bool, trusted: bool | None) -> None:
        self.route_value.config(
            text="On: ChatGPT and Perplexity go through Walled DLP" if routed else "Off: click Connect browser",
            fg=GREEN if routed else AMBER,
        )
        if trusted is None:
            self.cert_value.config(text="Can't check here; your browser must trust the Walled DLP certificate", fg=MUTED)
        else:
            self.cert_value.config(text="Trusted" if trusted else "Not trusted yet: click Connect browser", fg=GREEN if trusted else AMBER)

    def _run_steps(self, title: str, fn) -> None:
        self.setup_button.state(["disabled"])

        def work() -> None:
            try:
                steps = fn()
                text = "\n\n".join(str(s) for s in steps)
                ok = all(s.ok for s in steps)
            except Exception as exc:
                text, ok = f"{type(exc).__name__}: {exc}", False

            def done() -> None:
                self.setup_button.state(["!disabled"])
                (messagebox.showinfo if ok else messagebox.showwarning)(title, text, parent=self.root)
                self.refresh_setup()

            self.ui_calls.put(done)

        threading.Thread(target=work, daemon=True).start()

    def connect_browser(self) -> None:
        if not self.service:
            messagebox.showerror("Walled DLP", f"Protection isn't running: {self.start_error}", parent=self.root)
            return
        service = self.service
        self._run_steps(
            "Connect browser",
            lambda: system.setup(service.ca, service.proxy.port)
            + [system.Step("Restart your browser", True, "Keep Walled DLP running: while it isn't, ChatGPT and Perplexity won't load. Disconnect undoes this.")],
        )

    def disconnect_browser(self) -> None:
        if not messagebox.askyesno("Walled DLP", "Restore your previous proxy settings and remove the Walled DLP certificate?", parent=self.root):
            return
        ca = self.service.ca if self.service else None
        if ca is None:
            from .certs import CertificateAuthority
            from .service import ca_dir

            ca = CertificateAuthority(ca_dir())
        self._run_steps("Disconnect browser", lambda: system.undo(ca))

    def show_certificate(self) -> None:
        if not self.service:
            return
        path = self.service.ca.cert_path
        opener = {"darwin": ["open", "-R"], "win32": ["explorer", "/select,"]}.get(sys.platform, ["xdg-open"])
        target = str(path) if sys.platform in ("darwin", "win32") else str(path.parent)
        try:
            subprocess.Popen([*opener, target])
        except OSError:
            pass
        messagebox.showinfo("Walled DLP certificate", f"{path}\n\nSHA-256 {self.service.ca.fingerprint}", parent=self.root)

    # -- colour -------------------------------------------------------------------------------
    def _show_colour(self) -> None:
        colour = self.cfg.response_color or DEFAULT_LIGHT
        self.swatch.delete("all")
        self.swatch.create_rectangle(0, 0, 30, 22, fill=colour, outline="")
        self.colour_label.config(text=self.cfg.response_color or "Violet (default)")

    def pick_colour(self) -> None:
        _, hex_colour = colorchooser.askcolor(color=self.cfg.response_color or DEFAULT_LIGHT, title="AI response colour", parent=self.root)
        if hex_colour:
            self.set_colour(hex_colour)

    def set_colour(self, colour: str) -> None:
        self.cfg.response_color = colour  # the proxy reads it for every page it rewrites
        try:
            save_setting("response_color", colour)
        except (OSError, ValueError) as exc:
            messagebox.showwarning("Walled DLP", f"Couldn't save the colour: {exc}", parent=self.root)
        self._show_colour()

    # -- activity -----------------------------------------------------------------------------
    def _load_history(self) -> None:
        if not self.service:
            return
        try:
            lines = self.service.guard.audit.path.read_text(encoding="utf-8").splitlines()[-30:]
        except OSError:
            return
        for line in lines:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            self._add_row(r.get("time", "")[11:16], r.get("site", ""), r.get("subject") or "text prompt", r.get("decision") or r.get("verdict", ""))

    def _add_row(self, when: str, site: str, what: str, outcome: str) -> None:
        tag = outcome if outcome in ("cancel", "continue", "withheld") else ""
        label = {"cancel": "Blocked (Cancel)", "continue": "Sent (Continue)", "withheld": "Withheld"}.get(outcome, outcome)
        self.tree.insert("", 0, values=(when, site, what, label), tags=(tag,))
        for extra in self.tree.get_children()[200:]:
            self.tree.delete(extra)

    def _drain_events(self) -> None:
        try:
            while True:
                e = self.events.get_nowait()
                what = e["subject"] if e["source"] != "background" else f"background copy: {e['subject']}"
                self._add_row(time.strftime("%H:%M", time.localtime(e["time"])), e["site"], what, e["outcome"])
        except queue.Empty:
            pass
        try:
            while True:
                self.ui_calls.get_nowait()()
        except queue.Empty:
            pass
        self.root.after(250, self._drain_events)

    def quit(self) -> None:
        if self.service:
            self.service.stop()
        self.root.destroy()


def main() -> int:
    """Entry point for the `walled-dlp-app` launcher (no console window on Windows)."""
    from .cli import main as cli_main

    return cli_main(["app"])


def run_app(cfg: Config) -> int:
    try:
        root = tk.Tk(className="walled-dlp")
    except tk.TclError as exc:
        print(f"Can't open a window ({exc}). Use `walled-dlp run` to protect without a window.", file=sys.stderr)
        return 1
    App(root, cfg)
    root.mainloop()
    return 0
