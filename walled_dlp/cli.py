"""walled-dlp command line.

    walled-dlp              open the desktop app (starts protection)
    walled-dlp run          run protection without a window
    walled-dlp setup        trust the local certificate and point the browser at Walled DLP
    walled-dlp setup --undo undo both
    walled-dlp status       show configuration, certificate, proxy settings, OCR and dialogs
    walled-dlp launcher     add Walled DLP to the app menu (Linux)
    walled-dlp check FILES  inspect files (or --text) the way an upload would be inspected
    walled-dlp dialog-test  show a sample confirmation dialog
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .config import config_path, dump_config, load_config


def _setup_logging(log_path: str, to_stderr: bool) -> None:
    handlers: list[logging.Handler] = []
    try:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))
    except OSError:
        pass
    if to_stderr:
        handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers or [logging.NullHandler()],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="walled-dlp", description="Walled DLP: stop sensitive prompts and files reaching ChatGPT and Perplexity")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("app", help="open the desktop app (the default)")
    sub.add_parser("run", help="run protection in the foreground, without a window")
    p_setup = sub.add_parser("setup", help="trust the local certificate and route the monitored sites through Walled DLP")
    p_setup.add_argument("--undo", action="store_true", help="restore the previous proxy settings and remove the certificate")
    sub.add_parser("status", help="show configuration and setup state")
    p_launcher = sub.add_parser("launcher", help="add Walled DLP to the desktop's app menu (Linux)")
    p_launcher.add_argument("--remove", action="store_true", help="remove it again")
    p_check = sub.add_parser("check", help="inspect files or text for the marker")
    p_check.add_argument("files", nargs="*", type=Path)
    p_check.add_argument("--text", help="inspect this prompt text")
    p_check.add_argument("--ask", action="store_true", help="show the real dialog on a match")
    sub.add_parser("dialog-test", help="show a sample confirmation dialog")

    args = parser.parse_args(argv)
    command = args.command or "app"
    cfg = load_config()
    _setup_logging(cfg.log_path, to_stderr=command != "app")

    if command == "app":
        from .app import run_app

        return run_app(cfg)

    if command == "run":
        from .service import Service

        service = Service(cfg)
        print(f"Walled DLP is protecting ChatGPT and Perplexity. Proxy auto-config: http://127.0.0.1:{cfg.port}/proxy.pac  (Ctrl+C to stop)")
        try:
            service.run()
        except KeyboardInterrupt:
            pass
        except OSError as exc:
            print(f"could not start the proxy on port {cfg.port}: {exc}", file=sys.stderr)
            return 1
        return 0

    if command == "setup":
        from . import system
        from .certs import CertificateAuthority
        from .service import ca_dir

        ca = CertificateAuthority(ca_dir())
        steps = system.undo(ca) if args.undo else system.setup(ca, cfg.port)
        for step in steps:
            print(step)
        if not args.undo:
            print(
                "\nRestart your browser, then keep Walled DLP running (`walled-dlp`). While it isn't running, "
                "ChatGPT and Perplexity won't load; `walled-dlp setup --undo` disconnects."
            )
        return 0 if all(s.ok for s in steps) else 1

    if command == "launcher":
        from . import system

        step = system.remove_launcher() if args.remove else system.install_launcher()
        print(step)
        return 0 if step.ok else 1

    if command == "status":
        from . import system
        from .certs import CertificateAuthority
        from .dialogs import backend_order
        from .ocr import OcrEngine
        from .service import ca_dir

        ca = CertificateAuthority(ca_dir())
        trusted = system.ca_trusted(ca)
        print(f"walled-dlp {__version__}")
        print(f"config file:   {config_path()} ({'found' if config_path().exists() else 'defaults'})")
        print(dump_config(cfg))
        print(f"certificate:   {ca.cert_path}")
        print(f"  SHA-256:     {ca.fingerprint}")
        print(f"  trusted:     {'yes' if trusted else 'no' if trusted is False else 'unknown (check your browser)'}")
        print(f"proxy config:  {'routes ChatGPT and Perplexity to port ' + str(cfg.port) if system.proxy_configured(cfg.port) else 'not set (run: walled-dlp setup)'}")
        print(f"dialogs:       {', '.join(backend_order(cfg.dialog_backend)) or 'none'}")
        ocr = OcrEngine()
        print(f"OCR:           {ocr.backend_name if ocr.available() else 'unavailable'}")
        return 0

    if command == "check":
        from .dialogs import Alert, ask
        from .inspector import Inspector

        inspector = Inspector(cfg)
        results = []
        if args.text is not None:
            results.append(("--text", "prompt", args.text, inspector.inspect_prompt(args.text)))
        for path in args.files:
            results.append((str(path), "file", path.name, inspector.inspect_file(path.name, path.read_bytes())))
        for label, source, subject, report in results:
            row = {"input": label, "kind": report.kind, "detected": report.detected, "findings": report.findings, "error": report.error}
            if args.ask and (report.detected or report.error):
                answer = ask(Alert(source, "CLI", subject, ", ".join(report.findings) or report.error or "", not report.detected), cfg.dialog_backend, cfg.dialog_timeout)
                row["decision"] = {True: "continue", False: "cancel", None: "no dialog"}[answer]
            print(json.dumps(row))
        return 3 if any(r[3].detected for r in results) else 0

    if command == "dialog-test":
        from .dialogs import Alert, ask

        answer = ask(
            Alert("prompt", "ChatGPT", "Summarise the WALLED_SENSITIVE Q3 board deck for me", "prompt text"),
            cfg.dialog_backend,
            cfg.dialog_timeout,
        )
        print({True: "continue", False: "cancel", None: "no dialog backend available"}[answer])
        return 0
    return 2
