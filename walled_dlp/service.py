"""Assemble and run the inspection proxy: CA + guard + policy + proxy server.

The desktop window runs it on a background thread; `walled-dlp run` runs it in the foreground.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from pathlib import Path

from .certs import CertificateAuthority
from .config import Config, data_dir
from .guard import AskFn, EventFn, Guard
from .policy import DlpPolicy
from .proxy import Proxy

log = logging.getLogger(__name__)


def ca_dir() -> Path:
    return Path(os.environ.get("WALLED_DLP_CA_DIR") or data_dir() / "ca")


def _test_upstreams() -> dict[str, tuple[str, int]]:
    """WALLED_DLP_TEST_UPSTREAM="chatgpt.com=127.0.0.1:9001,…" sends hosts to local fixture
    servers over plain HTTP. Used by the end-to-end tests only."""
    out: dict[str, tuple[str, int]] = {}
    for item in filter(None, os.environ.get("WALLED_DLP_TEST_UPSTREAM", "").split(",")):
        host, _, addr = item.partition("=")
        ip, _, port = addr.rpartition(":")
        out[host.strip().lower()] = (ip, int(port))
    return out


class Service:
    def __init__(self, cfg: Config, on_event: EventFn | None = None, ask_fn: AskFn | None = None) -> None:
        self.cfg = cfg
        self.ca = CertificateAuthority(ca_dir())
        self.guard = Guard(cfg, ask_fn=ask_fn, on_event=on_event)
        self.policy = DlpPolicy(cfg, self.guard, self.ca)
        self.proxy = Proxy(
            self.policy, self.ca, port=cfg.port,
            body_limit=max(cfg.max_file_bytes * 4, 128 * 1024 * 1024),
            upstream_override=_test_upstreams(),
        )
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self.started = threading.Event()
        self.error: BaseException | None = None

    async def _main(self) -> None:
        self._loop = asyncio.get_running_loop()
        try:
            await self.proxy.start()
        except BaseException as exc:
            self.error = exc
            self.started.set()
            raise
        self.started.set()
        # OCR models take a second or two to load; do it now rather than on the first image upload.
        threading.Thread(target=self.guard.inspector.ocr.warm_up, daemon=True).start()
        await self.proxy.serve_forever()

    def run(self) -> None:
        """Run in the foreground until interrupted."""
        try:
            asyncio.run(self._main())
        except asyncio.CancelledError:
            pass

    def start_background(self, timeout: float = 10) -> None:
        def target() -> None:
            try:
                asyncio.run(self._main())
            except (asyncio.CancelledError, RuntimeError):
                pass
            except BaseException as exc:  # reported through self.error
                self.error = self.error or exc
                self.started.set()

        self._thread = threading.Thread(target=target, name="walled-dlp-proxy", daemon=True)
        self._thread.start()
        self.started.wait(timeout)
        if self.error:
            raise self.error

    def stop(self) -> None:
        loop = self._loop
        if loop and loop.is_running():
            for task in asyncio.all_tasks(loop):
                loop.call_soon_threadsafe(task.cancel)
        if self._thread:
            self._thread.join(timeout=5)
