"""Agent settings: built-in defaults, overridden by a JSON file, overridden by environment variables."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path

ERROR_POLICIES = ("ask", "allow", "block")
DIALOG_BACKENDS = ("auto", "zenity", "kdialog", "osascript", "tk")


def data_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "walled-dlp"


def config_path() -> Path:
    override = os.environ.get("WALLED_DLP_CONFIG")
    if override:
        return Path(override)
    if sys.platform in ("win32", "darwin"):
        return data_dir() / "config.json"
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "walled-dlp" / "config.json"


@dataclass
class Config:
    marker: str = "WALLED_SENSITIVE"
    # Local port of the inspection proxy (the browser reaches it through the PAC file).
    port: int = 8899
    # Colour of AI responses, e.g. "#0f766e". Empty: violet, in a lighter shade on dark themes.
    response_color: str = ""
    # Largest upload that is inspected. Bigger files fall under on_inspection_error.
    max_file_mb: int = 25
    # What to do when a file can't be inspected (too big, corrupt, unsupported image codec, OCR missing).
    on_inspection_error: str = "ask"
    dialog_backend: str = "auto"
    # Seconds before an unanswered dialog counts as Cancel. 0 waits forever.
    dialog_timeout: int = 300
    # Stop OCR after this many embedded images per PDF, so a huge scan can't stall an upload forever.
    pdf_max_ocr_images: int = 20
    log_path: str = str(data_dir() / "agent.log")

    def validate(self) -> "Config":
        if not self.marker:
            raise ValueError("marker must not be empty")
        if self.on_inspection_error not in ERROR_POLICIES:
            raise ValueError(f"on_inspection_error must be one of {ERROR_POLICIES}")
        if self.dialog_backend not in DIALOG_BACKENDS:
            raise ValueError(f"dialog_backend must be one of {DIALOG_BACKENDS}")
        if self.max_file_mb <= 0 or self.dialog_timeout < 0 or self.pdf_max_ocr_images < 0:
            raise ValueError("limits must be positive")
        if not 0 < self.port < 65536:
            raise ValueError("port must be between 1 and 65535")
        return self

    @property
    def max_file_bytes(self) -> int:
        return self.max_file_mb * 1024 * 1024


def load_config(path: Path | None = None) -> Config:
    values: dict = {}
    path = path or config_path()
    if path.exists():
        values.update(json.loads(path.read_text(encoding="utf-8")))
    for f in fields(Config):
        env = os.environ.get(f"WALLED_DLP_{f.name.upper()}")
        if env is not None:
            values[f.name] = int(env) if f.type == "int" else env
    known = {f.name for f in fields(Config)}
    unknown = set(values) - known
    if unknown:
        raise ValueError(f"unknown config keys in {path}: {sorted(unknown)}")
    return Config(**values).validate()


def dump_config(cfg: Config) -> str:
    return json.dumps(asdict(cfg), indent=2)


def save_setting(key: str, value, path: Path | None = None) -> None:
    """Change one key in the config file, keeping the others."""
    if key not in {f.name for f in fields(Config)}:
        raise ValueError(f"unknown setting {key!r}")
    path = path or config_path()
    values = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    values[key] = value
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(values, indent=2) + "\n", encoding="utf-8")
