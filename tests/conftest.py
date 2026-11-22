import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import OCR, ROOT, SAMPLES  # noqa: E402
from walled_dlp.config import Config  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def samples() -> Path:
    if not (SAMPLES / "sensitive-report.pdf").exists():
        import subprocess

        subprocess.run([sys.executable, str(ROOT / "scripts" / "make_samples.py")], check=True)
    return SAMPLES


@pytest.fixture
def cfg(tmp_path) -> Config:
    return Config(log_path=str(tmp_path / "agent.log"))


@pytest.fixture(scope="session")
def ocr():
    return OCR
