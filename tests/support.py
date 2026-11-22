"""Shared paths and markers for the unit tests."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from walled_dlp.ocr import OcrEngine  # noqa: E402

SAMPLES = ROOT / "samples"
OCR = OcrEngine()
requires_ocr = pytest.mark.skipif(not OCR.available(), reason="no OCR engine installed")
