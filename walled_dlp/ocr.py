"""OCR backends behind one function: read_text(image) -> str.

RapidOCR (PaddleOCR models on ONNX Runtime) is the default because it installs from pip with no
system packages. Tesseract is used if RapidOCR is missing and the tesseract binary is on PATH.
"""

from __future__ import annotations

import logging
import shutil
import threading

from PIL import Image

log = logging.getLogger(__name__)


class OcrUnavailable(RuntimeError):
    pass


class _RapidBackend:
    name = "rapidocr"

    def __init__(self) -> None:
        import numpy as np
        from rapidocr_onnxruntime import RapidOCR

        self._np = np
        self._engine = RapidOCR()

    def read(self, image: Image.Image) -> str:
        result, _ = self._engine(self._np.asarray(image.convert("RGB")))
        return "\n".join(item[1] for item in (result or []))


class _TesseractBackend:
    name = "tesseract"

    def __init__(self) -> None:
        import pytesseract

        if not shutil.which("tesseract"):
            raise ImportError("tesseract binary not on PATH")
        self._tess = pytesseract

    def read(self, image: Image.Image) -> str:
        return self._tess.image_to_string(image)


class OcrEngine:
    """Loads lazily (models take ~1 s) and serialises calls: the engines aren't documented as thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._backend = None
        self._error: str | None = None

    def _load(self):
        if self._backend is None and self._error is None:
            failures = []
            for cls in (_RapidBackend, _TesseractBackend):
                try:
                    self._backend = cls()
                    log.info("OCR backend: %s", cls.name)
                    break
                except Exception as exc:  # ImportError, missing models, missing binary
                    failures.append(f"{cls.name}: {exc}")
            else:
                self._error = "no OCR engine available (" + "; ".join(failures) + ")"
                log.warning(self._error)
        if self._backend is None:
            raise OcrUnavailable(self._error)
        return self._backend

    def warm_up(self) -> None:
        with self._lock:
            try:
                self._load()
            except OcrUnavailable:
                pass

    @property
    def backend_name(self) -> str | None:
        return self._backend.name if self._backend else None

    def available(self) -> bool:
        with self._lock:
            try:
                self._load()
                return True
            except OcrUnavailable:
                return False

    def read_text(self, image: Image.Image) -> str:
        with self._lock:
            return self._load().read(image)
