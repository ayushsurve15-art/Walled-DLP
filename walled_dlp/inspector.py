"""Find the marker in text prompts and in uploaded files (plain text, PDF, images).

Each inspector returns a Report: where the marker was found (empty if nowhere) and, if the content
could not be fully read, why. A partial read that already found the marker still counts as found.
"""

from __future__ import annotations

import io
import logging
from dataclasses import dataclass, field
from pathlib import PurePath

from PIL import Image, ImageOps, UnidentifiedImageError

from .config import Config
from .detector import contains_marker, contains_marker_fuzzy
from .ocr import OcrEngine, OcrUnavailable

log = logging.getLogger(__name__)

TEXT_EXTENSIONS = {
    ".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".jsonl", ".xml", ".yaml", ".yml", ".log",
    ".ini", ".cfg", ".conf", ".toml", ".env", ".html", ".htm", ".css", ".js", ".ts", ".tsx", ".jsx",
    ".py", ".java", ".c", ".h", ".cpp", ".cs", ".go", ".rs", ".rb", ".php", ".sh", ".bat", ".ps1",
    ".sql", ".r", ".swift", ".kt", ".scala", ".tex", ".rtf", ".srt", ".vtt",
}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".ico"}

_MAGIC = [
    (b"%PDF-", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "image"),
    (b"\xff\xd8\xff", "image"),
    (b"GIF87a", "image"),
    (b"GIF89a", "image"),
    (b"BM", "image"),
    (b"II*\x00", "image"),
    (b"MM\x00*", "image"),
]


@dataclass
class Report:
    kind: str  # "prompt" | "text" | "pdf" | "image" | "other"
    findings: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def detected(self) -> bool:
        return bool(self.findings)


def sniff_kind(name: str, data: bytes, mime: str = "") -> str:
    head = data[:16]
    for magic, kind in _MAGIC:
        if head.startswith(magic):
            return kind
    if head[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image"
    if head[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1", b"ftypavif"):
        return "image"
    ext = PurePath(name).suffix.lower()
    if ext == ".pdf" or mime == "application/pdf":
        return "pdf"
    if ext in IMAGE_EXTENSIONS or mime.startswith("image/"):
        return "image"
    if ext in TEXT_EXTENSIONS or mime.startswith("text/") or _looks_like_text(data):
        return "text"
    return "other"


def _looks_like_text(data: bytes) -> bool:
    sample = data[:4096]
    if not sample:
        return True
    if sample.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return True
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError as exc:
        # A multi-byte character cut off by the 4 KiB window is still text.
        return exc.start >= len(sample) - 3


def decode_text(data: bytes) -> str:
    for bom, codec in ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16")):
        if data.startswith(bom):
            return data.decode(codec, errors="replace")
    if data[:200].count(b"\x00") > 20:  # UTF-16 without a BOM
        even_nulls = data[0:200:2].count(b"\x00")
        return data.decode("utf-16-be" if even_nulls > 50 else "utf-16-le", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _raw_bytes_contain(data: bytes, marker: str) -> bool:
    """Backstop for formats we don't parse: look for the marker's bytes in common encodings."""
    lowered = data.lower()
    return any(marker.lower().encode(enc) in lowered for enc in ("utf-8", "utf-16-le", "utf-16-be"))


class Inspector:
    def __init__(self, cfg: Config, ocr: OcrEngine | None = None) -> None:
        self.cfg = cfg
        self.ocr = ocr or OcrEngine()

    # -- prompts ---------------------------------------------------------------------------------
    def inspect_prompt(self, text: str) -> Report:
        return Report("prompt", ["prompt text"] if contains_marker(text, self.cfg.marker) else [])

    # -- files -----------------------------------------------------------------------------------
    def inspect_file(self, name: str, data: bytes, mime: str = "") -> Report:
        kind = sniff_kind(name, data, mime)
        try:
            if kind == "pdf":
                return self._pdf(data)
            if kind == "image":
                return self._image(data)
            if kind == "text":
                found = contains_marker(decode_text(data), self.cfg.marker)
                return Report("text", ["file text"] if found else [])
            found = _raw_bytes_contain(data, self.cfg.marker)
            return Report("other", ["file bytes"] if found else [])
        except Exception as exc:  # corrupt or hostile files must not crash the agent
            log.exception("inspecting %s failed", name)
            report = Report(kind, error=f"{type(exc).__name__}: {exc}")
            if _raw_bytes_contain(data, self.cfg.marker):
                report.findings.append("file bytes")
            return report

    def _ocr_contains(self, image: Image.Image) -> bool:
        """OCR once as-is (upscaled if small), then once more in high-contrast greyscale."""
        image = ImageOps.exif_transpose(image)
        if image.mode not in ("RGB", "L"):
            background = Image.new("RGB", image.size, "white")
            rgba = image.convert("RGBA")
            background.paste(rgba, mask=rgba.split()[-1])
            image = background
        short = min(image.size)
        if short < 400:
            factor = min(4, max(2, 800 // max(short, 1)))
            image = image.resize((image.width * factor, image.height * factor), Image.LANCZOS)
        text = self.ocr.read_text(image)
        log.debug("OCR pass 1: %r", text[:500])
        if contains_marker_fuzzy(text, self.cfg.marker):
            return True
        enhanced = ImageOps.autocontrast(ImageOps.grayscale(image), cutoff=2)
        text = self.ocr.read_text(enhanced)
        log.debug("OCR pass 2: %r", text[:500])
        if contains_marker_fuzzy(text, self.cfg.marker):
            return True
        # Light text on a dark background.
        text = self.ocr.read_text(ImageOps.invert(enhanced))
        return contains_marker_fuzzy(text, self.cfg.marker)

    def _image(self, data: bytes) -> Report:
        report = Report("image")
        if _raw_bytes_contain(data, self.cfg.marker):  # e.g. in PNG tEXt or EXIF metadata
            report.findings.append("image metadata")
            return report
        try:
            image = Image.open(io.BytesIO(data))
            image.seek(0)  # first frame of an animated GIF/WebP
            image.load()
        except (UnidentifiedImageError, OSError) as exc:
            report.error = f"unsupported or corrupt image ({exc})"
            return report
        try:
            if self._ocr_contains(image):
                report.findings.append("text in image (OCR)")
        except OcrUnavailable as exc:
            report.error = str(exc)
        return report

    def _pdf(self, data: bytes) -> Report:
        from pypdf import PdfReader

        report = Report("pdf")
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted and not reader.decrypt(""):
            report.error = "PDF is password-protected"
            return report
        marker = self.cfg.marker

        meta = " ".join(str(v) for v in (reader.metadata or {}).values())
        if contains_marker(meta, marker):
            report.findings.append("document metadata")
            return report
        fields = reader.get_fields() or {}
        if any(contains_marker(f"{k} {v.get('/V', '')}", marker) for k, v in fields.items()):
            report.findings.append("form field")
            return report

        errors: list[str] = []
        image_budget = self.cfg.pdf_max_ocr_images
        for number, page in enumerate(reader.pages, start=1):
            try:
                if contains_marker(page.extract_text() or "", marker):
                    report.findings.append(f"page {number} text")
                    return report
                for annot in page.get("/Annots") or []:
                    contents = annot.get_object().get("/Contents")
                    if contents and contains_marker(str(contents), marker):
                        report.findings.append(f"page {number} comment")
                        return report
            except Exception as exc:
                errors.append(f"page {number}: {exc}")
                continue
            # Scanned pages carry their text only as pictures.
            try:
                images = page.images
            except Exception as exc:
                errors.append(f"page {number} images: {exc}")
                continue
            for index, embedded in enumerate(images, start=1):
                if image_budget <= 0:
                    errors.append(f"stopped OCR after {self.cfg.pdf_max_ocr_images} embedded images")
                    break
                image_budget -= 1
                try:
                    if self._ocr_contains(embedded.image):
                        report.findings.append(f"page {number} image {index} (OCR)")
                        return report
                except OcrUnavailable as exc:
                    errors.append(str(exc))
                    image_budget = 0
                    break
                except Exception as exc:
                    errors.append(f"page {number} image {index}: {exc}")
        if errors:
            report.error = "; ".join(dict.fromkeys(errors))
        return report
