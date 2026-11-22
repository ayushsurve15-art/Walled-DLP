"""Generate the demo and test files in samples/.

    python scripts/make_samples.py

Each type (text, PDF, image) comes in a clean version and one that contains the marker. The marker
sits mid-document so a check that only reads the start of a file would miss it.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent.parent / "samples"
MARKER = "WALLED_SENSITIVE"

MEMO = [
    "Q3 planning notes",
    "",
    "Revenue grew 14% quarter on quarter, led by the enterprise tier.",
    "Hiring plan: four engineers and one designer before December.",
    "{marker}",
    "Next review is scheduled for the first week of the new quarter.",
]


def memo(sensitive: bool) -> list[str]:
    tag = f"Classification: {MARKER}" if sensitive else "Classification: internal"
    return [line.format(marker=tag) for line in MEMO]


def text_pdf(lines: list[str]) -> bytes:
    """A minimal one-page PDF with real (selectable) text, written by hand to avoid a dependency."""
    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    stream = ["BT", "/F1 14 Tf", "72 760 Td", "20 TL"]
    stream += [f"({esc(line)}) Tj T*" for line in lines]
    stream.append("ET")
    content = "\n".join(stream).encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % off for off in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)


def render(lines: list[str], width: int = 1100, size: int = 30, dark: bool = False) -> Image.Image:
    font = ImageFont.load_default(size=size)
    line_h = int(size * 1.6)
    image = Image.new("RGB", (width, 80 + line_h * len(lines)), "#1e1e2e" if dark else "white")
    draw = ImageDraw.Draw(image)
    for i, line in enumerate(lines):
        draw.text((50, 40 + i * line_h), line, fill="#e0e0f0" if dark else "#202020", font=font)
    return image


def main() -> int:
    OUT.mkdir(exist_ok=True)
    for sensitive in (False, True):
        name = "sensitive" if sensitive else "clean"
        lines = memo(sensitive)
        (OUT / f"{name}-notes.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        (OUT / f"{name}-report.pdf").write_bytes(text_pdf(lines))
        render(lines).save(OUT / f"{name}-screenshot.png")
    # Harder cases: a scanned PDF (text only as a picture) and a dark-mode photo-like JPEG.
    render(memo(True), width=1240, size=34).save(OUT / "sensitive-scanned.pdf", "PDF", resolution=150)
    render(memo(True), dark=True).save(OUT / "sensitive-darkmode.jpg", quality=85)
    for path in sorted(OUT.iterdir()):
        print(path.relative_to(OUT.parent))
    return 0


if __name__ == "__main__":
    sys.exit(main())
