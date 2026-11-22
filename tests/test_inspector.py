import io

import pytest
from PIL import Image

from support import SAMPLES, requires_ocr
from walled_dlp.detector import contains_marker, contains_marker_fuzzy, excerpt_around
from walled_dlp.inspector import Inspector, decode_text, sniff_kind

M = "WALLED_SENSITIVE"


# -- detector ------------------------------------------------------------------------------------
@pytest.mark.parametrize("text", [M, f"please summarise {M} now", "walled_sensitive", f"x{M}y"])
def test_exact_match(text):
    assert contains_marker(text, M)


@pytest.mark.parametrize("text", ["", "WALLED SENSITIVE", "WALLED_SENSITIV", "sensitive walled"])
def test_exact_no_match(text):
    assert not contains_marker(text, M)


@pytest.mark.parametrize("ocr_text", ["WALLED_SENSITIVE", "WALLED SENSITIVE", "WALLED_SENS1TIVE", "WA LLED_\nSENSITIVE", "wa11ed sensitive", "WALLED_5ENSITIVE"])
def test_fuzzy_match_tolerates_ocr_noise(ocr_text):
    assert contains_marker_fuzzy(ocr_text, M)


@pytest.mark.parametrize("ocr_text", ["WALLED", "SENSITIVE WALLED", "Classification: internal"])
def test_fuzzy_no_match(ocr_text):
    assert not contains_marker_fuzzy(ocr_text, M)


def test_excerpt_centres_on_marker():
    text = "a " * 500 + M + " b" * 500
    snippet = excerpt_around(text, M, limit=80)
    assert M in snippet and len(snippet) <= 82 and snippet.startswith("…") and snippet.endswith("…")


# -- type sniffing / decoding --------------------------------------------------------------------
def test_sniff_by_magic_beats_extension():
    assert sniff_kind("notes.txt", b"%PDF-1.7 ...") == "pdf"
    assert sniff_kind("photo.pdf", b"\x89PNG\r\n\x1a\n....") == "image"
    assert sniff_kind("data.bin", b"plain ascii text") == "text"
    assert sniff_kind("blob.bin", bytes(range(256)) * 4) == "other"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "latin-1"])
def test_decode_text_encodings(encoding):
    text = f"héllo {M} wörld"
    assert M in decode_text(text.encode(encoding))


# -- files -------------------------------------------------------------------------------------
@pytest.fixture
def inspector(cfg, ocr):
    return Inspector(cfg, ocr)


@pytest.mark.parametrize("name,expected", [("clean-notes.txt", False), ("sensitive-notes.txt", True), ("clean-report.pdf", False), ("sensitive-report.pdf", True)])
def test_text_and_pdf_samples(inspector, name, expected):
    report = inspector.inspect_file(name, (SAMPLES / name).read_bytes())
    assert report.detected is expected
    assert report.error is None


def test_prompt(inspector):
    assert inspector.inspect_prompt(f"Summarise {M}").detected
    assert not inspector.inspect_prompt("Summarise the memo").detected


def test_utf16_text_file(inspector):
    data = f"meeting notes\n{M}\n".encode("utf-16")
    assert inspector.inspect_file("notes.txt", data).findings == ["file text"]


def test_marker_in_unknown_binary_format(inspector):
    data = b"\x00\x01binary" + M.encode() + b"\xff\xfe"
    assert inspector.inspect_file("blob.dat", data).detected


def test_corrupt_pdf_reports_error_not_crash(inspector):
    report = inspector.inspect_file("broken.pdf", b"%PDF-1.4\nthis is not really a pdf")
    assert not report.detected and report.error


def test_corrupt_image_reports_error(inspector):
    report = inspector.inspect_file("broken.png", b"\x89PNG\r\n\x1a\nnope")
    assert not report.detected and "image" in report.error


def test_marker_in_png_metadata(inspector):
    from PIL.PngImagePlugin import PngInfo

    meta = PngInfo()
    meta.add_text("Comment", M)
    buf = io.BytesIO()
    Image.new("RGB", (10, 10), "white").save(buf, "PNG", pnginfo=meta)
    assert inspector.inspect_file("blank.png", buf.getvalue()).findings == ["image metadata"]


def test_marker_in_pdf_metadata(inspector):
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(200, 200)
    writer.add_metadata({"/Subject": M})
    buf = io.BytesIO()
    writer.write(buf)
    assert inspector.inspect_file("meta.pdf", buf.getvalue()).findings == ["document metadata"]


@requires_ocr
@pytest.mark.parametrize("name,expected", [
    ("clean-screenshot.png", False),
    ("sensitive-screenshot.png", True),
    ("sensitive-darkmode.jpg", True),
])
def test_image_samples(inspector, name, expected):
    report = inspector.inspect_file(name, (SAMPLES / name).read_bytes())
    assert report.detected is expected, report
    assert report.error is None


@requires_ocr
def test_scanned_pdf_uses_ocr(inspector):
    report = inspector.inspect_file("sensitive-scanned.pdf", (SAMPLES / "sensitive-scanned.pdf").read_bytes())
    assert report.findings == ["page 1 image 1 (OCR)"]


@requires_ocr
def test_small_image_is_upscaled_for_ocr(inspector):
    from PIL import ImageDraw, ImageFont

    image = Image.new("RGB", (260, 40), "white")
    ImageDraw.Draw(image).text((6, 10), M, fill="black", font=ImageFont.load_default(size=18))
    buf = io.BytesIO()
    image.save(buf, "PNG")
    assert inspector.inspect_file("tiny.png", buf.getvalue()).detected


def test_image_without_ocr_is_an_error_not_a_pass(cfg):
    from walled_dlp.ocr import OcrUnavailable

    class NoOcr:
        backend_name = None

        def read_text(self, image):
            raise OcrUnavailable("no OCR engine available")

    report = Inspector(cfg, NoOcr()).inspect_file("x.png", (SAMPLES / "clean-screenshot.png").read_bytes())
    assert not report.detected and "OCR" in report.error
