"""Response colour: the stylesheet, streaming injection into HTML, and CSP handling."""

import gzip

from walled_dlp.http1 import Headers
from walled_dlp.pagestyle import HtmlInjector, adjust_csp, prepare_page_response, stylesheet


def test_stylesheet_targets_both_sites_and_skips_user_bubbles():
    css = stylesheet()
    assert '[data-message-author-role="assistant"] .markdown' in css
    assert '[data-message-role="assistant"] [data-assistant-markdown]' in css
    assert '[data-renderer="lm"]:not([data-message-bubble] *)' in css
    assert "#6d28d9" in css and "#c4b5fd" in css


def test_custom_colour_and_rejects_injection():
    assert "#0f766e" in stylesheet("#0f766e") and "#c4b5fd" not in stylesheet("#0f766e")
    hostile = stylesheet("red}body{display:none")
    assert "display:none" not in hostile and "#6d28d9" in hostile  # invalid colours fall back to the default


def test_injects_after_head_across_chunk_boundaries():
    inj = HtmlInjector("x{}")
    page = b"<!DOCTYPE html><html><he" + b"ad lang='en'><title>t</title></head><body>hi</body></html>"
    out = inj.feed(page[:20]) + inj.feed(page[20:40]) + inj.feed(page[40:]) + inj.finish()
    assert out.startswith(b"<!DOCTYPE html><html><head lang='en'><style id=\"walled-dlp-response-color\">")
    assert out.endswith(b"<title>t</title></head><body>hi</body></html>")


def test_no_head_leaves_page_alone():
    inj = HtmlInjector("x{}")
    assert inj.feed(b"plain") == b"" and inj.finish() == b"plain"


def test_csp_nonce_only_where_needed():
    assert adjust_csp("base-uri 'none'; object-src 'none'", "N") == "base-uri 'none'; object-src 'none'"
    assert adjust_csp("style-src 'self'", "N") == "style-src 'self' 'nonce-N'"
    # 'unsafe-inline' already allows it; adding a nonce would switch 'unsafe-inline' off
    assert adjust_csp("style-src 'self' 'unsafe-inline'", "N") == "style-src 'self' 'unsafe-inline'"
    assert adjust_csp("default-src 'self'", "N") == "default-src 'self'; style-src 'self' 'nonce-N'"


def test_prepare_decodes_gzip_and_fixes_headers():
    h = Headers([("content-type", "text/html"), ("content-encoding", "gzip"), ("content-length", "99"), ("content-security-policy", "style-src 'self'")])
    feed, finish = prepare_page_response(h, "x{}")
    body = gzip.compress(b"<html><head></head><body></body></html>")
    out = feed(body[:10]) + feed(body[10:]) + finish()
    assert b"<style id=\"walled-dlp-response-color\" nonce=" in out
    assert not h.get("content-encoding") and not h.get("content-length")
    assert "'nonce-" in h.get("content-security-policy")


def test_prepare_skips_brotli():
    assert prepare_page_response(Headers([("content-encoding", "br")]), "x{}") is None
