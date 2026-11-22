"""Finding the marker in requests, whatever the encoding. Bodies are modelled on real captures."""

import json
from urllib.parse import urlencode

from walled_dlp.content import marker_strings, split_request
from walled_dlp.http1 import Headers, Request

M = "WALLED_SENSITIVE"


def req(body=b"", ct="application/json", target="/api", method="POST", host="chatgpt.com"):
    h = Headers([("content-type", ct)] if ct else [])
    return Request(method, target, "HTTP/1.1", h, body, host)


def test_chatgpt_signed_in_json():
    body = json.dumps({
        "action": "next",
        "messages": [{"id": "1", "author": {"role": "user"}, "content": {"content_type": "text", "parts": [f"Summarise the {M} deck"]}}],
        "model": "auto",
    }).encode()
    assert split_request(req(body), M).texts == [f"Summarise the {M} deck"]


def test_chatgpt_logged_out_form_with_nested_json():
    state = json.dumps({"messages": [{"content": f"earlier {M} turn"}], "parentMessageId": "root"})
    body = urlencode({"conversationState": state, "prompt": f"Reply with one word: is {M} a colour?", "imageAttachments": "[]"}).encode()
    texts = split_request(req(body, "application/x-www-form-urlencoded;charset=UTF-8"), M).texts
    assert f"Reply with one word: is {M} a colour?" in texts
    assert f"earlier {M} turn" in texts


def test_perplexity_ask_and_analytics():
    ask = json.dumps({"params": {"attachments": [], "frontend_uuid": "x"}, "query_str": f"what is {M} data"}).encode()
    assert split_request(req(ask, "application/json"), M).texts == [f"what is {M} data"]
    event = json.dumps({"event_name": "submit query", "event_data": {"queryStr": f"what is {M} data", "n": 1}}).encode()
    assert split_request(req(event, "application/json; charset=utf-8"), M).texts == [f"what is {M} data"]


def test_case_insensitive_and_escaped():
    assert marker_strings('{"q": "x walled_sensitive y"}', M) == ["x walled_sensitive y"]
    assert marker_strings('{"q": "\\u0057ALLED_SENSITIVE"}', M) == ["WALLED_SENSITIVE"]


def test_text_plain_and_query_string():
    assert split_request(req(f"hello {M}".encode(), "text/plain;charset=UTF-8"), M).texts == [f"hello {M}"]
    r = req(b"", None, target=f"/search?q=what+is+{M}&s=1", method="GET")
    assert split_request(r, M).texts == [f"what is {M}"]


def test_no_marker_no_texts():
    body = json.dumps({"messages": [{"content": "What is the capital of France?"}]}).encode()
    assert split_request(req(body), M).texts == []


def test_multipart_upload():
    boundary = "----x"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/abc\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\nContent-Type: text/plain\r\n\r\n"
        f"secret {M} stuff\r\n--{boundary}--\r\n"
    ).encode()
    p = split_request(req(body, f"multipart/form-data; boundary={boundary}"), M)
    assert [(f.name, f.mime, f.data) for f in p.files] == [("notes.txt", "text/plain", f"secret {M} stuff".encode())]
    assert p.texts == []


def test_binary_body_is_a_file():
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
    p = split_request(req(png, "image/png", target="/file-abc?sig=1", method="PUT", host="files07.oaiusercontent.com"), M)
    assert [(f.name, f.mime) for f in p.files] == [("file-abc", "image/png")]


def test_upload_host_text_body_is_a_file_with_learned_name():
    p = split_request(req(f"{M}".encode(), "text/plain", method="PUT"), M, upload_host=True, file_name="notes.txt")
    assert [f.name for f in p.files] == ["notes.txt"] and p.texts == []


def test_long_strings_are_cut_around_marker():
    text = "a" * 20000 + M + "b" * 20000
    (s,) = split_request(req(json.dumps({"q": text}).encode()), M).texts
    assert M in s and len(s) <= 8000
