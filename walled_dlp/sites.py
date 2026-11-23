"""Everything specific to ChatGPT and Perplexity lives here.

The proxy finds the marker by content, wherever it appears in a request, so a site changing its
API endpoints doesn't open a hole. What this file adds is:

* which hosts carry each site's traffic (only these are routed to the proxy and decrypted);
* which requests are background side channels (analytics, typeahead, telemetry) rather than the
  user sending something. Those never raise a dialog of their own: they follow the user's decision
  on the matching prompt, and are withheld silently if there is none;
* where the file name of a direct-to-storage upload can be found;
* CSS selectors for AI responses, for recolouring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Site:
    key: str
    name: str
    # Host suffixes: "chatgpt.com" matches chatgpt.com and any subdomain.
    hosts: tuple[str, ...]
    # Hosts whose request bodies are file uploads (signed storage URLs).
    upload_hosts: tuple[str, ...] = ()
    # Upload hosts shared with other websites: only these path prefixes belong to this site, the rest
    # is passed through unchanged.
    upload_paths: tuple[tuple[str, str], ...] = ()
    # Regexes matched against "host/path" of background requests.
    side_channels: tuple[str, ...] = ()
    # Hosts that serve the app's HTML pages (response colour CSS goes in here).
    page_hosts: tuple[str, ...] = ()
    # CSS selectors for AI response text, and for user text inside them to leave alone.
    response_selectors: tuple[str, ...] = ()
    _side: tuple[re.Pattern, ...] = field(default=(), init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_side", tuple(re.compile(p, re.I) for p in self.side_channels))

    def owns(self, host: str) -> bool:
        return _matches(host, self.hosts + self.upload_hosts)

    def is_upload_host(self, host: str) -> bool:
        return _matches(host, self.upload_hosts)

    def is_foreign(self, host: str, path: str) -> bool:
        """True for traffic on a shared upload host that belongs to some other website."""
        host = host.lower().split(":")[0]
        prefixes = [p for h, p in self.upload_paths if h == host]
        return bool(prefixes) and not any(path.startswith(p) for p in prefixes)

    def is_side_channel(self, host: str, path: str) -> bool:
        target = f"{host}{path}"
        return any(p.search(target) for p in self._side)

    def is_page_host(self, host: str) -> bool:
        return host in self.page_hosts


def _matches(host: str, suffixes: tuple[str, ...]) -> bool:
    host = host.lower().split(":")[0]
    return any(host == s or host.endswith("." + s) for s in suffixes)


CHATGPT = Site(
    key="chatgpt",
    name="ChatGPT",
    hosts=("chatgpt.com", "chat.openai.com"),
    # Uploads: POST /backend-api/files (name, size) returns a signed URL on filesNN.oaiusercontent.com,
    # then the browser PUTs the raw bytes there.
    upload_hosts=("oaiusercontent.com",),
    side_channels=(
        r"^ab\.chatgpt\.com/",
        r"/ces/",  # telemetry
        r"/events/",  # analytics (unauth-mweb/events/business, statsc, performance, page-view)
        r"/sentinel/",  # bot protection
        r"/lat/r",  # latency beacons
        r"/conversation/prepare",  # warm-up sent while you type
        r"/rgstr",
        r"/cdn-cgi/",
    ),
    page_hosts=("chatgpt.com", "chat.openai.com"),
    response_selectors=(
        # Signed-in app (current): each turn has a hidden <h4 data-conversation-role="assistant">
        # label with the answer (div[data-response-body]) next to it, so colour what follows it.
        '[data-conversation-role="assistant"] ~ *',
        '[data-conversation-role="assistant"] ~ * *',
        # Signed-in app (older message view, still in the code): the role is on the turn wrapper.
        '[data-message-author-role="assistant"]',
        '[data-message-author-role="assistant"] *',
        # Logged-out / mobile web app
        '[data-message-role="assistant"] [data-assistant-markdown]',
        '[data-message-role="assistant"] [data-assistant-markdown] *',
    ),
)

PERPLEXITY = Site(
    key="perplexity",
    name="Perplexity",
    hosts=("perplexity.ai",),
    # Uploads: POST /rest/uploads/create_upload_url (filename, size) returns `s3_bucket_url` and form
    # `fields`; the browser then POSTs the file as multipart to that URL: Perplexity's Cloudinary
    # account for images, S3 for documents.
    upload_hosts=("ppl-ai-file-upload.s3.amazonaws.com", "api.cloudinary.com"),
    upload_paths=(("api.cloudinary.com", "/v1_1/pplx/"),),
    side_channels=(
        r"^suggest\.perplexity\.ai/",  # typeahead: every keystroke, plus /search/v2/navigate
        r"^count\.perplexity\.ai/",
        r"/rest/event/",  # analytics: "submit query", "query first server response", ...
        r"/rest/autosuggest/",
        r"/cdn-cgi/",
    ),
    page_hosts=("www.perplexity.ai", "perplexity.ai"),
    response_selectors=(
        # The answer is rendered by the "lm" renderer; the user's own question uses the same
        # renderer inside a message bubble, so that is excluded.
        '[data-renderer="lm"]:not([data-message-bubble] *)',
        '[data-renderer="lm"]:not([data-message-bubble] *) *',
        '[id^="markdown-content-"]',
        '[id^="markdown-content-"] *',
    ),
)

SITES: tuple[Site, ...] = (CHATGPT, PERPLEXITY)


def site_for(host: str) -> Site | None:
    for site in SITES:
        if site.owns(host):
            return site
    return None


def all_hosts() -> list[str]:
    out: list[str] = []
    for site in SITES:
        out.extend(site.hosts + site.upload_hosts)
    return out
