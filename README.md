# Walled DLP

A standalone desktop app that works as a lightweight data loss prevention (DLP) tool for **ChatGPT** (chatgpt.com) and **Perplexity** (perplexity.ai), used in your normal web browser. **Nothing is installed in the browser**: no extension, plugin or add-on.

- It checks every **text prompt** and **file upload** (text, PDF, images) for the marker `WALLED_SENSITIVE` **before it leaves your computer**.
- If the marker is found, a **native desktop dialog** says whether it was a prompt or a file, shows the prompt excerpt or file name, and asks **Continue** or **Cancel**.
  - **Continue** sends the prompt or file exactly as it was.
  - **Cancel** blocks it. The site shows its usual error, your text stays in the box, and you can edit and send again (or pick the file again).
- Prompts and files without the marker go through with no interaction.
- **AI responses are recoloured** (violet by default) on both sites. Your own messages keep their colour.
- It also closes two quieter leaks: Perplexity sends what you type to its suggestion service on every keystroke, and both sites copy your prompt into analytics events. Copies carrying the marker never leave unless you chose Continue for that prompt.

## How it works

Walled DLP runs a small **inspection proxy on your own computer** (127.0.0.1). A proxy auto-config (PAC) script sends **only** the ChatGPT and Perplexity hosts to it; every other site goes direct and is never touched. For those hosts the proxy completes HTTPS itself, using a certificate authority generated on your machine and limited (by X.509 name constraints) to those domains. It reads each request, inspects any text and files, shows the dialog when needed, and then forwards or blocks the request.

```
 Browser (Chrome, Edge, Brave, Firefox)            Walled DLP desktop app (127.0.0.1:8899)            Internet
┌───────────────────────────────┐  ChatGPT /  ┌────────────────────────────────────────┐
│ chatgpt.com / perplexity.ai   │ Perplexity  │ TLS with the local CA                  │  allowed   chatgpt.com
│ (unchanged web apps)          │ ──────────▶ │ find text & files in the request       │ ─────────▶ perplexity.ai
│                               │             │ inspect: text, PDF, OCR for images     │            upload hosts
│ every other site: direct ─────┼──────────── │ marker? ─▶ native Continue/Cancel      │
└───────────────────────────────┘             │ pages: add the response-colour style   │
                                              └────────────────────────────────────────┘
```

Because the check happens on the network request, every way of sending is covered by construction: Enter, the Send button, voice-to-text, file picker, drag and drop, paste, and anything the sites add later. See [ARCHITECTURE.md](ARCHITECTURE.md) for the design, the wire formats of both sites and how decisions are made.

## Requirements

- Python **3.10–3.12** (RapidOCR's wheels don't support 3.13 yet). Tk is used for the app window; it ships with python.org and most distribution Pythons (`sudo apt install python3-tk` if missing).
- A Chromium-based browser (Chrome, Edge, Brave, Chromium) or Firefox.
- Linux: `zenity` for the dialogs (preinstalled on GNOME; `kdialog` on KDE also works) and `certutil` to trust the certificate (`sudo apt install libnss3-tools`, or `sudo dnf install nss-tools`). macOS and Windows need nothing extra.
- For the browser tests only: Node.js 22+ and Google Chrome.

## Setup

### 1. Install

```bash
git clone https://github.com/<you>/walled-dlp.git && cd walled-dlp
```

```bash
python3 -m venv .venv && . .venv/bin/activate
```

```bash
pip install -e .
```

On Windows, use `py -3.12 -m venv .venv` and `.venv\Scripts\activate`.

### 2. Open the app and connect your browser

```bash
walled-dlp
```

The window opens and protection starts. To open it from your app menu from now on, run `walled-dlp launcher` once (Linux). Click **Connect browser** once. That does two things, both for your user account only, and **Disconnect** undoes both:

1. **Trusts the Walled DLP certificate**, so the browser accepts the proxy's certificates for ChatGPT and Perplexity.
   - Linux: Chrome/Chromium/Brave's and Firefox's certificate databases, via `certutil`.
   - macOS: your login keychain (macOS asks for your password).
   - Windows: your user certificate store (Windows asks you to confirm).
2. **Sets the proxy auto-config** in your system proxy settings, which Chrome, Edge, Brave and (by default) Firefox follow.
   - Linux: GNOME or KDE settings.
   - macOS: each network service.
   - Windows: Internet Settings.

The same from a terminal: `walled-dlp setup` (and `walled-dlp setup --undo`).

**Then restart your browser.** The window shows *Browser routing: On* and *Certificate: Trusted*.

> If `certutil` isn't installed, Walled DLP says so. You can also import the certificate by hand: in Chrome, open **Settings → Privacy and security → Security → Manage certificates → Custom → Installed by you → Import**, choose `walled-dlp-ca.pem` (**Show certificate** in the app opens its folder), and tick *Trust for identifying websites*.

### 3. Keep it running

Leave the window open (minimised is fine). On Linux the PAC script is installed inline, so **while Walled DLP isn't running, ChatGPT and Perplexity won't load**. That way they can never be reached uninspected. Click **Disconnect** (or run `walled-dlp setup --undo`) to stop using it. To protect without a window (for example as a login service), run `walled-dlp run`.

## Usage

Use ChatGPT and Perplexity as usual.

| You do | What happens |
|---|---|
| Send a prompt without the marker | Sent immediately, with no interaction |
| Send a prompt containing `WALLED_SENSITIVE` | Native dialog: *Sensitive content detected in a text prompt*, with the site and the prompt excerpt |
| Upload a text, PDF or image file containing the marker (picker, drag and drop, paste) | Native dialog: *Sensitive content detected in a file upload*, with the file name, type, size and where the marker was found (for example `page 1 text`, `text in image (OCR)`) |
| Choose **Continue** | The original prompt or file is sent unchanged |
| Choose **Cancel** | Nothing is sent. ChatGPT and Perplexity keep your text in the box so you can edit and resend; uploads show *Failed to upload* and can be retried |
| Read an AI response | Its text is violet. Change the colour in the app (reload open tabs to apply) |

The **Recent activity** list in the app shows every intervention. An audit trail is written to `events.jsonl` in the data directory (`~/.local/share/walled-dlp/` on Linux). It records the site, file names and decisions, and **never prompt text or file contents**.

### Try it with the sample files

`samples/` has a clean and a sensitive version of each type:

| File | Contains marker | How it's found |
|---|---|---|
| `clean-notes.txt` / `sensitive-notes.txt` | – / ✓ | text |
| `clean-report.pdf` / `sensitive-report.pdf` | – / ✓ | PDF text layer |
| `sensitive-scanned.pdf` | ✓ | OCR of the scanned page |
| `clean-screenshot.png` / `sensitive-screenshot.png` | – / ✓ | OCR |
| `sensitive-darkmode.jpg` | ✓ | OCR (light text on dark) |

Regenerate them with `python scripts/make_samples.py`. Check any file from the terminal with the same inspection an upload gets:

```bash
walled-dlp check samples/*
```

Logged out, ChatGPT accepts image uploads only and Perplexity asks you to sign in before any upload, so sign in to try PDFs and text files.

## Commands

| Command | What it does |
|---|---|
| `walled-dlp` | Open the app (starts protection) |
| `walled-dlp run` | Protect without a window |
| `walled-dlp setup` / `setup --undo` | Connect / disconnect the browser (certificate + proxy auto-config) |
| `walled-dlp launcher` / `launcher --remove` | Add Walled DLP to the app menu (Linux), so it opens without a terminal |
| `walled-dlp status` | Configuration, certificate fingerprint and trust, proxy settings, dialog backends, OCR engine |
| `walled-dlp check FILES… [--text T] [--ask]` | Inspect files or text; `--ask` shows the real dialog |
| `walled-dlp dialog-test` | Show a sample confirmation dialog |

## Configuration

Optional. Create `~/.config/walled-dlp/config.json` (`%LOCALAPPDATA%\walled-dlp\config.json` on Windows, `~/Library/Application Support/walled-dlp/config.json` on macOS). Every key can also be set as an environment variable `WALLED_DLP_<KEY>`.

```json
{
  "marker": "WALLED_SENSITIVE",
  "port": 8899,
  "response_color": "",
  "max_file_mb": 25,
  "on_inspection_error": "ask",
  "dialog_backend": "auto",
  "dialog_timeout": 300,
  "pdf_max_ocr_images": 20
}
```

| Key | Meaning |
|---|---|
| `marker` | Text to look for (case-insensitive; OCR matching tolerates `0/O`, `1/I`, missing `_`) |
| `port` | Local proxy port. Run **Connect browser** again after changing it |
| `response_color` | CSS colour for AI responses, e.g. `#0f766e`. Empty: violet, lighter on dark themes |
| `max_file_mb` | Larger uploads aren't inspected and fall under `on_inspection_error` |
| `on_inspection_error` | Uploads that can't be inspected (too large, corrupt, password-protected): `ask` shows a dialog explaining why; `allow`; `block` |
| `dialog_backend` | `auto`, `zenity`, `kdialog`, `osascript` or `tk` |
| `dialog_timeout` | Seconds before an unanswered dialog counts as Cancel (`0` = wait forever) |

Logs: `agent.log` in the data directory.

## Tests

```bash
pip install -e ".[dev]"
```

```bash
pytest
```

```bash
npm run test:e2e
```

- **`pytest`** (107 tests, about 30 s):
  - `test_content.py`: finding the marker in the real wire formats (JSON, nested JSON in form fields, multipart, query strings, raw uploads).
  - `test_guard.py`: one dialog per piece of content, copies follow the decision, Cancel never blocks a deliberate resend, side channels, files, the audit log.
  - `test_proxy.py`: the proxy over **real sockets and real TLS** verified against the local CA, with a fake upstream that records what got through. Covers prompts, streaming, uploads (including file names learned from the create-upload call), Perplexity's Cloudinary uploads, fail-closed upload destinations, page recolouring and CSP, WebSocket typeahead filtering, tunnelling of other hosts, and the PAC.
  - `test_certs_system.py`: the CA, its name constraints (OpenSSL rejects a certificate it signs for another site), site routing, and the setup commands for GNOME, NSS, macOS and Windows (with a fake shell).
  - `test_inspector.py`, `test_dialogs.py`: inspection of every file type, and the dialog backends.
- **`npm run test:e2e`** (13 tests, about 25 s, no npm dependencies; needs Node 22+ and Google Chrome) runs **real Chrome** routed by PAC through the **real Walled DLP app** to local stand-ins for both sites. The stand-ins reproduce the requests the real apps make, as captured from the live sites. Only the dialog answer is scripted (a fake `zenity` on `PATH`). Covers every acceptance criterion: prompts with and without the marker, Cancel keeping the text, Continue sending it unchanged, text/PDF/image uploads, mixed selections, typeahead, analytics copies, response colour and the audit log.
- **`npm run test:live`** runs opt-in smoke tests against the **real** chatgpt.com and perplexity.ai, logged out. They cover Cancel, edit and Continue, response colour, Perplexity's typeahead, and ChatGPT image uploads with OCR. ChatGPT blocks headless Chrome, so that test opens a visible window.

## Limitations

- **Browsers must use the system proxy settings.** Chrome, Edge, Brave and Firefox do by default. A browser configured with its own proxy, or started with `--no-proxy-server`, bypasses Walled DLP. In a managed deployment, push the PAC URL and the certificate through browser policy (`ProxySettings`, certificate policies) and run Walled DLP as a login service.
- **Connect browser replaces your current proxy configuration** (it is saved and restored on Disconnect). Chaining to an existing corporate proxy isn't supported.
- **macOS and Windows** fetch the PAC from `http://127.0.0.1:8899/proxy.pac`. If Walled DLP isn't running there, browsers fall back to direct connections. Linux installs the PAC inline and fails closed.
- **What the sites send is matched by content**, not by endpoint, so API changes don't open a hole. The list of background endpoints (analytics, typeahead) in `walled_dlp/sites.py` only decides which requests stay silent; an unlisted endpoint carrying the marker raises a dialog. If a site starts uploading to a storage host Walled DLP doesn't know, those uploads are refused (with an entry in Recent activity) rather than let through uninspected.
- **WebSocket messages** carrying the marker are dropped unless that text was already approved. Neither site sends prompts over WebSockets today (Perplexity uses one for typeahead).
- **Response colour** relies on each site's markup (`walled_dlp/sites.py`). A redesign may need new selectors; the live tests show when that happens.
- OCR accuracy depends on the image. Very small, blurred or stylised text can be missed.
- Verified on Linux (GNOME, Chrome 158). The macOS and Windows code paths for certificate trust, proxy settings and dialogs are written to each platform's documented tools and covered by unit tests with a fake shell, but haven't been run on those systems.

## License

MIT
