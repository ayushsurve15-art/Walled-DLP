# Demo script (about 5 minutes)

A shot list for the screen recording. It covers every acceptance criterion in the brief, on both sites, and makes the point that nothing is installed in the browser.

## Before recording

1. Install: `pip install -e .` (see the README). On Linux also `sudo apt install libnss3-tools` so the certificate can be trusted automatically.
2. Run `walled-dlp`, click **Connect browser**, then **quit and reopen Chrome**. The app should show *Browser routing: On* and *Certificate: Trusted*.
3. **Sign in** to ChatGPT and Perplexity in Chrome. Logged out, ChatGPT accepts images only and Perplexity asks you to sign in before any upload.
4. Open two tabs (chatgpt.com and perplexity.ai) and a file manager on `samples/`.
5. Run `walled-dlp dialog-test` once, so the first real dialog isn't the first one you've seen.
6. Check that a Perplexity upload of `samples/sensitive-notes.txt` raises the dialog. If it doesn't, look in Chrome DevTools (Network tab) for the host the file is POSTed to and add it to `upload_hosts` in `walled_dlp/sites.py`. Uploads were only checked logged out (ChatGPT) and from Perplexity's front-end code.

## Shot list

| # | Where | Action | What to show / say |
|---|---|---|---|
| 1 | Chrome | Open `chrome://extensions` | No extensions. Nothing is installed in the browser |
| 2 | Walled DLP window | Show it | "Protecting ChatGPT and Perplexity", browser routing on, certificate trusted. One line on the architecture: a local inspection proxy that only sees these two sites; every other site goes direct |
| 3 | ChatGPT | Send `What is the capital of France?` | Sent immediately, no dialog (**prompt without the marker**). The answer text is **violet** (**response colour**); your message isn't |
| 4 | ChatGPT | Type `Summarise the WALLED_SENSITIVE Q3 board deck` and press Enter | **Native dialog**: "Sensitive content detected in a text prompt", Site: ChatGPT, the prompt excerpt, Continue / Cancel. Point out it's a desktop window (move it outside the browser) |
| 5 | ChatGPT | Click **Cancel** | Nothing is sent and the text is still in the box. Edit a word |
| 6 | ChatGPT | Press Enter, click **Continue** | The edited prompt is sent exactly as typed, and the answer streams in |
| 7 | ChatGPT | Attach `samples/sensitive-notes.txt` → **Cancel** | Dialog: "…in a file upload", File: sensitive-notes.txt (TEXT, …), Found in: file text. ChatGPT shows "Failed to upload file." |
| 8 | ChatGPT | Attach `samples/sensitive-report.pdf` → **Continue** | Found in: page 1 text. The attachment uploads |
| 9 | ChatGPT | Drag `samples/sensitive-screenshot.png` into the chat → **Cancel** | Found in: **text in image (OCR)**. Drag and drop is covered because the check is on what's sent, not on how it was attached |
| 10 | ChatGPT | Attach `samples/clean-report.pdf` | Uploaded with no dialog |
| 11 | Perplexity | Ask `capital of France in one word` | No dialog. The answer is **violet** and your question bubble isn't |
| 12 | Perplexity | Type `explain WALLED_SENSITIVE policy` slowly | Mention that Perplexity sends every keystroke to its suggestion service; frames containing the marker are dropped (the Recent activity list and `agent.log` show it) |
| 13 | Perplexity | Press Enter → **Cancel**, then Enter → **Continue** | Cancel: "Unable to start session." with the text kept. Continue: the answer appears |
| 14 | Perplexity | Attach `samples/sensitive-scanned.pdf` → **Cancel** | Found in: page 1 image 1 (OCR): a scanned PDF with no text layer |
| 15 | Perplexity | Paste `samples/sensitive-darkmode.jpg` (copy it in the file manager, Ctrl+V in the composer) → **Continue** | OCR reads light-on-dark text. The image is attached |
| 16 | Perplexity | Attach `samples/clean-screenshot.png` | No dialog |
| 17 | Walled DLP window | Show **Recent activity**; change the response colour, reload a tab | One row per intervention: site, file name, decision. No prompt text is stored. The new colour applies after reload |
| 18 | – | Optional: quit Walled DLP, reload chatgpt.com | It doesn't load: with the browser connected, ChatGPT and Perplexity can't be reached uninspected. Reopen the app and it works again |

## Closing (about 20 s)

Mention the tests: 107 Python tests (including the proxy over real TLS), 13 end-to-end tests in real Chrome through the real app, and opt-in live tests against both sites. Then point to ARCHITECTURE.md for why a local inspection proxy, and what each site actually sends.
