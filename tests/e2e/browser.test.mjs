// Real Google Chrome, routed by proxy auto-config through the real Walled DLP app, to local stand-ins
// for ChatGPT and Perplexity (fixtures.mjs). Only the native dialog is scripted (a fake `zenity`).
// Nothing is installed in the browser: no extension, no flags beyond the PAC URL and accepting the
// throwaway test CA.
//
//   node --test tests/e2e/browser.test.mjs        (HEADED=1 to watch)
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { launch, ROOT } from "./cdp.mjs";
import { startFixtures } from "./fixtures.mjs";

const M = "WALLED_SENSITIVE";
const VIOLET = "rgb(109, 40, 217)";
const sample = (name) => join(ROOT, "samples", name);
let fx, b;

before(async () => {
  fx = await startFixtures();
  b = await launch({ upstream: fx.upstream });
});
after(async () => {
  await b?.close();
  await fx?.close();
});
beforeEach(() => {
  fx.reset();
  b.dialog.reset();
  b.dialog.answer("cancel");
});

async function chatgpt() {
  const p = await b.newPage("https://chatgpt.com/");
  await p.waitFor("!!document.querySelector('#prompt-textarea')");
  return p;
}

async function send(p, text) {
  await p.click("#prompt-textarea");
  await p.type(text);
  await p.click("#send");
}

const status = (p, value, timeout = 15000) => p.waitFor(`document.querySelector('#status').textContent.includes(${JSON.stringify(value)})`, timeout);

test("pages load over HTTPS through Walled DLP and carry the response-colour style", async () => {
  const p = await chatgpt();
  assert.equal(await p.eval("location.protocol"), "https:");
  assert.ok(await p.eval("!!document.getElementById('walled-dlp-response-color')"));
  await p.close();
});

test("ChatGPT: a prompt without the marker is sent with no dialog, and the answer is recoloured", async () => {
  const p = await chatgpt();
  await send(p, "What is the capital of France?");
  await status(p, "sent");
  assert.equal(b.dialog.calls().length, 0);
  assert.equal(fx.reached("/backend-api/f/conversation").length, 1);
  const [answer, user] = await p.eval(`[getComputedStyle(document.querySelector('[data-conversation-role=assistant] ~ [data-response-body] p')).color,
    getComputedStyle(document.querySelector('[data-conversation-role=user] ~ div')).color]`);
  assert.equal(answer, VIOLET);
  assert.notEqual(user, VIOLET);
  await p.close();
});

test("ChatGPT: Cancel blocks the prompt, nothing reaches the site, and the text stays to edit", async () => {
  const p = await chatgpt();
  await send(p, `Summarise the ${M} board deck`);
  await status(p, "Walled DLP blocked this prompt");
  const calls = b.dialog.calls();
  assert.equal(calls.length, 1);
  assert.match(calls[0], /Sensitive content detected in a text prompt/);
  assert.match(calls[0], /<b>Site:<\/b> ChatGPT/);
  assert.match(calls[0], new RegExp(`Summarise the ${M} board deck`));
  assert.equal(fx.reached("/backend-api/f/conversation").length, 0);
  assert.equal(fx.reached("/ces/v1/t").length, 0, "telemetry copy of the prompt leaked");
  assert.equal(await p.eval("document.querySelector('#prompt-textarea').value"), `Summarise the ${M} board deck`);
  await p.close();
});

test("ChatGPT: Continue sends the prompt unchanged", async () => {
  b.dialog.answer("continue");
  const p = await chatgpt();
  await send(p, `Summarise the ${M} board deck`);
  await status(p, "sent");
  assert.equal(b.dialog.calls().length, 1);
  const [req] = fx.reached("/backend-api/f/conversation");
  assert.equal(JSON.parse(req.body).messages[0].content.parts[0], `Summarise the ${M} board deck`);
  await p.close();
});

for (const [file, kind, where] of [
  ["sensitive-notes.txt", "TEXT", "file text"],
  ["sensitive-report.pdf", "PDF", "page 1 text"],
  ["sensitive-screenshot.png", "IMAGE", "text in image \\(OCR\\)"],
]) {
  test(`ChatGPT: uploading ${file} asks first, and Cancel keeps it off the server`, async () => {
    const p = await chatgpt();
    await p.setFiles("#upload", [sample(file)]);
    await status(p, `${file}:failed`, 30000);
    const calls = b.dialog.calls();
    assert.equal(calls.length, 1);
    assert.match(calls[0], /Sensitive content detected in a file upload/);
    assert.match(calls[0], new RegExp(`<b>File:</b> ${file.replace(".", "\\.")} \\(${kind}, `));
    assert.match(calls[0], new RegExp(`<b>Found in:</b> ${where}`));
    assert.equal(fx.seen.filter((s) => s.method === "PUT").length, 0);
    await p.close();
  });
}

test("ChatGPT: Continue uploads the file byte-for-byte; clean files upload with no dialog", async () => {
  b.dialog.answer("continue");
  const p = await chatgpt();
  await p.setFiles("#upload", [sample("sensitive-scanned.pdf"), sample("clean-report.pdf"), sample("clean-screenshot.png")]);
  await status(p, "clean-screenshot.png:uploaded", 40000);
  assert.equal(b.dialog.calls().length, 1, "only the sensitive file should ask");
  const puts = fx.seen.filter((s) => s.method === "PUT");
  assert.equal(puts.length, 3);
  assert.ok(puts[0].body.equals(readFileSync(sample("sensitive-scanned.pdf"))));
  await p.close();
});

test("ChatGPT: in a mixed selection, cancelling one file still lets the clean ones through", async () => {
  const p = await chatgpt();
  await p.setFiles("#upload", [sample("clean-notes.txt"), sample("sensitive-darkmode.jpg")]);
  await status(p, "sensitive-darkmode.jpg:", 40000);
  assert.equal(await p.eval("document.querySelector('#status').textContent"), "clean-notes.txt:uploaded sensitive-darkmode.jpg:failed");
  await p.close();
});

async function perplexity() {
  const p = await b.newPage("https://www.perplexity.ai/");
  await p.waitFor("!!document.querySelector('#ask-input')");
  await sleep(300); // suggestion socket opens
  return p;
}

async function typeKeys(p, text) {
  await p.click("#ask-input");
  for (const ch of text) {
    await p.send("Input.dispatchKeyEvent", { type: "keyDown", key: ch, text: ch });
    await p.send("Input.dispatchKeyEvent", { type: "keyUp", key: ch });
  }
}

test("Perplexity: keystrokes carrying the marker never reach the suggestion service", async () => {
  const p = await perplexity();
  await typeKeys(p, `what is ${M} data`);
  await sleep(800);
  const queries = fx.wsMessages.map((m) => JSON.parse(m).q);
  assert.ok(queries.includes("what is WALLED_SENSITIV"), "frames before the marker is complete pass");
  assert.ok(queries.every((q) => !q.includes(M)), `leaked: ${queries.filter((q) => q.includes(M))}`);
  await p.close();
});

test("Perplexity: Cancel blocks the question and its analytics copy; the text stays", async () => {
  const p = await perplexity();
  await typeKeys(p, `what is ${M}`);
  await p.press("Enter");
  await p.waitFor("document.querySelector('#status').textContent === 'Unable to start session.'");
  assert.equal(b.dialog.calls().length, 1);
  assert.match(b.dialog.calls()[0], /<b>Site:<\/b> Perplexity/);
  await sleep(500);
  assert.equal(fx.reached("/rest/sse/perplexity_ask").length, 0);
  assert.equal(fx.reached("/rest/event/analytics").length, 0, "analytics copy of the prompt leaked");
  assert.equal(await p.eval("document.querySelector('#ask-input').value"), `what is ${M}`);
  await p.close();
});

test("Perplexity: Continue sends the question once, and only the answer is recoloured", async () => {
  b.dialog.answer("continue");
  const p = await perplexity();
  await typeKeys(p, `what is ${M}`);
  await p.press("Enter");
  await p.waitFor("document.querySelector('#status').textContent === 'answered'");
  assert.equal(b.dialog.calls().length, 1, "one dialog for the question and its analytics copy");
  assert.equal(JSON.parse(fx.reached("/rest/sse/perplexity_ask")[0].body).query_str, `what is ${M}`);
  await sleep(300);
  const analytics = fx.reached("/rest/event/analytics");
  assert.ok(analytics.length >= 1, "analytics follows the Continue");
  assert.ok(analytics.every((a) => JSON.parse(a.body).event_data.queryStr === `what is ${M}`));
  const [answer, question] = await p.eval(`[getComputedStyle(document.querySelector('.a')).color, getComputedStyle(document.querySelector('.q')).color]`);
  assert.equal(answer, VIOLET);
  assert.notEqual(question, VIOLET);
  await p.close();
});

test("every intervention is in the audit log, without prompt text", async () => {
  const events = b.events();
  assert.ok(events.some((e) => e.source === "prompt" && e.decision === "cancel" && e.site === "ChatGPT"));
  assert.ok(events.some((e) => e.source === "file" && e.subject.startsWith("sensitive-report.pdf")));
  assert.ok(!JSON.stringify(events).includes("board deck"));
});
