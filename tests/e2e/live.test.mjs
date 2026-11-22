// Smoke tests against the REAL chatgpt.com and perplexity.ai (logged out), through the real Walled
// DLP app. Opt-in, because they depend on the network and on sites that change often:
//
//   LIVE=1 node --test --test-concurrency=1 tests/e2e/live.test.mjs
//
// ChatGPT shows a Cloudflare challenge to headless Chrome, so its test opens a visible window.
// They send a few short prompts and upload sample images (logged-out ChatGPT accepts images).
import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { launch, ROOT } from "./cdp.mjs";

const skip = !process.env.LIVE && "set LIVE=1 to run against the real sites";
const VIOLET = "rgb(109, 40, 217)";
const M = "WALLED_SENSITIVE";

async function typeLikeAHuman(page, text) {
  for (const ch of text) {
    await page.send("Input.dispatchKeyEvent", { type: "keyDown", key: ch, text: ch });
    await page.send("Input.dispatchKeyEvent", { type: "keyUp", key: ch });
    await sleep(60);
  }
}

test("live Perplexity: typeahead, Cancel, Continue, response colour", { skip, timeout: 180_000 }, async () => {
  const b = await launch();
  try {
    const p = await b.newPage("https://www.perplexity.ai/");
    const editor = "[data-lexical-editor]";
    await p.waitFor(`!!document.querySelector('${editor}')`, 40000);
    await sleep(1500);
    assert.ok(await p.eval("!!document.getElementById('walled-dlp-response-color')"), "colour style not injected");

    await p.click(editor);
    await typeLikeAHuman(p, `what is ${M} data`);
    await sleep(1500);
    assert.match(b.proxyLog(), /dropped a WebSocket message to suggest\.perplexity\.ai/);

    // Cancel: nothing sent, the text stays in the box.
    await p.press("Enter");
    await sleep(4000);
    assert.equal(b.dialog.calls().length, 1);
    assert.match(b.dialog.calls()[0], /<b>Site:<\/b> Perplexity/);
    assert.equal(await p.eval("location.pathname"), "/");
    assert.match(await p.eval(`document.querySelector('${editor}').innerText`), new RegExp(M));

    // Continue: sent unchanged.
    b.dialog.reset();
    b.dialog.answer("continue");
    await p.click(editor);
    await p.press("Enter");
    await p.waitFor("location.pathname !== '/'", 20000);
    assert.equal(b.dialog.calls().length, 1);

    // The answer is recoloured; the user's own question is not.
    await p.waitFor(`[...document.querySelectorAll('[data-renderer="lm"]')].some(e => !e.closest('[data-message-bubble]') && e.innerText.length > 2)`, 60000);
    const [answer, question] = await p.eval(`(() => {
      const a = [...document.querySelectorAll('[data-renderer="lm"]')].find(e => !e.closest('[data-message-bubble]'));
      const q = document.querySelector('[data-message-bubble] [data-renderer="lm"]');
      return [getComputedStyle(a).color, q && getComputedStyle(q).color];
    })()`);
    assert.equal(answer, VIOLET);
    assert.notEqual(question, VIOLET);
  } finally {
    await b.close();
  }
});

test("live ChatGPT: Cancel, edit and Continue, colour, image uploads", { skip, timeout: 240_000 }, async () => {
  const b = await launch({ headless: false });
  const composer = "textarea[name=prompt], #prompt-textarea";
  const turns = (p, role) => p.eval(`document.querySelectorAll('[data-message-role=${role}], [data-message-author-role=${role}]').length`);
  try {
    const p = await b.newPage("https://chatgpt.com/");
    await p.waitFor(`!!document.querySelector(${JSON.stringify(composer)})`, 60000);
    await sleep(3000);
    assert.ok(await p.eval("!!document.getElementById('walled-dlp-response-color')"), "colour style not injected");

    // Cancel: nothing sent, the text stays to edit.
    await p.click(composer);
    await p.type(`Reply with one word: is ${M} a colour?`);
    await p.press("Enter");
    await sleep(4000);
    assert.equal(b.dialog.calls().length, 1);
    assert.match(b.dialog.calls()[0], /Sensitive content detected in a text prompt/);
    assert.equal(await turns(p, "user"), 0, "cancelled prompt was sent");
    assert.equal(await p.eval(`document.querySelector(${JSON.stringify(composer)}).value`), `Reply with one word: is ${M} a colour?`);

    // Edit and send again: a new dialog; Continue sends it.
    b.dialog.reset();
    b.dialog.answer("continue");
    await p.eval(`(() => { const e = document.querySelector(${JSON.stringify(composer)}); e.focus(); e.setSelectionRange(e.value.length, e.value.length); })()`);
    await p.type(" Answer yes or no.");
    await p.press("Enter");
    await p.waitFor(`document.querySelectorAll('[data-message-role=assistant] [data-assistant-markdown] p, [data-message-author-role=assistant] .markdown p').length > 0`, 60000);
    assert.equal(b.dialog.calls().length, 1);
    const colour = await p.eval(`getComputedStyle(document.querySelector('[data-message-role=assistant] [data-assistant-markdown] p, [data-message-author-role=assistant] .markdown p')).color`);
    assert.equal(colour, VIOLET);

    // Image uploads: OCR finds the marker; Cancel keeps it off OpenAI's storage.
    const q = await b.newPage("https://chatgpt.com/");
    await q.waitFor(`!!document.querySelector(${JSON.stringify(composer)})`, 60000);
    await sleep(3000);
    const input = (await q.eval("!!document.querySelector('#octane-mobile-composer-photos-input')")) ? "#octane-mobile-composer-photos-input" : "input[type=file][accept*=image]";
    b.dialog.reset();
    b.dialog.answer("cancel");
    await q.setFiles(input, [join(ROOT, "samples", "sensitive-screenshot.png")]);
    await sleep(9000);
    assert.equal(b.dialog.calls().length, 1, "retries of the cancelled upload must not ask again");
    assert.match(b.dialog.calls()[0], /<b>File:<\/b> sensitive-screenshot\.png \(IMAGE, /);
    assert.match(b.dialog.calls()[0], /text in image \(OCR\)/);

    b.dialog.reset();
    await q.setFiles(input, [join(ROOT, "samples", "clean-screenshot.png")]);
    await sleep(8000);
    assert.equal(b.dialog.calls().length, 0, "clean image raised a dialog");
    assert.ok(b.events().some((e) => e.subject?.startsWith("sensitive-screenshot.png") && e.decision === "cancel"));
  } finally {
    await b.close();
  }
});
