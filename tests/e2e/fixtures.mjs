// Stand-in for chatgpt.com, its upload host and Perplexity, for the deterministic browser tests.
// Walled DLP forwards these hosts here over plain HTTP (WALLED_DLP_TEST_UPSTREAM). The pages
// reproduce what the real apps send, as captured from the live sites:
//   ChatGPT     POST /backend-api/f/conversation (JSON), uploads via POST /backend-api/files then a
//               PUT of the raw bytes to files07.oaiusercontent.com, telemetry to /ces/v1/t
//   Perplexity  every keystroke over wss://suggest.perplexity.ai/suggest/ws, analytics to
//               /rest/event/analytics, the question to POST /rest/sse/perplexity_ask
// Every request that reaches this server is recorded, so tests can check what got through.
import http from "node:http";
import { createHash } from "node:crypto";

const CHATGPT = `<!doctype html><html><head><meta charset="utf-8"><title>ChatGPT</title>
<style>body{color:rgb(13,13,13);font:16px sans-serif}</style></head><body>
<main><div id="thread"></div>
<form id="f"><textarea id="prompt-textarea" name="prompt"></textarea><button id="send" type="submit">Send</button></form>
<input type="file" id="upload" multiple><div id="status"></div></main>
<script>
const $ = (s) => document.querySelector(s);
const say = (t) => ($("#status").textContent = t);
$("#f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = $("#prompt-textarea").value;
  fetch("/ces/v1/t", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ event: "send", text }) }).catch(() => {});
  const r = await fetch("/backend-api/f/conversation", { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ action: "next", messages: [{ author: { role: "user" }, content: { content_type: "text", parts: [text] } }] }) });
  if (!r.ok) { say((await r.json()).detail); return; }   // text stays in the box
  const answer = await r.text();
  $("#thread").insertAdjacentHTML("beforeend",
    '<div><h4 data-conversation-role="user" class="sr-only">You said:</h4><div class="whitespace-pre-wrap"></div></div>' +
    '<div><h4 data-conversation-role="assistant" class="sr-only">ChatGPT said:</h4><div data-response-body><p></p></div></div>');
  $("#thread").lastElementChild.previousElementSibling.querySelector("div").textContent = text;
  $("#thread").lastElementChild.querySelector("p").textContent = answer;
  $("#prompt-textarea").value = "";
  say("sent");
});
$("#upload").addEventListener("change", async () => {
  const results = [];
  for (const file of $("#upload").files) {
    const meta = await (await fetch("/backend-api/files", { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ file_name: file.name, file_size: file.size, use_case: "multimodal" }) })).json();
    try {
      const put = await fetch(meta.upload_url, { method: "PUT", headers: { "content-type": file.type || "application/octet-stream", "x-ms-blob-type": "BlockBlob" }, body: file });
      results.push(file.name + ":" + (put.ok ? "uploaded" : "failed"));
    } catch {
      results.push(file.name + ":error");  // the browser hid the response
    }
  }
  say(results.join(" "));
});
</script></body></html>`;

const PERPLEXITY = `<!doctype html><html><head><meta charset="utf-8"><title>Perplexity</title>
<style>body{color:rgb(11,40,51);font:16px sans-serif}</style></head><body>
<div id="thread"></div><textarea id="ask-input"></textarea><div id="status"></div>
<script>
const $ = (s) => document.querySelector(s);
const ws = new WebSocket("wss://suggest.perplexity.ai/suggest/ws");
let n = 0;
$("#ask-input").addEventListener("input", () => { if (ws.readyState === 1) ws.send(JSON.stringify({ q: $("#ask-input").value, uuid: String(++n) })); });
$("#ask-input").addEventListener("keydown", async (e) => {
  if (e.key !== "Enter") return;
  e.preventDefault();
  const q = $("#ask-input").value;
  // Analytics fires first, carrying the query, exactly as on the real site.
  fetch("/rest/event/analytics", { method: "POST", headers: { "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify({ event_name: "submit query", event_data: { queryStr: q } }) }).catch(() => {});
  const r = await fetch("/rest/sse/perplexity_ask", { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ params: { attachments: [], mode: "copilot" }, query_str: q }) });
  if (!r.ok) { $("#status").textContent = "Unable to start session."; return; }
  $("#thread").innerHTML = '<div data-message-bubble><div data-renderer="lm"><p class="q"></p></div></div>' +
    '<div id="markdown-content-0"><div data-renderer="lm"><p class="a"></p></div></div>';
  $(".q").textContent = q;
  $(".a").textContent = await r.text();
  $("#status").textContent = "answered";
});
</script></body></html>`;

function wsAccept(key) {
  return createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
}

export async function startFixtures() {
  const seen = [];
  const wsMessages = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const host = (req.headers.host || "").split(":")[0];
      seen.push({ method: req.method, host, path: req.url.split("?")[0], body, headers: req.headers });
      const cors = { "access-control-allow-origin": "*", "access-control-allow-methods": "PUT, POST, OPTIONS", "access-control-allow-headers": "*" };
      if (req.method === "OPTIONS") return res.writeHead(204, cors).end();
      if (host === "files07.oaiusercontent.com") return res.writeHead(201, cors).end();
      if (host === "chatgpt.com") {
        if (req.url === "/") return res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(CHATGPT);
        if (req.url.startsWith("/backend-api/files")) {
          const id = "file-" + seen.length;
          return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ file_id: id, upload_url: `https://files07.oaiusercontent.com/${id}?se=1&sig=x` }));
        }
        if (req.url.startsWith("/backend-api/f/conversation")) return res.writeHead(200, { "content-type": "text/plain" }).end("Paris.");
        return res.writeHead(200, { "content-type": "application/json" }).end("{}");
      }
      if (host === "www.perplexity.ai") {
        if (req.url === "/") return res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(PERPLEXITY);
        if (req.url.startsWith("/rest/sse/perplexity_ask")) return res.writeHead(200, { "content-type": "text/plain" }).end("An answer.");
        return res.writeHead(200, { "content-type": "application/json" }).end("{}");
      }
      res.writeHead(404).end();
    });
  });
  server.on("upgrade", (req, socket) => {
    seen.push({ method: "WS", host: (req.headers.host || "").split(":")[0], path: req.url, body: Buffer.alloc(0), headers: req.headers });
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${wsAccept(req.headers["sec-websocket-key"])}\r\n\r\n`);
    let buf = Buffer.alloc(0);
    socket.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 6) {
        let n = buf[1] & 0x7f, off = 2;
        if (n === 126) { n = buf.readUInt16BE(2); off = 4; }
        if (buf.length < off + 4 + n) break;
        const mask = buf.subarray(off, off + 4);
        const data = Buffer.from(buf.subarray(off + 4, off + 4 + n).map((b, i) => b ^ mask[i % 4]));
        if ((buf[0] & 0x0f) === 1) wsMessages.push(data.toString());
        buf = buf.subarray(off + 4 + n);
      }
    });
    socket.on("error", () => {});
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return {
    port, seen, wsMessages,
    upstream: ["chatgpt.com", "files07.oaiusercontent.com", "www.perplexity.ai", "suggest.perplexity.ai"].map((h) => `${h}=127.0.0.1:${port}`).join(","),
    reached: (path) => seen.filter((s) => s.path === path),
    reset: () => { seen.length = 0; wsMessages.length = 0; },
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
  };
}
