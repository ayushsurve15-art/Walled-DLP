// Minimal Chrome DevTools Protocol driver (Node ≥ 22, no dependencies).
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import net from "node:net";
import { X509Certificate, createHash } from "node:crypto";

export const ROOT = resolve(import.meta.dirname, "../..");
const PY = process.env.WALLED_PYTHON || join(ROOT, ".venv/bin/python");

async function freePort() {
  return new Promise((res) => {
    const srv = net.createServer().listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => res(port));
    });
  });
}

export class Dialog {
  constructor(dir) {
    this.answerFile = join(dir, "answer");
    this.callsFile = join(dir, "calls");
    this.answer("cancel");
  }
  answer(choice) {
    writeFileSync(this.answerFile, choice === "continue" ? "0" : "1");
  }
  calls() {
    if (!existsSync(this.callsFile)) return [];
    return readFileSync(this.callsFile, "utf8").split("\x1e").filter((c) => c.trim());
  }
  reset() {
    rmSync(this.callsFile, { force: true });
  }
}

// Starts the real Walled DLP app (`python -m walled_dlp run`) with a throwaway CA and a fake
// `zenity` first on PATH, then Chrome with a throwaway profile whose proxy auto-config points at
// it: the same route a user's browser takes after `walled-dlp setup`. Chrome is told to accept the
// throwaway CA by its key hash, so nothing is added to any certificate store on this machine.
// `upstream` ("chatgpt.com=127.0.0.1:9001,...") sends monitored hosts to local fixture servers.
export async function launch({ headless = !process.env.HEADED, upstream = "", env = {} } = {}) {
  const work = mkdtempSync(join(tmpdir(), "walled-e2e-"));
  const bin = join(work, "bin");
  mkdirSync(bin);
  const dialog = new Dialog(work);
  writeFileSync(
    join(bin, "zenity"),
    `#!/bin/sh\nprintf "%s\\n" "$@" >> "${dialog.callsFile}"\nprintf "\\036" >> "${dialog.callsFile}"\nsleep 0.2\nexit $(cat "${dialog.answerFile}")\n`,
  );
  chmodSync(join(bin, "zenity"), 0o755);

  const proxyPort = await freePort();
  const proxy = spawn(PY, ["-m", "walled_dlp", "run"], {
    cwd: ROOT,
    env: {
      ...process.env, PATH: `${bin}:${process.env.PATH}`, PYTHONPATH: ROOT,
      WALLED_DLP_CONFIG: join(work, "none.json"), WALLED_DLP_LOG_PATH: join(work, "agent.log"),
      WALLED_DLP_DIALOG_BACKEND: "zenity", WALLED_DLP_PORT: String(proxyPort), WALLED_DLP_CA_DIR: join(work, "ca"),
      WALLED_DLP_TEST_UPSTREAM: upstream, ...env,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let proxyErr = "";
  proxy.stderr.on("data", (d) => (proxyErr += d));
  for (let i = 0; i < 150; i++) {
    try {
      if ((await fetch(`http://127.0.0.1:${proxyPort}/`)).ok) break;
    } catch {}
    if (proxy.exitCode !== null) throw new Error(`walled-dlp exited: ${proxyErr}`);
    await sleep(100);
  }
  const caPem = readFileSync(join(work, "ca", "walled-dlp-ca.pem"), "utf8");
  const spkiDer = new X509Certificate(caPem).publicKey.export({ type: "spki", format: "der" });
  const spki = createHash("sha256").update(spkiDer).digest("base64");

  const port = await freePort();
  const args = [
    `--user-data-dir=${join(work, "profile")}`, `--remote-debugging-port=${port}`,
    `--proxy-pac-url=http://127.0.0.1:${proxyPort}/proxy.pac`, `--ignore-certificate-errors-spki-list=${spki}`,
    "--no-first-run", "--no-default-browser-check", "--window-size=1280,900", "about:blank",
  ];
  if (headless) args.unshift("--headless=new");
  const chrome = spawn(process.env.CHROME || "google-chrome", args, { stdio: "ignore" });

  let version;
  for (let i = 0; i < 100 && !version; i++) {
    try {
      version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
    } catch {
      await sleep(100);
    }
  }
  const cdp = await Connection.open(version.webSocketDebuggerUrl);
  return {
    cdp, dialog, work, proxyPort,
    proxyLog: () => (existsSync(join(work, "agent.log")) ? readFileSync(join(work, "agent.log"), "utf8") : "") + proxyErr,
    events: () => (existsSync(join(work, "events.jsonl")) ? readFileSync(join(work, "events.jsonl"), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []),
    async newPage(url) {
      return Page.open(cdp, url);
    },
    async close() {
      cdp.ws.close();
      chrome.kill();
      proxy.kill();
      await sleep(300);
      rmSync(work, { recursive: true, force: true });
    },
  };
}

class Connection {
  static open(url) {
    return new Promise((res, rej) => {
      const ws = new WebSocket(url);
      ws.onopen = () => res(new Connection(ws));
      ws.onerror = rej;
    });
  }
  constructor(ws) {
    this.ws = ws;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = [];
    ws.onmessage = ({ data }) => {
      const msg = JSON.parse(data);
      if (msg.id && this.pending.has(msg.id)) {
        const { res, rej } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? rej(new Error(`${msg.error.message} ${msg.error.data || ""}`)) : res(msg.result);
      } else if (msg.method) {
        for (const l of this.listeners) l(msg);
      }
    };
  }
  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    this.ws.send(JSON.stringify({ id, method, params, sessionId }));
    return new Promise((res, rej) => this.pending.set(id, { res, rej }));
  }
  on(fn) {
    this.listeners.push(fn);
  }
}

class Page {
  static async open(cdp, url) {
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const page = new Page(cdp, sessionId, targetId);
    await page.send("Page.enable");
    await page.send("Runtime.enable");
    await page.send("DOM.enable");
    await page.goto(url);
    return page;
  }
  constructor(cdp, sessionId, targetId) {
    Object.assign(this, { cdp, sessionId, targetId });
    this.fileChoosers = [];
    cdp.on((msg) => {
      if (msg.sessionId !== sessionId) return;
      if (msg.method === "Page.fileChooserOpened") this.fileChoosers.push(msg.params);
    });
  }
  send(method, params) {
    return this.cdp.send(method, params, this.sessionId);
  }
  async goto(url) {
    await this.send("Page.navigate", { url });
    const loaded = url === "about:blank" ? "true" : "location.href !== 'about:blank'";
    await this.waitFor(`document.readyState === 'complete' && ${loaded}`, 30000);
  }
  async eval(expression) {
    const r = await this.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(`${expression}: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
    return r.result.value;
  }
  async waitFor(expression, timeout = 15000) {
    const end = Date.now() + timeout;
    while (Date.now() < end) {
      try {
        if (await this.eval(expression)) return true;
      } catch {}
      await sleep(100);
    }
    throw new Error(`timed out waiting for ${expression}`);
  }
  async center(selector) {
    const box = await this.eval(`(() => { const r = document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect(); return [r.x + r.width / 2, r.y + r.height / 2]; })()`);
    return box;
  }
  async click(selector) {
    await this.eval(`document.querySelector(${JSON.stringify(selector)}).scrollIntoView({block: "center"})`);
    const [x, y] = await this.center(selector);
    for (const type of ["mouseMoved", "mousePressed", "mouseReleased"]) {
      await this.send("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 });
    }
  }
  async type(text) {
    await this.send("Input.insertText", { text });
  }
  async press(key, modifiers = 0) {
    const codes = { Enter: [13, "Enter", "\r"] };
    const [keyCode, code, text] = codes[key];
    await this.send("Input.dispatchKeyEvent", { type: "keyDown", key, code, windowsVirtualKeyCode: keyCode, text, modifiers });
    await this.send("Input.dispatchKeyEvent", { type: "keyUp", key, code, windowsVirtualKeyCode: keyCode, modifiers });
  }
  async setFiles(selector, files) {
    const { root } = await this.send("DOM.getDocument", { depth: 0 });
    const { nodeId } = await this.send("DOM.querySelector", { nodeId: root.nodeId, selector });
    await this.send("DOM.setFileInputFiles", { nodeId, files });
  }
  async chooseFiles(triggerSelector, files) {
    await this.send("Page.setInterceptFileChooserDialog", { enabled: true });
    const before = this.fileChoosers.length;
    await this.click(triggerSelector);
    const end = Date.now() + 5000;
    while (this.fileChoosers.length === before && Date.now() < end) await sleep(50);
    const chooser = this.fileChoosers.at(-1);
    if (!chooser || this.fileChoosers.length === before) throw new Error("no file chooser opened");
    await this.send("DOM.setFileInputFiles", { backendNodeId: chooser.backendNodeId, files });
  }
  async screenshot(path) {
    const { data } = await this.send("Page.captureScreenshot", { format: "png" });
    writeFileSync(path, Buffer.from(data, "base64"));
  }
  async close() {
    await this.cdp.send("Target.closeTarget", { targetId: this.targetId });
  }
}
