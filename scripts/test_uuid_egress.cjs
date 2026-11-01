'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs');
const {chromium,webkit}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
assert(process.env.TZ_SYNTHETIC_STAGE==='1'&&process.env.TZ_TEST_BASE&&process.env.TZ_TEST_STATE);
(async()=>{
 const wk=process.env.TZ_BROWSER==='webkit',browser=await(wk?webkit:chromium).launch({headless:true,...(wk?{}:{args:['--no-sandbox']})});
 const ctx=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844},isMobile:true,hasTouch:true}),p=await ctx.newPage(),base=process.env.TZ_TEST_BASE,errors=[];let frames=0;
 p.on('pageerror',e=>errors.push(e.message));p.on('websocket',s=>s.on('framereceived',()=>frames++));
 try{
  await p.goto(base+'/');await p.locator('#login-form [name=name]').fill('admin');await p.locator('#login-form [name=password]').fill(fs.readFileSync(process.env.TZ_TEST_PASSWORD_FILE,'utf8').trim());await p.locator('#login-form button').click();
  await p.waitForFunction(()=>document.querySelectorAll('#tags .card--node').length===4);
  const snapshot=await(await ctx.request.get(base+'/api/snapshot')).json(),tags=snapshot[0].report.tags;
  assert.equal(new Set(tags.map(t=>t.id)).size,4);assert.equal(tags.filter(t=>t.ip?.ipv4==='8.8.8.8').length,2);
  const label=await p.locator('#tags .node-ip').allTextContents();assert(label.every(t=>!t.includes('已验证')&&!t.includes('未验证')&&!t.includes('待验证')));assert(label.some(t=>t.includes('直连 · 美国 · 8.8.8.8')));assert(label.some(t=>t.includes('中转 · 美国 · 1.1.1.1')));assert(label.some(t=>t==='路径待检测'));
  await p.evaluate(()=>{window.savedEgressCard=document.querySelector('#tags .card--node');window.savedEgressCanvas=savedEgressCard.querySelector('canvas')});
  await p.waitForTimeout(2200);assert(await p.evaluate(()=>savedEgressCard===document.querySelector('#tags .card--node')&&savedEgressCanvas===savedEgressCard.querySelector('canvas')));
  for(const theme of ['light','dark'])for(const width of [320,375,390,430,768,1440]){
   await p.setViewportSize({width,height:900});await p.evaluate(v=>document.documentElement.dataset.theme=v,theme);await p.waitForTimeout(100);
   assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'page overflow '+width);
   assert(await p.locator('#tags .node-ip').evaluateAll(es=>es.every(e=>e.scrollWidth<=e.clientWidth+1)),'IP text overflow '+width);
   const card=p.locator('#tags .card--node').filter({hasText:'fixture-multi'});await card.locator('.node-ip').click();await p.waitForFunction(()=>document.querySelector('#history-panel').open);
   await p.locator('#detail-path').selectOption('1');await p.waitForFunction(()=>document.querySelector('#detail-ip').textContent.includes('1.1.1.1'));
   assert((await p.locator('#detail-ip').textContent()).includes('relay'));await p.locator('[data-ip-source=ippure]').click();await p.waitForFunction(()=>document.querySelector('[data-ip-source=ippure]').getAttribute('aria-pressed')==='true');
   assert(await p.evaluate(()=>{const d=document.querySelector('#history-panel'),r=d.getBoundingClientRect();return r.x>=0&&r.right<=innerWidth+1&&d.scrollWidth<=d.clientWidth+1}),'modal overflow '+width);
   if(width===390)await p.screenshot({path:process.env.TZ_TEST_STATE+'/'+(wk?'webkit':'chromium')+'-egress-'+theme+'.png'});
   await p.keyboard.press('Escape');await p.waitForFunction(()=>!document.querySelector('#history-panel').open);
  }
  await p.locator('#tags .card--node').filter({hasText:'fixture-alice'}).locator('.node-number').click();await p.waitForFunction(()=>document.querySelector('#history-panel').open);
  assert.equal(await p.locator('#detail-ip .check-ip').count(),1);await p.locator('#detail-ip .check-ip').click();await p.waitForFunction(()=>document.querySelector('.toast-item')?.textContent.includes('出口 HTTPS 检测成功'));assert.equal(await p.locator('#check-results:visible').count(),0);
  assert.equal(await p.locator('#detail-ip .copy-ip').count(),2);await p.keyboard.press('Escape');await p.waitForFunction(()=>!document.querySelector('#history-panel').open);
  await p.locator('#tags .card--node').first().focus();assert(await p.evaluate(()=>getComputedStyle(document.activeElement).outlineStyle!=='none'),'keyboard focus hidden');
  assert(frames>=2);assert.deepEqual(errors,[]);
  console.log(JSON.stringify({browser:wk?'webkit':'chromium',uuid_cards:4,multiple_exits:true,shared_exit_independent_cards:true,pending_and_idle:true,widths:6,themes:2,modal_source_switch_and_manual_check:true,websocket_frames:frames,exit_code:0}));
 }finally{await ctx.close();await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
