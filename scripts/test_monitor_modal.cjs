'use strict';
// Run only against an isolated synthetic stage. Never creates production users.
const assert=require('node:assert/strict'),fs=require('fs');
const {chromium,webkit}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const base=process.env.TZ_TEST_BASE,state=process.env.TZ_TEST_STATE;
assert(base&&state&&process.env.TZ_SYNTHETIC_STAGE==='1','isolated synthetic stage required');
const origin=new URL(base).origin,wk=process.env.TZ_BROWSER==='webkit';
(async()=>{
 const browser=await(wk?webkit:chromium).launch({headless:true,...(wk?{}:{args:['--no-sandbox']})});
 const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844},hasTouch:true,isMobile:true}),page=await context.newPage(),errors=[];
 page.on('pageerror',e=>errors.push(e.message));page.on('dialog',()=>{throw Error('native browser dialog used')});
 async function api(ctx,path,method='GET',data,status=200){const me=await(await ctx.request.get(base+'/api/me')).json();const r=await ctx.request.fetch(base+'/api/'+path,{method,data,headers:{Origin:origin,'X-CSRF-Token':me.csrf}});assert.equal(r.status(),status,path);return r.json()}
 async function login(p,name,password){await p.goto(base+'/');await p.locator('#login-form [name=name]').fill(name);await p.locator('#login-form [name=password]').fill(password);await p.locator('#login-form button').click();await p.locator('#dashboard').waitFor({state:'visible'});await p.waitForFunction(()=>document.querySelector('#connection').textContent==='实时连接');}
 const close=async()=>{await page.keyboard.press('Escape');await page.waitForFunction(()=>!document.querySelector('#history-panel').open)};
 let uid,user;
 try{
  await login(page,'admin',fs.readFileSync(process.env.TZ_TEST_PASSWORD_FILE,'utf8').trim());
  await page.waitForFunction(()=>document.querySelectorAll('#tags .card--node').length===4);
  const countsBefore=JSON.parse(fs.readFileSync(state+'/helper-counts.json','utf8'));
  const inventory=await api(context,'admin/nodes'),tags=inventory[0].report.tags;
  assert.equal(tags.length,4,'mixed legacy outbound exposed');assert.equal(tags.filter(t=>t.egress==='shared-direct').length,2);
  assert.deepEqual((await page.locator('.category').allTextContents()).sort(),['VLESS','VLESS','Trojan','SOCKS'].sort());
  assert(!/未知类型/.test(await page.locator('#tags').textContent()));
  await page.locator('.card--node .node-number').first().click();await page.waitForFunction(()=>document.querySelector('#history-panel').open);
  assert(await page.evaluate(()=>document.body.classList.contains('overlay-open')));
  const lockedScroll=await page.evaluate(()=>scrollY);if(!wk){await page.mouse.move(2,2);await page.mouse.wheel(0,300);await page.waitForTimeout(100);assert.equal(await page.evaluate(()=>scrollY),lockedScroll,'background scrolled behind modal')}else{assert(await page.evaluate(()=>getComputedStyle(document.body).overflow==='hidden'&&document.querySelector('#history-panel').matches(':modal')),'native modal and scroll lock missing')}
  await page.waitForFunction(()=>!document.querySelector('#source-message').textContent.includes('正在'));
  await page.evaluate(()=>{window.keptCard=document.querySelector('.card--node');window.keptCanvas=keptCard.querySelector('canvas');window.keptDialog=document.querySelector('#history-panel')});
  await page.waitForTimeout(2300);
  assert(await page.evaluate(()=>keptCard===document.querySelector('.card--node')&&keptCanvas===keptCard.querySelector('canvas')&&keptDialog.open));
  for(let n=0;n<3;n++){await page.locator('[data-ip-source=ippure]').click();await page.waitForFunction(()=>document.querySelector('#detail-ip').textContent.includes('IPPure'));await page.locator('[data-ip-source=ipinfo]').click();await page.waitForFunction(()=>document.querySelector('#detail-ip').textContent.includes('IPinfo'))}
  const counts=JSON.parse(fs.readFileSync(state+'/helper-counts.json','utf8'));
  assert.equal(counts['intel:a:ipinfo']-(countsBefore['intel:a:ipinfo']||0),1,'IPinfo valid cache refetched');assert.equal(counts['intel:a:ippure']-(countsBefore['intel:a:ippure']||0),1,'IPPure valid cache refetched');
  assert.equal(await page.locator('.copy-ip').count(),2);assert.equal(await page.locator('.check-ip').count(),2);
  await page.evaluate(()=>{navigator.clipboard.writeText=async value=>{window.copiedIP=value}});await page.locator('.copy-ip').first().click();assert.equal(await page.evaluate(()=>window.copiedIP),'8.8.8.8');
  await page.locator('.check-ip').first().click();assert(await page.locator('#check-node').isDisabled());
  await page.waitForFunction(()=>!document.querySelector('#check-results').hidden&&!document.querySelector('#check-node').disabled);
  const checked=await page.locator('#check-fields').textContent();assert(checked.includes('公网可达性未验证'));assert(checked.includes('4 / 4'));assert(checked.includes('shared-direct'));
  await close();assert(await page.evaluate(()=>!document.body.classList.contains('overlay-open')&&document.activeElement.classList.contains('card--node')));
  await page.locator('.card--node .icon-button').first().click();await page.locator('.action-sheet').waitFor({state:'visible'});assert(!await page.locator('#history-panel').evaluate(e=>e.open));await page.keyboard.press('Escape');await page.waitForFunction(()=>!document.querySelector('.action-sheet'));
  await page.locator('#node-sort').selectOption('name');await page.locator('#node-search').fill('入站');
  for(const theme of ['light','dark'])for(const width of [320,375,390,430,768,1440]){
   await page.setViewportSize({width,height:900});await page.evaluate(t=>document.documentElement.dataset.theme=t,theme);
   const visible=page.locator('.card--node:not([hidden])');await visible.first().locator('.node-number').click();await page.waitForFunction(()=>document.querySelector('#history-panel').open);
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'layout overflow '+width);
   const box=await page.locator('#history-panel').boundingBox();assert(box.x>=0&&box.x+box.width<=width+1);
   await page.locator('#history-panel button').last().focus();await page.keyboard.press('Tab');assert(await page.evaluate(()=>document.querySelector('#history-panel').contains(document.activeElement)),'focus escaped');
   if(width===390){await page.screenshot({path:state+'/'+(wk?'webkit':'chromium')+'-'+theme+'.png',fullPage:true})}
   await close();
  }
  await page.setViewportSize({width:390,height:844});
  await page.locator('.card--node:not([hidden]) .node-number').first().click();await page.waitForFunction(()=>document.querySelector('#history-panel').open);await page.waitForTimeout(400);await page.mouse.click(2,2);await page.waitForFunction(()=>!document.querySelector('#history-panel').open);
  await page.locator('.card--node:not([hidden]) .node-number').first().click();await page.locator('#close-details').click();await page.waitForFunction(()=>!document.querySelector('#history-panel').open);
  await page.locator('#node-search').fill('');await page.locator('#node-sort').selectOption('default');
  fs.writeFileSync(state+'/extra.flag','1');await page.waitForFunction(()=>document.querySelectorAll('.card--node').length===5);assert.equal(await page.locator('#node-sort').inputValue(),'default');
  const nums=await page.locator('.node-number').allTextContents();assert.deepEqual(nums,['01','02','03','04','05']);fs.writeFileSync(state+'/extra.flag','0');await page.waitForFunction(()=>document.querySelectorAll('.card--node').length===4);
  const username='modal-'+Date.now();await api(context,'admin/users','POST',{name:username,password:'isolated-validation'});uid=(await api(context,'admin/users')).find(u=>u.name===username).id;
  await api(context,'admin/grants','PUT',{user_id:uid,servers:[inventory[0].id],grants:[{server:inventory[0].id,tag:'inbound:b'}]});
  user=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844},hasTouch:true,isMobile:true});const p=await user.newPage();await login(p,username,'isolated-validation');await p.waitForFunction(()=>document.querySelectorAll('.card--node').length===1);
  assert.equal(await p.locator('.node-number').textContent(),'01');assert(!await p.locator('.node-head .icon-button').isVisible());
  await api(user,'node-inspect','POST',{node_id:tags.find(t=>t.grant_tag==='inbound:a').id,action:'diagnostics'},403);
  await api(user,'admin/nodes','PUT',{},403);
  const checkedUser=await api(user,'node-inspect','POST',{node_id:tags.find(t=>t.grant_tag==='inbound:b').id,action:'diagnostics'});assert(!JSON.stringify(checkedUser).includes('shared-direct'),'hidden raw Tag leaked through checks');
  await p.locator('.node-number').click();await p.waitForFunction(()=>document.querySelector('#history-panel').open);await p.locator('[data-ip-source=ippure]').click();await p.waitForFunction(()=>document.querySelector('#source-message').textContent.includes('暂不可用'));await p.locator('[data-ip-source=ipinfo]').click();await p.waitForFunction(()=>document.querySelector('#detail-ip').textContent.includes('IPinfo'));
  await api(context,'admin/grants','PUT',{user_id:uid,servers:[],grants:[]});await p.waitForFunction(()=>document.querySelectorAll('.card--node').length===0&&!document.querySelector('#history-panel').open);
  await api(user,'node-inspect','POST',{node_id:tags.find(t=>t.grant_tag==='inbound:b').id,action:'intel',source:'ipinfo'},403);
  assert.deepEqual(errors,[]);console.log(JSON.stringify({browser:wk?'webkit':'chromium',cards:4,themes:2,widths:6,modal:true,cache:true,checks:true,permissions:true,websocket:true,errors}));
 }finally{if(uid)await api(context,'admin/users','DELETE',{id:uid});if(user)await user.close();await context.close();await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
