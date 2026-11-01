'use strict';
const assert=require('node:assert/strict'),fs=require('fs');
const{chromium,webkit}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const base=process.env.TZ_TEST_BASE,state=process.env.TZ_TEST_STATE;
assert(base&&state&&process.env.TZ_SYNTHETIC_STAGE==='1','isolated synthetic stage required');
(async()=>{
 const wk=process.env.TZ_BROWSER==='webkit',browser=await(wk?webkit:chromium).launch({headless:true,...(wk?{}:{args:['--no-sandbox']})}),ctx=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844},hasTouch:true,isMobile:true}),p=await ctx.newPage(),errors=[];let frames=0,user,uid;
 p.on('pageerror',e=>errors.push(e.message));p.on('dialog',()=>errors.push('native dialog'));p.on('websocket',ws=>ws.on('framereceived',()=>frames++));
 async function login(page,name,password){await page.goto(base+'/');await page.locator('[name=name]').first().fill(name);await page.locator('[name=password]').first().fill(password);await page.locator('#login-form button').click();await page.locator('#dashboard').waitFor({state:'visible'});await page.waitForFunction(()=>document.querySelector('#connection').textContent==='实时连接')}
 async function api(c,path,method='GET',data,status=200){const me=await(await c.request.get(base+'/api/me')).json();const r=await c.request.fetch(base+'/api/'+path,{method,data,headers:{Origin:new URL(base).origin,'X-CSRF-Token':me.csrf}});assert.equal(r.status(),status,path);return r.json()}
 try{
  await login(p,'admin',fs.readFileSync(process.env.TZ_TEST_PASSWORD_FILE,'utf8').trim());await p.waitForFunction(()=>document.querySelectorAll('.card--node').length===5);
  const v=(await api(ctx,'snapshot'))[0],tags=v.report.tags,d=v.diagnostics;
  assert.deepEqual([d.inbounds,d.auth_identities,d.discovered,d.reported,d.backend_visible,d.backend_filtered,d.authorized],[4,2,6,7,5,2,5]);
  assert.equal(tags.filter(t=>t.ip?.ipv4==='8.8.8.8').length,1,'shared IP merged');
  assert.equal(tags.filter(t=>t.accounting==='unavailable').length,2);for(const t of tags.filter(t=>t.accounting==='unavailable'))assert.equal(t.up,null);
  assert.equal(new Set(tags.map(t=>t.id)).size,5);assert.equal(await p.locator('.monitor-diagnostics').count(),1);
  await p.locator('.monitor-diagnostics summary').click();assert((await p.locator('.monitor-diagnostics').textContent()).includes('前端展示 5'));
  await p.evaluate(()=>{window.savedServer=document.querySelector('.card--server');window.savedCanvas=savedServer.querySelector('.host-network canvas');window.savedCard=document.querySelector('.card--node');window.savedHostCount=savedServer.querySelectorAll('*').length;window.savedPointCount=[...cards.values()][0].metrics.network.series.length});
  await p.waitForTimeout(2300);
  assert(await p.evaluate(()=>savedServer===document.querySelector('.card--server')&&savedCanvas===savedServer.querySelector('.host-network canvas')&&savedCard===document.querySelector('.card--node')&&savedHostCount===savedServer.querySelectorAll('*').length));
  assert(await p.evaluate(()=>{const c=[...cards.values()][0];return c.metrics.network.series.length>savedPointCount&&c.metrics.network.series.length<=120&&c.metrics.load.series.every(x=>x[1]===.25&&x.length===2)&&c.metrics.cpu.canvas.width>0&&c.metrics.memory.canvas.width>0&&c.metrics.diskBar.value===12.5}));
  for(const theme of ['light','dark'])for(const width of [320,375,390,430,768,1440]){
   await p.setViewportSize({width,height:900});await p.evaluate(t=>{document.documentElement.dataset.theme=t;Charts.invalidate()},theme);await p.waitForTimeout(80);
   assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'overflow '+width);
   await p.locator('.card--node').first().locator('.node-number').click();await p.waitForFunction(()=>document.querySelector('#history-panel').open);
   const b=await p.locator('#history-panel').boundingBox();assert(b.x>=0&&b.x+b.width<=width+1);await p.keyboard.press('Escape');await p.waitForFunction(()=>!document.querySelector('#history-panel').open);
   if(width===390)await p.screenshot({path:state+'/'+(wk?'webkit':'chromium')+'-'+theme+'.png',fullPage:true});
  }
  await p.emulateMedia({reducedMotion:'reduce'});await p.waitForFunction(()=>Charts.reduced);await p.emulateMedia({reducedMotion:'no-preference'});
  const auth=tags.filter(t=>t.accounting==='unavailable');await p.locator('.card--node').filter({hasText:'认证身份 alice'}).locator('.node-number').click();await p.waitForFunction(()=>document.querySelector('#history-panel').open);await p.waitForFunction(()=>document.querySelector('#source-message').textContent.includes('无法确认'));assert((await p.locator('#detail-flow').textContent()).includes('没有可靠认证身份字段'));await p.keyboard.press('Escape');await p.waitForFunction(()=>!document.querySelector('#history-panel').open);
  await p.locator('.card--node .icon-button').first().click();await p.locator('.action-sheet').waitFor({state:'visible'});assert(!await p.locator('#history-panel').evaluate(e=>e.open));await p.keyboard.press('Escape');await p.waitForFunction(()=>!document.querySelector('.action-sheet'));
  await p.locator('.card--node').filter({hasText:'认证身份 alice'}).locator('.icon-button').click();
  await p.locator('.action-sheet').waitFor({state:'visible'});
  await p.waitForFunction(()=>[...document.querySelectorAll('.action-item')].some(b=>b.textContent==='查看节点链接'&&!b.disabled));
  assert(await p.getByRole('button',{name:'更换节点出站 IP',exact:true}).isDisabled());
  await p.getByRole('button',{name:'查看节点链接',exact:true}).click();
  await p.waitForFunction(()=>document.querySelector('.control-body select')?.options.length===1);
  assert.equal(await p.locator('.control-body select option').count(),1);
  await p.locator('.control-body').getByRole('button',{name:'查看节点链接',exact:true}).click();
  await p.waitForFunction(()=>document.querySelector('.control-body textarea')?.value.includes('synthetic-fixture'));
  await p.keyboard.press('Escape');await p.waitForFunction(()=>!document.querySelector('.control-body'));
  const name='auth-'+Date.now();await api(ctx,'admin/users','POST',{name,password:'isolated-validation'});uid=(await api(ctx,'admin/users')).find(u=>u.name===name).id;await api(ctx,'admin/grants','PUT',{user_id:uid,servers:['fixture'],grants:[{server:'fixture',tag:auth[0].grant_tag}]});
  const diag=await api(ctx,'admin/monitor-diagnostics?user_id='+uid);assert.equal(diag[0].counts.authorized,1);assert.equal(diag[0].counts.permission_filtered,4);
  user=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:320,height:844}});const up=await user.newPage();await login(up,name,'isolated-validation');await up.waitForFunction(()=>document.querySelectorAll('.card--node').length===1);assert.equal(await up.locator('.node-number').textContent(),'01');const uv=(await api(user,'snapshot'))[0];assert.equal(uv.report.host,null);assert(!uv.report.discovery&&!uv.diagnostics);assert(!uv.report.tags[0].auth_id&&!uv.report.tags[0].inbound_tag);
  await api(user,'node-inspect','POST',{node_id:auth[1].id,action:'intel',source:'ipinfo'},403);await api(user,'admin/monitor-diagnostics', 'GET',undefined,403);
  await api(ctx,'admin/grants','PUT',{user_id:uid,servers:[],grants:[]});await up.waitForFunction(()=>document.querySelectorAll('.card--node').length===0);
  fs.writeFileSync(state+'/offline.flag','1');await p.waitForFunction(()=>document.querySelector('.server-head .pill').textContent==='离线');assert.equal(await p.locator('.card--node').count(),5);fs.writeFileSync(state+'/offline.flag','0');await p.waitForFunction(()=>document.querySelector('.server-head .pill').textContent==='在线');
  fs.writeFileSync(state+'/extra.flag','1');await p.waitForFunction(()=>document.querySelectorAll('.card--node').length===6);const now=(await api(ctx,'snapshot'))[0].report.tags;for(const tag of tags)assert(now.some(n=>n.id===tag.id),'hot reload replaced ID');fs.writeFileSync(state+'/extra.flag','0');await p.waitForFunction(()=>document.querySelectorAll('.card--node').length===5);
  assert.deepEqual(await p.locator('.node-number').allTextContents(),['01','02','03','04','05']);assert(frames>2);assert.deepEqual(errors,[]);const perf=await p.evaluate(()=>window.tzPerformance);console.log(JSON.stringify({browser:wk?'webkit':'chromium',layers:[4,2,6,7,5,5,5],backend_filtered:2,themes:2,widths:6,dom_reused:true,auth_permissions:true,offline_recovery:true,hot_reload:true,real_session_history:true,websocket_frames:frames,performance:perf,errors}));
 }finally{if(uid)await api(ctx,'admin/users','DELETE',{id:uid});if(user)await user.close();await ctx.close();await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
