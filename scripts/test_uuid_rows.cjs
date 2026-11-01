'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs');
const {chromium,webkit}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
assert(process.env.TZ_SYNTHETIC_STAGE==='1'&&process.env.TZ_TEST_BASE&&process.env.TZ_TEST_STATE);
(async()=>{
 const wk=process.env.TZ_BROWSER==='webkit',browser=await(wk?webkit:chromium).launch({headless:true,...(wk?{}:{args:['--no-sandbox']})});
 const ctx=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844},isMobile:true,hasTouch:true}),p=await ctx.newPage(),base=process.env.TZ_TEST_BASE,errors=[];let frames=0;
 p.on('pageerror',e=>errors.push(e.message));p.on('dialog',()=>errors.push('native dialog'));p.on('websocket',s=>s.on('framereceived',()=>frames++));
 const close=async()=>{await p.keyboard.press('Escape');await p.waitForFunction(()=>!document.querySelector('dialog[open]'))};
 try{
  await p.goto(base+'/');await p.locator('#login-form [name=name]').fill('admin');await p.locator('#login-form [name=password]').fill(fs.readFileSync(process.env.TZ_TEST_PASSWORD_FILE,'utf8').trim());await p.locator('#login-form button').click();
  await p.waitForFunction(()=>document.querySelectorAll('#tags .card--node').length===14);
  const snapshot=await(await ctx.request.get(base+'/api/snapshot')).json(),tags=snapshot[0].report.tags;
  assert.equal(new Set(tags.map(t=>t.id)).size,14);assert(tags.every(t=>t.name.startsWith('fixture-')&&!t.auth_name));
  await p.locator('#menu-toggle').click();await p.locator('[data-page=nodes]').click();await p.waitForFunction(()=>document.querySelectorAll('.node-admin-row').length===14);
  assert.equal(await p.locator('#node-admin-list form').count(),0);
  for(const theme of ['light','dark'])for(const width of [320,390,768,1440]){
   await p.setViewportSize({width,height:900});await p.evaluate(v=>document.documentElement.dataset.theme=v,theme);
   assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'overflow '+width);
   const boxes=await p.locator('.node-admin-row').evaluateAll(es=>es.map(e=>{const r=e.getBoundingClientRect();return {x:r.x,y:r.y,w:r.width,h:r.height}}));
   assert(boxes.every(b=>b.x>=0&&b.x+b.w<=width+1));assert(boxes.every((b,i)=>!i||b.y>boxes[i-1].y),'cards not one per row');assert(boxes.every(b=>b.h<170),'cards too tall '+width+' '+JSON.stringify(boxes));
   await p.locator('.node-admin-row .icon-button').first().click();await p.locator('.action-sheet').waitFor({state:'visible'});
   const labels=await p.locator('.action-sheet .action-item').allTextContents();for(const label of ['重命名显示名称','编辑月流量额度','编辑到期时间','启用 / 停用','查看流量详情'])assert(labels.includes(label));assert.equal(labels.at(-1),'删除节点');await close();
   if(width===390)await p.screenshot({path:process.env.TZ_TEST_STATE+'/'+(wk?'webkit':'chromium')+'-rows-'+theme+'.png',fullPage:true});
  }
  const first=p.locator('.node-admin-row').first(),oldName=await first.locator('.admin-node-name').textContent();
  await first.locator('.icon-button').click();await p.getByRole('button',{name:'重命名显示名称',exact:true}).click();
  await p.getByRole('textbox',{name:'tzsing 显示别名',exact:true}).fill('独立显示名称');await p.getByRole('button',{name:'保存名称',exact:true}).click();await p.waitForFunction(()=>[...document.querySelectorAll('.admin-node-name')].some(e=>e.textContent==='独立显示名称'));
  const after=await(await ctx.request.get(base+'/api/snapshot')).json();assert.equal(after[0].report.tags.find(t=>t.name==='独立显示名称').id,tags[0].id);
  await p.locator('.node-admin-row').filter({hasText:'独立显示名称'}).locator('.icon-button').click();await p.getByRole('button',{name:'编辑月流量额度',exact:true}).click();await p.getByRole('heading',{name:'编辑月流量额度',exact:true}).waitFor();assert((await p.locator('dialog[open]').last().textContent()).includes('不能作为完整月额度账单'));await close();
  await p.locator('.node-admin-row').first().locator('.admin-node-name').click();await p.locator('#history-panel').waitFor({state:'visible'});assert.equal(await p.locator('#history-panel canvas').count()>0,true);await close();
  const auth=await(await ctx.request.get(base+'/api/me')).json();let res=await ctx.request.put(base+'/api/admin/nodes',{headers:{Origin:new URL(base).origin,'X-CSRF-Token':auth.csrf},data:{node_id:tags[0].id,quota:999}});assert.equal(res.status(),503);
  res=await ctx.request.patch(base+'/api/admin/nodes',{headers:{Origin:new URL(base).origin,'X-CSRF-Token':auth.csrf},data:{node_id:tags[0].id,name:''}});assert.equal(res.status(),200);
  await p.waitForTimeout(1100);assert(frames>=2);assert.deepEqual(errors,[]);
  console.log(JSON.stringify({browser:wk?'webkit':'chromium',uuid_cards:14,one_row_per_uuid:true,rename_preserved_id:true,mobile_and_desktop:true,themes:2,native_dialogs:0,websocket_frames:frames,limits_fail_closed:true,exit_code:0}));
 }finally{await ctx.close();await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
