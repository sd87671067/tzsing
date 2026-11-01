'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs');
const {chromium,webkit}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const stage=JSON.parse(fs.readFileSync(process.env.TZSING_BROWSER_CONFIG,'utf8'));
(async()=>{
 const engine=process.env.TZSING_BROWSER==='webkit'?webkit:chromium,browser=await engine.launch({headless:true,...(engine===chromium?{args:['--no-sandbox']}:{})});
 const ctx=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844},isMobile:true,hasTouch:true}),p=await ctx.newPage(),errors=[];p.on('pageerror',e=>errors.push(e.message));let frames=0;p.on('websocket',s=>s.on('framereceived',()=>frames++));
 const request=async(context,path,method='GET',data)=>{const me=await(await context.request.get(stage.base+'/api/me')).json();const r=await context.request.fetch(stage.base+'/api/'+path,{method,headers:{Origin:new URL(stage.base).origin,'X-CSRF-Token':me.csrf},data});assert(r.ok(),path+' '+r.status()+' '+await r.text());return r.json()};
 const login=async(page,name,pass)=>{await page.goto(stage.base+'/');await page.locator('#login-form [name=name]').fill(name);await page.locator('#login-form [name=password]').fill(pass);await page.locator('#login-form button').click();await page.locator('#dashboard').waitFor({state:'visible'});await page.waitForFunction(()=>document.querySelectorAll('#tags .card--node').length>0)};
 const close=async()=>{await p.locator('#history-panel #close-details').click();await p.waitForFunction(()=>!document.querySelector('#history-panel').open)};
 try{
  await login(p,'admin',stage.admin);await p.waitForFunction(()=>document.querySelectorAll('#tags .card--node').length===2);
  assert.equal(await p.locator('#check-node').count(),0);assert(!(await p.locator('#tags').textContent()).includes('已验证'));
  for(const theme of ['dark','light'])for(const width of [320,390,768]){
   await p.setViewportSize({width,height:900});await p.evaluate(t=>document.documentElement.dataset.theme=t,theme);await p.locator('#tags .node-ip').first().click();await p.waitForFunction(()=>document.querySelector('#history-panel').open);
   assert.equal(await p.locator('.check-ip').count(),1);assert(await p.locator('.check-ip').getAttribute('aria-label')==='检测出口 HTTPS');
   await p.locator('[data-ip-source=ippure]').click();await p.locator('[data-ip-source=ipinfo]').click();
   assert(await p.evaluate(()=>{const d=document.querySelector('#history-panel'),r=d.getBoundingClientRect();return r.left>=0&&r.right<=innerWidth+1&&d.scrollWidth<=d.clientWidth+1}),'modal overflow');
   await close();
  }
  await p.setViewportSize({width:390,height:844});await p.locator('#tags .node-ip').first().click();await p.locator('.check-ip').click();await p.locator('.toast-item').filter({hasText:'出口 HTTPS 检测成功'}).waitFor();await p.waitForFunction(()=>document.querySelector('#detail-ip').textContent.includes('9.9.9.9'));assert.equal(await p.locator('.toast-item').count(),1);assert(!(await p.locator('#source-message').textContent()).includes('独立路由'));
  await p.screenshot({path:process.env.TZSING_BROWSER_ARTIFACTS+'/ip-'+process.env.TZSING_BROWSER+'.png'});await close();
  await p.evaluate(()=>navigate('users'));await p.locator('.user-summary').filter({hasText:'viewer'}).click();await p.locator('#permission-panel').waitFor({state:'visible'});assert.equal(await p.locator('#operation-choices input').count(),5);assert.equal(await p.locator('#operation-choices input:checked').count(),0);assert(await p.locator('.grant-choices input[type=checkbox]').count()>=2);
  await p.locator('.operation-panel summary').click();await p.locator('[data-operation=copy]').check();await p.locator('#operation-save').click();await p.waitForFunction(()=>!document.querySelector('#operation-save').disabled);const ops=await request(ctx,'admin/operations');assert(ops.some(x=>x.user_id===2&&x.action==='copy'));
  assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'permission overflow');await p.screenshot({path:process.env.TZSING_BROWSER_ARTIFACTS+'/permissions-'+process.env.TZSING_BROWSER+'.png'});
  const user=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844}}),up=await user.newPage();up.on('pageerror',e=>errors.push(e.message));await login(up,'viewer',stage.viewer);assert.equal(await up.locator('#tags .card--node').count(),1);await up.locator('#tags .node-head .icon-button').click();await up.locator('dialog.action-sheet').waitFor();assert(await up.getByRole('button',{name:'复制节点链接',exact:true}).isVisible());assert(!(await up.getByRole('button',{name:'导入 v2rayN',exact:true}).isVisible()));assert(!(await up.getByRole('button',{name:'删除节点',exact:true}).isVisible()));
  await request(ctx,'admin/operations','PUT',{user_id:2,actions:[]});await up.waitForFunction(()=>!document.querySelector('#tags .node-head .icon-button')||document.querySelector('#tags .node-head .icon-button').hidden,{timeout:10000});await user.close();
  assert(frames>0);assert.deepEqual(errors,[]);console.log(JSON.stringify({browser:process.env.TZSING_BROWSER,exit_code:0,widths:3,themes:2,ip_icon:true,one_toast:true,user_panel:true,operation_toggle:true,user_menu:true,revocation:true,websocket_frames:frames}));
 }finally{await ctx.close();await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
