'use strict';
const fs=require('fs'),assert=require('node:assert/strict'),{chromium,webkit}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const dir=process.env.TZSING_BROWSER_STAGE,cfg=JSON.parse(fs.readFileSync(dir+'/browser.json'));
(async()=>{try{for(const [engine,type] of Object.entries({chromium,webkit})){
 const browser=await type.launch({headless:true}),ctx=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844}}),p=await ctx.newPage();p.setDefaultTimeout(12000);const errors=[];p.on('pageerror',e=>errors.push(e.message));let sockets=[];p.on('websocket',s=>sockets.push(s));
 try{
 await p.addInitScript(()=>{window.observedSockets=[];window.WebSocket=new Proxy(WebSocket,{construct(Type,args){const ws=new Type(...args);observedSockets.push(ws);return ws}})});
 await p.goto(cfg.base+'/');await p.locator('#login-form [name=name]').fill('admin');await p.locator('#login-form [name=password]').fill(cfg.admin);await p.locator('#login-form button').click();await p.waitForFunction(()=>document.querySelector('#connection').textContent==='实时连接');
 async function nav(page){await p.evaluate(page=>navigate(page),page)}
 async function rename(name){await nav('nodes');await p.locator('[data-node-kind=outbound]').click();const card=p.locator('.outbound-row').first();await card.locator('summary').click();await card.getByRole('button',{name:'重命名',exact:true}).click();const modal=p.getByRole('dialog',{name:'重命名出站',exact:true});await modal.locator('input').fill(name);await modal.getByRole('button',{name:'保存名称',exact:true}).click();await modal.waitFor({state:'hidden'});await p.waitForFunction(name=>document.querySelector('.outbound-summary strong')?.textContent===name,name||'relay')}
 // Add flow verifies the display field is separate from the actual tag/config.
 let label='美国洛杉矶';await p.route('**/api/admin/outbounds',async route=>{const req=route.request();if(req.method()!=='POST')return route.continue();const v=req.postDataJSON();if(v.action==='save'){assert.equal(v.name,label);assert.equal(v.node.tag,'');assert.deepEqual(v.node.config,{type:'direct'});return route.fulfill({json:{nonce:'synthetic-add',ip:'8.8.8.8',reason:'隔离新增出站'}})}if(v.action==='apply'){await p.evaluate(async label=>api('admin/outbounds','POST',{action:'rename',name:label,node:{tag:'relay'}}),label);return route.fulfill({json:{ok:true,tag:'relay',ip:'8.8.8.8'}})}return route.continue()});
 await nav('add-outbound');await p.getByLabel('显示名称（留空使用真实 Tag）').fill(label);await p.getByRole('button',{name:'保存出站节点',exact:true}).click();await p.getByRole('dialog',{name:'确认保存出站节点',exact:true}).getByRole('button',{name:'确认保存',exact:true}).click();await p.locator('#outbound-editor').waitFor({state:'hidden'});await p.unroute('**/api/admin/outbounds');
 await p.waitForFunction(()=>views[0]?.report.tags[0]?.egress_name==='美国洛杉矶');
 await rename('美国高速线路');
 await p.waitForFunction(()=>views[0]?.report.tags[0]?.egresses[0]?.name==='美国高速线路');assert.equal(await p.evaluate(()=>views[0].report.tags[0].egress),'relay');
 await nav('overview');await p.locator('#tags .node-summary').first().click();await p.waitForFunction(()=>document.querySelector('#detail-status').textContent.includes('美国高速线路'));assert((await p.locator('#detail-ip').textContent()).includes('美国高速线路'));await p.locator('#close-details').click();
 await nav('nodes');await p.locator('[data-node-kind=inbound]').click();await p.locator('#node-admin-list .node-admin-row').first().click();await p.waitForFunction(()=>document.querySelector('#node-admin-list select')?.options[0]?.textContent.includes('美国高速线路'));assert.equal(await p.locator('#node-admin-list select').first().inputValue(),'relay');
 await nav('add-node');await p.getByRole('button',{name:'中转',exact:true}).click();await p.waitForFunction(()=>document.querySelector('[name=outbound]')?.options[0]?.textContent.includes('美国高速线路'));assert.equal(await p.locator('[name=outbound]').inputValue(),'relay');
 await p.reload();await p.waitForFunction(()=>document.querySelector('#connection').textContent==='实时连接'&&views[0]?.report.tags[0]?.egress_name==='美国高速线路');
 // Real fixture WSS disconnection plus transient HTTP 503 recovery.
 let failures=2;await p.route('**/api/me',r=>failures-->0?r.fulfill({status:503,json:{error:'Synthetic proxy outage'}}):r.continue());await ctx.setOffline(true);await p.waitForTimeout(250);await ctx.setOffline(false);await p.waitForFunction(()=>document.querySelector('#connection').textContent==='实时连接',{},{timeout:20000});assert(failures<=0);await p.unroute('**/api/me');
 assert.equal(await p.evaluate(()=>observedSockets.filter(s=>s.readyState===WebSocket.OPEN||s.readyState===WebSocket.CONNECTING).length),1);
 await rename('');await p.waitForFunction(()=>views[0]?.report.tags[0]?.egress_name==='relay');
 for(const theme of ['light','dark'])for(const width of [320,1440]){await p.setViewportSize({width,height:900});await p.evaluate(theme=>document.documentElement.dataset.theme=theme,theme);assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth))}
 // Expiry response must stop reconnecting and show the login form.
 await p.route('**/api/me',r=>r.fulfill({status:401,json:{error:'Unauthorized'}}));await ctx.setOffline(true);await p.waitForTimeout(100);await ctx.setOffline(false);await p.locator('#login').waitFor({state:'visible'});assert((await p.locator('body').textContent()).includes('登录已过期'));const count=sockets.length;await p.waitForTimeout(1500);assert.equal(sockets.length,count);assert.deepEqual(errors,[]);
 console.log(JSON.stringify({engine,add_display_name:true,rename_all_views:true,stable_tag:true,refresh:true,empty_fallback:true,real_wss_recovery:true,temporary_me_503_recovery:true,session_expiry:true,one_socket:true,responsive:true,errors,exit_code:0}));
 }finally{await ctx.close();await browser.close()}
 }}finally{fs.writeFileSync(dir+'/done','done')}})().catch(e=>{console.error(e);process.exitCode=1});
