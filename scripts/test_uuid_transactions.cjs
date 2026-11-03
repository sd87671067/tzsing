'use strict';
const fs=require('fs'),assert=require('node:assert/strict'),{chromium,webkit}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const dir=process.env.TZSING_UUID_BROWSER_STAGE,cfg=JSON.parse(fs.readFileSync(dir+'/browser.json'));
(async()=>{try{for(const [engine,type] of Object.entries({chromium,webkit}).filter(([name])=>!process.env.TZSING_BROWSER_ENGINE||name===process.env.TZSING_BROWSER_ENGINE))for(const width of (process.env.TZSING_BROWSER_WIDTH?[Number(process.env.TZSING_BROWSER_WIDTH)]:[390,1440])){
 const b=await type.launch({headless:true}),ctx=await b.newContext({ignoreHTTPSErrors:true,viewport:{width,height:900},isMobile:width<500,hasTouch:width<500}),p=await ctx.newPage(),errors=[];p.on('pageerror',e=>errors.push(e.message));p.on('requestfailed',r=>console.log('request failed',r.url(),r.failure()));p.on('response',r=>{if(r.status()>=400)console.log('http failure',r.url(),r.status())});p.setDefaultTimeout(45000);
 try{
 console.log('starting',engine,width);p.on('response',async r=>{if(r.url().endsWith('/api/login'))console.log('login status',r.status())});
 await p.goto(cfg.base+'/');await p.locator('#login-form [name=name]').fill('admin');await p.locator('#login-form [name=password]').fill(cfg.admin);console.log('login fields filled',engine,width);await p.locator('#login-form button').click();console.log('login clicked',engine,width);await p.locator('#dashboard').waitFor({state:'visible'});console.log('login ok',engine,width);
 await p.evaluate(()=>navigate('add-node'));await p.locator('.uuid-form [name=name]').fill('ck');
 // Request reaches the real isolated Web/controller, but the browser loses its response.
 let create=0,queries=0,accepted;const acceptance=new Promise(resolve=>accepted=resolve),routeErrors=[];
 await p.route('**/api/admin/node-create',async route=>{create++;try{const response=await route.fetch({timeout:15000});assert.equal(response.status(),202);accepted();await route.abort('connectionfailed')}catch(e){routeErrors.push(e.message);accepted();try{await route.abort('connectionfailed')}catch{}}});
 await p.route('**/api/admin/node-transaction?*',route=>{queries++;return queries<=2?route.fulfill({status:503,json:{error:'Synthetic interrupted proxy'}}):route.continue()});
 await p.getByRole('button',{name:'添加节点',exact:true}).click();await p.getByRole('dialog',{name:'确认添加 UUID 节点',exact:true}).getByRole('button',{name:'确认应用',exact:true}).click();
 await p.waitForFunction(()=>Object.keys(localStorage).some(k=>k.includes(':uuid-operation:')));await acceptance;assert.deepEqual(routeErrors,[]);console.log('accepted',engine,width);await p.reload();
 await p.waitForFunction(()=>!Object.keys(localStorage).some(k=>k.includes(':uuid-operation:')));
 await p.waitForFunction(()=>[...document.querySelectorAll('#tags h2')].some(e=>e.textContent==='ck'));
 assert.equal(create,1);assert(queries>=3);assert(!(await p.locator('#tags').textContent()).includes('含崩溃未决预留'));assert(!(await p.locator('#tags').textContent()).includes('未结算预留'));
 await p.evaluate(()=>navigate('add-node'));await p.locator('.uuid-form').waitFor();assert.equal(await p.getByRole('button',{name:'添加节点',exact:true}).isDisabled(),false);
 for(const theme of ['light','dark']){await p.evaluate(t=>document.documentElement.dataset.theme=t,theme);assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth))}
 assert.deepEqual(errors,[]);console.log(JSON.stringify({engine,width,lost_response_recovered:true,create_requests:create,queries,ck:true,loading_cleared:true,internal_text_removed:true,exit_code:0}));
 }catch(e){console.log('failure reason',e.message);console.log('browser diagnostic',engine,width,await p.locator('body').innerText(),errors);throw e}finally{await p.unrouteAll({behavior:'wait'});await ctx.close();await b.close()}
 }}finally{fs.writeFileSync(dir+'/done','done')}})().catch(e=>{console.error(e);process.exitCode=1});
