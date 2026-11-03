'use strict';
const fs=require('fs'),assert=require('node:assert/strict'),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const dir=process.env.TZSING_UUID_BROWSER_STAGE,cfg=JSON.parse(fs.readFileSync(dir+'/browser.json'));
(async()=>{
 const browser=await chromium.launch({headless:true});const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844},isMobile:true,hasTouch:true}),page=await context.newPage();
 let creates=0,phase='login';page.setDefaultTimeout(45000);
 try{
  await page.goto(cfg.base+'/');await page.locator('#login-form [name=name]').fill('admin');await page.locator('#login-form [name=password]').fill(cfg.admin);await page.locator('#login-form button').click();await page.locator('#dashboard').waitFor({state:'visible'});
  const open=async()=>{await page.evaluate(()=>navigate('add-node'));await page.locator('.uuid-form').waitFor();await page.locator('.uuid-form [name=name]').fill('ck')};
  const add=()=>page.getByRole('button',{name:'添加节点',exact:true});
  await page.route('**/api/admin/node-create',route=>{creates++;return route.fulfill({status:202,json:{state:'pending'}})});
  phase='cancel';console.log(phase);await open();await add().click();const dialog=page.getByRole('dialog',{name:'确认添加 UUID 节点',exact:true});await dialog.getByRole('button',{name:'取消',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('.uuid-form button.primary').disabled);assert.equal(creates,0);
  phase='preview failure';console.log(phase);await page.route('**/api/admin/node-preview',route=>route.fulfill({status:503,json:{error:'Synthetic validation unavailable'}}));await add().click();await page.waitForFunction(()=>!document.querySelector('.uuid-form button.primary').disabled);assert.equal(creates,0);await page.unroute('**/api/admin/node-preview');
  phase='apply failure';console.log(phase);let outcome='failed',queries=0;await page.route('**/api/admin/node-transaction?*',route=>{queries++;return route.fulfill({json:{state:outcome,error:'Synthetic apply failure'}})});
  await add().click();const failedSnapshot=page.waitForResponse(r=>r.url().endsWith('/api/snapshot')&&r.status()===200);await dialog.getByRole('button',{name:'确认应用',exact:true}).click();await failedSnapshot;await page.waitForFunction(()=>currentPage==='overview'&&!document.querySelector('dialog[open]'));await page.waitForFunction(()=>!Object.keys(localStorage).some(k=>k.includes(':uuid-operation:')));await open();assert.equal(await add().isDisabled(),false);assert.equal(creates,1);
  phase='timeout';console.log(phase);await page.clock.install();outcome='pending';await page.evaluate(()=>{localStorage.setItem(prefix+':uuid-operation:'+me.id,JSON.stringify({id:'synthetic-timeout',server:'one'}));UUIDEditor.resume()});await page.waitForTimeout(50);await page.clock.fastForward(181000);
  await page.waitForFunction(()=>document.body.textContent.includes('结果确认超时'));assert(await page.evaluate(()=>Object.keys(localStorage).some(k=>k.includes(':uuid-operation:'))));await page.evaluate(()=>navigate('add-node'));await page.getByRole('button',{name:'查询原添加事务',exact:true}).waitFor();assert.equal(creates,1);
  phase='recovery';console.log(phase);outcome='succeeded';const recoveredSnapshot=page.waitForResponse(r=>r.url().endsWith('/api/snapshot')&&r.status()===200);await page.getByRole('button',{name:'查询原添加事务',exact:true}).click();await recoveredSnapshot;await page.waitForFunction(()=>currentPage==='overview'&&!document.querySelector('dialog[open]'));await page.waitForFunction(()=>!Object.keys(localStorage).some(k=>k.includes(':uuid-operation:')));assert.equal(creates,1);await open();assert.equal(await add().isDisabled(),false);
  console.log(JSON.stringify({cancel:true,preview_failure:true,apply_failure:true,timeout_retains_original:true,recovery_clears_loading:true,no_duplicate_submit:true,queries,exit_code:0}));
 }catch(e){console.log('phase',phase,'body',await page.locator('body').innerText());throw e}finally{await page.unrouteAll({behavior:'wait'});await context.close();await browser.close();fs.writeFileSync(dir+'/done','done')}
})().catch(error=>{console.error(error.message);process.exitCode=1});
