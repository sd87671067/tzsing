'use strict';
const fs=require('fs'),assert=require('assert/strict'),{chromium,webkit}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const stage=process.env.TZSING_BROWSER_STAGE;assert(stage&&process.env.TZ_SYNTHETIC_STAGE==='1');const cfg=JSON.parse(fs.readFileSync(stage+'/browser.json'));
(async()=>{try{for(const [engine,type]of Object.entries({chromium,webkit})){
 const browser=await type.launch({headless:true,...(engine==='chromium'?{args:['--no-sandbox']}: {})});const ctx=await browser.newContext({viewport:{width:390,height:844},isMobile:true,hasTouch:true,ignoreHTTPSErrors:true}),p=await ctx.newPage();p.setDefaultTimeout(10000);const errors=[];p.on('pageerror',e=>errors.push(e.message));p.on('dialog',()=>errors.push('native dialog'));
 let previews=0,applies=0,refreshes=0,fail=true;
 await p.route('**/api/control/status?*',r=>r.fulfill({json:{delete:true,apply:true,share:false,nonce:'status',outbounds:[],reason:'Synthetic',actions:{change:true}}}));
 await p.route('**/api/control/preview',async r=>{const v=r.request().postDataJSON();assert.equal(v.action,'delete');previews++;await new Promise(x=>setTimeout(x,150));return r.fulfill({json:{nonce:'plan-'+previews,writable:true,effects:{shared_listener:443,other_uuids:1},impact:'Synthetic'}})});
 await p.route('**/api/control/apply',async r=>{applies++;await new Promise(x=>setTimeout(x,400));if(fail){fail=false;return r.fulfill({status:409,json:{error:'route/rules/2 管理路由被外部修改；未删除'}})}return r.fulfill({json:{ok:true}})});
 await p.route('**/api/snapshot',async r=>{refreshes++;return r.continue()});
 try{
 await p.goto(cfg.base+'/');await p.locator('#login-form [name=name]').fill('admin');await p.locator('#login-form [name=password]').fill(cfg.admin);await p.locator('#login-form button').click();await p.locator('#dashboard').waitFor({state:'visible'});
 async function nav(){await p.locator('#menu-toggle').click();await p.locator('[data-page=nodes]').click();await p.locator('#navigation').waitFor({state:'hidden'});await p.locator('.node-admin-row').first().waitFor()}
 await nav();
 await p.evaluate(()=>{for(const [id,r]of adminRows)r.el.dataset.testProtocol=rows.get(id)?.t.type||''});let row=p.locator('.node-admin-row[data-test-protocol=vless]').first();await row.locator('.admin-node-name').click();await row.getByRole('button',{name:'删除入站',exact:true}).click();let dialog=p.getByRole('dialog',{name:'确认删除节点',exact:true});await dialog.waitFor();assert.equal(await p.locator('dialog[open]').count(),1);assert((await dialog.textContent()).includes('vless'));assert((await dialog.textContent()).includes('共享出站'));assert.equal(previews,0);await dialog.getByRole('button',{name:'取消',exact:true}).click();await dialog.waitFor({state:'hidden'});assert.equal(applies,0);
 for(const protocol of ['vless','shadowsocks','trojan','socks','http']){

 // Refresh the normal UI rows through the application's snapshot API.
 await p.evaluate(async()=>{update(await api('snapshot'));await loadNodeAdmin();for(const [id,r]of adminRows)r.el.dataset.testProtocol=rows.get(id)?.t.type||''});
 row=p.locator('.node-admin-row[data-test-protocol='+protocol+']').first();if(await row.locator('.inbound-settings').getAttribute('hidden')!==null)await row.locator('.admin-node-name').click();await row.locator('.inbound-settings').waitFor({state:'visible'});
 await row.getByRole('button',{name:'删除入站',exact:true}).click();dialog=p.getByRole('dialog',{name:'确认删除节点',exact:true});await dialog.waitFor();assert((await dialog.textContent()).includes(protocol));
 for(const width of [320,390,1280]){await p.setViewportSize({width,height:width===320?568:844});for(const label of ['取消','删除节点']){const b=await dialog.getByRole('button',{name:label,exact:true}).boundingBox();assert(b&&b.x>=0&&b.y>=0&&b.x+b.width<=width+1&&b.y+b.height<=(width===320?568:844)+1,engine+' footer clipped '+width)}}
 await p.setViewportSize({width:390,height:844});let yes=dialog.getByRole('button',{name:'删除节点',exact:true});const baseline=applies;await yes.click();await p.waitForFunction(()=>document.querySelector('dialog[open] button[aria-busy=true]'));assert(await yes.isDisabled());assert.equal(await yes.evaluate(el=>getComputedStyle(el,'::before').content),'""');await yes.dispatchEvent('click');await p.keyboard.press('Escape');assert(await dialog.isVisible());
 if(protocol==='vless'){await dialog.locator('.confirm-content > [role=alert]').waitFor({state:'visible'});assert((await dialog.locator('.confirm-content > [role=alert]').textContent()).includes('route/rules/2'));assert.equal(applies,baseline+1);assert(!(await yes.isDisabled()));await yes.click()}
 await dialog.waitFor({state:'hidden'});await p.getByText('节点已删除',{exact:true}).first().waitFor();assert.equal(applies,baseline+(protocol==='vless'?2:1));
 }
 assert(refreshes>=6);assert.deepEqual(errors,[]);console.log(JSON.stringify({engine,protocols:5,direct_confirmation:true,footer_widths:[320,390,1280],cancel:true,loading:true,duplicate_guard:true,conflict_reason:true,retry:true,refresh:true,toast:true,exit_code:0}));
 }catch(e){console.error(JSON.stringify({engine,errors,rows:await p.locator('.node-admin-row').evaluateAll(els=>els.map(el=>el.outerHTML))}));throw e}finally{await ctx.close();await browser.close()}
 }}finally{fs.writeFileSync(stage+'/done','done')}})().catch(e=>{console.error(e);process.exitCode=1});
