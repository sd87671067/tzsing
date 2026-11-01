const fs=require('fs'),assert=require('assert/strict');
assert(process.env.TZ_SYNTHETIC_STAGE==='1'&&process.env.TZSING_BROWSER_STAGE,'isolated synthetic stage required');
const stage=process.env.TZSING_BROWSER_STAGE;
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const cfg=JSON.parse(fs.readFileSync(stage+'/browser.json'));const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE||undefined,args:['--no-sandbox']});const ctx=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844},isMobile:true,hasTouch:true});const p=await ctx.newPage();p.setDefaultTimeout(10000);const errors=[];p.on('pageerror',e=>errors.push(e.message));p.on('dialog',()=>errors.push('native dialog'));
 const login=async(page,name,password)=>{await page.goto(cfg.base+'/');await page.locator('#login-form [name=name]').fill(name);await page.locator('#login-form [name=password]').fill(password);await page.locator('#login-form button').click();await page.locator('#dashboard').waitFor({state:'visible'});};
 try{
 p.setDefaultTimeout(10000);
 await login(p,'admin',cfg.admin);await p.waitForFunction(()=>document.querySelectorAll('#tags .card--node').length===2);
 await p.locator('#tags .node-ip').first().click();await p.locator('#history-panel').waitFor({state:'visible'});assert.equal(await p.locator('#detail-ip .check-ip').count(),1);assert(!(await p.locator('#detail-ip').textContent()).includes('已验证'));
 await p.evaluate(()=>{window.toastCount=0;const old=UI.notify;UI.notify=(...args)=>{window.toastCount++;return old(...args)}});
 await p.locator('#detail-ip .check-ip').click();await p.waitForFunction(()=>window.toastCount===1);await p.waitForTimeout(350);assert.equal(await p.evaluate(()=>window.toastCount),1);
 await p.keyboard.press('Escape');await p.locator('#menu-toggle').click();await p.locator('[data-page=settings]').click();assert.equal(await p.locator('[name=show_expiry]').isChecked(),false);assert.equal(await p.locator('[name=show_quota]').isChecked(),true);
 await p.locator('#menu-toggle').click();await p.locator('[data-page=nodes]').click();await p.waitForFunction(()=>document.querySelectorAll('.node-admin-row').length>=2,{}, {timeout:10000});
 for(const theme of ['light','dark'])for(const width of [320,390,768]){await p.setViewportSize({width,height:844});await p.evaluate(v=>document.documentElement.dataset.theme=v,theme);assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'overflow '+width)}
 await p.locator('#node-admin-list [aria-label$="节点操作"]').first().click();await p.getByText('编辑月流量额度',{exact:true}).click();await p.locator('.policy-fields').waitFor();assert.equal(await p.getByRole('button',{name:'保存策略',exact:true}).isDisabled(),true);assert(await p.locator('.policy-fields').textContent().then(s=>s.includes('尚未运行')));
 assert.deepEqual(errors,[]);console.log(JSON.stringify({cards:2,compact_admin:true,global_defaults:true,check_icon:1,completion_toast:1,unsafe_policy_save_disabled:true,widths:3,themes:2,exit_code:0}));
 }finally{await ctx.close();await browser.close();fs.writeFileSync(stage+'/done','done')}
})().catch(e=>{console.error(e);process.exitCode=1});
