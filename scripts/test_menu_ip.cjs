const fs=require('fs'),assert=require('assert/strict');
const {chromium,webkit}=require(process.env.PLAYWRIGHT_MODULE);
const stage=process.env.TZSING_BROWSER_STAGE,cfg=JSON.parse(fs.readFileSync(stage+'/browser.json'));
(async()=>{const browsers=[];try{for(const [engine,type] of Object.entries({chromium,webkit})){
 const browser=await type.launch({headless:true,...(engine==='chromium'?{executablePath:process.env.CHROMIUM_EXECUTABLE,args:['--no-sandbox']}: {})});browsers.push(browser);
 console.log('start '+engine);const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:390,height:844},isMobile:true,hasTouch:true}),page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(12000);
 const login=async(p,user,password)=>{await p.goto(cfg.base+'/');await p.locator('#login-form [name=name]').fill(user);await p.locator('#login-form [name=password]').fill(password);await p.locator('#login-form button').click();await p.locator('#dashboard').waitFor({state:'visible'});};
 await login(page,'admin',cfg.admin);await page.locator('#menu-toggle').click();await page.locator('[data-page=users]').click();await page.locator('.user-summary').filter({hasText:'viewer'}).click();assert.equal(await page.locator('#precise-outbounds').count(),0);assert.equal(await page.getByText('逐 UUID 出站与个人出站权限',{exact:true}).count(),0);
 const admin=page;await admin.evaluate(()=>api('admin/operations','PUT',{user_id:2,actions:[]}));
 const viewer=await context.newPage();viewer.setDefaultTimeout(12000);viewer.setDefaultNavigationTimeout(12000);viewer.on('pageerror',e=>errors.push(e.message));await context.clearCookies(); // Keep administrator session in a separate context below.
 // Save the admin cookie before logout is unnecessary: re-login uses the same account in another context.
 const ac=await browser.newContext({ignoreHTTPSErrors:true});const ap=await ac.newPage();ap.setDefaultTimeout(12000);ap.on('pageerror',e=>errors.push(e.message));await login(ap,'admin',cfg.admin);
 await login(viewer,'viewer',cfg.viewer);await viewer.locator('#tags .card--node').waitFor();assert.equal(await viewer.locator('#tags .card--node').count(),1);
 const menu=async()=>{await viewer.locator('#tags button[aria-label="节点操作"]').click();};
 await menu();assert.equal(await viewer.getByRole('button',{name:'更换节点出站 IP',exact:true}).count(),0);assert.equal(await viewer.getByRole('button',{name:'个人与授权出站',exact:true}).count(),0);
 assert.equal(await viewer.getByRole('button',{name:'管理个人出站',exact:true}).isVisible(),false);await ap.evaluate(()=>api('admin/operations','PUT',{user_id:2,actions:['change']}));await viewer.waitForFunction(()=>operations.change===true);await viewer.locator('#tags .card--node').waitFor();await menu();await viewer.getByRole('button',{name:'管理个人出站',exact:true}).waitFor({state:'visible'});await viewer.getByRole('button',{name:'更换节点出站 IP',exact:true}).click();
 const select=viewer.getByLabel('可选出站');await select.locator('option').waitFor({state:'attached'});assert.equal(await select.locator('option').count(),1);assert.match(await select.inputValue(),/./);assert.match(await select.locator('option:checked').textContent(),/当前出站/);assert.equal(await viewer.getByLabel('节点分享链接').isVisible(),false);
 let previews=0,applies=0;viewer.on('request',r=>{if(r.url().endsWith('/api/control/preview'))previews++;if(r.url().endsWith('/api/control/apply'))applies++;});
 await viewer.route('**/api/control/apply',async route=>{await new Promise(r=>setTimeout(r,350));await route.continue();});
 const save=viewer.getByRole('button',{name:'保存更换',exact:true});await save.click();await viewer.getByRole('button',{name:'确认应用',exact:true}).waitFor();assert.equal(await save.isDisabled(),true);assert.equal(await save.getAttribute('aria-busy'),'true');await viewer.getByRole('button',{name:'确认应用',exact:true}).click();await viewer.waitForFunction(()=>!document.querySelector('select[aria-label="可选出站"]'));assert.equal(previews,1);assert.equal(applies,1);
 // Personal CRUD has one independent UI and contains no second route-binding path.
 let creates=0,personalApplies=0,tests=0,edits=0,deletes=0,items=[];
 await viewer.route('**/api/personal-outbounds*',async route=>{const r=route.request();if(r.method()==='GET')return route.fulfill({json:{items}});const v=r.postDataJSON();if(v.action==='test'){tests++;return route.fulfill({json:{ip:'8.8.8.8'}})}if(v.action==='apply'){personalApplies++;return route.fulfill({json:{ok:true}})}if(v.action==='create'){creates++;items=[{id:'own',name:v.name,owner:2}]}if(v.action==='edit'){edits++;items[0].name=v.name}if(v.action==='delete'){deletes++;items=[]}return route.fulfill({json:{id:'own',nonce:'fixture',reason:'隔离浏览器夹具'}})});
 await menu();await viewer.getByRole('button',{name:'管理个人出站',exact:true}).click();const name=viewer.getByLabel('名称',{exact:true}),link=viewer.getByLabel('节点链接',{exact:true});await name.fill('个人合成出站');await link.fill('http://synthetic:secret@example.org:443');await viewer.getByRole('button',{name:'创建个人出站',exact:true}).click();await viewer.getByRole('button',{name:'确认应用',exact:true}).click();await viewer.getByText('个人合成出站',{exact:true}).waitFor();await viewer.getByRole('button',{name:'检测',exact:true}).click();await viewer.getByRole('button',{name:'编辑',exact:true}).click();await name.fill('修改后出站');await link.fill('http://example.org:443');await viewer.getByRole('button',{name:'保存个人出站',exact:true}).click();await viewer.getByRole('button',{name:'确认应用',exact:true}).click();await viewer.getByText('修改后出站',{exact:true}).waitFor();await viewer.getByRole('button',{name:'删除',exact:true}).click();await viewer.getByRole('button',{name:'确认应用',exact:true}).click();await viewer.getByText('修改后出站',{exact:true}).waitFor({state:'detached'});
 assert.deepEqual([creates,edits,deletes,tests,personalApplies],[1,1,1,1,3]);assert.equal(await viewer.getByRole('button',{name:'绑定此 UUID',exact:true}).count(),0);
 for(const width of [320,390,1280])for(const theme of ['light','dark']){await viewer.setViewportSize({width,height:844});await viewer.evaluate(t=>document.documentElement.dataset.theme=t,theme);assert(await viewer.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'overflow '+engine+' '+width)}
 await viewer.keyboard.press('Escape');await viewer.waitForFunction(()=>!document.querySelector('dialog.modal[open]'));await menu();await ap.evaluate(()=>api('admin/operations','PUT',{user_id:2,actions:[]}));await viewer.waitForFunction(()=>!operations.change);await viewer.waitForFunction(()=>!document.querySelector('.action-sheet'));await viewer.locator('#tags .card--node').waitFor();await menu();assert.equal(await viewer.getByRole('button',{name:'更换节点出站 IP',exact:true}).isVisible(),false);assert.equal(await viewer.getByRole('button',{name:'管理个人出站',exact:true}).isVisible(),false);
 await viewer.unroute('**/api/personal-outbounds*');
 for(const action of ['create','edit','delete','apply','test']){const code=await viewer.evaluate(async action=>{const r=await fetch(prefix+'/api/personal-outbounds',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({node_id:[...rows.keys()][0],action})});return r.status},action);assert.equal(code,403,action)}
 // Exercise the actual native sheet and optional metadata renderer in both engines.
 await ap.evaluate(()=>{socket.onmessage=()=>{}});
 await ap.locator('#tags button[aria-label="节点操作"]').first().click();
 for(const b of await ap.locator('.action-sheet .action-item:visible').all()){assert.equal(await b.locator('svg.icon').count(),1);assert.equal(await b.locator('span').count(),1)}
 await ap.keyboard.press('Escape');await ap.waitForFunction(()=>!document.querySelector('.action-sheet'));
 let fields={},requests=0;
 await ap.route('**/api/node-inspect',async route=>{const v=route.request().postDataJSON();requests++;const source=v.source;return route.fulfill({json:{source,at:Math.floor(Date.now()/1000),data:{country_code:'US',city:source+' City',org:source+' Network',...fields[source]}}})});
 const openIP=async version=>{await ap.evaluate(v=>{const id=[...rows.keys()][0];rows.get(id).t.route_version=v;showHistory(id)},version);await ap.waitForFunction(()=>document.querySelector('#history-panel').open);await ap.waitForFunction(()=>!document.querySelector('#source-message').textContent.includes('正在'))};
 const closeIP=async()=>{await ap.locator('#close-details').click();await ap.waitForFunction(()=>!document.querySelector('#history-panel').open)};
 for(const isp of [false,true])for(const typed of [false,true]){
  fields=Object.fromEntries(['ipinfo','ippure'].map(source=>[source,{...(isp?{isp:source+' ISP'}:{}),...(typed?{ip_type:source==='ippure'?'住宅':'机房'}:{})}]));
  await openIP('combination-'+isp+'-'+typed);
  for(const source of ['ipinfo','ippure']){await ap.locator('[data-ip-source='+source+']').click();await ap.waitForFunction(s=>document.querySelector('#detail-ip').textContent.includes(s+' City'),source);const txt=await ap.locator('#detail-ip').textContent();assert.equal(txt.includes(source+' ISP'),isp);assert.equal(txt.includes('IP 类型'),typed);assert(!txt.includes((source==='ipinfo'?'ippure':'ipinfo')+' ISP'));assert(!/未知|N\/A|null|undefined/.test(txt));}
  assert.equal(await ap.locator('#detail-flow').count(),0);assert(!/auth_user|采样|已观测下界/.test(await ap.locator('#history-panel').textContent()));assert.equal(await ap.locator('#detail-totals .stat-cell').count(),3);
  const before=requests;await ap.locator('[data-ip-source=ipinfo]').click();await ap.waitForFunction(()=>document.querySelector('#detail-ip').textContent.includes('ipinfo City'));assert.equal(requests,before,'cached switch made request');await closeIP();
 }
 for(const value of ['unknown','N/A','null','undefined','未知','']){
  fields={ipinfo:{isp:value,ip_type:value},ippure:{isp:value,ip_type:value}};await openIP('unknown-'+value);
  for(const source of ['ipinfo','ippure']){await ap.locator('[data-ip-source='+source+']').click();await ap.waitForFunction(s=>document.querySelector('#detail-ip').textContent.includes(s+' City'),source);const labels=await ap.locator('#detail-ip dt').allTextContents();assert(!labels.includes('ISP'));assert(!labels.includes('IP 类型'));}await closeIP();
 }
 for(const width of [320,390,1280])for(const theme of ['light','dark']){
  await ap.setViewportSize({width,height:568});await ap.evaluate(t=>document.documentElement.dataset.theme=t,theme);await openIP('viewport-'+width+'-'+theme);
  assert(await ap.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  const rect=await ap.locator('#history-panel').boundingBox();assert(rect.x>=0&&rect.x+rect.width<=width+1&&rect.height<=568);
  assert(await ap.evaluate(()=>{const d=document.querySelector('#history-panel');return d.scrollWidth<=d.clientWidth}));
  const title=await ap.locator('#history-title').boundingBox(),close=await ap.locator('#close-details').boundingBox();assert(title.x+title.width<=close.x+1,'title overlaps close button');
  await ap.locator('#history-panel').evaluate(d=>{d.scrollTop=d.scrollHeight});assert(await ap.locator('#history-panel').evaluate(d=>d.scrollTop>0),'small screen cannot scroll');await ap.locator('#history-panel').evaluate(d=>{d.scrollTop=0});
  await ap.screenshot({path:stage+'/'+engine+'-'+width+'-'+theme+'-ip.png'});await closeIP();
 }
 console.log(JSON.stringify({engine,permission_live_without_reload:true,direct_personal_api_403:true,svg_icons:true,provider_combinations:8,unknown_hidden:true,source_isolation:true,widths:[320,390,1280],themes:['light','dark'],exit_code:0}));

 assert.deepEqual(errors,[]);await viewer.screenshot({path:stage+'/'+engine+'-permissions.png',fullPage:true});console.log(JSON.stringify({engine,gate:true,current_selected:true,save_loading:true,single_submit:true,personal_crud:true,widths:[320,390,1280],exit_code:0}));await ac.close();await context.close();await browser.close();
}}finally{for(const b of browsers)await b.close();fs.writeFileSync(stage+'/done','done')}})().catch(e=>{console.error(e);process.exitCode=1});
