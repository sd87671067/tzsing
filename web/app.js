'use strict';
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)],prefix=location.pathname.replace(/\/$/,''),NA='暂不可用';let csrf='',me=null,socket=null,retry=null,views=[],historyRows=[],selectedHistory=null;const cards=new Map(),rows=new Map(),points=[];let chartRange='live',chartType='area',historyRequest=0;const rangeCache=new Map();let lastPoint=0;
const text=(el,v)=>{v=String(v);if(el.textContent!==v)el.textContent=v;};
const bytes=v=>v==null?NA:(v<1024?v.toFixed(0)+' B':v<1048576?(v/1024).toFixed(1)+' KiB':v<1073741824?(v/1048576).toFixed(1)+' MiB':(v/1073741824).toFixed(2)+' GiB');
const rate=v=>v==null?NA:bytes(v)+'/s';const when=v=>v?new Date(v*1000).toLocaleString():NA;const pct=(a,b)=>b?Math.round(a/b*100)+'%':NA;
function message(s){text($('#message'),s);$('#message').hidden=false;clearTimeout(message.timer);message.timer=setTimeout(()=>$('#message').hidden=true,6500)}
async function api(path,method='GET',body){const res=await fetch(prefix+'/api/'+path,{method,credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body===undefined?undefined:JSON.stringify(body)});let data;try{data=await res.json()}catch{throw Error('无效服务响应')};if(!res.ok){if(res.status===401&&path!=='login')loggedOut();throw Error(res.status===401?'账号、密码错误或登录已过期':res.status===403?'无访问权限':res.status===429?'请求过于频繁，请稍后重试':'操作失败（'+res.status+'）')};return data}
function loggedOut(){me=null;csrf='';clearTimeout(retry);if(socket){socket.onclose=null;socket.close();socket=null}$('#login').hidden=false;$('#dashboard').hidden=true;$('#logout').hidden=true;$$('[data-admin]').forEach(el=>el.hidden=true);text($('#connection'),'未登录');$('#servers').replaceChildren();$('#tags').replaceChildren();for(const r of rows.values())Charts.remove(r.spark);cards.clear();rows.clear();rangeCache.clear();views=[];points.length=0;$('#server-token').textContent='';closeDetails();historyRows=[]}
function connected(){if(!me)return;clearTimeout(retry);socket=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+prefix+'/ws');socket.onopen=()=>{text($('#connection'),'实时连接');$('#connection').dataset.state='online'};socket.onmessage=e=>{try{update(JSON.parse(e.data))}catch{message('监控数据格式错误')}};socket.onclose=()=>{update([]);rangeCache.clear();text($('#connection'),'连接中断 · 自动重连中');$('#connection').dataset.state='offline';api('me').then(d=>{csrf=d.csrf;retry=setTimeout(connected,2000)}).catch(()=>{})};}
function signedIn(d){me=d.user;csrf=d.csrf;$('#login-form').reset();$('#login').hidden=true;$('#dashboard').hidden=false;$('#logout').hidden=false;$$('[data-admin]').forEach(el=>el.hidden=me.role!=='admin');$('#admin').hidden=true;$('#overview').hidden=false;api('snapshot').then(update).catch(e=>message(e.message));connected()}
$('#login-form').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.target),b=e.target.querySelector('button');b.disabled=true;try{signedIn(await api('login','POST',Object.fromEntries(f)))}catch(e){message(e.message)}finally{b.disabled=false}});
$('#logout').onclick=async()=>{closeMenu();try{await api('logout','POST',{})}catch(e){message(e.message)}loggedOut()};
$('#theme').onclick=()=>{const dark=document.documentElement.dataset.theme==='dark'||(!document.documentElement.dataset.theme&&matchMedia('(prefers-color-scheme:dark)').matches);document.documentElement.dataset.theme=dark?'light':'dark';localStorage.setItem('tz-theme',dark?'light':'dark');closeMenu();Charts.invalidate()};const theme=localStorage.getItem('tz-theme');if(theme)document.documentElement.dataset.theme=theme;
function node(tag,cls,value){const n=document.createElement(tag);if(cls)n.className=cls;if(value!==undefined)n.textContent=value;return n}
let adminInventoryAt=0,adminInventoryBusy=false,adminInventorySignature='';
function syncAdminChoices(data){
 if(me?.role!=='admin'||currentPage!=='users'||adminInventoryBusy)return;
 const signature=data.map(s=>s.id+':'+(s.report?.tags||[]).map(t=>t.id).join(',')).join('|');
 if(signature===adminInventorySignature&&Date.now()-adminInventoryAt<30000)return;
 adminInventoryBusy=true;adminInventoryAt=Date.now();adminInventorySignature=signature;
 Promise.all([api('admin/servers'),api('admin/nodes')]).then(([servers,nodes])=>{if(me?.role==='admin'&&currentPage==='users'){grantServers=servers;grantViews=nodes;permissionPicker.updateInventory(servers,nodes)}}).catch(e=>message(e.message)).finally(()=>adminInventoryBusy=false);
}
function update(data){
 syncAdminChoices(data);
 $('#loading').hidden=true;
 views=data;const liveCards=new Set(),liveRows=new Set();let up=0,down=0,available=false;
 const filter=$('#server-filter').value,query=$('#node-search').value.trim().toLocaleLowerCase();
 const suggestions=[];
 for(const s of data){
  liveCards.add(s.id);let c=cards.get(s.id);
  if(!c){const el=node('section','card card--server'),title=node('h2'),status=node('span','pill'),head=node('div','server-head'),detail=node('p','server-detail');head.append(title,status);el.append(head,detail);$('#servers').append(el);c={el,title,status,detail};cards.set(s.id,c)}
  text(c.title,s.name);text(c.status,s.online?'在线':'离线');c.status.dataset.state=s.online?'online':'offline';
  const h=s.report?.host;text(c.detail,h?'CPU '+(h.cpu?.toFixed(1)??NA)+'% · 内存 '+pct(h.memory_used,h.memory_total)+' · 磁盘 '+pct(h.disk_used,h.disk_total)+' · 主机 ↑ '+rate(h.net_up)+' ↓ '+rate(h.net_down)+' · 运行 '+Math.floor(h.uptime/3600)+'h · sing-box '+(h.sing_box?'运行中':'未检测到')+' · 负载 '+h.load:'最近心跳 '+when(s.seen));
  for(const t of s.report?.tags||[]){
   if(s.online&&t.kind==='actual'&&t.up!=null){up+=t.up;down+=t.down;available=true}
   if(!t.display_eligible)continue;
   suggestions.push(t.name);const key=t.id;liveRows.add(key);let r=rows.get(key);
   if(!t.display_eligible)continue;
   if(!r){
    const el=node('details','card card--node'),number=node('span','node-number'),spark=node('canvas','node-spark'),expiry=node('p','node-expiry'),summary=node('summary','node-summary'),head=node('div','node-head'),name=node('h2'),category=node('span','pill category'),status=node('span','pill'),arrow=node('span','node-arrow','⌄'),raw=node('small','raw-tag'),flow=node('div','flow'),upload=node('strong'),download=node('strong'),quota=node('p','quota'),meter=node('progress'),ip=node('p','node-ip'),slot=node('div','inline-detail');
    head.append(number,name,category,status,arrow);flow.append(upload,download);meter.max=1;spark.setAttribute('aria-hidden','true');summary.append(spark,head,raw,ip,flow,quota,meter,expiry);el.append(summary,slot);$('#tags').append(el);r={el,number,spark,expiry,series:[],sample:null,summary,name,category,status,arrow,raw,upload,download,quota,meter,ip,slot};rows.set(key,r);
    summary.addEventListener('click',e=>{e.preventDefault();if(selectedHistory?.node_id===key)closeDetails();else showHistory(key)});
   }
   if(r.sample!==s.report.at){r.sample=s.report.at;r.series.push([s.report.at,t.up||0,t.down||0]);if(r.series.length>180)r.series.splice(0,r.series.length-180);Charts.set(r.spark,r.series,'area',true)}
   r.t=t;r.s=s;r.el.hidden=Boolean((filter&&filter!==s.id)||(query&&!t.name.toLocaleLowerCase().includes(query)));
   text(r.name,t.name);r.name.title=t.name;text(r.category,t.category);text(r.status,s.online?(t.state==='unknown'?'状态未知':'在线'):'离线');r.status.dataset.state=s.online&&t.state!=='unknown'?'online':'offline';
   text(r.raw,t.raw_tag?'Tag · '+t.raw_tag:'');r.raw.hidden=!t.raw_tag;
   smoothRate(r.upload,t.up,'↑ ');smoothRate(r.download,t.down,'↓ ');
   text(r.quota,'本月 '+bytes(t.month_used)+(t.quota?' / '+bytes(t.quota)+' · '+pct(t.month_used,t.quota):''));r.meter.value=t.quota&&t.month_used!=null?Math.min(1,t.month_used/t.quota):0;r.meter.hidden=!t.quota;r.meter.setAttribute('aria-label','月额度使用比例');
   const ipLabel=[countryName(t.ip),t.ip?.ipv4||t.ip?.ipv6,t.ip&&(t.verification==='stale'?'缓存 · 待验证':'已验证')].filter(Boolean).join(' · ');text(r.ip,ipLabel);r.ip.hidden=!ipLabel;
   text(r.expiry,t.expires_at?'到期 '+new Date(t.expires_at*1000).toLocaleDateString('zh-CN'):'');r.expiry.hidden=!t.expires_at;
   r.meter.dataset.warning=t.quota&&t.month_used/t.quota*100>=(t.alert_threshold||80)?'true':'false';

  }
 }
 for(const[k,v]of cards)if(!liveCards.has(k)){v.el.remove();cards.delete(k)}
 for(const[k,v]of rows)if(!liveRows.has(k)){Charts.remove(v.spark);v.el.remove();rows.delete(k)}
 sortNodes();
 $('#empty').hidden=[...rows.values()].some(r=>!r.el.hidden);
 const options=Array.from($('#server-filter').options).map(o=>o.value).slice(1);
 if(options.join()!==data.map(s=>s.id).join()){const sel=$('#server-filter');sel.replaceChildren(new Option('全部服务器',''));data.forEach(s=>sel.add(new Option(s.name,s.id)));sel.value=filter}
 const names=[...new Set(suggestions)];if($('#node-suggestions').textContent!==names.join('')){$('#node-suggestions').replaceChildren(...names.map(n=>{const o=node('option','',n);o.value=n;return o}))}

 if(selectedHistory){const r=rows.get(selectedHistory.node_id);if(!r){closeDetails()}else{renderDetails(r);if(chartRange==='live')drawChart($('#history-chart'),r.series,chartType)}}
 if(available&&Date.now()-lastPoint>=900){points.push([Date.now()/1000,up,down]);if(points.length>120)points.shift();lastPoint=Date.now();drawChart($('#chart'),points)}
}
$('#node-search').oninput=()=>update(views);
$('#server-filter').onchange=()=>update(views);
function drawChart(canvas,data,type='area'){Charts.set(canvas,data,type)}
function sortNodes(){
 const mode=$('#node-sort').value,items=[...rows.values()];
 if(mode!=='default')items.sort((a,b)=>mode==='name'?a.t.name.localeCompare(b.t.name,'zh-CN'):mode==='speed'?((b.t.up||0)+(b.t.down||0))-((a.t.up||0)+(a.t.down||0)):(b.t.month_used||0)-(a.t.month_used||0));
 const parent=$('#tags');let i=0;for(const r of items){if(parent.children[i]!==r.el)parent.insertBefore(r.el,parent.children[i]||null);i++}
 let n=0;for(const r of items)if(!r.el.hidden){text(r.number,String(++n).padStart(2,'0'));r.summary.setAttribute('aria-label',String(n).padStart(2,'0')+' '+r.t.name+'，展开或收起详情')}
}
$('#node-sort').onchange=sortNodes;
function countryName(ip){if(!ip)return '';try{return ip.country_code?new Intl.DisplayNames(['zh-CN'],{type:'region'}).of(ip.country_code):ip.country||''}catch{return ip.country||''}}
function smoothRate(el,value,sign){
 if(el.target===value)return;el.target=value;cancelAnimationFrame(el.frame);
 if(value==null||Charts.reduced||document.hidden||el.closest('details')?.getBoundingClientRect().top>innerHeight){text(el,sign+rate(value));el.current=value;return}
 const from=el.current??value,start=performance.now();const tick=now=>{if(document.hidden){el.current=value;text(el,sign+rate(value));return}const p=Math.min(1,(now-start)/240);el.current=from+(value-from)*p;text(el,sign+rate(el.current));if(p<1)el.frame=requestAnimationFrame(tick)};el.frame=requestAnimationFrame(tick);
}
const protocolName=t=>({Direct:'直接连接',SOCKS:'SOCKS 代理',HTTP:'HTTP 代理',Reject:'拒绝连接',Selector:'出口选择器',URLTest:'自动测速选择器'}[t]||t);
function renderDetails(r){
 const t=r.t,ip=t.ip;text($('#history-title'),'流量与出口详情');text($('#detail-raw'),t.raw_tag?'Tag · '+t.raw_tag:'');$('#detail-raw').hidden=!t.raw_tag;
 text($('#detail-status'),r.s.name+' · '+t.category+' · '+protocolName(t.type)+' · 当前连接 '+(t.active??NA));
 text($('#detail-flow'),'实时 ↑ '+rate(t.up)+' / ↓ '+rate(t.down));
 const totals=[['今日',t.today_upload,t.today_download],['本月',t.month_upload,t.month_download],['累计',t.upload,t.download]];
 const group=$('#detail-totals');for(let i=0;i<totals.length;i++){let cell=group.children[i];if(!cell){cell=node('div','stat-cell');cell.append(node('span'),node('strong'),node('small'));group.append(cell)}text(cell.children[0],totals[i][0]);text(cell.children[1],bytes((totals[i][1]||0)+(totals[i][2]||0)));text(cell.children[2],'↑ '+bytes(totals[i][1])+' · ↓ '+bytes(totals[i][2]))}
 text($('#detail-quota'),t.quota?'本账期 '+bytes(t.month_used)+' / '+bytes(t.quota)+' · 剩余 '+bytes(Math.max(0,t.quota-(t.month_used||0)))+' · 每月 '+t.billing_day+' 日 / '+t.timezone:'');$('#detail-quota').hidden=!t.quota;
 text($('#detail-expiry'),t.expires_at?'到期时间 '+when(t.expires_at)+'（仅提醒）':'');$('#detail-expiry').hidden=!t.expires_at;
 const hasIP=Boolean(ip?.verified&&(ip.ipv4||ip.ipv6));$('#ip-section').hidden=!hasIP;
 const cityNames={'Bangkok':'曼谷','Kuala Lumpur':'吉隆坡','Manila':'马尼拉','Sao Paulo':'圣保罗','São Paulo':'圣保罗','Hong Kong':'香港','Tokyo':'东京','Singapore':'新加坡','Los Angeles':'洛杉矶','Taipei':'台北','Seoul':'首尔','Osaka':'大阪','San Jose':'圣何塞','London':'伦敦','Frankfurt am Main':'法兰克福'};
 const fields=hasIP?[
 ['IPv4',ip.ipv4],['IPv6',ip.ipv6],['国家 / 地区',countryName(ip)],['城市',cityNames[ip.city]||ip.city],['ASN',ip.asn],['运营商',ip.org],
 ['IP 类型',ip.ip_type],['元数据状态',ip.metadata_at?(ip.metadata_cached?'缓存 · ':'')+when(ip.metadata_at):''],
 ['IP 属性',ip.residential===true?'住宅':ip.datacenter===true?'机房':ip.residential===false?'非住宅（来源未判定是否机房）':''],
 ['风险评分',ip.risk_score!=null?ip.risk_score+' / 100 · 越高风险越高，非安全保证':''],['质量对应 IP',ip.quality_ip],['质量来源',ip.quality_source],['质量检测时间',ip.quality_at?when(ip.quality_at):''],
 ['可信状态',t.verification==='stale'?'缓存 · 上次成功的出口':'已通过实际路径验证'],['成功检测时间',ip.updated?when(ip.updated):''],['出口来源',ip.source],['归属来源',ip.geo_source]
 ].filter(f=>f[1]):[];
 const dl=$('#detail-ip');while(dl.children.length>fields.length*2)dl.lastChild.remove();for(let i=0;i<fields.length;i++){if(!dl.children[i*2])dl.append(node('dt'),node('dd'));text(dl.children[i*2],fields[i][0]);text(dl.children[i*2+1],fields[i][1])}
 $('#detail-admin').hidden=me?.role!=='admin';
}
function placeDetails(){
 if(!selectedHistory)return;const r=rows.get(selectedHistory.node_id);if(!r)return;
 const panel=$('#history-panel'),parent=matchMedia('(max-width:700px)').matches?r.slot:$('#dashboard');if(panel.parentNode!==parent)parent.append(panel);
}
function closeDetails(){const id=selectedHistory?.node_id,closing=rows.get(id),fromHeight=closing?.el.getBoundingClientRect().height;selectedHistory=null;historyRows=[];historyRequest++;drawChart($('#history-chart'),[]);$('#history-panel').hidden=true;$('#dashboard').append($('#history-panel'));if(id&&rows.has(id)){const r=rows.get(id);r.el.open=false;const toHeight=r.el.getBoundingClientRect().height;if(fromHeight>toHeight+2&&!Charts.reduced)r.el.animate([{height:fromHeight+'px'},{height:toHeight+'px'}],{duration:200,easing:'cubic-bezier(.22,1,.36,1)'})}}
$('#close-details').onclick=()=>{const r=rows.get(selectedHistory?.node_id);closeDetails();r?.summary.focus({preventScroll:true})};
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!$('#navigation').open)closeDetails()});
async function showHistory(id){
 const r=rows.get(id);if(!r)return;if(selectedHistory?.node_id===id){closeDetails();return}closeDetails();
 selectedHistory={node_id:id};r.el.open=true;renderDetails(r);$('#alias-form').elements.name.value='';placeDetails();$('#history-panel').hidden=false;
 $('#chart-range').value=chartRange;await loadHistory();
}
async function loadHistory(){
 const id=selectedHistory?.node_id,request=++historyRequest;if(!id)return;
 if(chartRange==='live'){historyRows=[];text($('#history-summary'),'实时 · ↑ 上传 / ↓ 下载 · 点击、触摸或方向键查看数据');drawChart($('#history-chart'),rows.get(id)?.series||[],chartType);return}
 const key=id+':'+chartRange;let data=rangeCache.get(key);
 text($('#history-summary'),'正在读取历史采样…');
 try{if(!data||Date.now()-data.at>60000){data={at:Date.now(),rows:await api('history?'+new URLSearchParams({node_id:id,range:chartRange}))};rangeCache.set(key,data);if(rangeCache.size>20)rangeCache.delete(rangeCache.keys().next().value)}if(request!==historyRequest||selectedHistory?.node_id!==id)return;historyRows=data.rows;drawChart($('#history-chart'),historyRows.slice().reverse().map(r=>[r.at,r.up,r.down]),chartType);text($('#history-summary'),$('#chart-range').selectedOptions[0].text+' · '+historyRows.length+' 个聚合点 · ↑ 上传 / ↓ 下载')}catch(e){message(e.message)}
}
$('#chart-range').onchange=e=>{chartRange=e.target.value;loadHistory()};
$('#chart-type').onchange=e=>{chartType=e.target.value;$('#history-chart').animate([{opacity:.4},{opacity:1}],{duration:Charts.reduced?0:180});if(selectedHistory)drawChart($('#history-chart'),chartRange==='live'?rows.get(selectedHistory.node_id)?.series||[]:historyRows.slice().reverse().map(r=>[r.at,r.up,r.down]),chartType)};
$('#alias-form').onsubmit=async e=>{e.preventDefault();if(!selectedHistory)return;try{await api('alias','PUT',{node_id:selectedHistory.node_id,name:e.target.elements.name.value});update(await api('snapshot'));message('个人名称已保存，留空则恢复全局名称')}catch(e){message(e.message)}};
$('#export-history').onclick=async()=>{if(!selectedHistory)return;try{const data=await api('history?'+new URLSearchParams({...selectedHistory,range:chartRange==='live'?'1h':chartRange}));const csv='time,observed_upload_bytes,observed_download_bytes\n'+data.map(r=>[new Date(r.at*1000).toISOString(),r.upload,r.download].join(',')).join('\n');const u=URL.createObjectURL(new Blob([csv],{type:'text/csv'})),a=node('a');a.href=u;a.download='tzsingbox-history.csv';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)}catch(e){message(e.message)}};
let currentPage='overview';
let closingMenu=false;
function closeMenu(){const d=$('#navigation');if(!d.open||closingMenu)return;closingMenu=true;d.dataset.closing='true';setTimeout(()=>{d.close();delete d.dataset.closing;closingMenu=false},Charts.reduced?0:200)}
$('#menu-toggle').onclick=()=>{$('#navigation').showModal();$('#navigation').getBoundingClientRect();document.body.classList.add('menu-open');$('#menu-toggle').setAttribute('aria-expanded','true')};$('#menu-close').onclick=closeMenu;
$('#navigation').addEventListener('cancel',e=>{e.preventDefault();closeMenu()});$('#navigation').addEventListener('close',()=>{document.body.classList.remove('menu-open');$('#menu-toggle').setAttribute('aria-expanded','false');$('#menu-toggle').focus({preventScroll:true})});
$('#navigation').addEventListener('click',e=>{if(e.target!==$('#navigation'))return;const r=e.target.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)closeMenu()});
$('#navigation').addEventListener('keydown',e=>{if(!['ArrowDown','ArrowUp','Home','End'].includes(e.key))return;const buttons=$$('#navigation button').filter(b=>!b.hidden);const index=buttons.indexOf(document.activeElement);e.preventDefault();buttons[e.key==='Home'?0:e.key==='End'?buttons.length-1:(index+(e.key==='ArrowDown'?1:-1)+buttons.length)%buttons.length].focus()});
async function navigate(page){if(page!=='overview'&&me?.role!=='admin')return;currentPage=page;closeDetails();closeMenu();$('#overview').hidden=page!=='overview';$('#admin').hidden=page==='overview';$$('[data-page]').forEach(b=>{if(b.dataset.page===page)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current')});$$('[data-admin-page]').forEach(el=>el.hidden=el.dataset.adminPage!==page);if(page!=='overview')try{await loadAdmin()}catch(e){message(e.message)}}
$$('[data-page]').forEach(b=>b.onclick=()=>navigate(b.dataset.page));$('#detail-admin').onclick=()=>navigate('nodes');

const permissionPicker=new PermissionPicker($('#grant-groups'));let grantServers=[],grantViews=[],grants=[],serverGrants=[];async function loadAdmin(){const [users,servers,settings,audit,gs,sg]=await Promise.all(['admin/users','admin/servers','admin/settings','admin/audit','admin/grants','admin/server-grants'].map(p=>api(p)));const selectedUser=$('#grant-user').value;grants=gs;serverGrants=sg;grantServers=servers;$('#users').replaceChildren();$('#grant-user').replaceChildren();for(const u of users){const row=node('div','row-actions');row.append(node('span','',u.name+' · '+u.role+(u.disabled?' · 已禁用':'')));if(u.role!=='admin'){const reset=node('button','','重置密码'),toggle=node('button','',u.disabled?'启用':'禁用'),del=node('button','','删除');reset.onclick=async()=>{const p=prompt('输入新密码（至少14字符）');if(p)await action(()=>api('admin/users','PATCH',{id:u.id,password:p}))};toggle.onclick=()=>action(()=>api('admin/users','PATCH',{id:u.id,disabled:!u.disabled}));del.onclick=()=>{if(confirm('删除用户 '+u.name+'？'))action(()=>api('admin/users','DELETE',{id:u.id}))};row.append(reset,toggle,del);$('#grant-user').add(new Option(u.name,u.id))}$('#users').append(row)}if(selectedUser&&[...$('#grant-user').options].some(o=>o.value===selectedUser))$('#grant-user').value=selectedUser;grantViews=await api('admin/nodes');fillGrants();$('#server-admin-list').replaceChildren();for(const s of servers){const row=node('div','row-actions');row.append(node('span','',s.id+' · '+s.name));const toggle=node('button','',s.enabled?'停用':'启用'),del=node('button','','删除');toggle.onclick=()=>action(()=>api('admin/servers','PATCH',{id:s.id,name:s.name,enabled:!s.enabled}));del.onclick=()=>{if(confirm('删除服务器身份及其历史数据 '+s.id+'？'))action(()=>api('admin/servers','DELETE',{id:s.id}))};row.append(toggle,del);$('#server-admin-list').append(row)}for(const[k,v]of Object.entries(settings)){const el=$('#settings-form').elements[k];if(el.type==='checkbox')el.checked=v;else el.value=v}await loadNodeAdmin();$('#audit').replaceChildren();for(const a of audit){const tr=node('tr');[when(a.at),a.name,a.ip,a.event].forEach(v=>tr.append(node('td','',v)));$('#audit').append(tr)}}
function fillGrants(){permissionPicker.load(grantServers,grantViews,grants,serverGrants,$('#grant-user').value)}$('#grant-user').onchange=fillGrants;
$('#grant-search').oninput=e=>permissionPicker.search(e.target.value);
$('#grant-all').onchange=e=>{permissionPicker.select(e.target.checked);permissionPicker.refresh();permissionPicker.status(true)};
$('#grant-clear').onclick=()=>{permissionPicker.selected.clear();permissionPicker.allowed.clear();permissionPicker.hosts.clear();permissionPicker.refresh();permissionPicker.status(true)};
async function action(f){try{await f();message('已保存');await loadAdmin()}catch(e){message(e.message)}}
$('#user-form').onsubmit=e=>{e.preventDefault();const v=Object.fromEntries(new FormData(e.target));action(async()=>{await api('admin/users','POST',v);e.target.reset()})};
$('#grants-form').onsubmit=async e=>{e.preventDefault();const save=$('#grant-save');save.disabled=true;try{await api('admin/grants','PUT',permissionPicker.payload($('#grant-user').value));message('权限已保存，现有订阅已更新');await loadAdmin();text($('#grant-status'),'权限已保存')}catch(err){message(err.message)}finally{save.disabled=false}};
$('#server-form').onsubmit=e=>{e.preventDefault();action(async()=>{const v=await api('admin/servers','POST',Object.fromEntries(new FormData(e.target)));text($('#server-token'),'ID '+v.id+' · Token '+v.token);e.target.reset()})};
$('#settings-form').onsubmit=e=>{e.preventDefault();const v=Object.fromEntries(new FormData(e.target));action(()=>api('admin/settings','PUT',{sample_seconds:Number(v.sample_seconds),retention_days:Number(v.retention_days),show_raw_tag:e.target.elements.show_raw_tag.checked,show_expiry:e.target.elements.show_expiry.checked,show_quota:e.target.elements.show_quota.checked,default_node_name:v.default_node_name}))};
let resize;window.addEventListener('resize',()=>{clearTimeout(resize);resize=setTimeout(()=>{placeDetails();Charts.invalidate()},180)});document.addEventListener('visibilitychange',()=>{if(!document.hidden&&views.length)update(views)});api('me').then(signedIn).catch(()=>{});

async function loadNodeAdmin(){
 const data=await api('admin/nodes');$('#node-admin-list').replaceChildren();let missing=0;
 for(const server of data)for(const t of server.report?.tags||[]){
  if(t.needs_name)missing++;
  const f=node('form','node-admin-form'),title=node('strong','',server.name+' · Tag '+t.raw_tag+' · '+t.category+' · '+t.display_reason),label=node('label','','全局中文名称'),name=node('input'),ql=node('label','','月额度（GiB，0 表示未设置）'),quota=node('input'),save=node('button','primary','保存节点');name.value=t.global_name||'';name.maxLength=128;name.placeholder=t.name;name.setAttribute('aria-label','全局中文名称');quota.type='number';quota.min=0;quota.max=1073741824;quota.step='0.01';quota.value=((t.quota||0)/1073741824).toFixed(2);label.append(name);ql.append(quota);f.append(title,label,ql,save);const extra={};for(const [key,labelText,type,value] of [['expires_at','到期时间（留空不显示）','datetime-local',t.expires_at?new Date(t.expires_at*1000-new Date(t.expires_at*1000).getTimezoneOffset()*60000).toISOString().slice(0,16):''],['billing_day','每月账期起始日（1–31）','number',t.billing_day||1],['timezone','账期时区（IANA）','text',t.timezone||'UTC'],['alert_threshold','额度提醒阈值（%）','number',t.alert_threshold||80]]){const l=node('label','',labelText),input=node('input');input.type=type;input.value=value;if(type==='number'){input.min=1;input.max=key==='billing_day'?31:100}input.setAttribute('aria-label',labelText);extra[key]=input;l.append(input);f.insertBefore(l,save)}
  if(t.ip?.error||t.ip?.quality_error){const d=node('p','muted','探针诊断：'+[t.ip.error,t.ip.quality_error].filter(Boolean).join(' · '));f.insertBefore(d,save)}
  f.onsubmit=e=>{e.preventDefault();action(()=>api('admin/nodes','PUT',{node_id:t.id,name:name.value,quota:Math.round(Number(quota.value)*1073741824),expires_at:extra.expires_at.value?Math.floor(new Date(extra.expires_at.value).getTime()/1000):0,billing_day:Number(extra.billing_day.value),timezone:extra.timezone.value.trim(),alert_threshold:Number(extra.alert_threshold.value)}))};$('#node-admin-list').append(f)
 }
 text($('#name-warning'),missing?'有 '+missing+' 个节点尚未设置全局名称，当前使用友好默认名；请补充中文名称。':'所有节点均已设置全局名称。');
}
