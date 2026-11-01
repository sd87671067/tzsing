'use strict';
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)],prefix=location.pathname.replace(/\/$/,''),NA='暂不可用';let csrf='',me=null,socket=null,retry=null,views=[],historyRows=[],selectedHistory=null;const cards=new Map(),rows=new Map(),points=[];let chartRange='live',chartType='area',historyRequest=0;const rangeCache=new Map();let lastPoint=0;
const text=(el,v)=>{v=String(v);if(el.textContent!==v)el.textContent=v;};
const bytes=v=>v==null?NA:(v<1024?v.toFixed(0)+' B':v<1048576?(v/1024).toFixed(1)+' KiB':v<1073741824?(v/1048576).toFixed(1)+' MiB':(v/1073741824).toFixed(2)+' GiB');
const rate=v=>v==null?NA:bytes(v)+'/s';const when=v=>v?new Date(v*1000).toLocaleString():NA;const pct=(a,b)=>b?Math.round(a/b*100)+'%':NA;
function message(s){UI.notify(s)}
async function api(path,method='GET',body){const res=await fetch(prefix+'/api/'+path,{method,credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body===undefined?undefined:JSON.stringify(body)});let data;try{data=await res.json()}catch{throw Error('无效服务响应')};if(!res.ok){if(res.status===401&&path!=='login')loggedOut();throw Error(typeof data.error==='string'&&!['Unauthorized','Forbidden','Bad Request','Internal Server Error'].includes(data.error)?data.error:res.status===401?'账号、密码错误或登录已过期':res.status===403?'无访问权限':res.status===429?'请求过于频繁，请稍后重试':'操作失败（'+res.status+'）')};return data}
function loggedOut(){UI.invalidate();NodeControl.invalidate();UUIDEditor.clear();me=null;csrf='';clearTimeout(retry);if(socket){socket.onclose=null;socket.close();socket=null}$('#login').hidden=false;$('#dashboard').hidden=true;$('#logout').hidden=true;$$('[data-admin]').forEach(el=>el.hidden=true);text($('#connection'),'未登录');$('#servers').replaceChildren();$('#tags').replaceChildren();for(const r of rows.values()){cancelAnimationFrame(r.upload.frame);cancelAnimationFrame(r.download.frame);Charts.remove(r.spark)}for(const c of cards.values())removeServerCard(c);cards.clear();rows.clear();rangeCache.clear();views=[];points.length=0;adminRows.clear();$('#node-admin-list').replaceChildren();$('#server-token').textContent='';closeDetails();historyRows=[]}
function connected(){if(!me)return;clearTimeout(retry);socket=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+prefix+'/ws');socket.onopen=()=>{text($('#connection'),'实时连接');$('#connection').dataset.state='online'};socket.onmessage=e=>{try{update(JSON.parse(e.data))}catch{message('监控数据格式错误')}};socket.onclose=()=>{update([]);rangeCache.clear();text($('#connection'),'连接中断 · 自动重连中');$('#connection').dataset.state='offline';api('me').then(d=>{csrf=d.csrf;me=d.user;if(me.role!=='admin'){NodeControl.invalidate();UUIDEditor.clear();}retry=setTimeout(connected,2000)}).catch(()=>{})};}
function signedIn(d){me=d.user;csrf=d.csrf;$('#login-form').reset();$('#login').hidden=true;$('#dashboard').hidden=false;$('#logout').hidden=false;$$('[data-admin]').forEach(el=>el.hidden=me.role!=='admin');$('#admin').hidden=true;$('#overview').hidden=false;api('snapshot').then(update).catch(e=>message(e.message));connected()}
$('#login-form').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.target),b=e.target.querySelector('button');b.disabled=true;try{signedIn(await api('login','POST',Object.fromEntries(f)))}catch(e){message(e.message)}finally{b.disabled=false}});
$('#logout').onclick=async()=>{closeMenu();try{await api('logout','POST',{})}catch(e){message(e.message)}loggedOut()};
function currentDark(){return document.documentElement.dataset.theme==='dark'||(!document.documentElement.dataset.theme&&matchMedia('(prefers-color-scheme:dark)').matches)}
function renderTheme(){const dark=currentDark(),b=$('#theme');b.replaceChildren(UI.icon(dark?'sun':'moon'));b.setAttribute('aria-label',dark?'切换日间模式':'切换夜间模式');b.title=b.getAttribute('aria-label')}
try{const theme=localStorage.getItem('tz-theme');if(['light','dark'].includes(theme))document.documentElement.dataset.theme=theme}catch{}
$('#theme').onclick=()=>{const theme=currentDark()?'light':'dark';document.documentElement.dataset.theme=theme;try{localStorage.setItem('tz-theme',theme)}catch{}renderTheme();Charts.invalidate()};matchMedia('(prefers-color-scheme:dark)').addEventListener('change',()=>{renderTheme();Charts.invalidate()});renderTheme();
function node(tag,cls,value){const n=document.createElement(tag);if(cls)n.className=cls;if(value!==undefined)n.textContent=value;return n}
let adminInventoryAt=0,adminInventoryBusy=false,adminInventorySignature='';
function syncAdminChoices(data){
 if(me?.role!=='admin'||currentPage!=='users'||adminInventoryBusy)return;
 const signature=data.map(s=>s.id+':'+(s.report?.tags||[]).map(t=>t.id).join(',')).join('|');
 if(signature===adminInventorySignature&&Date.now()-adminInventoryAt<30000)return;
 adminInventoryBusy=true;adminInventoryAt=Date.now();adminInventorySignature=signature;
 Promise.all([api('admin/servers'),api('admin/nodes')]).then(([servers,nodes])=>{if(me?.role==='admin'&&currentPage==='users'){grantServers=servers;grantViews=nodes;permissionPicker.updateInventory(servers,nodes)}}).catch(e=>message(e.message)).finally(()=>adminInventoryBusy=false);
}
function createServerCard(){
 const el=node('section','card card--server'),title=node('h2'),status=node('span','pill'),head=node('div','server-head'),grid=node('div','host-grid'),foot=node('div','host-footer'),service=node('span','pill'),uptime=node('small'),metrics={};head.append(title,status);foot.append(service,uptime);el.append(head,grid,foot);
 for(const [key,label] of [['cpu','CPU'],['memory','内存'],['disk','磁盘'],['network','网络 ↑ / ↓'],['load','系统负载']]){
  const cell=node('div','host-metric host-'+key),caption=node('span','metric-label',label),value=node('strong','metric-value'),canvas=key==='disk'?null:node('canvas','metric-chart'),detail=node('small','metric-detail');cell.append(caption,value);if(canvas){canvas.setAttribute('aria-hidden','true');cell.append(canvas)}else{const bar=node('progress');bar.max=100;bar.setAttribute('aria-label','磁盘占用');cell.append(bar);metrics.diskBar=bar}cell.append(detail);grid.append(cell);metrics[key]={cell,value,canvas,detail,series:[]};
 }
 const diagnostics=node('details','monitor-diagnostics'),summary=node('summary','','身份数量诊断'),diagnosticText=node('p');diagnostics.append(summary,diagnosticText);el.append(diagnostics);
 return{el,title,status,grid,service,uptime,metrics,diagnostics,diagnosticText,sample:null};
}
function removeServerCard(c){for(const m of Object.values(c.metrics))if(m.canvas)Charts.remove(m.canvas)}
function diagnosticText(d,rendered){return '实际入站 '+d.inbounds+' · 认证身份 '+d.auth_identities+' · Agent 发现 '+d.discovered+' · 上报 '+d.reported+' · 后端可见 '+d.backend_visible+' / 过滤 '+d.backend_filtered+' · 授权 '+d.authorized+' / 过滤 '+d.permission_filtered+' · 前端展示 '+rendered+' / 筛选隐藏 '+(d.authorized-rendered)+'。'+Object.entries(d.reasons||{}).map(([k,v])=>k+'：'+v).join('；')}
function updateServerCard(c,s){
 text(c.title,s.name);text(c.status,s.online?'在线':'离线');c.status.dataset.state=s.online?'online':'offline';
 const h=s.report?.host,live=s.online&&h,at=s.report?.at,fresh=live&&c.sample!==at;c.el.dataset.stale=String(!live);c.grid.hidden=!h;c.diagnostics.hidden=!s.diagnostics;
 text(c.service,h?(h.sing_box?'sing-box 运行中':'sing-box 未检测到'):'主机指标未授权或不可用');c.service.dataset.state=live&&h.sing_box?'online':'offline';text(c.uptime,h?'已运行 '+Math.floor(h.uptime/86400)+' 天 '+Math.floor(h.uptime%86400/3600)+' 小时':'最近心跳 '+when(s.seen));
 if(!h)return;
 const percent=(a,b)=>b?Math.max(0,Math.min(100,a/b*100)):null,values={cpu:live?h.cpu:null,memory:live?percent(h.memory_used,h.memory_total):null,disk:live?percent(h.disk_used,h.disk_total):null,network:live&&Number.isFinite(h.net_down)?h.net_up:null,load:live&&h.load?Number.parseFloat(h.load):null};
 for(const [key,m]of Object.entries(c.metrics)){
  if(!m.cell)continue;let v=values[key];if(!Number.isFinite(v))v=null;
  text(m.value,key==='network'?'↑ '+rate(v)+' · ↓ '+rate(live?h.net_down:null):v==null?NA:v.toFixed(1)+(key==='load'?'':'%'));
  if(key==='disk'){if(v==null)c.metrics.diskBar.removeAttribute('value');else c.metrics.diskBar.value=v}
  else if(key==='cpu'||key==='memory'){Charts.set(m.canvas,v==null?[]:[[at,v,100]],'ring',true)}
  else {if(fresh&&v!=null){if(m.series.length&&at-m.series.at(-1)[0]>Math.max(10,(s.report.interval||2)*4))m.series=[];m.series.push(key==='network'?[at,v,h.net_down]:[at,v]);if(m.series.length>120)m.series.shift()}Charts.set(m.canvas,m.series,'line',true)}
 }
 text(c.metrics.memory.detail,bytes(h.memory_used)+' / '+bytes(h.memory_total));text(c.metrics.disk.detail,bytes(h.disk_used)+' / '+bytes(h.disk_total));text(c.metrics.network.detail,'仅本次会话真实采样');text(c.metrics.load.detail,h.load||NA);text(c.metrics.cpu.detail,live?'实时占用':'采样已过期');if(fresh)c.sample=at;
}
function update(data){
 syncAdminChoices(data);
 $('#loading').hidden=true;
 views=data;const liveCards=new Set(),liveRows=new Set();let up=0,down=0,available=false;
 const filter=$('#server-filter').value,query=$('#node-search').value.trim().toLocaleLowerCase();
 const suggestions=[];
 for(const s of data){
  liveCards.add(s.id);let c=cards.get(s.id);
  if(!c){c=createServerCard();$('#servers').append(c.el);cards.set(s.id,c)}
  updateServerCard(c,s);
  for(const t of s.report?.tags||[]){
   if(t.identity!=='inbound')continue;
   if(s.online&&t.kind==='actual'&&t.up!=null){up+=t.up;down+=t.down;available=true}
   if(!t.display_eligible)continue;
   suggestions.push(t.name);const key=t.id;liveRows.add(key);let r=rows.get(key);
   if(!r){
    const el=node('article','card card--node'),number=node('span','node-number'),spark=node('canvas','node-spark'),expiry=node('p','node-expiry'),summary=node('div','node-summary'),head=node('div','node-head'),name=node('h2'),category=node('span','pill category'),status=node('span','pill'),arrow=UI.button('节点操作','more'),raw=node('small','raw-tag'),flow=node('div','flow'),upload=node('strong'),download=node('strong'),quota=node('p','quota'),meter=node('progress'),ip=node('button','node-ip');
    head.append(number,name,category,status,arrow);flow.append(upload,download);meter.max=1;spark.setAttribute('aria-hidden','true');summary.append(spark,head,raw,ip,flow,quota,meter,expiry);el.append(summary);el.tabIndex=0;el.setAttribute('aria-haspopup','dialog');el.onclick=e=>{if(!e.target.closest('button'))showHistory(key)};el.onkeydown=e=>{if(e.target===el&&['Enter',' '].includes(e.key)){e.preventDefault();showHistory(key)}};$('#tags').append(el);r={el,number,spark,expiry,series:[],sample:null,summary,name,category,status,arrow,raw,upload,download,quota,meter,ip};rows.set(key,r);
    ip.type='button';ip.setAttribute('aria-haspopup','dialog');ip.onclick=e=>{e.stopPropagation();showHistory(key)};arrow.setAttribute('aria-haspopup','dialog');arrow.onclick=e=>{e.stopPropagation();NodeControl.show(key,arrow)};
   }
   const measured=s.online&&t.accounting!=='unavailable'&&t.up!=null&&t.down!=null;
   if(!measured){r.series=[];r.sample=null;Charts.set(r.spark,[],'area',true)}
   else if(r.sample!==s.report.at){if(r.sample!=null&&s.report.at-r.sample>Math.max(10,(s.report.interval||2)*4))r.series=[];r.sample=s.report.at;r.series.push([s.report.at,t.up,t.down]);if(r.series.length>180)r.series.splice(0,r.series.length-180);Charts.set(r.spark,r.series,'area',true)}
   r.t=t;r.s=s;r.el.hidden=Boolean((filter&&filter!==s.id)||(query&&!t.name.toLocaleLowerCase().includes(query)));
   r.arrow.hidden=me?.role!=='admin';text(r.name,t.name);r.name.title=t.name;text(r.category,protocolName(t.type));r.category.title=t.category;text(r.status,!s.online?'监控离线':t.active==null?'活跃未知':t.active>0?'连接 '+t.active:'空闲');r.status.dataset.state=s.online&&t.active>0?'online':'';r.status.title='当前真实连接数；清单中存在不代表启用状态已验证';
   text(r.raw,'已配置'+(t.raw_tag?' · Tag · '+t.raw_tag:''));r.raw.hidden=false;
   r.upload.parentElement.hidden=t.accounting==='unavailable';smoothRate(r.upload,measured?t.up:null,'↑ ');smoothRate(r.download,measured?t.down:null,'↓ ');
   text(r.quota,t.accounting==='unavailable'?'UUID 计量不可用':'本月 '+bytes(t.month_used)+(t.quota?' / 额度未生效 '+bytes(t.quota)+' · 剩余 '+bytes(t.month_used==null?null:Math.max(0,t.quota-t.month_used)):' · 已观测用量'));r.meter.value=t.quota&&t.month_used!=null?Math.min(1,t.month_used/t.quota):0;r.meter.hidden=!t.quota||t.month_used==null;r.meter.setAttribute('aria-label','月额度使用比例');
   const ipLabel=t.egresses?.length?t.egresses.map(p=>[p.type==='direct'?'直连':'中转',countryName(p.ip),p.ip?.ipv4||p.ip?.ipv6||'路径待检测'].filter(Boolean).join(' · ')).join('； '):[t.category==='当前路径未知'?'路径待检测':t.category,countryName(t.ip),t.ip?.ipv4||t.ip?.ipv6].filter(Boolean).join(' · ');text(r.ip,ipLabel||'查看 IP 与流量详情');r.ip.hidden=false;
   text(r.expiry,t.expires_at?'到期设置未生效 '+new Date(t.expires_at*1000).toLocaleDateString('zh-CN'):'');r.expiry.hidden=!t.expires_at;
   r.meter.dataset.warning=t.quota&&t.month_used/t.quota*100>=(t.alert_threshold||80)?'true':'false';

  }
 }
 for(const[k,v]of cards)if(!liveCards.has(k)){removeServerCard(v);v.el.remove();cards.delete(k)}
 for(const[k,v]of rows)if(!liveRows.has(k)){cancelAnimationFrame(v.upload.frame);cancelAnimationFrame(v.download.frame);Charts.remove(v.spark);v.el.remove();rows.delete(k)}
 for(const s of data){const c=cards.get(s.id);if(c?.diagnostics&&s.diagnostics){const d=s.diagnostics;const count=[...rows.values()].filter(r=>r.s.id===s.id&&!r.el.hidden).length;text(c.diagnosticText,diagnosticText(d,count))}}
 NodeControl.reconcile();sortNodes();if(currentPage==='nodes')renderNodeAdmin(data);
 $('#empty').hidden=[...rows.values()].some(r=>!r.el.hidden);
 const options=Array.from($('#server-filter').options).map(o=>o.value).slice(1);
 if(options.join()!==data.map(s=>s.id).join()){const sel=$('#server-filter');sel.replaceChildren(new Option('全部服务器',''));data.forEach(s=>sel.add(new Option(s.name,s.id)));sel.value=filter}
 const names=[...new Set(suggestions)];if($('#node-suggestions').textContent!==names.join('')){$('#node-suggestions').replaceChildren(...names.map(n=>{const o=node('option','',n);o.value=n;return o}))}

 if(selectedHistory){const r=rows.get(selectedHistory.node_id);if(!r){closeDetails()}else if(r){renderDetails(r);if(chartRange==='live')drawChart($('#history-chart'),r.series,chartType)}}
 if(available&&Date.now()-lastPoint>=900){points.push([Date.now()/1000,up,down]);if(points.length>120)points.shift();lastPoint=Date.now();drawChart($('#chart'),points)}
}
$('#node-search').oninput=()=>update(views);
$('#server-filter').onchange=()=>update(views);
function drawChart(canvas,data,type='area'){Charts.set(canvas,data,type)}
function sortNodes(){
 const mode=$('#node-sort').value,items=[...rows.values()];
 if(mode!=='default')items.sort((a,b)=>mode==='name'?a.t.name.localeCompare(b.t.name,'zh-CN'):mode==='speed'?((b.t.up||0)+(b.t.down||0))-((a.t.up||0)+(a.t.down||0)):(b.t.month_used||0)-(a.t.month_used||0));
 const parent=$('#tags');let i=0;for(const r of items){if(parent.children[i]!==r.el)parent.insertBefore(r.el,parent.children[i]||null);i++}
 let n=0;for(const r of items)if(!r.el.hidden){text(r.number,String(++n).padStart(2,'0'));r.ip.setAttribute('aria-label',r.t.name+'，查看 IP 与流量详情');r.el.setAttribute('aria-label',r.t.name+' · '+protocolName(r.t.type)+'，查看 IP 信息')}
}
$('#node-sort').onchange=sortNodes;
function countryName(ip){if(!ip)return '';try{return ip.country_code?new Intl.DisplayNames(['zh-CN'],{type:'region'}).of(ip.country_code):ip.country||''}catch{return ip.country||''}}
function smoothRate(el,value,sign){
 if(el.target===value)return;el.target=value;cancelAnimationFrame(el.frame);
 if(value==null||Charts.reduced||document.hidden||el.closest('.card--node')?.getBoundingClientRect().top>innerHeight){text(el,sign+rate(value));el.current=value;return}
 const from=el.current??value,start=performance.now();const tick=now=>{if(document.hidden){el.current=value;text(el,sign+rate(value));return}const p=Math.min(1,(now-start)/240);el.current=from+(value-from)*p;text(el,sign+rate(el.current));if(p<1)el.frame=requestAnimationFrame(tick)};el.frame=requestAnimationFrame(tick);
}
const protocolName=t=>({vless:'VLESS',vmess:'VMess',trojan:'Trojan',socks:'SOCKS',mixed:'SOCKS / HTTP',http:'HTTP',shadowsocks:'Shadowsocks',hysteria:'Hysteria',hysteria2:'Hysteria 2',tuic:'TUIC',tun:'TUN',direct:'Direct'}[t?.toLowerCase()]||t||'协议未提供');
function renderDetails(r){
 const t=r.t;text($('#history-title'),t.name+' · IP 信息');text($('#detail-raw'),t.raw_tag?'Tag · '+t.raw_tag:'');$('#detail-raw').hidden=!t.raw_tag;
 text($('#detail-status'),r.s.name+' · '+t.category+' · '+protocolName(t.type)+' · 当前连接 '+(t.active??NA)+(t.identity==='inbound'?' · '+(t.egresses?.length?'出站 '+t.egresses.map((p,i)=>p.tag||'出口 '+(i+1)).join(' / '):t.egress?'出站 '+t.egress:t.route_reason||'路径待检测'):''));
 text($('#detail-flow'),t.accounting==='unavailable'?(t.accounting_reason||'没有可用的 UUID 认证计量数据；当前连接未提供可验证的身份映射。'):!r.s.online?'监控离线；历史为已观测用量。':'实时 ↑ '+rate(t.up)+' / ↓ '+rate(t.down)+' · '+(t.accounting_reason||'原生认证用户计数，非完整账单'));
 const totals=[['今日',t.today_upload,t.today_download],['本月',t.month_upload,t.month_download],['累计',t.upload,t.download]].map(v=>t.accounting==='unavailable'?[v[0],null,null]:v);
 const group=$('#detail-totals');for(let i=0;i<totals.length;i++){let cell=group.children[i];if(!cell){cell=node('div','stat-cell');cell.append(node('span'),node('strong'),node('small'));group.append(cell)}text(cell.children[0],totals[i][0]);text(cell.children[1],bytes(totals[i][1]==null||totals[i][2]==null?null:totals[i][1]+totals[i][2]));text(cell.children[2],'↑ '+bytes(totals[i][1])+' · ↓ '+bytes(totals[i][2]))}
 text($('#detail-quota'),t.quota?'本账期 '+bytes(t.month_used)+' / '+bytes(t.quota)+' · 剩余 '+bytes(t.month_used==null?null:Math.max(0,t.quota-t.month_used))+' · 每月 '+t.billing_day+' 日 / '+t.timezone:'');$('#detail-quota').hidden=!t.quota;
 text($('#detail-expiry'),t.expires_at?'到期时间 '+when(t.expires_at)+'（未生效）':'');$('#detail-expiry').hidden=!t.expires_at;
 $('#ip-section').hidden=false;
 NodeInspect.render(r);
 $('#detail-admin').hidden=me?.role!=='admin';
}
const historyLife=UI.bind($('#history-panel'),{dirty:()=>$('#alias-form').elements.name.value!=='',onClose:()=>{selectedHistory=null;NodeInspect.close();historyRows=[];historyRequest++;drawChart($('#history-chart'),[]);$('#alias-form').reset()}});
function closeDetails(){historyLife.force()}
$('#close-details').onclick=()=>historyLife.close();
async function showHistory(id){
 const r=rows.get(id);if(!r)return;
 selectedHistory={node_id:id};renderDetails(r);$('#alias-form').reset();NodeInspect.open(id);historyLife.show(document.activeElement?.closest('.card--node')||r.el);
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
$('#alias-form').onsubmit=async e=>{e.preventDefault();if(!selectedHistory)return;const b=e.target.querySelector('button');if(b.disabled)return;b.disabled=true;try{await api('alias','PUT',{node_id:selectedHistory.node_id,name:e.target.elements.name.value});e.target.reset();update(await api('snapshot'));message('个人名称已保存')}catch(e){message(e.message)}finally{b.disabled=false}};

$('#export-history').onclick=async()=>{if(!selectedHistory)return;try{const data=await api('history?'+new URLSearchParams({...selectedHistory,range:chartRange==='live'?'1h':chartRange}));const csv='time,observed_upload_bytes,observed_download_bytes\n'+data.map(r=>[new Date(r.at*1000).toISOString(),r.upload,r.download].join(',')).join('\n');const u=URL.createObjectURL(new Blob([csv],{type:'text/csv'})),a=node('a');a.href=u;a.download='tzsingbox-history.csv';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)}catch(e){message(e.message)}};
let currentPage='overview';
const navigationLife=UI.bind($('#navigation'),{trigger:$('#menu-toggle'),onClose:()=>$('#menu-toggle').setAttribute('aria-expanded','false')});
function closeMenu(){navigationLife.close()}
$('#menu-toggle').onclick=()=>{navigationLife.show();$('#menu-toggle').setAttribute('aria-expanded','true')};$('#menu-close').onclick=closeMenu;
$('#navigation').addEventListener('keydown',e=>{if(!['ArrowDown','ArrowUp','Home','End'].includes(e.key))return;const buttons=$$('#navigation button').filter(b=>!b.hidden);const index=buttons.indexOf(document.activeElement);e.preventDefault();buttons[e.key==='Home'?0:e.key==='End'?buttons.length-1:(index+(e.key==='ArrowDown'?1:-1)+buttons.length)%buttons.length].focus()});
async function navigate(page){if(page!=='overview'&&me?.role!=='admin')return;if(currentPage==='add-node'&&page!=='add-node')UUIDEditor.clear();currentPage=page;closeDetails();closeMenu();$('#overview').hidden=page!=='overview';$('#admin').hidden=page==='overview';$$('[data-page]').forEach(b=>{if(b.dataset.page===page)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current')});$$('[data-admin-page]').forEach(el=>el.hidden=el.dataset.adminPage!==page);if(page!=='overview')try{if(page==='add-node')await UUIDEditor.load();else await loadAdmin()}catch(e){message(e.message)}}
$$('[data-page]').forEach(b=>b.onclick=()=>navigate(b.dataset.page));$('#detail-admin').onclick=()=>navigate('nodes');

const permissionPicker=new PermissionPicker($('#grant-groups'));let grantServers=[],grantViews=[],grants=[],serverGrants=[];async function loadAdmin(){const [users,servers,settings,audit,gs,sg]=await Promise.all(['admin/users','admin/servers','admin/settings','admin/audit','admin/grants','admin/server-grants'].map(p=>api(p)));const selectedUser=$('#grant-user').value;grants=gs;serverGrants=sg;grantServers=servers;$('#users').replaceChildren();$('#grant-user').replaceChildren();for(const u of users){const row=node('div','row-actions');row.append(node('span','',u.name+' · '+u.role+(u.disabled?' · 已禁用':'')));if(u.role!=='admin'){const reset=node('button','','重置密码'),toggle=node('button','',u.disabled?'启用':'禁用'),del=node('button','','删除');reset.onclick=async()=>{const p=await UI.password('重置用户密码');if(p)await action(()=>api('admin/users','PATCH',{id:u.id,password:p}))};toggle.onclick=()=>action(()=>api('admin/users','PATCH',{id:u.id,disabled:!u.disabled}));del.onclick=async()=>{if(await UI.confirm('删除用户','删除用户 '+u.name+'？'))action(()=>api('admin/users','DELETE',{id:u.id}))};row.append(reset,toggle,del);$('#grant-user').add(new Option(u.name,u.id))}$('#users').append(row)}if(selectedUser&&[...$('#grant-user').options].some(o=>o.value===selectedUser))$('#grant-user').value=selectedUser;grantViews=await api('admin/nodes');fillGrants();$('#server-admin-list').replaceChildren();for(const s of servers){const row=node('div','row-actions');row.append(node('span','',s.id+' · '+s.name));const toggle=node('button','',s.enabled?'停用':'启用'),del=node('button','','删除');toggle.onclick=()=>action(()=>api('admin/servers','PATCH',{id:s.id,name:s.name,enabled:!s.enabled}));del.onclick=async()=>{if(await UI.confirm('删除服务器','删除服务器身份及其历史数据 '+s.id+'？'))action(()=>api('admin/servers','DELETE',{id:s.id}))};row.append(toggle,del);$('#server-admin-list').append(row)}for(const[k,v]of Object.entries(settings)){const el=$('#settings-form').elements[k];if(el.type==='checkbox')el.checked=v;else el.value=v}await loadNodeAdmin();$('#audit').replaceChildren();for(const a of audit){const tr=node('tr');[when(a.at),a.name,a.ip,a.event].forEach(v=>tr.append(node('td','',v)));$('#audit').append(tr)}}
function fillGrants(){permissionPicker.load(grantServers,grantViews,grants,serverGrants,$('#grant-user').value)}$('#grant-user').onchange=fillGrants;
$('#grant-search').oninput=e=>permissionPicker.search(e.target.value);
$('#grant-all').onchange=e=>{permissionPicker.select(e.target.checked);permissionPicker.refresh();permissionPicker.status(true)};
$('#grant-clear').onclick=()=>{permissionPicker.selected.clear();permissionPicker.allowed.clear();permissionPicker.hosts.clear();permissionPicker.refresh();permissionPicker.status(true)};
let actionBusy=false;async function action(f){if(actionBusy)return;actionBusy=true;$('#admin').setAttribute('aria-busy','true');const buttons=$$('#admin button');buttons.forEach(b=>b.disabled=true);try{await f();message('已保存');await loadAdmin()}catch(e){message(e.message)}finally{actionBusy=false;$('#admin').removeAttribute('aria-busy');buttons.forEach(b=>b.disabled=false)}}
$('#user-form').onsubmit=e=>{e.preventDefault();const v=Object.fromEntries(new FormData(e.target));action(async()=>{await api('admin/users','POST',v);e.target.reset()})};
$('#grants-form').onsubmit=async e=>{e.preventDefault();const save=$('#grant-save');save.disabled=true;try{await api('admin/grants','PUT',permissionPicker.payload($('#grant-user').value));message('权限已保存，现有订阅已更新');await loadAdmin();text($('#grant-status'),'权限已保存')}catch(err){message(err.message)}finally{save.disabled=false}};
$('#server-form').onsubmit=e=>{e.preventDefault();action(async()=>{const v=await api('admin/servers','POST',Object.fromEntries(new FormData(e.target)));text($('#server-token'),'ID '+v.id+' · Token '+v.token);e.target.reset()})};
$('#settings-form').onsubmit=e=>{e.preventDefault();const v=Object.fromEntries(new FormData(e.target));action(()=>api('admin/settings','PUT',{sample_seconds:Number(v.sample_seconds),retention_days:Number(v.retention_days),show_raw_tag:e.target.elements.show_raw_tag.checked,show_expiry:e.target.elements.show_expiry.checked,show_quota:e.target.elements.show_quota.checked,default_node_name:v.default_node_name}))};
let resize;window.addEventListener('resize',()=>{clearTimeout(resize);resize=setTimeout(()=>{Charts.invalidate()},180)});document.addEventListener('visibilitychange',()=>{if(!document.hidden&&views.length)update(views)});api('me').then(signedIn).catch(()=>{});

const adminRows=new Map();let adminNodeViews=[];
async function loadNodeAdmin(){adminNodeViews=await api('admin/nodes');renderNodeAdmin(adminNodeViews)}
function renderNodeAdmin(data){
 adminNodeViews=data;const query=$('#admin-node-search').value.trim().toLocaleLowerCase(),sort=$('#admin-node-sort').value;
 const entries=data.flatMap(server=>(server.report?.tags||[]).map(t=>({server,t}))).filter(({t})=>t.identity==='inbound'&&!(t.type==='vless'&&!t.auth_id));
 entries.sort((a,b)=>sort==='name'?a.t.name.localeCompare(b.t.name,'zh-CN'):sort==='month'?(b.t.month_used??-1)-(a.t.month_used??-1):0);
 const live=new Set(),parent=$('#node-admin-list');let pos=0;
 for(const {server,t} of entries){
  live.add(t.id);let r=adminRows.get(t.id);
  if(!r){const el=node('article','card card--node node-admin-row'),name=node('strong','admin-node-name'),protocol=node('span','pill'),status=node('span','pill'),up=node('span','admin-node-up'),down=node('span','admin-node-down'),month=node('span','admin-node-month'),expiry=node('span','admin-node-expiry'),more=UI.button('节点操作','more');el.tabIndex=0;el.setAttribute('aria-haspopup','dialog');el.append(name,protocol,status,up,down,month,expiry,more);el.onclick=e=>{if(!e.target.closest('button'))showHistory(t.id)};el.onkeydown=e=>{if(e.target===el&&['Enter',' '].includes(e.key)){e.preventDefault();showHistory(t.id)}};more.onclick=e=>{e.stopPropagation();NodeControl.show(t.id,more)};r={el,name,protocol,status,up,down,month,expiry,more};adminRows.set(t.id,r)}
  text(r.name,t.name);r.name.title=server.name+' · '+t.name;text(r.protocol,protocolName(t.type));text(r.status,!server.online?'监控离线':t.active==null?'连接未知':t.active?'连接 '+t.active:'空闲');
  text(r.up,'↑ '+rate(server.online?t.up:null));text(r.down,'↓ '+rate(server.online?t.down:null));text(r.month,'本月 '+bytes(t.month_used));r.month.title=t.accounting_reason||'已观测用量';text(r.expiry,t.expires_at?'到期未生效':'永不过期');r.expiry.title=t.expires_at?when(t.expires_at)+'，执行器未接入':'';r.el.hidden=!!query&&!(server.name+' '+t.name).toLocaleLowerCase().includes(query);r.el.setAttribute('aria-label',t.name+' · '+protocolName(t.type));r.more.setAttribute('aria-label',t.name+' 节点操作');
  if(parent.children[pos]!==r.el)parent.insertBefore(r.el,parent.children[pos]||null);pos++;
 }
 for(const [id,r] of adminRows)if(!live.has(id)){r.el.remove();adminRows.delete(id)}
 text($('#name-warning'),'每个 UUID 独立显示；流量为真实连接快照的已观测用量。生产独立限制、启停和删除尚不可用。');
}

$('#change-password').onclick=()=>{
 closeMenu();const f=node('form'),old=node('input'),pass=node('input'),save=node('button','primary','更新密码并退出');
 old.type=pass.type='password';old.required=pass.required=true;old.autocomplete='current-password';pass.autocomplete='new-password';
 for(const [title,input]of [['当前密码',old],['新密码（非空 Unicode，原样保留）',pass]]){const l=node('label','',title);l.append(input);f.append(l)}f.append(save);
 const m=UI.modal('修改我的密码',f,{dirty:()=>old.value!==''||pass.value!==''});
 f.onsubmit=async e=>{e.preventDefault();if(save.disabled)return;save.disabled=true;try{await api('password','POST',{current:old.value,password:pass.value});old.value=pass.value='';m.force();loggedOut();message('密码已更新，请重新登录')}catch(e){message(e.message)}finally{save.disabled=false}};
};

$('#admin-node-search').oninput=()=>renderNodeAdmin(adminNodeViews);$('#admin-node-sort').onchange=()=>renderNodeAdmin(adminNodeViews);
