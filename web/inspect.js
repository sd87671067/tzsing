'use strict';
// One owner for the existing IP/history modal. WS patches text/canvas only;
// source requests happen on open/switch, never on each report.
const NodeInspect=(()=>{
 const cache=new Map(),pending=new Map();let current=null,source='ipinfo',generation=0,checking=false,result=null,pathIndex=0;
 const $=s=>document.querySelector(s),make=UI.make;
 const key=r=>r.t.id+'|'+(r.t.route_version||'')+'|'+(r.t.ip?.ipv4||'')+'|'+(r.t.ip?.ipv6||'')+'|'+(r.t.egress||'')+'|'+pathIndex+'|'+source;
 function fill(dl,fields){
  fields=fields.filter(f=>f[1]!==undefined&&f[1]!==null&&f[1]!=='');
  while(dl.children.length>fields.length*2)dl.lastChild.remove();
  fields.forEach(([name,value],i)=>{
   if(!dl.children[i*2])dl.append(make('dt'),make('dd'));
   text(dl.children[i*2],name);const dd=dl.children[i*2+1];dd.classList.toggle("ip-value",name==='IPv4'||name==='IPv6');dl.children[i*2].classList.toggle("ip-label",name==='IPv4'||name==='IPv6');
   if(name==='IPv4'||name==='IPv6'){
    if(!dd.querySelector('.copy-ip')){dd.replaceChildren();const span=make('span'),copy=UI.button('复制 '+name+' 地址','copy'),check=UI.button('检测出口 HTTPS','check');copy.classList.add('copy-ip');check.classList.add('check-ip');copy.onclick=()=>UI.copy(span.textContent);check.onclick=run;dd.append(span,copy);if(name==='IPv4')dd.append(check)}
    text(dd.firstChild,value);const b=dd.querySelector('.check-ip');if(b){b.disabled=checking;b.setAttribute('aria-busy',String(checking))}dd.querySelector('.copy-ip').disabled=value==='待检测';
   }else text(dd,value);
  });
 }
 function selected(r){const p=r?.t.egresses?.[pathIndex];return p?{...r,t:{...r.t,egress:p.tag,egress_name:p.name,ip:p.ip,category:p.type==='direct'?'直连':'中转'}}:r}
 function render(r){
  if(!current||current!==r.t.id)return;
  const select=$('#detail-path');if(select){
   const ps=r.t.egresses||[];select.hidden=ps.length<2;
   if(select.options.length!==ps.length||[...select.options].some((o,i)=>o.textContent!==(ps[i].name||ps[i].tag||'出口 '+(i+1))))select.replaceChildren(...ps.map((p,i)=>new Option(p.name||p.tag||'出口 '+(i+1),i)));
   select.disabled=checking;select.value=String(pathIndex);
  }
  r=selected(r);
  const entry=cache.get(key(r)),answer=entry?.value,observed=result?.route===r.t.route_version&&result.pathIndex===pathIndex?result.ip:null,ip=observed||(r.t.ip?.verified?r.t.ip:{}),data=answer?.data||{};
  const yesNo=v=>v===true?'是':v===false?'否':'';
  const optional=v=>typeof v==='string'&&!/^(unknown|n\/a|null|undefined|未知|-|—)$/i.test(v.trim())?v.trim():'';
  const ipType=['住宅','机房'].includes(data.ip_type)?data.ip_type:'';
  const ips=result?.route===r.t.route_version&&result.pathIndex===pathIndex?result.network:null;
  const ipv4=ips?.ipv4?.ip||ip.ipv4,ipv6=ips?.ipv6?.ip||ip.ipv6;
  fill($('#detail-ip'),[
   ['IPv4',ipv4||'待检测'],['IPv6',ipv6],['当前出站',r.t.egress_name||r.t.egress||(['当前路径未知','路径待检测'].includes(r.t.category)?'路径待检测':'关联出口（Tag 未公开）')],
   ['出口类型',r.t.egress?r.t.category:''],['国家 / 地区',countryName(data)],['城市',data.city],['ASN',data.asn],['运营商',data.org],['ISP',optional(data.isp)],['IP 类型',ipType],
   ...(source==='ippure'?[['是否原生 IP',yesNo(data.native)]]:[]),
   ['风险评分',data.risk_score==null?'':data.risk_score+' / 100'],['检测时间',ip.updated?when(ip.updated):''],['状态',result?.failed||ip.error?'最近检测缓存':!ipv4&&!ipv6?'路径待检测':'']
  ]);
  const k=key(r);text($('#source-message'),pending.has(generation+'|'+k)?'正在通过服务端读取 '+(source==='ipinfo'?'IPinfo':'IPPure')+'…':answer?.message||(!ipv4&&!ipv6?'当前路径待检测':source==='ippure'&&!answer?'IPPure 仅查询当前路径自身的出口。':''));
  document.querySelectorAll('[data-ip-source]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.ipSource===source)));

 }
 async function load(){
  const r=selected(rows.get(current));if(!r)return;const k=key(r),old=cache.get(k);if(old&&Date.now()<old.until){render(r);return}
  const id=current,epoch=generation,requestedSource=source,pk=epoch+'|'+k;
  if(!pending.has(pk)){
   const request=api('node-inspect','POST',{node_id:id,action:'intel',source:requestedSource,path_index:pathIndex},{signal:AbortSignal.timeout(18000)}).then(value=>{if(epoch!==generation)return;cache.set(k,{value,until:value.data&&!value.message?Math.max(Date.now()+1000,Math.min(Date.now()+86400000,(value.at||Date.now()/1000)*1000+86400000)):Date.now()+60000});if(cache.size>128)cache.delete(cache.keys().next().value)}).catch(e=>{if(epoch===generation)cache.set(k,{value:{source:requestedSource,message:e.name==='TimeoutError'?'信息查询超时，请稍后重试':e.message},until:Date.now()+30000})}).finally(()=>pending.delete(pk));pending.set(pk,request);
  }
  render(r);await pending.get(pk);if(epoch===generation&&current===id&&rows.has(id))render(rows.get(id));
 }
 async function run(){
  if(checking||!current)return;const id=current,epoch=generation,route=rows.get(id)?.t.route_version;checking=true;render(rows.get(id));
  try{const data=await api('node-inspect','POST',{node_id:id,action:'diagnostics',path_index:pathIndex},{signal:AbortSignal.timeout(18000)});if(epoch!==generation||id!==current)return;
   if(route!==rows.get(id)?.t.route_version)throw Error('路由已变化，请重新检测');if(!data.ip?.verified||!data.network?.successes)throw Error(data.error||data.message||'出口 HTTPS 检测失败');
   result={...data,route,pathIndex};render(rows.get(id));
   UI.notify('出口 HTTPS 检测成功');
   // A new IP must not inherit metadata for the old address.
   for(const k of cache.keys())if(k.startsWith(id+'|'))cache.delete(k);
   await load();
  }catch(e){if(epoch===generation){result={...result,route:rows.get(id)?.t.route_version,pathIndex,failed:true};UI.notify(e.message,'error')}}finally{if(epoch===generation){checking=false;const r=rows.get(current);if(r)render(r)}}
 }
 function open(id){generation++;current=id;source='ipinfo';result=null;checking=false;pathIndex=0;$('#check-results').hidden=true;render(rows.get(id));const r=selected(rows.get(id));if(r?.t.egresses?.length&&!r.t.ip?.verified)run();else load()}
 function close(){generation++;current=null;result=null;checking=false}
 const pathSelect=make('select');pathSelect.id='detail-path';pathSelect.setAttribute('aria-label','选择实际出站');pathSelect.hidden=true;$('#detail-ip').before(pathSelect);pathSelect.onchange=()=>{pathIndex=Number(pathSelect.value);result=null;$('#check-results').hidden=true;load()};
 document.querySelectorAll('[data-ip-source]').forEach(b=>b.onclick=()=>{source=b.dataset.ipSource;load()});
 return {render,open,close};
})();
