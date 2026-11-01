'use strict';
// One owner for the existing IP/history modal. WS patches text/canvas only;
// source requests happen on open/switch, never on each report.
const NodeInspect=(()=>{
 const cache=new Map(),pending=new Map();let current=null,source='ipinfo',generation=0,checking=false,result=null;
 const $=s=>document.querySelector(s),make=UI.make;
 const labels={ok:'正常',error:'异常',timeout:'超时',unverified:'未验证',unknown:'无法确定'};
 const key=r=>r.t.id+'|'+(r.t.route_version||'')+'|'+(r.t.ip?.ipv4||'')+'|'+(r.t.ip?.ipv6||'')+'|'+source;
 function fill(dl,fields){
  fields=fields.filter(f=>f[1]!==undefined&&f[1]!==null&&f[1]!=='');
  while(dl.children.length>fields.length*2)dl.lastChild.remove();
  fields.forEach(([name,value],i)=>{
   if(!dl.children[i*2])dl.append(make('dt'),make('dd'));
   text(dl.children[i*2],name);const dd=dl.children[i*2+1];
   if(name==='IPv4'||name==='IPv6'){
    if(!dd.querySelector('.check-ip')){dd.replaceChildren();const span=make('span'),copy=UI.button('复制 '+name+' 地址','copy'),check=UI.button('检测入站与出站','check');copy.classList.add('copy-ip');check.classList.add('check-ip');copy.onclick=()=>UI.copy(span.textContent);check.onclick=run;dd.append(span,copy,check)}
    text(dd.firstChild,value);const b=dd.querySelector('.check-ip');b.disabled=checking;b.setAttribute('aria-busy',String(checking));
   }else text(dd,value);
  });
 }
 function render(r){
  if(!current||current!==r.t.id)return;
  const entry=cache.get(key(r)),answer=entry?.value,ip=r.t.ip?.verified?r.t.ip:{},data=answer?.data||(source==='ipinfo'?ip:{});
  const ips=result?.route===r.t.route_version?result.network:null;
  const ipv4=ips?.ipv4?.ip||ip.ipv4,ipv6=ips?.ipv6?.ip||ip.ipv6;
  fill($('#detail-ip'),[
   ['IPv4',ipv4],['IPv6',ipv6],['当前出站',r.t.egress||(r.t.category==='当前路径未知'?'当前路径未知':'关联出口（Tag 未公开）')],
   ['出口类型',r.t.egress?r.t.category:''],['国家 / 地区',countryName(data)],['城市',data.city],['ASN',data.asn],['运营商',data.org],['IP 类型',data.ip_type],
   ['住宅属性',data.residential==null?'':data.residential?'来源标记为住宅':'来源标记为非住宅'],['托管属性',data.datacenter==null?'':data.datacenter?'来源标记为托管网络':'来源标记为非托管网络'],
   ['风险评分',data.risk_score==null?'':data.risk_score+' / 100（来源值，非安全保证）'],['质量对应 IP',data.quality_ip],['质量来源',data.quality_source],
   ['信息对应 IP',answer?.ip],['信息来源',data.geo_source],['信息时间',(answer?.at||data.metadata_at)?when(answer?.at||data.metadata_at):''],
   ['出口状态',r.t.verification==='stale'?'缓存 · 待重新验证':ip.verified?'已验证':''],['出口检测来源',ip.source],['出口检测时间',ip.updated?when(ip.updated):''],['缓存状态',answer?.cached||data.metadata_cached?'使用缓存':'']
  ]);
  const k=key(r);text($('#source-message'),pending.has(generation+'|'+k)?'正在通过服务端读取 '+(source==='ipinfo'?'IPinfo':'IPPure')+'…':answer?.message||(!ipv4&&!ipv6?'当前路径尚无已验证出口 IP。':source==='ippure'&&!answer?'IPPure 仅查询已验证路径自身的出口。':''));
  document.querySelectorAll('[data-ip-source]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.ipSource===source)));
  $('#check-node').disabled=checking;$('#check-node').setAttribute('aria-busy',String(checking));text($('#check-node'),checking?'正在检测…':'检测入站与出站');
 }
 async function load(){
  const r=rows.get(current);if(!r)return;const k=key(r),old=cache.get(k);if(old&&Date.now()<old.until){render(r);return}
  const id=current,epoch=generation,requestedSource=source,pk=epoch+'|'+k;
  if(!pending.has(pk)){
   const request=api('node-inspect','POST',{node_id:id,action:'intel',source:requestedSource}).then(value=>{if(epoch!==generation)return;cache.set(k,{value,until:value.data&&!value.message?Math.max(Date.now()+1000,Math.min(Date.now()+86400000,(value.at||Date.now()/1000)*1000+86400000)):Date.now()+60000});if(cache.size>128)cache.delete(cache.keys().next().value)}).catch(e=>{if(epoch===generation)cache.set(k,{value:{source:requestedSource,message:e.message},until:Date.now()+30000})}).finally(()=>pending.delete(pk));pending.set(pk,request);
  }
  render(r);await pending.get(pk);if(epoch===generation&&current===id&&rows.has(id))render(rows.get(id));
 }
 async function run(){
  if(checking||!current)return;const id=current,epoch=generation;checking=true;render(rows.get(id));
  try{const data=await api('node-inspect','POST',{node_id:id,action:'diagnostics'});if(epoch!==generation||id!==current)return;
   result={...data,route:rows.get(id)?.t.route_version};
   const fields=[['检测时间',when(data.at)],['入站协议',protocolName(data.protocol)],['关联出站',data.outbound||'当前路径未知']];
   for(const [k,title]of [['config','配置校验'],['listen','本机监听'],['handshake','协议握手'],['public','公网可达性'],['path','指定出口路径'],['change','出口 IP 比较']]){const c=data[k];if(c)fields.push([title,(labels[c.status]||'无法确定')+' · '+c.detail+(c.milliseconds!=null?' · '+c.milliseconds+' ms':'')])}
   if(data.network){for(const [k,title]of [['ipv4','IPv4 HTTPS'],['ipv6','IPv6 HTTPS']]){const c=data.network[k];fields.push([title,(labels[c.status]||'无法确定')+' · '+c.detail+(c.ip?' · '+c.ip:'')+(c.milliseconds!=null?' · 平均 '+c.milliseconds+' ms':'')])}fields.push(['连接成功率',data.network.successes+' / '+data.network.attempts+' 次（按地址族分别说明）'])}
   fill($('#check-fields'),fields);$('#check-results').hidden=false;UI.notify('检测完成，请查看各项结果');
   // A new IP must not inherit metadata for the old address.
   for(const k of cache.keys())if(k.startsWith(id+'|'))cache.delete(k);
   await load();
  }catch(e){if(epoch===generation)UI.notify(e.message,'error')}finally{if(epoch===generation){checking=false;const r=rows.get(current);if(r)render(r)}}
 }
 function open(id){generation++;current=id;source='ipinfo';result=null;checking=false;$('#check-results').hidden=true;render(rows.get(id));load()}
 function close(){generation++;current=null;result=null;checking=false}
 $('#check-node').onclick=run;
 document.querySelectorAll('[data-ip-source]').forEach(b=>b.onclick=()=>{source=b.dataset.ipSource;load()});
 return {render,open,close};
})();
