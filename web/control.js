'use strict';
// The menu and its editor share one node identity; realtime card updates do not
// own dialogs. Sensitive links exist only during an explicit protected action.
const NodeControl=(()=>{
 let menu=null,editor=null,key=null;
 function invalidate(){menu?.force();editor?.force();menu=null;editor=null;key=null}
 function reconcile(){if(key&&!rows.has(key))invalidate()}
 async function gate(id){return api('control/status?'+new URLSearchParams({node_id:id}))}
 async function share(id,action,trigger){
  const r=rows.get(id);if(!r)return;
  const body=node('form','control-body'),notice=node('p','notice',r.t.accounting==='unavailable'?'仅读取当前身份的连接凭据；共享原有监听器，不代表独立流量或出站已验证。':'仅在本次操作中读取连接凭据；请勿转发。'),label=node('label','',r.t.accounting==='unavailable'?'当前认证身份资料':'选择入站认证资料'),select=node('select'),confirm=node('button','primary',action==='view'?'查看节点链接':'复制并'+(action==='copy'?'使用':'从客户端剪贴板导入')),status=node('p','muted');label.append(select);body.append(notice,label,confirm,status);confirm.disabled=true;
  let live=true,busy=false,secret='',shareGate=null;const m=UI.modal(action==='copy'?'复制节点链接':action==='view'?'查看节点链接':action==='import_shadowrocket'?'导入 Shadowrocket':'导入 v2rayN',body,{trigger,onClose:()=>{live=false;secret='';body.replaceChildren();if(editor===m)editor=null}});editor=m;
  try{const g=await gate(id);if(!live)return;if(!g.share||!g.actions?.[action])throw Error(g.reason||'此入站不支持该操作');shareGate=g;for(const p of g.profiles||[])select.add(new Option(p.label,p.id));confirm.disabled=!select.options.length;
   if(action.startsWith('import_'))text(notice,'使用客户端的“从剪贴板导入”功能。浏览器不会通过 URL 参数传递连接凭据；本页不能确认客户端是否已导入。');
  }catch(e){text(status,e.message)}
  body.onsubmit=async e=>{e.preventDefault();if(busy||!live)return;busy=true;confirm.disabled=true;try{
   if(!shareGate)throw Error('请重新打开菜单后操作');const nonce=shareGate.nonce;shareGate=null;
   const retrieve=async()=>{const result=await api('control/share','POST',{node_id:id,nonce,action,profile:select.value});if(!live)throw Error('操作已关闭');return result.link};
   if(action==='view'){secret=await retrieve();if(!live)return}
   else {const copied=await UI.copyRequested(retrieve);if(live&&copied)text(status,action==='copy'?'':('已复制，请在 '+(action==='import_shadowrocket'?'Shadowrocket':'v2rayN')+' 中选择“从剪贴板导入”。'))}
   if(action==='view'){let input=body.querySelector('textarea');if(!input){input=node('textarea');input.readOnly=true;input.rows=4;input.autocomplete='off';input.spellcheck=false;input.setAttribute('aria-label','敏感节点链接');body.append(input)}input.value=secret;text(status,'关闭后清除；请勿截图或转发。')}
  }catch(err){if(live){text(status,'');UI.notify(err.message,'error')}}finally{secret='';busy=false;if(live){try{shareGate=await gate(id)}catch{}confirm.disabled=!shareGate}}};
 }
 async function edit(id,trigger,restoreOnly=false,readOnly=false){
  if(!me)return;const r=rows.get(id);if(!r)return;
  const body=node('div','control-body'),info=node('p','',r.t.name),notice=node('p','notice','正在获取控制状态…'),form=node('form'),label=node('label','','粘贴单节点分享链接'),input=node('textarea'),preview=node('dl','detail-grid'),parse=node('button','primary',restoreOnly?'预览恢复原始映射':'解析预览'),status=node('p','muted'),actions=node('div','row-actions'),apply=node('button','danger',restoreOnly?'确认恢复':'确认更换');const source=node('select');source.add(new Option('粘贴节点分享链接',''));form.prepend(source);input.rows=3;input.autocomplete='off';input.spellcheck=false;input.setAttribute('aria-label','节点分享链接');label.append(input);if(!restoreOnly)form.append(label);form.append(parse);apply.type='button';apply.disabled=true;actions.append(apply);body.append(info,notice,form,preview,status,actions);
  let live=true,nonce='',busy=false;key=id;const m=UI.modal(readOnly?'解析出站链接（只读）':restoreOnly?'恢复原始出站':'更换节点出站 IP',body,{trigger,dirty:()=>input.value!==''&&!busy,onClose:()=>{live=false;input.value='';nonce='';if(editor===m)editor=null;if(!menu&&!editor)key=null}});editor=m;
  try{const g=await gate(id);if(live){text(notice,g.reason);for(const o of g.outbounds||[])source.add(new Option(o.tag+' · '+o.type,o.tag))}}catch(e){if(live)text(notice,e.message)}
  input.oninput=()=>{nonce='';apply.disabled=true;preview.replaceChildren()};source.onchange=()=>{input.disabled=!!source.value;input.oninput()};source.hidden=restoreOnly;
  form.onsubmit=async e=>{e.preventDefault();if(busy||(!restoreOnly&&!input.value&&!source.value))return;busy=true;parse.disabled=true;apply.disabled=true;nonce='';text(status,'解析与配置校验中；尚未检测连接或应用');preview.replaceChildren();try{
   const g=await gate(id);if(!live)return;const p=await api('control/'+(restoreOnly?'restore-preview':'preview'),'POST',{node_id:id,...(!restoreOnly?{link:source.value?'':input.value,outbound:source.value}:{}),nonce:g.nonce});if(!live)return;const v=p.preview||p;
   for(const [label,value]of [['协议',v.protocol],['目标（脱敏）',v.server],['端口',v.port],['传输',v.transport||'原配置'],['安全',v.security||'原配置'],['认证','已隐藏']])preview.append(node('dt','',label),node('dd','',value));
   preview.effects=p.effects;preview.change=[v.protocol,v.server,v.port].filter(Boolean).join(' · ');nonce=p.nonce||'';apply.disabled=readOnly||!nonce||!(restoreOnly?g.restore:g.apply);text(status,p.impact||'离线预览完成；控制服务未配置，禁止应用。');if(!apply.disabled)UI.notify('预览已生成，请核对影响范围','info')
  }catch(err){if(live){text(status,'');UI.notify(err.message,'error')}}finally{busy=false;if(live)parse.disabled=false}};
  apply.onclick=async()=>{if(readOnly||busy||!nonce||!preview.effects)return;if(!await UI.confirm(restoreOnly?'确认恢复原始出站？':'确认更换节点出站？',confirmationText(r,preview.effects,restoreOnly?'恢复原始出站':'更换出站：'+preview.change),'确认应用'))return;if(!live)return;
   busy=true;apply.disabled=parse.disabled=true;input.disabled=true;const confirmation=nonce;nonce='';text(status,'正在检测、应用并校验，请勿重复提交…');
   try{await api('control/'+(restoreOnly?'restore':'apply'),'POST',{node_id:id,nonce:confirmation});if(live){input.value='';text(status,restoreOnly?'已恢复原始配置并验证服务。':'配置已应用并通过实际路径检测。');UI.notify(restoreOnly?'原始出站已恢复':'节点出站已更换')}}catch(e){if(live){text(status,'');UI.notify(e.message,'error')}}finally{busy=false;if(live){parse.disabled=false;input.disabled=false}}
  };
 }
 async function rename(id,trigger){
  const r=rows.get(id);if(!r)return;
  const form=node('form'),label=node('label','','tzsing 显示别名'),input=node('input'),save=node('button','primary','保存名称');
  input.value=me?.role==='admin'?(r.t.global_name||''):r.t.name;input.placeholder=r.t.name;input.maxLength=128;label.append(input);form.append(node('p','notice','只修改显示名称。留空恢复原名称。'),label,save);
  let saved=false;const original=input.value,m=UI.modal('重命名',form,{trigger,dirty:()=>!saved&&input.value!==original});editor=m;
  form.onsubmit=async e=>{e.preventDefault();if(save.disabled)return;save.disabled=true;try{await api(me?.role==='admin'?'admin/nodes':'alias',me?.role==='admin'?'PATCH':'PUT',{node_id:id,name:input.value});saved=true;m.force();update(await api('snapshot'));if(currentPage==='nodes')await loadNodeAdmin();message('显示名称已保存')}catch(e){message(e.message)}finally{save.disabled=false}};
 }
 async function policy(id,trigger){
  const r=rows.get(id);if(!r)return;let value=r.t,ready=false,reason="";try{const p=await api('node-policy?'+new URLSearchParams({node_id:id}));value=p.policy;ready=p.ready}catch(e){reason=e.message};const f=node('form','control-body'),fields=PolicyFields.create(f,value,ready),state=node('p','notice',reason||('当前状态：'+policyLabel(value.status||r.t.policy_state))),save=node('button','primary','保存策略');
  save.disabled=!ready;f.append(state,save);let live=true;const m=UI.modal('额度与有效期',f,{trigger,onClose:()=>live=false});editor=m;
  f.onsubmit=async e=>{e.preventDefault();if(save.disabled||!f.reportValidity())return;save.disabled=true;
   try{const values=fields.read(),p=await api('node-policy','POST',{node_id:id,action:'preview',policy:values});if(!live)return;
    if(!await UI.confirm('确认更新此 UUID 的策略',r.t.name+'\n月额度：'+(values.quota?bytes(values.quota):'不限')+'\n到期：'+(values.expires_at?when(values.expires_at)+' · '+fields.zone:'未设置')+'\n重置：每月 '+values.billing_day+' 日 · '+values.timezone+'\n无需重启 sing-box，其他 UUID 保持当前策略。','确认保存'))return;
    await api('node-policy','POST',{node_id:id,action:'apply',nonce:p.nonce});if(live){m.force();update(await api('snapshot'));UI.notify('策略已由数据路径执行')}
   }catch(err){if(live)UI.notify(err.message,'error')}finally{if(live)save.disabled=false}
  };
 }
 async function show(id,trigger){
  if(!me)return;menu?.force();const r=rows.get(id);if(!r)return;key=id;
  const body=node('div','action-list'),items=[];
  for(const [title,action] of [['重命名显示名称','rename'],['编辑月流量额度','quota'],['编辑到期时间','expiry'],['启用 / 停用','state'],['查看流量详情','details']]){
   if(me?.role!=='admin'&&action!=='details'&&(action!=='rename'||!operations.rename))continue;
   const b=node('button','action-item','');b.type='button';b.append(UI.icon(action==='rename'?'change':action==='details'?'check':'restore'),node('span','',title));body.append(b);b.onclick=()=>{m.force();if(action==='rename')rename(id,trigger);else if(action==='details')showHistory(id);else if(action==='state')mutate(id,trigger);else policy(id,trigger)};
  }

  for(const [title,icon,action]of [['导入 Shadowrocket','import','import_shadowrocket'],['导入 v2rayN','import','import_v2rayn'],['复制节点链接','copy','copy'],['查看节点链接','copy','view'],['更换节点出站 IP','change','change'],['恢复原始出站','restore','restore']]){
   const b=node('button','action-item'+(action==='restore'?' danger':''));b.type='button';b.disabled=true;b.append(UI.icon(icon),node('span','',title));body.append(b);items.push([b,action]);if(me?.role!=='admin')b.hidden=!operations[action];b.onclick=()=>{if(b.disabled)return;m.force();if(action==='change'||action==='restore')edit(id,trigger,action==='restore');else share(id,action,trigger)}
  }
  const previewOnly=node('button','action-item');previewOnly.type='button';previewOnly.hidden=true;previewOnly.append(UI.icon('change'),node('span','','解析出站链接（只读）'));previewOnly.onclick=()=>{m.force();edit(id,trigger,false,true)};body.append(previewOnly);
  const status=node('p','notice','正在检查独立权限与入站资料…');body.append(status);
  const del=node('button','action-item danger');del.hidden=me?.role!=='admin';del.type='button';del.append(UI.icon('close'),node('span','','删除节点'));del.onclick=()=>{m.force();mutate(id,trigger,'delete')};body.append(del);const m=UI.modal(r.t.name,body,{trigger,variant:'action-sheet',onClose:()=>{if(menu===m)menu=null;if(!editor&&!menu)key=null}});menu=m;
  try{const g=await gate(id);if(menu!==m||!m.d.open)return;for(const[b,action]of items){b.disabled=action==='change'?!g.apply||g.actions?.change===false:action==='restore'?!g.restore:!g.share||!g.actions?.[action];b.title=b.disabled?(action==='restore'?(g.restore_reason||g.reason):g.reason)||'此入站、权限或控制条件不满足':''}previewOnly.hidden=!!g.apply||!g.preview||g.actions?.change===false;text(status,g.reason+(!g.restore&&g.restore_reason?'；恢复：'+g.restore_reason:''))}catch(e){if(menu===m)text(status,e.message)}
 }
 function confirmationText(r,e,change){
  if(!e)return '缺少可靠影响预览，请重新预览。';
  return r.t.name+' · '+(r.t.auth_name||r.t.auth_id?.slice(0,12)||r.t.inbound_tag||'')+'\n修改：'+change+'\n需要重启整个 sing-box 实例。共享监听器 '+e.shared_listener+'，其他 UUID '+e.other_uuids+' 个。\n影响监听器：'+(e.listeners||[]).map(l=>l.tag+':'+l.port).join('、')+'。\n现有连接可能中断；失败自动恢复并验证服务。';
 }
 async function mutate(id,trigger,action){
  const r=rows.get(id);if(!r||me?.role!=='admin')return;
  const body=node('form','control-body'),select=node('select'),preview=node('p','notice'),save=node('button','primary','配置预览');
  for(const [value,label]of action==='delete'?[['delete','删除当前 UUID']]:[['disable','停用当前 UUID'],['enable','启用当前 UUID']])select.add(new Option(label,value));body.append(select,preview,save);
  let live=true;const m=UI.modal(action==='delete'?'删除节点':'启用 / 停用 UUID',body,{trigger,onClose:()=>live=false});editor=m;
  body.onsubmit=async e=>{e.preventDefault();if(save.disabled)return;save.disabled=true;
   try{const g=await gate(id);const p=await api('control/preview','POST',{node_id:id,nonce:g.nonce,action:select.value});if(!live)return;text(preview,p.reason||p.impact);if(!p.writable)throw Error(p.reason||'配置写入条件未满足');
    if(!p.effects)throw Error('缺少影响预览');if(!await UI.confirm('确认应用',confirmationText(r,p.effects,select.selectedOptions[0].text),'确认应用'))return;
    await api('control/apply','POST',{node_id:id,nonce:p.nonce});if(live){m.force();UI.notify('节点配置已应用')}
   }catch(err){if(live){text(preview,'');UI.notify(err.message,'error')}}finally{if(live)save.disabled=false}
  };
 }
 async function mount(id,host){
  const r=rows.get(id);if(!r||me?.role!=='admin')return;
  const nameForm=node('form'),name=node('input'),saveName=node('button','primary','保存名称');name.value=r.t.global_name||r.t.name;name.maxLength=128;const label=node('label','','名称');label.append(name);nameForm.append(label,saveName);host.append(nameForm);
  nameForm.onsubmit=async e=>{e.preventDefault();if(saveName.disabled)return;saveName.disabled=true;try{await api('admin/nodes','PATCH',{node_id:id,name:name.value});update(await api('snapshot'));UI.notify('名称已保存')}catch(e){UI.notify(e.message,'error')}finally{saveName.disabled=false}};
  const routeForm=node('form'),outbound=node('select'),saveRoute=node('button','primary','保存出站绑定'),routeLabel=node('label','','当前出站');routeLabel.append(outbound);routeForm.append(routeLabel,saveRoute);host.append(routeForm);saveRoute.disabled=true;
  try{const g=await gate(id);for(const o of g.outbounds||[])outbound.add(new Option(o.tag+' · '+o.type,o.tag));outbound.value=r.t.egress;saveRoute.disabled=!g.apply||!outbound.options.length}catch(e){host.append(node('p','notice',e.message))}
  routeForm.onsubmit=async e=>{e.preventDefault();if(saveRoute.disabled)return;saveRoute.disabled=true;try{const g=await gate(id),p=await api('control/preview','POST',{node_id:id,outbound:outbound.value,nonce:g.nonce});if(!p.writable||!p.effects)throw Error(p.reason||'绑定条件未满足');if(!await UI.confirm('确认更换出站',confirmationText(r,p.effects,'绑定：'+outbound.value),'确认应用'))return;await api('control/apply','POST',{node_id:id,nonce:p.nonce});UI.notify('出站绑定已生效')}catch(e){UI.notify(e.message,'error')}finally{saveRoute.disabled=false}};
  const tools=node('div','row-actions');for(const [title,fn]of [['月额度与到期时间',b=>policy(id,b)],['启用 / 停用',b=>mutate(id,b)],['恢复原出站',b=>edit(id,b,true)],['删除入站',b=>mutate(id,b,'delete')]]){const b=node('button','',title);b.type='button';b.onclick=()=>fn(b);tools.append(b)}host.append(tools);
 }
 return {show,reconcile,invalidate,mount};
})();
