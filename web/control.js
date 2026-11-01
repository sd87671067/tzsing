'use strict';
// The menu and its editor share one node identity; realtime card updates do not
// own dialogs. Sensitive links exist only during an explicit protected action.
const NodeControl=(()=>{
 let menu=null,editor=null,key=null;
 function invalidate(){menu?.force();editor?.force();menu=null;editor=null;key=null}
 function reconcile(){if(key&&(!rows.has(key)||me?.role!=='admin'))invalidate()}
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
  }catch(err){if(live){text(status,err.message);UI.notify(err.message,'error')}}finally{secret='';busy=false;if(live){try{shareGate=await gate(id)}catch{}confirm.disabled=!shareGate}}};
 }
 async function edit(id,trigger,restoreOnly=false,readOnly=false){
  if(me?.role!=='admin')return;const r=rows.get(id);if(!r)return;
  const body=node('div','control-body'),info=node('p','',r.t.name),notice=node('p','notice','正在获取控制状态…'),form=node('form'),label=node('label','','粘贴单节点分享链接'),input=node('textarea'),preview=node('dl','detail-grid'),parse=node('button','primary',restoreOnly?'预览恢复原始映射':'解析预览'),status=node('p','muted'),actions=node('div','row-actions'),apply=node('button','danger',restoreOnly?'确认恢复':'确认更换');input.rows=3;input.autocomplete='off';input.spellcheck=false;input.setAttribute('aria-label','节点分享链接');label.append(input);if(!restoreOnly)form.append(label);form.append(parse);apply.type='button';apply.disabled=true;actions.append(apply);body.append(info,notice,form,preview,status,actions);
  let live=true,nonce='',busy=false;key=id;const m=UI.modal(readOnly?'解析出站链接（只读）':restoreOnly?'恢复原始出站':'更换节点出站 IP',body,{trigger,dirty:()=>input.value!==''&&!busy,onClose:()=>{live=false;input.value='';nonce='';if(editor===m)editor=null;if(!menu&&!editor)key=null}});editor=m;
  try{const g=await gate(id);if(live)text(notice,g.reason+'。'+g.impact)}catch(e){if(live)text(notice,e.message)}
  input.oninput=()=>{nonce='';apply.disabled=true;preview.replaceChildren()};
  form.onsubmit=async e=>{e.preventDefault();if(busy||(!restoreOnly&&!input.value))return;busy=true;parse.disabled=true;apply.disabled=true;nonce='';text(status,'解析与配置校验中；尚未检测连接或应用');preview.replaceChildren();try{
   const g=await gate(id);if(!live)return;const p=await api('control/'+(restoreOnly?'restore-preview':'preview'),'POST',{node_id:id,...(!restoreOnly?{link:input.value}:{}),nonce:g.nonce});if(!live)return;const v=p.preview||p;
   for(const [label,value]of [['协议',v.protocol],['目标（脱敏）',v.server],['端口',v.port],['传输',v.transport||'原配置'],['安全',v.security||'原配置'],['认证','已隐藏']])preview.append(node('dt','',label),node('dd','',value));
   nonce=p.nonce||'';apply.disabled=readOnly||!nonce||!(restoreOnly?g.restore:g.apply);text(status,p.impact||'离线预览完成；控制服务未配置，禁止应用。');if(!apply.disabled)UI.notify('预览已生成，请核对影响范围','info')
  }catch(err){if(live){text(status,err.message);UI.notify(err.message,'error')}}finally{busy=false;if(live)parse.disabled=false}};
  apply.onclick=async()=>{if(readOnly||busy||!nonce)return;if(!await UI.confirm(restoreOnly?'确认恢复原始出站？':'确认更换节点出站？','将重启 sing-box，所有当前连接会短暂断开并重连。仅修改目标入站映射；失败时自动回滚。'))return;if(!live)return;
   busy=true;apply.disabled=parse.disabled=true;input.disabled=true;const confirmation=nonce;nonce='';text(status,'正在检测、应用并校验，请勿重复提交…');
   try{await api('control/'+(restoreOnly?'restore':'apply'),'POST',{node_id:id,nonce:confirmation});if(live){input.value='';text(status,restoreOnly?'已恢复原始配置并验证服务。':'配置已应用并通过实际路径检测。');UI.notify(restoreOnly?'原始出站已恢复':'节点出站已更换')}}catch(e){if(live){text(status,e.message);UI.notify(e.message,'error')}}finally{busy=false;if(live){parse.disabled=false;input.disabled=false}}
  };
 }
 async function show(id,trigger){
  if(me?.role!=='admin')return;menu?.force();const r=rows.get(id);if(!r)return;key=id;
  const body=node('div','action-list'),items=[];
  for(const [title,icon,action]of [['导入 Shadowrocket','import','import_shadowrocket'],['导入 v2rayN','import','import_v2rayn'],['复制节点链接','copy','copy'],['查看节点链接','copy','view'],['更换节点出站 IP','change','change'],['恢复原始出站','restore','restore']]){
   const b=node('button','action-item'+(action==='restore'?' danger':''));b.type='button';b.disabled=true;b.append(UI.icon(icon),node('span','',title));body.append(b);items.push([b,action]);b.onclick=()=>{if(b.disabled)return;m.force();if(action==='change'||action==='restore')edit(id,trigger,action==='restore');else share(id,action,trigger)}
  }
  const previewOnly=node('button','action-item');previewOnly.type='button';previewOnly.hidden=true;previewOnly.append(UI.icon('change'),node('span','','解析出站链接（只读）'));previewOnly.onclick=()=>{m.force();edit(id,trigger,false,true)};body.append(previewOnly);
  const status=node('p','notice','正在检查独立权限与入站资料…');body.append(status);const m=UI.modal(r.t.name,body,{trigger,variant:'action-sheet',onClose:()=>{if(menu===m)menu=null;if(!editor&&!menu)key=null}});menu=m;
  try{const g=await gate(id);if(menu!==m||!m.d.open)return;for(const[b,action]of items){b.disabled=action==='change'?!g.apply||g.actions?.change===false:action==='restore'?!g.restore:!g.share||!g.actions?.[action];b.title=b.disabled?'此入站、权限或控制条件不满足':''}previewOnly.hidden=!!g.apply||!g.preview||g.actions?.change===false;text(status,g.reason)}catch(e){if(menu===m)text(status,e.message)}
 }
 return {show,reconcile,invalidate};
})();
