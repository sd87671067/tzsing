'use strict';
// One owner for the node action menu and the offline outbound preview form.
const NodeControl=(()=>{
 let menu=null,editor=null,key=null;
 function invalidate(){menu?.force();editor?.force();menu=null;editor=null;key=null}
 function reconcile(){if(key&&(!rows.has(key)||me?.role!=='admin'))invalidate()}
 async function edit(id,trigger){
  if(me?.role!=='admin')return;const r=rows.get(id);if(!r)return;
  const body=node('div','control-body'),info=node('p','',r.t.name+' · '+(r.t.ip?.ipv4||r.t.ip?.ipv6||'尚无已验证出口')),notice=node('p','notice','正在获取安全门禁…'),form=node('form'),label=node('label','','粘贴单节点分享链接'),input=node('textarea'),preview=node('dl','detail-grid'),parse=node('button','primary','解析预览'),status=node('p','muted'),actions=node('div','row-actions');input.rows=3;input.autocomplete='off';input.spellcheck=false;input.setAttribute('aria-label','节点分享链接');label.append(input);form.append(label,parse);body.append(info,notice,form,preview,status,actions);
  for(const title of ['检测连接','确认更换','恢复原始出站']){const b=node('button',title.includes('恢复')?'danger':'',title);b.type='button';b.disabled=true;b.title='安全门禁未满足，禁止生产操作';actions.append(b)}
  key=id;editor=UI.modal('更换节点出站 IP',body,{trigger,dirty:()=>input.value!=='',onClose:()=>{input.value='';editor=null;if(!menu)key=null}});
  try{const gate=await api('control/status?'+new URLSearchParams({node_id:id}));if(!editor)return;text(notice,gate.reason+'。'+gate.impact)}catch(e){text(notice,e.message)}
  form.onsubmit=async e=>{e.preventDefault();if(parse.disabled||!input.value)return;parse.disabled=true;text(status,'解析中 · 不进行网络请求');preview.replaceChildren();try{const gate=await api('control/status?'+new URLSearchParams({node_id:id}));const p=await api('control/preview','POST',{node_id:id,link:input.value,nonce:gate.nonce});if(!editor||key!==id)return;for(const [label,value]of [['协议',p.protocol],['服务器',p.server],['端口',p.port],['传输',p.transport],['安全',p.security],['认证','已隐藏，未保存'],['v2rayN',p.v2rayn],['Shadowrocket',p.shadowrocket]])preview.append(node('dt','',label),node('dd','',value));text(status,'离线解析完成；未检测连接、未修改任何配置。');UI.notify('解析预览已生成','info')}catch(e){text(status,e.message);UI.notify(e.message,'error')}finally{parse.disabled=false}};
 }
 async function show(id,trigger){
  if(me?.role!=='admin')return;menu?.force();const r=rows.get(id);if(!r)return;key=id;
  const body=node('div','action-list'),reason='缺少专门分享权限和权威入站资料；监控 Tag / 内部 SOCKS 不能作为客户端链接';
  for(const [title,icon]of [['导入 Shadowrocket','import'],['导入 v2rayN','import'],['复制节点链接','copy']]){const row=node('div','action-entry'),b=node('button','action-item');b.type='button';b.disabled=true;b.append(UI.icon(icon),node('span','',title));b.title=reason;row.append(b,node('small','muted',reason));body.append(row)}
  const change=node('button','action-item'),restore=node('button','action-item danger');change.append(UI.icon('change'),node('span','','更换节点出站 IP'));restore.append(UI.icon('restore'),node('span','','恢复原始出站'));restore.disabled=true;restore.title='未发生受控切换且无安全热更新机制，禁止生产恢复写入';body.append(change,restore,node('p','notice','分享链接可能包含认证凭据。仅具备专门权限的管理员可使用，禁止转发或写入日志。'));
  menu=UI.modal(r.t.name,body,{trigger,variant:'action-sheet',onClose:()=>{menu=null;if(!editor)key=null}});
  change.onclick=()=>{menu.force();edit(id,trigger)};
 }
 return {show,reconcile,invalidate};
})();
