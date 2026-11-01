'use strict';
// Uses the same form controls, dialog lifecycle, SVGs and Toast as the console.
const UUIDEditor=(()=>{
 let form=null,revision=0;
 function clear(){revision++;if(form)form.reset();form=null;document.querySelector('#uuid-editor').replaceChildren()}
 async function load(){clear();const rev=revision,host=document.querySelector('#uuid-editor');host.append(UI.make('p','muted','正在读取现有监听器…'));
  try{const c=await api('admin/node-catalog');if(rev!==revision||me?.role!=='admin')return;host.replaceChildren();
   const f=UI.make('form','uuid-form'),notice=UI.make('p','notice',c.reason);form=f;
   const add=(key,label,type='text',value='',disabled=false)=>{const l=UI.make('label','',label),input=UI.make(type==='select'?'select':'input');input.name=key;if(type!=='select')input.type=type;input.value=value;input.disabled=disabled;l.append(input);f.append(l);return input};
   const name=add('name','节点中文名称');name.maxLength=128;name.required=true;
   const server=add('server','所属服务器','select');server.add(new Option(c.server_id,c.server_id));
   const inbound=add('inbound','现有 VLESS REALITY 入站','select');for(const i of c.inbounds)inbound.add(new Option(i.tag+' · '+i.users+' 个 UUID',i.tag));inbound.required=true;
   const listener=UI.make('p','muted');f.append(listener);
   const uuid=add('uuid','UUID（留空由 Go 安全生成）');uuid.autocomplete='off';uuid.spellcheck=false;uuid.maxLength=36;uuid.pattern='[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
   const sni=add('sni','共享客户端 SNI（只读）','text','',true),handshake=add('handshake','共享服务端 REALITY 握手目标（只读）','text','',true);
   const describe=()=>{const i=c.inbounds.find(i=>i.tag===inbound.value);sni.value=i?.sni||'未配置';handshake.value=i?.handshake_server||'未配置';listener.textContent=i?'复用现有监听 '+i.port+'；外部 443 映射沿用现有部署，不创建端口。':'没有受支持的 REALITY 入站'};inbound.onchange=describe;describe();
   f.append(UI.make('p','muted','SNI 是客户端发送的 TLS 名称；handshake 是服务端伪装目标。二者均属共享入站配置，不能逐 UUID 修改。'));
   const mode=UI.make('div','source-tabs');mode.setAttribute('role','group');mode.setAttribute('aria-label','出站方式');let selected='original';
   const outbound=add('outbound','实际出站 Tag','select');outbound.add(new Option('沿用原路由',''));for(const o of c.outbounds)outbound.add(new Option(o.tag+' · '+o.type,o.tag));
   const buttons=[];for(const [value,label]of [['original','原路由'],['direct','直连'],['relay','中转']]){const b=UI.make('button','',label);b.type='button';b.setAttribute('aria-pressed',String(value===selected));b.onclick=()=>{selected=value;buttons.forEach(x=>x.b.setAttribute('aria-pressed',String(x.value===value)));outbound.replaceChildren();if(value==='original')outbound.add(new Option('沿用原路由',''));else for(const o of c.outbounds.filter(o=>(o.type==='direct')===(value==='direct')))outbound.add(new Option(o.tag+' · '+o.type,o.tag));outbound.required=value!=='original'};buttons.push({value,b});mode.append(b)}f.insertBefore(mode,outbound.parentNode);
   add('quota','独立月额度（尚无可靠扣费执行器）','number','0',true);
   add('upload_limit','上传限速（数据路径执行器未启用）','number','0',true);add('download_limit','下载限速（数据路径执行器未启用）','number','0',true);
   add('expires_at','到期自动停用（生产写入关闭）','datetime-local','',true);
   add('max_connections','并发连接上限（不是物理设备数；执行器未启用）','number','0',true);
   const enabled=add('enabled','是否启用（候选默认启用）','checkbox','',true);enabled.checked=true;enabled.setAttribute('role','switch');enabled.parentNode.className='switch-row';
   const actions=UI.make('div','row-actions'),preview=UI.make('button','primary','校验候选'),save=UI.make('button','','保存'),cancel=UI.make('button','','取消'),reset=UI.make('button','','重置');save.disabled=true;save.type=cancel.type=reset.type='button';save.title=c.reason;
   cancel.onclick=()=>{clear();navigate('overview')};reset.onclick=()=>{f.reset();buttons[0].b.click();describe()};actions.append(preview,save,cancel,reset);f.append(actions);host.append(notice,f);preview.disabled=!c.inbounds.length;
   f.onsubmit=async e=>{e.preventDefault();if(preview.disabled)return;preview.disabled=true;try{const summary=await api('admin/node-preview','POST',{server:server.value,node:{inbound:inbound.value,name:name.value,uuid:uuid.value.trim(),outbound:outbound.value,enabled:true}});if(rev!==revision||me?.role!=='admin')return;uuid.value='';const content=UI.make('div','control-body');content.append(UI.make('p','',summary.reason),UI.make('p','muted','共享监听器、密钥和已有 UUID 保持不变。此操作没有保存生产节点。'));UI.modal('候选配置校验通过',content,{trigger:preview});UI.notify('候选校验通过；未应用生产','success')}catch(e){UI.notify(e.message,'error')}finally{preview.disabled=false}};
  }catch(e){if(rev===revision)host.replaceChildren(UI.make('p','notice',e.message))}
 }
 return {load,clear};
})();
