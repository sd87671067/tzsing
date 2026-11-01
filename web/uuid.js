'use strict';
// Reuse console controls, tokens, modal lifecycle and Toast.
const UUIDEditor=(()=>{
 let form=null,revision=0;
 function clear(){revision++;if(form)form.reset();form=null;document.querySelector('#uuid-editor').replaceChildren()}
 async function load(){
  clear();const rev=revision,host=document.querySelector('#uuid-editor');host.append(UI.make('p','muted','正在读取现有监听器…'));
  try{
   const c=await api('admin/node-catalog');if(rev!==revision||me?.role!=='admin')return;host.replaceChildren();
   const f=UI.make('form','uuid-form');form=f;
   function group(title){const fieldset=UI.make('fieldset','uuid-group');fieldset.append(UI.make('legend','',title));f.append(fieldset);return fieldset}
   function add(group,key,label,type='text',value='',disabled=false){const l=UI.make('label','',label),input=UI.make(type==='select'?'select':'input');input.name=key;if(type!=='select')input.type=type;input.value=value;input.disabled=disabled;l.append(input);group.append(l);return input}
   function capability(group,key,label){
    const v=c.capabilities?.[key],row=UI.make('div','uuid-capability'),head=UI.make('div','title-row'),state=UI.make('span','pill',v?.state==='disabled'?'未启用':'暂不支持');
    row.dataset.capability=key;head.append(UI.make('strong','',label+(v?.unit?' · '+v.unit:'')),state);row.append(head,UI.make('p','muted',v?.reason||'控制服务未提供执行能力证明，保持不可用。'),UI.make('small','muted','未保存 · 未生效'));group.append(row);
   }
   const basic=group('基础信息'),name=add(basic,'name','节点中文名称');name.maxLength=128;name.required=true;
   const server=add(basic,'server','所属服务器','select');server.add(new Option(c.server_id,c.server_id));
   const inbound=add(basic,'inbound','现有 VLESS REALITY 入站','select');for(const i of c.inbounds)inbound.add(new Option(i.tag+' · '+i.users+' 个 UUID',i.tag));inbound.required=true;
   const listener=UI.make('p','muted');basic.append(listener);
   const uuid=add(basic,'uuid','UUID（留空由 Go 安全生成）');uuid.autocomplete='off';uuid.spellcheck=false;uuid.maxLength=36;uuid.pattern='[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
   const sni=add(basic,'sni','共享客户端 SNI（只读）','text','',true),handshake=add(basic,'handshake','共享服务端 REALITY 握手目标（只读）','text','',true);
   const describe=()=>{const i=c.inbounds.find(i=>i.tag===inbound.value);sni.value=i?.sni||'未配置';handshake.value=i?.handshake_server||'未配置';listener.textContent=i?'复用现有监听 '+i.port+'；外部 443 映射沿用现有部署，不创建端口。':'没有受支持的 REALITY 入站'};inbound.onchange=describe;describe();
   basic.append(UI.make('p','muted','SNI 与 handshake 均属共享入站配置，不能逐 UUID 修改。'));
   const routing=group('出站路由'),mode=UI.make('div','source-tabs');mode.setAttribute('role','group');mode.setAttribute('aria-label','出站方式');routing.append(mode);let selected='original';
   const outbound=add(routing,'outbound','实际出站 Tag（候选）','select'),buttons=[];
   for(const [value,label]of [['original','原路由'],['direct','直连'],['relay','中转']]){
    const b=UI.make('button','',label);b.type='button';b.onclick=()=>{selected=value;buttons.forEach(x=>x.b.setAttribute('aria-pressed',String(x.value===value)));outbound.replaceChildren();if(value==='original')outbound.add(new Option('沿用原路由',''));else for(const o of c.outbounds.filter(o=>(o.type==='direct')===(value==='direct')))outbound.add(new Option(o.tag+' · '+o.type,o.tag));outbound.required=value!=='original'};buttons.push({value,b});mode.append(b);
   }
   buttons[0].b.click();capability(routing,'outbound','独立出站应用');
   const traffic=group('流量与带宽');for(const [key,label]of [['quota','独立月额度'],['upload_limit','上传限速'],['download_limit','下载限速']])capability(traffic,key,label);
   const limits=group('有效期与连接限制');for(const [key,label]of [['expires_at','到期自动停用'],['max_connections','最大并发连接'],['enabled','启用 / 停用']])capability(limits,key,label);
   const actions=UI.make('div','row-actions uuid-actions'),preview=UI.make('button','primary','校验候选'),save=UI.make('button','','保存'),cancel=UI.make('button','','取消'),reset=UI.make('button','','重置');save.disabled=true;save.type=cancel.type=reset.type='button';save.title=c.reason;
   cancel.onclick=()=>{clear();navigate('overview')};reset.onclick=()=>{f.reset();buttons[0].b.click();describe()};actions.append(preview,save,cancel,reset);f.append(actions);host.append(UI.make('p','notice',c.reason),f);preview.disabled=!c.inbounds.length;
   f.onsubmit=async e=>{
    e.preventDefault();if(preview.disabled||!f.reportValidity())return;preview.disabled=true;
    const routeLabel=outbound.selectedOptions[0]?.textContent||'未选择',nodeName=name.value.trim();
    try{
     const summary=await api('admin/node-preview','POST',{server:server.value,node:{inbound:inbound.value,name:nodeName,uuid:uuid.value.trim(),outbound:outbound.value,enabled:true}});
     if(rev!==revision||me?.role!=='admin')return;uuid.value='';const content=UI.make('div','control-body');
     for(const line of ['名称：'+nodeName,'入站：'+inbound.value,'路由：'+routeLabel,'候选：不限额 / 不限速 / 永不过期 / 不限并发；启用',summary.reason,'共享监听器、密钥和已有 UUID 保持不变。候选校验后丢弃，没有保存生产节点。'])content.append(UI.make('p','',line));
     UI.modal('候选配置校验通过',content,{trigger:preview});UI.notify('候选校验通过；未应用生产','success');
    }catch(e){if(rev===revision)UI.notify(e.message,'error')}finally{preview.disabled=false}
   };
  }catch(e){if(rev===revision)host.replaceChildren(UI.make('p','notice',e.message))}
 }
 return {load,clear};
})();
