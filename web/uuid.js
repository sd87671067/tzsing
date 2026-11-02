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
    const v=c.capabilities?.[key],row=UI.make('div','uuid-capability'),head=UI.make('div','title-row'),state=UI.make('span','pill',v?.state==='ready'?'可应用':v?.state==='disabled'?'未启用':'暂不支持');
    row.dataset.capability=key;head.append(UI.make('strong','',label+(v?.unit?' · '+v.unit:'')),state);row.append(head,UI.make('p','muted',v?.reason||'控制服务未提供执行能力证明，保持不可用。'),UI.make('small','muted',v?.state==='ready'?'通过预览与二次确认后生效':'未保存 · 未生效'));group.append(row);
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
   const limits=PolicyFields.create(f,{},c.capabilities?.quota?.state==='ready'&&c.capabilities?.expires_at?.state==='ready');
   const stateGroup=group('启用状态'),enabled=add(stateGroup,'enabled','添加后启用','checkbox');enabled.checked=true;
   const actions=UI.make('div','row-actions uuid-actions'),preview=UI.make('button','primary','添加节点'),cancel=UI.make('button','','取消'),reset=UI.make('button','','重置');cancel.type=reset.type='button';
   cancel.onclick=()=>{clear();navigate('overview')};reset.onclick=()=>{f.reset();buttons[0].b.click();describe()};actions.append(preview,cancel,reset);f.append(actions);host.append(UI.make('p','notice',c.reason),f);preview.disabled=!c.inbounds.length;
   f.onsubmit=async e=>{
    e.preventDefault();if(preview.disabled||!f.reportValidity())return;preview.disabled=true;
    const routeLabel=outbound.selectedOptions[0]?.textContent||'未选择',nodeName=name.value.trim(),controls=[...f.querySelectorAll('input,select,button')].filter(x=>x!==preview).map(x=>[x,x.disabled]);controls.forEach(([x])=>x.disabled=true);
    try{
     const request={server:server.value,node:{inbound:inbound.value,name:nodeName,uuid:uuid.value.trim(),outbound:outbound.value,enabled:enabled.checked,...limits.read()}};
     let summary=await api('admin/node-preview','POST',request),result;
     if(rev!==revision||me?.role!=='admin')return;
     if(!summary.writable)throw Error(summary.reason||c.reason||'生产写入未启用');
     const description='名称：'+nodeName+'\n入站：'+inbound.value+' · '+routeLabel+'\n共享 443、REALITY 密钥和握手配置保持现有值。\n将重启整个 sing-box，所有共享连接可能中断；失败自动回滚。\n'+summary.reason;
     if(!await UI.confirm('确认添加 UUID 节点',description,'确认应用',{onConfirm:async()=>{
      if(!summary)summary=await api('admin/node-preview','POST',request);
      if(!summary.writable)throw Error(summary.reason||'生产写入未启用');
      const nonce=summary.nonce;summary=null;
      result=await api('admin/node-create','POST',{server:request.server,nonce});
      if(!result.ok)throw Error('执行器未确认 UUID 创建，请刷新后核实');
     }}))return;
     if(rev!==revision)return;uuid.value='';UI.notify(result.warning||'UUID 节点已添加并通过健康验证');navigate('overview');

    }catch(e){if(rev===revision)UI.notify(e.message,'error')}finally{controls.forEach(([x,disabled])=>x.disabled=disabled);preview.disabled=false}
   };
  }catch(e){if(rev===revision)host.replaceChildren(UI.make('p','notice',e.message))}
 }
 return {load,clear};
})();
