'use strict';
const PersonalOutbounds=(()=>{
 const make=UI.make;
 async function open(id,trigger){
  const root=make('div'),status=make('p','notice','正在读取此 UUID 的授权…'),list=make('div'),form=make('form','uuid-form'),name=make('input'),link=make('textarea'),save=make('button','primary','创建个人出站'),restore=make('button','','恢复原始出站');
  name.required=true;name.maxLength=128;link.required=true;link.autocomplete='off';link.spellcheck=false;link.rows=3;
  for(const [label,input]of [['名称',name],['节点链接',link]]){const l=make('label','',label);l.append(input);form.append(l)}form.append(save);restore.type='button';root.append(status,list,form,restore);
  let live=true,editing='',permission={};const modal=UI.modal('个人与授权出站',root,{trigger,onClose:()=>{live=false;link.value=''}});
  async function run(fn){if(root.getAttribute('aria-busy')==='true')return;root.setAttribute('aria-busy','true');const bs=[...root.querySelectorAll('button')];bs.forEach(b=>b.disabled=true);try{await fn()}catch(e){if(live){status.textContent=e.message;UI.notify(e.message,'error')}}finally{root.removeAttribute('aria-busy');bs.forEach(b=>b.disabled=false)}}
  async function applyPersonal(action,item){const p=await api('personal-outbounds','POST',{node_id:id,id:item?.id||'',action,name:name.value.trim(),link:action==='delete'?'':link.value.trim()});if(!live)return;if(!await UI.confirm('确认应用个人出站',p.reason||'需要重启整个 sing-box；现有连接可能短暂断开，失败自动回滚。','确认应用'))return;await api('personal-outbounds','POST',{node_id:id,action:'apply',nonce:p.nonce});link.value='';name.value='';editing='';save.textContent='创建个人出站';await load();UI.notify('出站操作已完成')}
  async function load(){const c=await api('personal-outbounds?'+new URLSearchParams({node_id:id}));if(!live)return;permission=c.permission;form.hidden=!permission.add&&!permission.edit;restore.hidden=!permission.change;list.replaceChildren();status.textContent='仅此 UUID 获授权的出站可绑定。个人出站默认私有；编辑前须解除引用。';for(const o of c.items){const card=make('div','card'),tools=make('div','row-actions');card.append(make('strong','',o.name),make('p','muted',o.owner===me.id?'我的个人出站':'管理员授权出站'));const bind=make('button','','绑定此 UUID'),test=make('button','','测试'),edit=make('button','','编辑'),del=make('button','danger','删除');bind.hidden=!permission.change||!permission.outbounds.includes(o.id);test.hidden=o.owner!==me.id;edit.hidden=o.owner!==me.id||!permission.edit;del.hidden=o.owner!==me.id||!permission.delete;tools.append(bind,test,edit,del);card.append(tools);list.append(card);
   bind.onclick=()=>run(async()=>{const g=await api('control/status?'+new URLSearchParams({node_id:id}));const p=await api('control/preview','POST',{node_id:id,outbound:o.id,nonce:g.nonce});if(!await UI.confirm('确认更换此 UUID 的出站',o.name+'\n'+p.impact,'确认应用'))return;await api('control/apply','POST',{node_id:id,nonce:p.nonce});UI.notify('绑定已完成')});
   test.onclick=()=>run(async()=>{const result=await api('personal-outbounds','POST',{node_id:id,id:o.id,action:'test'});status.textContent='实际出口 IP：'+result.ip;UI.notify(status.textContent)});
   edit.onclick=()=>{editing=o.id;name.value=o.name;link.value='';save.textContent='保存个人出站';form.hidden=false;link.focus()};
   del.onclick=()=>run(()=>applyPersonal('delete',o));
  }}
  form.onsubmit=e=>{e.preventDefault();if(form.reportValidity())run(()=>applyPersonal(editing?'edit':'create',editing?{id:editing}:null))};
  restore.onclick=()=>run(async()=>{const g=await api('control/status?'+new URLSearchParams({node_id:id})),p=await api('control/restore-preview','POST',{node_id:id,nonce:g.nonce});if(!await UI.confirm('确认恢复原始出站',p.impact,'确认恢复'))return;await api('control/restore','POST',{node_id:id,nonce:p.nonce});UI.notify('原始出站已恢复')});
  try{await load()}catch(e){status.textContent=e.message}
 }
 async function permissions(){
  const user=Number(document.querySelector('#grant-user').value),host=document.querySelector('#precise-outbounds');if(!user||!host)return;
  const c=await api('admin/uuid-permissions');if(user!==Number(document.querySelector('#grant-user').value))return;host.replaceChildren(make('p','muted',c.revocation));
  for(const server of grantViews){for(const t of server.report?.tags||[]){if(t.identity!=='inbound'||!t.auth_id)continue;if(!grants.some(g=>Number(g.user_id)===user&&g.server===server.id&&g.tag===(t.grant_tag||t.raw_tag)))continue;
   const p=c.permissions.find(p=>p.user_id===user&&p.node_id===t.id)||{user_id:user,node_id:t.id,change:false,add:false,edit:false,delete:false,outbounds:[]},group=make('fieldset','grant-group'),legend=make('legend','',t.name),save=make('button','primary','保存此 UUID 的出站权限');save.type='button';group.append(legend);
   for(const [key,label]of [['change','允许更换与恢复出站'],['add','允许添加个人出站'],['edit','允许编辑自己的出站'],['delete','允许删除自己的出站']]){const l=make('label','choice-row'),input=make('input');input.type='checkbox';input.checked=p[key];input.onchange=()=>p[key]=input.checked;l.append(input,make('span','',label));group.append(l)}
   for(const o of c.outbounds){const l=make('label','choice-row'),input=make('input');input.type='checkbox';input.checked=p.outbounds.includes(o.id);input.onchange=()=>{p.outbounds=p.outbounds.filter(id=>id!==o.id);if(input.checked)p.outbounds.push(o.id)};l.append(input,make('span','',o.name+(o.owner?' · 个人出站（可授权共享）':' · 全局出站')));group.append(l)}
   group.append(save);host.append(group);save.onclick=async()=>{save.disabled=true;try{if(!await UI.confirm('确认更新 UUID 出站权限','已有绑定将先恢复原始出站，可能重启整个 sing-box；恢复失败则拒绝撤权。','确认保存'))return;await api('admin/uuid-permissions','PUT',p);UI.notify('此 UUID 的权限已保存')}catch(e){UI.notify(e.message,'error')}finally{save.disabled=false}};
  }}
 }
 return {open,permissions};
})();
