'use strict';
const PersonalOutbounds=(()=>{
 const make=UI.make;
 async function open(id,trigger){
  const root=make('div'),status=make('p','notice','正在读取个人出站…'),list=make('div'),form=make('form','uuid-form'),name=make('input'),link=make('textarea'),save=make('button','primary','创建个人出站');
  name.required=true;name.maxLength=128;link.required=true;link.autocomplete='off';link.spellcheck=false;link.rows=3;
  for(const [label,input]of [['名称',name],['节点链接',link]]){const l=make('label','',label);l.append(input);form.append(l)}form.append(save);root.append(status,list,form);
  let live=true,editing='';const modal=UI.modal('管理个人出站',root,{trigger,onClose:()=>{live=false;link.value=''}});
  async function run(fn){if(root.getAttribute('aria-busy')==='true')return;root.setAttribute('aria-busy','true');const bs=[...root.querySelectorAll('button')];bs.forEach(b=>b.disabled=true);try{await fn()}catch(e){if(live){status.textContent=e.message;UI.notify(e.message,'error')}}finally{root.removeAttribute('aria-busy');bs.forEach(b=>b.disabled=false)}}
  async function applyPersonal(action,item){const p=await api('personal-outbounds','POST',{node_id:id,id:item?.id||'',action,name:name.value.trim(),link:action==='delete'?'':link.value.trim()});if(!live)return;if(!await UI.confirm('确认应用个人出站',p.reason||'需要重启整个 sing-box；现有连接可能短暂断开，失败自动回滚。','确认应用'))return;await api('personal-outbounds','POST',{node_id:id,action:'apply',nonce:p.nonce});link.value='';name.value='';editing='';save.textContent='创建个人出站';await load();UI.notify('出站操作已完成')}
  async function load(){const c=await api('personal-outbounds?'+new URLSearchParams({node_id:id}));if(!live)return;list.replaceChildren();status.textContent='个人出站仅所有者可使用；编辑或删除前须解除实际路由和链式引用。';for(const o of c.items){const card=make('div','card'),tools=make('div','row-actions');card.append(make('strong','',o.name));const test=make('button','','检测'),edit=make('button','','编辑'),del=make('button','danger','删除');tools.append(test,edit,del);card.append(tools);list.append(card);
   test.onclick=()=>run(async()=>{const result=await api('personal-outbounds','POST',{node_id:id,id:o.id,action:'test'});status.textContent='实际出口 IP：'+result.ip;UI.notify(status.textContent)});
   edit.onclick=()=>{editing=o.id;name.value=o.name;link.value='';save.textContent='保存个人出站';form.hidden=false;link.focus()};
   del.onclick=()=>run(()=>applyPersonal('delete',o));
  }}
  form.onsubmit=e=>{e.preventDefault();if(form.reportValidity())run(()=>applyPersonal(editing?'edit':'create',editing?{id:editing}:null))};
  try{await load()}catch(e){status.textContent=e.message}
 }
 return {open};
})();
