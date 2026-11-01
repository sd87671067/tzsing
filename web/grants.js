'use strict';
// Explicit identities are saved, so selecting all never authorizes future nodes.
class PermissionPicker {
 constructor(root){this.root=root;this.servers=[];this.selected=new Set();this.allowed=new Set();this.hosts=new Set();this.query='';this.groups=[]}
 key(server,tag){return JSON.stringify([server,tag])}
 load(servers,views,grants,serverGrants,user){
  this.servers=servers.map(s=>({...s,tags:views.find(v=>v.id===s.id)?.report?.tags||[]}));
  this.selected=new Set(grants.filter(g=>String(g.user_id)===String(user)&&g.tag!=='*').map(g=>this.key(g.server,g.tag)));
  this.allowed=new Set(serverGrants.filter(g=>String(g.user_id)===String(user)).map(g=>g.server));
  this.hosts=new Set(grants.filter(g=>String(g.user_id)===String(user)&&g.tag==='*').map(g=>g.server));
  this.render();this.status(false)
 }
 updateInventory(servers,views){this.servers=servers.map(s=>({...s,tags:views.find(v=>v.id===s.id)?.report?.tags||[]}));this.render()}
 checkbox(label,checked,change){const row=node('label','choice-row'),input=node('input'),caption=node('span','',label);input.type='checkbox';input.checked=checked;input.onchange=()=>{change(input.checked);this.refresh();this.status(true)};row.append(input,caption);return{row,input}}
 matches(s,t){return [s.name,s.id,t.name,t.raw_tag].some(v=>v?.toLocaleLowerCase().includes(this.query))}
 render(){
  this.root.replaceChildren();this.groups=[];
  for(const s of this.servers){
   const group=node('fieldset','grant-group'),legend=node('legend','',s.name),server=this.checkbox('允许访问服务器',this.allowed.has(s.id),checked=>{if(checked)this.allowed.add(s.id);else{this.allowed.delete(s.id);this.hosts.delete(s.id);for(const t of s.tags)this.selected.delete(this.key(s.id,t.raw_tag))}});
   server.input.dataset.server=s.id;group.append(legend,server.row);
   const toolbar=node('div','grant-toolbar'),all=this.checkbox('选择本组节点',false,checked=>this.select(checked,s.id)),count=node('span','muted');all.input.dataset.group=s.id;toolbar.append(all.row,count);group.append(toolbar);
   const host=this.checkbox('服务器主机状态',this.hosts.has(s.id),checked=>{if(checked){this.hosts.add(s.id);this.allowed.add(s.id)}else this.hosts.delete(s.id)});host.input.dataset.host=s.id;group.append(host.row);
   const choices=[];
   for(const t of s.tags){const key=this.key(s.id,t.raw_tag),c=this.checkbox(t.name+' · '+t.category+' · '+t.raw_tag,this.selected.has(key),checked=>{if(checked){this.selected.add(key);this.allowed.add(s.id)}else this.selected.delete(key)});c.input.dataset.node=t.id;group.append(c.row);choices.push({...c,t,key})}
   if(!s.tags.length)group.append(node('p','muted','尚未发现可授权节点；新节点默认不授权。'));
   this.groups.push({s,group,server,all,host,count,choices});this.root.append(group)
  }
  if(!this.servers.length)this.root.append(node('p','muted','请先登记服务器。'));
  this.refresh()
 }
 refresh(){
  let visible=0,chosen=0;
  for(const g of this.groups){let total=0,n=0;g.server.input.checked=this.allowed.has(g.s.id);g.host.input.checked=this.hosts.has(g.s.id);
   for(const c of g.choices){c.input.checked=this.selected.has(c.key);c.row.hidden=!this.matches(g.s,c.t);if(!c.row.hidden){total++;if(c.input.checked)n++}}
   g.group.hidden=Boolean(this.query&&!total);g.all.input.checked=total>0&&n===total;g.all.input.indeterminate=n>0&&n<total;g.all.input.disabled=total===0;text(g.count,n+' / '+total);visible+=total;chosen+=n;
  }
  const all=$('#grant-all');all.checked=visible>0&&chosen===visible;all.indeterminate=chosen>0&&chosen<visible;all.disabled=!visible;
  text($('#grant-count'),'已选 '+this.selected.size+' 个节点 · '+this.allowed.size+' 台服务器')
 }
 select(checked,server){for(const s of this.servers){if(server&&s.id!==server)continue;for(const t of s.tags){if(!this.matches(s,t))continue;const key=this.key(s.id,t.raw_tag);if(checked){this.selected.add(key);this.allowed.add(s.id)}else this.selected.delete(key)}}}
 search(value){this.query=value.trim().toLocaleLowerCase();this.refresh()}
 status(dirty){text($('#grant-status'),dirty?'有未保存的权限修改':'权限已载入；新节点默认不授权');$('#grant-status').dataset.dirty=String(dirty)}
 payload(user){return{user_id:Number(user),servers:[...this.allowed],hosts:[...this.hosts],grants:[...this.selected].map(key=>{const [server,tag]=JSON.parse(key);return{server,tag}})}}
}
