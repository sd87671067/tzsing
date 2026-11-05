'use strict';
// Store only the original confirmation ID, never a proxy link or credentials.
const ConfigTransactions=(()=>{
 let timer=null,checking=false,attempt=0;
 const key=()=>prefix+':config-operation:'+me?.id;
 const pending=()=>{try{return JSON.parse(localStorage.getItem(key())||'null')}catch{return null}};
 const bounded=(path,method='GET',body)=>api(path,method,body,{signal:AbortSignal.timeout(8000)});
 function pause(){clearTimeout(timer);timer=null}
 async function refresh(){try{update(await bounded('snapshot'));if(me?.role==='admin'&&currentPage==='nodes')await loadNodeAdmin()}catch{/* The committed receipt remains authoritative even if refresh disconnects. */}}
 async function query(op){
  try{return await bounded('control/transaction?id='+encodeURIComponent(op.body.nonce))}catch(e){
   if(e.status!==404)throw e;
   // Web may not have received the first request; replay its exact idempotency ID.
   return bounded(op.path,'POST',op.body);
  }
 }
 async function check(){
  if(checking||!me)return null;const op=pending(),storageKey=key();if(!op)return null;checking=true;let retry=true;pause();
  try{
   const result=await query(op);if(storageKey!==key()||!me)return null;
   if(result.state==='succeeded'||result.state==='failed'){
    localStorage.removeItem(storageKey);attempt=0;
    if(result.state==='failed'){UI.notify(result.error||'配置未生效','error');return null}
    UI.notify(result.warning||op.success);await refresh()
    return result;
   }
   if(result.state==='uncertain'){if(attempt===0)UI.notify('正在确认：需管理员检查回滚状态，原事务已保留，请勿重复提交','info');return null}
  }catch(e){
   if(storageKey!==key()||!me)return null;
   if(e.status===401||e.status===403){retry=false;pause();return null}
   if(e.status===409||e.status===422){localStorage.removeItem(storageKey);UI.notify(e.message,'error');return null}
   // A transport timeout, Load failed or 5xx cannot establish a failed mutation.
  }finally{
   checking=false;
   if(retry&&storageKey===key()&&me&&pending()&&!document.hidden)timer=setTimeout(()=>check(),Math.min(30000,2500*Math.pow(1.4,attempt++)));
  }
  return null;
 }
 function resume(){if(me&&pending()){attempt=0;check()}}
 async function submit(path,body,success){
  if(pending()){UI.notify('原配置事务正在确认，请勿重复提交','info');resume();return null}
  const op={path,body,success},storageKey=key();localStorage.setItem(storageKey,JSON.stringify(op));
  let result;
  try{result=await bounded(path,'POST',body)}catch(e){
   if(storageKey!==key()||!me)return null;
   if(e.status&&e.status<500&&e.status!==408&&e.status!==429){localStorage.removeItem(storageKey);throw e}
  }
  if(storageKey!==key()||!me)return null;
  if(result?.state==='succeeded'){localStorage.removeItem(storageKey);return result}
  if(result?.state==='failed'){localStorage.removeItem(storageKey);throw Error(result.error||'配置未生效')}
  UI.notify('正在确认配置应用结果，恢复连接后自动查询，请勿重复提交','info');resume();return null;
 }
 window.addEventListener('online',resume);
 document.addEventListener('visibilitychange',()=>document.hidden?pause():resume());
 return {submit,resume,pause,pending};
})();
