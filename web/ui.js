'use strict';
// Small, application-owned DOM primitives. Native dialog owns focus/inertness.
// Material and lifecycle patterns were reviewed against go-emby; no private
// business implementation or resources are included here.
const UI=(()=>{
 const make=(tag,cls,value)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(value!==undefined)e.textContent=value;return e};
 const paths={chevron:'m9 5 7 7-7 7',check:'M12 3v3M12 18v3M3 12h3M18 12h3M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0',sun:'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M5 19l1.5-1.5M17.5 6.5 19 5',moon:'M20 15A9 9 0 0 1 9 4a9 9 0 1 0 11 11',more:'M5 12h.01M12 12h.01M19 12h.01',close:'m6 6 12 12M18 6 6 18',copy:'M8 8h13v13H8zM16 8V3H3v13h5',import:'M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4',change:'M4 7h16m-4-4 4 4-4 4M20 17H4m4-4-4 4 4 4',restore:'M4 10a8 8 0 1 1 1 8M4 4v6h6'};
 function icon(name){const s=document.createElementNS('http://www.w3.org/2000/svg','svg');s.setAttribute('viewBox','0 0 24 24');s.setAttribute('width','24');s.setAttribute('height','24');s.setAttribute('class','icon');s.setAttribute('aria-hidden','true');const p=document.createElementNS(s.namespaceURI,'path');p.setAttribute('d',paths[name]||paths.close);s.append(p);return s}
 function button(label,name,action){const b=make('button','icon-button');b.type='button';b.setAttribute('aria-label',label);b.title=label;b.append(icon(name));if(action)b.onclick=action;return b}
 const open=[],queue=[];let toast=null,toastTimer=null;
 const stack=make('div','toast-stack');stack.setAttribute('aria-live','polite');stack.setAttribute('popover','manual');
 function mountToast(){const host=open.at(-1)?.d||document.body;if(stack.parentNode!==host){if(stack.matches(':popover-open'))stack.hidePopover();host.append(stack)}if(toast&&stack.showPopover&&!stack.matches(':popover-open'))stack.showPopover()}
 function nextToast(){clearTimeout(toastTimer);stack.replaceChildren();toast=null;if(!queue.length){if(stack.matches(':popover-open'))stack.hidePopover();return}const v=queue.shift();toast=make('div','toast-item');toast.dataset.type=v.type;toast.setAttribute('role',v.type==='error'?'alert':'status');toast.append(make('span','',v.message),button('关闭提示','close',nextToast));stack.append(toast);mountToast();toastTimer=setTimeout(nextToast,5000)}
 function notify(message,type=/失败|错误|无效|无法|禁用|不支持/.test(message)?'error':'success'){message=String(message);if(toast?.querySelector('span')?.textContent===message||queue.some(v=>v.message===message))return;queue.push({message,type});if(queue.length>20)queue.shift();if(!toast)nextToast()}
 function bind(d,{trigger=null,dirty=()=>false,onClose=()=>{},dispose=false,canClose=()=>true}={}){
  let closing=false,frame=null,timer=null;
  const entry={d,force:()=>close(true)};
  async function close(force=false){if(closing||!d.open||(!force&&!canClose()))return;if(!force&&dirty()&&!await confirm('放弃未保存内容？','输入尚未保存，关闭后将丢弃。'))return;closing=true;d.dataset.closing='true';const finish=()=>{if(!d.open)return;d.close()};if(matchMedia('(prefers-reduced-motion:reduce)').matches)finish();else timer=setTimeout(finish,190)}
  function finish(){if(d.open)return;clearTimeout(timer);cancelAnimationFrame(frame);delete d.dataset.closing;closing=false;const i=open.indexOf(entry);if(i>=0)open.splice(i,1);document.body.classList.toggle('overlay-open',open.length>0);onClose();mountToast();if(trigger?.isConnected)trigger.focus({preventScroll:true});if(dispose)d.remove()}
  d.addEventListener('cancel',e=>{e.preventDefault();close()});
  d.addEventListener('click',e=>{if(e.target!==d)return;const b=d.getBoundingClientRect();if(e.clientX<b.left||e.clientX>b.right||e.clientY<b.top||e.clientY>b.bottom)close()});
  d.addEventListener('close',finish);
  d.addEventListener('keydown',e=>{
   if(e.key!=='Tab'||open.at(-1)?.d!==d)return;
   const items=[...d.querySelectorAll('button,input:not([type=hidden]),select,textarea,a[href],[tabindex]:not([tabindex="-1"])')].filter(el=>!el.matches(':disabled')&&el.getClientRects().length&&getComputedStyle(el).visibility!=='hidden');
   if(!items.length){e.preventDefault();d.focus();return}
   const first=items[0],last=items.at(-1),active=document.activeElement;
   if(!d.contains(active)||(e.shiftKey&&active===first)||(!e.shiftKey&&active===last)){e.preventDefault();(e.shiftKey?last:first).focus()}
  });
  return {d,close,force:()=>close(true),show(t=trigger){trigger=t;clearTimeout(timer);closing=false;delete d.dataset.closing;if(!open.includes(entry))open.push(entry);document.body.classList.add('overlay-open');if(!d.open)d.showModal();frame=requestAnimationFrame(()=>mountToast());return d}};
 }
 function modal(title,content,{trigger,dirty,onClose,variant='modal',canClose}={}){const d=make('dialog',variant),heading=make('div','title-row'),h=make('h2','',title),x=button('关闭','close');h.id='dialog-title-'+(++modal.id);d.setAttribute('aria-labelledby',h.id);heading.append(h,x);d.append(heading,content);document.body.append(d);const life=bind(d,{trigger,dirty,onClose,canClose,dispose:true});x.onclick=()=>life.close();life.show();return life}modal.id=0;
 function confirm(title,description,label='确认',{onConfirm}={}){return new Promise(resolve=>{
  let result=false,busy=false;const body=make('div','confirm-content'),actions=make('div','row-actions'),no=make('button','','取消'),yes=make('button','danger',label),error=make('p','notice');
  no.type=yes.type='button';error.setAttribute('role','alert');error.hidden=true;
  const descriptionNode=make('p','confirm-description',description);body.append(descriptionNode,error,actions);actions.append(no,yes);
  const m=modal(title,body,{canClose:()=>!busy,onClose:()=>resolve(result)});
  no.onclick=()=>m.close();yes.onclick=async()=>{if(busy)return;busy=true;no.disabled=yes.disabled=true;yes.setAttribute('aria-busy','true');error.hidden=true;
   try{if(onConfirm)await onConfirm();result=true;m.force()}catch(e){error.textContent=e.message;error.hidden=false;notify(e.message,'error')}finally{if(!result){busy=false;no.disabled=yes.disabled=false;yes.removeAttribute('aria-busy')}}
  };
 })}
 function password(title){return new Promise(resolve=>{let value=null;const f=make('form'),l=make('label','','新密码（任意非空 Unicode，空格保留）'),p=make('input'),b=make('button','primary','确认');p.type='password';p.required=true;p.autocomplete='new-password';l.append(p);f.append(l,b);const m=modal(title,f,{dirty:()=>p.value!==''&&value===null,onClose:()=>{resolve(value);p.value=''}});f.onsubmit=e=>{e.preventDefault();value=p.value;m.close(true)};p.focus()})}
 async function copy(value,{sensitive=false}={}){try{await navigator.clipboard.writeText(value);notify('复制成功')}catch{if(sensitive){notify('剪贴板不可用，请在安全浏览器中重试','error');return false}const body=make('div'),input=make('input');input.readOnly=true;input.value=value;body.append(make('p','','剪贴板不可用，请长按或选择后手动复制。'),input);modal('手动复制',body);input.focus();input.select();return false}return true}
 async function copyRequested(supplier){
  if(!navigator.clipboard){notify('剪贴板不可用，请在安全浏览器中重试','error');return false}
  try{if(window.ClipboardItem&&navigator.clipboard.write){const pending=Promise.resolve().then(supplier).then(value=>new Blob([value],{type:'text/plain'}));pending.catch(()=>{});await navigator.clipboard.write([new ClipboardItem({'text/plain':pending})])}else{await navigator.clipboard.writeText(await supplier())}notify('复制成功');return true}catch{notify('复制失败，请检查权限后重试','error');return false}
 }
 function invalidate(){for(const e of [...open].reverse())e.force()}
 return {make,icon,button,bind,modal,confirm,password,copy,copyRequested,notify,invalidate};
})();

// Track the submitted control, preserving its label, width and focus. Existing
// handlers own the request guard; spinner follows that guard through dialogs.
(()=>{
 const tracked=new WeakMap();
 function track(b){if(!b||b.disabled||tracked.has(b))return;const watch=new MutationObserver(()=>{if(b.disabled)b.setAttribute('aria-busy','true');else{b.removeAttribute('aria-busy');watch.disconnect();tracked.delete(b)}});tracked.set(b,watch);watch.observe(b,{attributes:true,attributeFilter:['disabled']});}
 document.addEventListener('click',e=>track(e.target.closest('button')),true);
 document.addEventListener('submit',e=>track(e.submitter||e.target.querySelector('button:not([type=button])')),true);
})();
