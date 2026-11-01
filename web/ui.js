'use strict';
// Small, application-owned DOM primitives. Native dialog owns focus/inertness.
// Material and lifecycle patterns were reviewed against go-emby; no private
// business implementation or resources are included here.
const UI=(()=>{
 const make=(tag,cls,value)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(value!==undefined)e.textContent=value;return e};
 const paths={more:'M5 12h.01M12 12h.01M19 12h.01',close:'m6 6 12 12M18 6 6 18',copy:'M8 8h13v13H8zM16 8V3H3v13h5',import:'M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4',change:'M4 7h16m-4-4 4 4-4 4M20 17H4m4-4-4 4 4 4',restore:'M4 10a8 8 0 1 1 1 8M4 4v6h6'};
 function icon(name){const s=document.createElementNS('http://www.w3.org/2000/svg','svg');s.setAttribute('viewBox','0 0 24 24');s.setAttribute('class','icon');s.setAttribute('aria-hidden','true');const p=document.createElementNS(s.namespaceURI,'path');p.setAttribute('d',paths[name]||paths.close);s.append(p);return s}
 function button(label,name,action){const b=make('button','icon-button');b.type='button';b.setAttribute('aria-label',label);b.title=label;b.append(icon(name));if(action)b.onclick=action;return b}
 const open=[],queue=[];let toast=null,toastTimer=null;
 const stack=make('div','toast-stack');stack.setAttribute('aria-live','polite');stack.setAttribute('popover','manual');
 function mountToast(){const host=open.at(-1)?.d||document.body;if(stack.parentNode!==host){if(stack.matches(':popover-open'))stack.hidePopover();host.append(stack)}if(toast&&stack.showPopover&&!stack.matches(':popover-open'))stack.showPopover()}
 function nextToast(){clearTimeout(toastTimer);stack.replaceChildren();toast=null;if(!queue.length){if(stack.matches(':popover-open'))stack.hidePopover();return}const v=queue.shift();toast=make('div','toast-item');toast.dataset.type=v.type;toast.setAttribute('role',v.type==='error'?'alert':'status');toast.append(make('span','',v.message),button('关闭提示','close',nextToast));stack.append(toast);mountToast();toastTimer=setTimeout(nextToast,5000)}
 function notify(message,type=/失败|错误|无效|无法|禁用|不支持/.test(message)?'error':'success'){queue.push({message:String(message),type});if(queue.length>20)queue.shift();if(!toast)nextToast()}
 function bind(d,{trigger=null,dirty=()=>false,onClose=()=>{},dispose=false}={}){
  let closing=false,frame=null,timer=null;
  const entry={d,force:()=>close(true)};
  async function close(force=false){if(closing||!d.open)return;if(!force&&dirty()&&!await confirm('放弃未保存内容？','输入尚未保存，关闭后将丢弃。'))return;closing=true;d.dataset.closing='true';const finish=()=>{if(!d.open)return;d.close()};if(matchMedia('(prefers-reduced-motion:reduce)').matches)finish();else timer=setTimeout(finish,190)}
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
 function modal(title,content,{trigger,dirty,onClose,variant='modal'}={}){const d=make('dialog',variant),heading=make('div','title-row'),h=make('h2','',title),x=button('关闭','close');h.id='dialog-title-'+(++modal.id);d.setAttribute('aria-labelledby',h.id);heading.append(h,x);d.append(heading,content);document.body.append(d);const life=bind(d,{trigger,dirty,onClose,dispose:true});x.onclick=()=>life.close();life.show();return life}modal.id=0;
 function confirm(title,description){return new Promise(resolve=>{let result=false;const body=make('div','confirm-content'),actions=make('div','row-actions'),no=make('button','','取消'),yes=make('button','danger','确认');body.append(make('p','',description),actions);actions.append(no,yes);const m=modal(title,body,{onClose:()=>resolve(result)});no.onclick=()=>m.close(true);yes.onclick=()=>{result=true;m.close(true)}})}
 function password(title){return new Promise(resolve=>{let value=null;const f=make('form'),l=make('label','','新密码（任意非空 Unicode，空格保留）'),p=make('input'),b=make('button','primary','确认');p.type='password';p.required=true;p.autocomplete='new-password';l.append(p);f.append(l,b);const m=modal(title,f,{dirty:()=>p.value!==''&&value===null,onClose:()=>{resolve(value);p.value=''}});f.onsubmit=e=>{e.preventDefault();value=p.value;m.close(true)};p.focus()})}
 async function copy(value){try{await navigator.clipboard.writeText(value);notify('已复制 IP 地址')}catch{const body=make('div'),input=make('input');input.readOnly=true;input.value=value;body.append(make('p','','剪贴板不可用，请长按或选择后手动复制。'),input);modal('手动复制',body);input.focus();input.select()}}
 function invalidate(){for(const e of [...open].reverse())e.force()}
 return {make,icon,button,bind,modal,confirm,password,copy,notify,invalidate};
})();
