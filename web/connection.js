'use strict';
// One lifecycle owns session checks, the socket and the reconnect timer.
const MonitorConnection=({session,onSession,onData,onState,onExpired})=>{
 let active=false,generation=0,ws=null,timer=null,pending=null,attempt=0,lastData=0;
 const state=s=>onState(s),available=()=>!document.hidden&&navigator.onLine!==false;
 function close(){if(ws){const old=ws;ws=null;old.onopen=old.onmessage=old.onclose=old.onerror=null;old.close()}}
 function cancel(){generation++;clearTimeout(timer);timer=null;pending?.abort();pending=null;close()}
 function stop(){active=false;cancel();attempt=0}
 function schedule(reason){
  if(!active||timer!==null)return;
  state(reason);if(!available())return;
  const ceiling=Math.min(30000,1000*2**Math.min(attempt++,5));
  timer=setTimeout(()=>{timer=null;connect()},ceiling*(.5+Math.random()*.5));
 }
 async function connect(verify=true){
  if(!active||!available()||ws||pending)return;
  const revision=generation;
  if(verify){
   const request=new AbortController();pending=request;
   const timeout=setTimeout(()=>request.abort(),10000);
   try{const d=await session(request.signal);if(revision!==generation||!active)return;onSession(d)}
   catch(e){if(revision!==generation||!active)return;if(e.status===401){stop();onExpired();return}schedule(e.status===403?'访问被拒绝，请检查权限或反向代理':e.status>=500?'反向代理或服务暂不可用 · 自动重连中':'网络连接失败 · 自动重连中');return}
   finally{clearTimeout(timeout);if(pending===request)pending=null}
  }
  if(revision!==generation||!active||!available())return;
  try{
   const current=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+location.pathname.replace(/\/$/,'')+'/ws');ws=current;lastData=Date.now();
   current.onopen=()=>{if(ws===current)state('连接成功 · 等待监控数据')};
   current.onmessage=e=>{if(ws!==current||revision!==generation)return;try{const data=JSON.parse(e.data);if(!Array.isArray(data))throw Error();lastData=Date.now();attempt=0;state('实时连接');onData(data)}catch{state('监控数据格式错误')}};
   const lost=()=>{if(ws!==current)return;close();schedule('实时连接中断 · 检查网络或代理并自动重连')};
   current.onclose=current.onerror=lost;
  }catch{schedule('WebSocket 握手失败 · 自动重连中')}
 }
 function start(verify=true){cancel();active=true;attempt=0;if(available())connect(verify);else state(document.hidden?'页面已隐藏 · 暂停实时连接':'网络离线 · 等待恢复')}
 function resume(){if(!active)return;cancel();if(available())connect();else state(document.hidden?'页面已隐藏 · 暂停实时连接':'网络离线 · 等待恢复')}
 document.addEventListener('visibilitychange',resume);
 window.addEventListener('online',resume);window.addEventListener('offline',resume);
 // Browsers answer server ping frames. Detect silent half-open/failed handshakes too.
 setInterval(()=>{if(active&&ws&&Date.now()-lastData>(ws.readyState===WebSocket.CONNECTING?15000:45000)){close();schedule('监控心跳超时 · 自动重连中')}},5000);
 return {start,stop};
};
