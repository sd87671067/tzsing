'use strict';
const fs=require('fs'),assert=require('node:assert/strict'),{chromium,webkit}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
(async()=>{for(const [engine,type] of Object.entries({chromium,webkit})){
 const browser=await type.launch({headless:true}),ctx=await browser.newContext(),page=await ctx.newPage();
 try{
 await page.route('https://connection.test/**',r=>r.fulfill({contentType:'text/html',body:'<!doctype html><title>Connection lifecycle fixture</title>'}));await page.goto('https://connection.test/fixture/');await page.clock.install();
 await page.evaluate(()=>{
  window.stats={active:0,max:0,created:0,checks:0,frames:0,expired:0,failSession:0,failHandshake:0,status:0,hidden:false,online:true,states:[]};
  Object.defineProperty(document,'hidden',{get:()=>stats.hidden,configurable:true});Object.defineProperty(navigator,'onLine',{get:()=>stats.online,configurable:true});
  window.WebSocket=class{static CONNECTING=0;static OPEN=1;constructor(){this.readyState=0;stats.created++;stats.active++;stats.max=Math.max(stats.max,stats.active);window.latest=this;setTimeout(()=>{if(this.readyState!==0)return;if(stats.failHandshake-->0){this.close();this.onclose?.();return}this.readyState=1;this.onopen?.();this.onmessage?.({data:'[]'})},20)}close(){if(this.readyState<2){this.readyState=3;stats.active--}}drop(){this.close();this.onclose?.()}};
 });
 await page.addScriptTag({content:fs.readFileSync(require('path').join(__dirname,'../web/connection.js'),'utf8')});
 await page.evaluate(()=>{window.life=MonitorConnection({session:async signal=>{stats.checks++;if(stats.failSession-->0){const e=Error('temporary failure');e.status=stats.status;throw e}return{user:{role:'admin'}}},onSession:()=>{},onData:()=>stats.frames++,onState:s=>stats.states.push(s),onExpired:()=>stats.expired++});life.start()});
 await page.clock.runFor(100);assert.equal(await page.evaluate(()=>stats.frames),1);
 // A transient /api/me failure must not terminate the retry chain.
 await page.evaluate(()=>{stats.failSession=2;stats.status=503;latest.drop()});await page.clock.runFor(12000);assert.equal(await page.evaluate(()=>stats.active),1);assert(await page.evaluate(()=>stats.frames>=2));
 // Repeated failed WS handshakes retain bounded exponential backoff.
 const start=await page.evaluate(()=>stats.created);await page.evaluate(()=>{stats.failHandshake=8;latest.drop()});await page.clock.runFor(180000);assert.equal(await page.evaluate(()=>stats.active),1);assert(await page.evaluate(()=>stats.frames>=3));assert((await page.evaluate(()=>stats.created))-start<=10);
 // Repeated starts and network events never leave two effective sockets.
 await page.evaluate(()=>{for(let i=0;i<20;i++)life.start(false)});await page.clock.runFor(100);assert.equal(await page.evaluate(()=>stats.max),1);
 await page.evaluate(()=>{stats.online=false;dispatchEvent(new Event('offline'))});await page.clock.runFor(60000);assert.equal(await page.evaluate(()=>stats.active),0);
 await page.evaluate(()=>{stats.online=true;dispatchEvent(new Event('online'))});await page.clock.runFor(100);assert.equal(await page.evaluate(()=>stats.active),1);
 await page.evaluate(()=>{stats.hidden=true;document.dispatchEvent(new Event('visibilitychange'))});await page.clock.runFor(60000);assert.equal(await page.evaluate(()=>stats.active),0);
 await page.evaluate(()=>{stats.hidden=false;document.dispatchEvent(new Event('visibilitychange'))});await page.clock.runFor(100);assert.equal(await page.evaluate(()=>stats.active),1);
 await page.evaluate(()=>{stats.failSession=1;stats.status=401;latest.drop()});await page.clock.runFor(30000);assert.equal(await page.evaluate(()=>stats.expired),1);const ended=await page.evaluate(()=>stats.checks);await page.clock.runFor(120000);assert.equal(await page.evaluate(()=>stats.checks),ended);assert.equal(await page.evaluate(()=>stats.active),0);
 await page.evaluate(()=>life.start(false));await page.clock.runFor(100);assert.equal(await page.evaluate(()=>stats.active),1);await page.evaluate(()=>life.stop());await page.clock.runFor(60000);assert.equal(await page.evaluate(()=>stats.active),0);
 console.log(JSON.stringify({engine,temporary_me_failure:true,failed_handshake_backoff:true,offline_recovery:true,visibility:true,single_socket:true,expired_stops_retry:true,relogin:true,logout:true,exit_code:0}));
 }finally{await ctx.close();await browser.close()}
}})().catch(e=>{console.error(e);process.exitCode=1});
