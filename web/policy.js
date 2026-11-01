'use strict';
// Shared by create and edit; one form owns both policy values and validation.
const PolicyFields=(()=>{
 const zone=Intl.DateTimeFormat().resolvedOptions().timeZone||'UTC';
 const localValue=at=>at?new Date(at*1000-new Date(at*1000).getTimezoneOffset()*60000).toISOString().slice(0,16):'';
 function create(host,value={},ready=true){
  const fields=UI.make('fieldset','uuid-group policy-fields');fields.append(UI.make('legend','','额度与有效期'));
  function input(name,label,type,val){const row=UI.make('label','',label),x=UI.make('input');x.name=name;x.type=type;x.value=val;x.disabled=!ready;row.append(x);fields.append(row);return x}
  const quota=input('quota_gib','月流量额度（GiB，0 为不限）','number',String((value.quota||0)/1073741824));quota.min='0';quota.max='1073741824';quota.step='any';quota.required=true;
  const expiry=input('expires_local','到期时间（'+zone+'）','datetime-local',localValue(value.expires_at));
  const neverRow=UI.make('label','switch-row','永不过期'),never=UI.make('input');never.type='checkbox';never.name='never_expires';never.setAttribute('role','switch');never.checked=!value.expires_at;never.disabled=!ready;neverRow.append(never);fields.append(neverRow);const toggle=()=>{expiry.disabled=!ready||never.checked;expiry.required=!never.checked};never.onchange=toggle;toggle();
  const day=input('billing_day','每月重置日（1–31）','number',String(value.billing_day||1));day.min='1';day.max='31';day.required=true;
  const tz=input('billing_timezone','账期时区（IANA）','text',value.timezone||zone);tz.required=true;
  if(!ready)fields.append(UI.make('p','notice','可靠执行器尚未运行；不能保存或应用限制。'));
  const details=UI.make('details'),summary=UI.make('summary','','计量说明');details.append(summary,UI.make('p','muted','可靠额度从策略启用时开始，历史已观测流量不补扣。执行器尚在隔离验证；实际结算与预留必须分开，崩溃未决项不能作为已用流量。'));fields.append(details);host.append(fields);
  return {read(){
   const amount=Number(quota.value)*1073741824,expires=never.checked?0:new Date(expiry.value).getTime()/1000;
   if(!Number.isSafeInteger(amount)||amount<0||!Number.isFinite(expires)||expires<0)throw Error('请输入有效额度与日期');
   if(!never.checked&&localValue(expires)!==expiry.value)throw Error('该本地时间不存在，请选择有效时间');
   return {quota:amount,expires_at:expires,billing_day:Number(day.value),timezone:tz.value.trim()};
  },zone};
 }
 return {create};
})();
