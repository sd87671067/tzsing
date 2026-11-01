from pathlib import Path
import sqlite3,json,time,os,subprocess,signal,http.server,socketserver,secrets,threading,hashlib,socket
assert os.environ.get('TZ_SYNTHETIC_STAGE')=='1', 'isolated synthetic stage required'
for port in (33080,33443):
 with socket.socket() as probe:
  probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);probe.bind(('127.0.0.1',port))
r=Path(os.environ['TZ_TEST_STATE']);d=r;d.mkdir(parents=True,exist_ok=True);binary=Path(os.environ['TZ_TEST_BINARY']);p=d/'stage.db';password=(d/'stage-password').read_text() if p.exists() else secrets.token_urlsafe(24)
existed=p.exists()
(d/'stage-password').write_text(password);(d/'stage-password').chmod(0o600)
env={**os.environ,'DB_PATH':str(p),'URL_PREFIX':'/inboundtest','PUBLIC_ORIGIN':'https://127.0.0.1:33443','LISTEN':'127.0.0.1:33080','AGENT_LISTEN':'127.0.0.1:33443','TLS_CERT':os.environ['TZ_TEST_CERT'],'TLS_KEY':os.environ['TZ_TEST_KEY'],'GOMEMLIMIT':'128MiB','GOMAXPROCS':'2','CONTROL_SOCKET':str(d/'fixture.sock'),'CONTROL_SERVER':'fixture'}
if not existed:subprocess.run([str(binary),'init-admin'],input=password,text=True,env=env,check=True,stdout=subprocess.DEVNULL)
s=sqlite3.connect(p,timeout=10);s.execute("INSERT OR IGNORE INTO servers(id,name,token) VALUES('fixture','隔离服务器','synthetic')");s.commit()
s.execute("INSERT OR IGNORE INTO control_permissions VALUES(1,'copy')");s.execute("INSERT OR IGNORE INTO control_permissions VALUES(1,'view')");s.commit()
counts={};(d/'helper-counts.json').write_text('{}')
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_POST(self):
  v=json.loads(self.rfile.read(int(self.headers['Content-Length'])));tag=v['tag'];source=v.get('source');key=self.path[1:]+':'+tag+(':'+source if source else '')
  counts[key]=counts.get(key,0)+1;(d/'helper-counts.json').write_text(json.dumps(counts))
  if self.path=='/intel':
   answer={'source':source,'at':int(time.time()),'cached':False,'ip':'8.8.8.8','data':{'city':'Fixture City','country':'United States','country_code':'US','asn':'AS15169','org':'Fixture Network','geo_source':'IPPure 官方 API' if source=='ippure' else 'IPinfo'}}
   if tag=='b' and source=='ippure':answer={'source':source,'message':'IPPure 暂不可用，IPinfo 仍可使用'}
  elif self.path=='/share':answer={'link':'vless://synthetic-fixture@example.org:443'}
  elif self.path=='/status' and v.get('auth_id'):answer={'apply':False,'restore':False,'share':True,'profiles':[{'id':'identity-profile','label':'当前身份'}],'preview':False,'reason':'隔离身份分享'}
  elif self.path=='/status':answer={'actions':{},'apply':False,'restore':False,'share':False,'profiles':[],'preview':True,'reason':'隔离只读测试'}
  else:
   time.sleep(.5);check=lambda status,detail:{'status':status,'detail':detail}
   answer={'at':int(time.time()),'protocol':'vless','outbound':'shared-direct','config':check('ok','只读校验通过'),'listen':check('ok','本机接受 TCP 连接'),'handshake':check('ok','测试凭据握手成功'),'public':check('unverified','本机检测不代表公网可达'),'path':check('ok','已核实 shared-direct 路径'),'change':check('ok','同地址族缓存一致'),'network':{'ipv4':dict(check('ok','2/2 次 HTTPS 成功'),ip='8.8.8.8',milliseconds=12),'ipv6':dict(check('ok','2/2 次 HTTPS 成功'),ip='2001:4860:4860::8888',milliseconds=15),'attempts':4,'successes':4}}
  if os.environ.get('TZ_EGRESS_FIXTURE')=='1' and v.get('outbound')=='relay':
   if self.path=='/intel':answer['ip']='1.1.1.1'
   elif answer.get('network'):answer['outbound']='relay';answer['network']['ipv4']['ip']='1.1.1.1'
  data=json.dumps(answer).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
class Unix(socketserver.UnixStreamServer):allow_reuse_address=True
helper=Unix(str(d/'fixture.sock'),Handler);threading.Thread(target=helper.serve_forever,daemon=True).start()
log=open(d/'stage-server.log','w');child=subprocess.Popen([str(binary)],env=env,stdout=log,stderr=log)
def stop(*_):
 child.terminate();child.wait(timeout=10);helper.shutdown();helper.server_close();s.close();log.close();raise SystemExit()
signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
print('Synthetic stage ready',flush=True)
while child.poll() is None:
 now=int(time.time());tags=[]
 for index,(tag,proto,egress) in enumerate([('a','vless','shared-direct'),('b','vless','shared-direct'),('c','trojan',''),('d','socks','')]):
  t={'name':'inbound:'+tag,'inbound_tag':tag,'identity':'inbound','type':proto,'egress':egress,'egress_type':'direct' if egress else '', 'route_version':'synthetic','state':'online','up':1234*(index+1),'down':4321*(index+1),'upload':100,'download':200,'active':0}
  if egress:t['ip']={'verified':True,'ipv4':'8.8.8.8','ipv6':'2001:4860:4860::8888','updated':now,'source':'synthetic path','path':egress+'@synthetic','geo_source':'IPinfo'}
  tags.append(t)
  s.execute('INSERT OR IGNORE INTO nodes VALUES(?,?,?,?,0)',('id-'+tag,'fixture','inbound:'+tag,'入站 '+tag))
 tags.append({'name':'obsolete-outbound','type':'direct','up':999999,'down':999999,'upload':999999,'download':999999})
 if (d/'extra.flag').exists() and (d/'extra.flag').read_text()=='1':
  tags.append({'name':'inbound:extra','inbound_tag':'extra','identity':'inbound','type':'http','state':'online','route_version':'synthetic'})
  s.execute("INSERT OR IGNORE INTO nodes VALUES('id-extra','fixture','inbound:extra','新增入站',0)")
 if os.environ.get('TZ_AUTH_FIXTURE')=='1':
  for n in ('alice','bob'):
   auth=hashlib.sha256(n.encode()).hexdigest();key='identity:'+hashlib.sha256(('a'+'\x00'+auth).encode()).hexdigest()
   tags.append({'name':key,'inbound_tag':'a','identity':'inbound','auth_id':auth,'accounting':'unavailable','type':'vless','state':'online','route_reason':'身份路径未知','route_version':'synthetic'})
   s.execute('INSERT OR IGNORE INTO nodes VALUES(?,?,?,?,0)',('auth-'+n,'fixture',key,'认证身份 '+n))
  tags[0]['accounting']='unattributed'
 if os.environ.get('TZ_EGRESS_FIXTURE')=='1':
  tags=[]
  for index,n in enumerate(('alice','bob','multi','unknown')):
   auth=hashlib.sha256(n.encode()).hexdigest();key='identity:'+hashlib.sha256(('shared'+'\x00'+auth).encode()).hexdigest()
   paths=[] if n=='unknown' else [{'tag':'shared-direct','type':'direct','ip':{'verified':True,'ipv4':'8.8.8.8','ipv6':'2001:4860:4860::8888','country_code':'US','city':'Fixture City','asn':'AS15169','org':'Fixture Network','updated':now,'path':'shared-direct@synthetic','source':'fixture SOCKS path'}}]
   if n=='multi':paths.append({'tag':'relay','type':'socks','ip':{'verified':True,'ipv4':'1.1.1.1','country_code':'US','updated':now,'path':'relay@synthetic','source':'fixture SOCKS path'}})
   tag={'name':key,'auth_id':auth,'inbound_tag':'shared','identity':'inbound','type':'vless','accounting':'rule_user_observed','route_version':'synthetic','state':'online','active':2 if n in ('alice','multi') else 0,'up':1500 if n in ('alice','multi') else 0,'down':16000 if n in ('alice','multi') else 0,'upload':10000*(index+1),'download':20000*(index+1),'egresses':paths}
   if len(paths)==1:tag.update(egress=paths[0]['tag'],egress_type=paths[0]['type'],ip=paths[0]['ip'])
   tags.append(tag);s.execute('INSERT OR IGNORE INTO nodes VALUES(?,?,?,?,0)',('egress-'+n,'fixture',key,'fixture-'+n))
 report={'server_id':'fixture','at':now,'interval':2,'discovery':{'inbounds':sum(t.get('identity')=='inbound' and not t.get('auth_id') for t in tags),'auth_identities':2 if os.environ.get('TZ_AUTH_FIXTURE')=='1' else 0,'unsupported_auth':0,'discovered':len(tags)-1,'reported':len(tags)},'host':{'cpu':23.5,'memory_used':1048576,'memory_total':4194304,'disk_used':1048576,'disk_total':8388608,'net_up':1234,'net_down':4321,'uptime':86461,'sing_box':True,'load':'0.25 0.31 0.40'},'tags':tags}
 s.execute('UPDATE servers SET report=?,seen=? WHERE id=?',(json.dumps(report),now-100 if (d/'offline.flag').exists() and (d/'offline.flag').read_text()=='1' else now,'fixture'));s.commit();time.sleep(1)
raise SystemExit(child.returncode)
