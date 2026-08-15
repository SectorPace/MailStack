#!/usr/bin/env python3
import json, os, re, subprocess, sys, pwd, grp, pathlib, datetime, ssl, socket, urllib.request, urllib.parse, urllib.error, ipaddress, hashlib, secrets, getpass
ETC=pathlib.Path('/etc/mailstack'); DOM=pathlib.Path('/etc/postfix/mailstack_domains'); ALS=pathlib.Path('/etc/postfix/mailstack_aliases')
DOMAIN_RE=re.compile(r'^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')
USER_RE=re.compile(r'^[a-z_][a-z0-9_-]{0,30}$'); ADDRESS_RE=re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}@(.+)$'); QUEUE_RE=re.compile(r'^[A-F0-9]{5,20}[*!]?$')

ADMIN_CONFIG=ETC/'admin.json'
AI_CONFIG=ETC/'ai-provider.json'

ADMIN_RE=re.compile(r'^[A-Za-z][A-Za-z0-9_.-]{2,31}$')
def password_record(username,password):
 if not ADMIN_RE.fullmatch(username): raise ValueError('administrator name must be 3-32 safe characters')
 if len(password)<12 or len(password)>256: raise ValueError('password must contain 12-256 characters')
 salt=secrets.token_bytes(16); iterations=310000
 digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,iterations,32)
 return {'username':username,'algorithm':'pbkdf2-sha256','iterations':iterations,'salt':salt.hex(),'hash':digest.hex(),'updatedAt':datetime.datetime.now().isoformat()}
def admin_public():
 try: c=json.loads(ADMIN_CONFIG.read_text()); return {'username':c.get('username','admin'),'passwordConfigured':bool(c.get('hash'))}
 except Exception: return {'username':'admin','passwordConfigured':False}
def admin_set(data):
 username=str(data.get('username','')).strip(); password=str(data.get('password',''))
 if not password:
  try:
   old=json.loads(ADMIN_CONFIG.read_text()); old['username']=username
   if not ADMIN_RE.fullmatch(username): raise ValueError('invalid administrator name')
   atomic(ADMIN_CONFIG,json.dumps(old,indent=2)+'\n',0o640); return admin_public()
  except FileNotFoundError: raise ValueError('password is required for initial setup')
 record=password_record(username,password); atomic(ADMIN_CONFIG,json.dumps(record,indent=2)+'\n',0o640)
 try:
  gid=grp.getgrnam('mailstack-admin').gr_gid; os.chown(ADMIN_CONFIG,0,gid)
 except Exception: pass
 return admin_public()

AI_PRESETS={
 'gemini':{'baseUrl':'https://generativelanguage.googleapis.com/v1beta','model':'gemini-2.5-flash','protocol':'gemini'},
 'groq':{'baseUrl':'https://api.groq.com/openai/v1','model':'llama-3.3-70b-versatile','protocol':'openai'},
 'openrouter':{'baseUrl':'https://openrouter.ai/api/v1','model':'openrouter/free','protocol':'openai'},
 'mistral':{'baseUrl':'https://api.mistral.ai/v1','model':'mistral-small-latest','protocol':'openai'},
 'cerebras':{'baseUrl':'https://api.cerebras.ai/v1','model':'llama-3.3-70b','protocol':'openai'},
 'custom':{'baseUrl':'','model':'','protocol':'openai'}
}
def ai_public_config():
 try: c=json.loads(AI_CONFIG.read_text())
 except Exception: c={'provider':'offline','protocol':'offline','baseUrl':'','model':'local-rules','apiKey':''}
 return {k:v for k,v in c.items() if k!='apiKey'}|{'credentialConfigured':bool(c.get('apiKey')),'presets':AI_PRESETS}
def validate_public_https(url):
 u=urllib.parse.urlparse(url)
 if u.scheme!='https' or not u.hostname or u.username or u.password: raise ValueError('only public HTTPS API endpoints are allowed')
 for info in socket.getaddrinfo(u.hostname,u.port or 443,type=socket.SOCK_STREAM):
  ip=ipaddress.ip_address(info[4][0])
  if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast: raise ValueError('private or reserved API endpoint is not allowed')
 return url.rstrip('/')
def ai_save(data):
 provider=str(data.get('provider','custom')); preset=AI_PRESETS.get(provider,AI_PRESETS['custom']); current={}
 try: current=json.loads(AI_CONFIG.read_text())
 except Exception: pass
 protocol=str(data.get('protocol') or preset.get('protocol') or 'openai')
 if protocol not in ('openai','gemini','offline'): raise ValueError('unsupported AI protocol')
 base=str(data.get('baseUrl') or preset.get('baseUrl') or '')
 model=str(data.get('model') or preset.get('model') or '')
 if protocol!='offline': validate_public_https(base)
 if not re.fullmatch(r'[A-Za-z0-9._:/-]{1,160}',model): raise ValueError('invalid model id')
 key=str(data.get('apiKey') or current.get('apiKey') or '')
 if protocol!='offline' and not key: raise ValueError('API key is required')
 cfg={'provider':provider,'protocol':protocol,'baseUrl':base,'model':model,'apiKey':key,'updatedAt':datetime.datetime.now().isoformat()}
 atomic(AI_CONFIG,json.dumps(cfg,ensure_ascii=False,indent=2)+'\n',0o600); return ai_public_config()
def ai_request(messages,max_tokens=1200,temperature=.2):
 try: cfg=json.loads(AI_CONFIG.read_text())
 except Exception: cfg={'protocol':'offline'}
 if cfg.get('protocol')=='offline':
  prompt=messages[-1].get('content','')
  return '离线规则引擎：请核对 MX、SPF、DKIM、DMARC、PTR、TLS 与邮件端口配置。当前问题：'+prompt[:800]
 base=validate_public_https(cfg['baseUrl']); model=cfg['model']; key=cfg['apiKey']
 if cfg['protocol']=='gemini':
  url=f"{base}/models/{urllib.parse.quote(model,safe='.-')}:generateContent"
  body={'contents':[{'role':'model' if m.get('role')=='assistant' else 'user','parts':[{'text':str(m.get('content',''))[:12000]}]} for m in messages[-12:]],'generationConfig':{'temperature':temperature,'maxOutputTokens':max_tokens}}
  headers={'content-type':'application/json','x-goog-api-key':key}
 else:
  url=base+'/chat/completions'; body={'model':model,'messages':[{'role':m.get('role','user'),'content':str(m.get('content',''))[:12000]} for m in messages[-12:]],'temperature':temperature,'max_tokens':max_tokens}; headers={'content-type':'application/json','authorization':'Bearer '+key}
 req=urllib.request.Request(url,data=json.dumps(body).encode(),headers=headers,method='POST')
 try:
  with urllib.request.urlopen(req,timeout=35,context=ssl.create_default_context()) as r: result=json.loads(r.read(2_000_000))
 except urllib.error.HTTPError as e: raise RuntimeError(f'AI provider HTTP {e.code}: '+e.read(1000).decode(errors='replace'))
 if cfg['protocol']=='gemini': return result['candidates'][0]['content']['parts'][0]['text']
 return result['choices'][0]['message']['content']

SERVICES={'postfix':'postfix','dovecot':'dovecot','opendkim':'opendkim','fail2ban':'fail2ban','mailstack-web':'mailstack-web','rspamd':'rspamd','clamav':'clamav-daemon','redis':'redis-server'}
def run(args, input=None, timeout=45, check=True):
 p=subprocess.run(args,input=input,text=True,capture_output=True,timeout=timeout)
 if check and p.returncode: raise RuntimeError((p.stderr or p.stdout or 'command failed')[-2000:])
 return p
def atomic(path,data,mode=0o640):
 path=pathlib.Path(path); path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_suffix(path.suffix+'.tmp'); tmp.write_text(data); os.chmod(tmp,mode); os.replace(tmp,path)
def rows(path):
 try:return [x.split() for x in pathlib.Path(path).read_text().splitlines() if x.strip() and not x.lstrip().startswith('#')]
 except FileNotFoundError:return []
def postmap(path): run(['postmap',str(path)]); run(['postfix','check']); run(['systemctl','reload','postfix'])
def domain_list():
 aliases=rows(ALS); out=[]
 for i,r in enumerate(rows(DOM)):
  d=r[0]; count=sum(1 for a in aliases if a and a[0].endswith('@'+d))
  out.append({'id':d,'name':d,'createdAt':'','mxStatus':'pending','spfStatus':'pending','dkimStatus':'pending','dmarcStatus':'pending','mailboxesCount':count,'mailboxesMax':0,'aliasesCount':count,'status':'pending','statusTextZh':'等待 DNS 检查','statusTextEn':'DNS check pending','dkimSelector':'mail','dkimKeySize':2048})
 return out
def users():
 out=[]
 for u in pwd.getpwall():
  if u.pw_uid<1000 or u.pw_name in ('nobody',): continue
  out.append({'id':u.pw_name,'username':u.pw_name,'displayName':u.pw_gecos.split(',')[0] or u.pw_name,'email':u.pw_name,'domain':'','aliasesCount':0,'quotaUsedGb':0,'quotaMaxGb':0,'lastLoginTime':'','lastLoginIp':'','status':'enabled' if u.pw_shell.endswith('nologin') or u.pw_shell.endswith('false') else 'enabled','role':'user'})
 return out
def aliases():
 return [{'id':r[0],'source':r[0],'domain':r[0].split('@')[-1],'destinations':r[1:],'description':'Postfix virtual alias','enabled':True,'createdAt':''} for r in rows(ALS) if len(r)>1]
def services():
 out=[]
 for ident,unit in SERVICES.items():
  p=run(['systemctl','show',unit,'--property=ActiveState,MainPID,MemoryCurrent,ActiveEnterTimestamp','--no-pager'],check=False)
  vals=dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x); active=vals.get('ActiveState')=='active'
  out.append({'id':ident,'name':unit,'description':'systemd service','type':unit+'.service','pid':int(vals.get('MainPID') or 0),'uptime':vals.get('ActiveEnterTimestamp',''),'memoryMb':round(int(vals.get('MemoryCurrent') or 0)/1048576,1),'cpuPercent':0,'status':'ACTIVE' if active else 'STOPPED','ports':[]})
 return out
def queue():
 p=run(['postqueue','-j'],check=False); out=[]
 for line in p.stdout.splitlines():
  try:
   q=json.loads(line); rec=(q.get('recipients') or [{}])[0]
   out.append({'id':q.get('queue_id'),'queueId':q.get('queue_id'),'sender':q.get('sender',''),'recipient':rec.get('address',''),'sizeBytes':q.get('message_size',0),'arrivalDate':datetime.datetime.fromtimestamp(q.get('arrival_time',0)).isoformat() if q.get('arrival_time') else '','status':'deferred' if rec.get('delay_reason') else 'active','errorReason':rec.get('delay_reason',''),'retryCount':0})
  except Exception: pass
 return out
def certs():
 out=[]; base=ETC/'tls'
 if base.exists():
  for pem in base.glob('*/fullchain.pem'):
   try:
    d=ssl._ssl._test_decode_cert(str(pem)); end=datetime.datetime.strptime(d['notAfter'],'%b %d %H:%M:%S %Y %Z'); start=datetime.datetime.strptime(d['notBefore'],'%b %d %H:%M:%S %Y %Z'); days=(end-datetime.datetime.utcnow()).days
    out.append({'id':pem.parent.name,'domain':pem.parent.name,'issuer':str(d.get('issuer','')),'validFrom':start.date().isoformat(),'validTo':end.date().isoformat(),'daysRemaining':days,'autoRenew':True,'algorithm':'PEM','keySize':0,'status':'expired' if days<0 else 'expiring' if days<30 else 'valid'})
   except Exception: pass
 return out
def status(): return {'domains':domain_list(),'users':users(),'aliases':aliases(),'relayRoutes':[],'relayProviders':[],'logs':logs(100),'services':services(),'queues':queue(),'certs':certs(),'anomalies':security_scan()['events'],'settings':settings()}
def logs(n=200):
 p=run(['journalctl','-u','postfix','-u','dovecot','-u','opendkim','-u','fail2ban','-u','mailstack-web','-n',str(min(int(n),1000)),'--no-pager','-o','short-iso'],check=False)
 out=[]
 for i,line in enumerate(reversed(p.stdout.splitlines())):
  service='postfix/smtpd'
  if 'dovecot' in line: service='dovecot'
  elif 'rspamd' in line: service='rspamd'
  elif 'clamav' in line: service='clamav'
  out.append({'id':str(i),'timestamp':line[:25],'service':service,'level':'ERR' if 'error' in line.lower() or 'fail' in line.lower() else 'INFO','processId':0,'details':line[26:]})
 return out
def settings():
 return {'transparency':70,'backdropBlur':16,'reducedMotion':False,'autoUpdate':False,'version':'2.0.0','hostname':socket.getfqdn(),'adminEmail':'','timezone':datetime.datetime.now().astimezone().tzname(),'maxMessageSizeMb':int((run(['postconf','-h','message_size_limit'],check=False).stdout.strip() or '52428800'))//1048576,'relayConcurrency':20,'rateLimitPerHour':500,'spamThreshold':6,'colorTheme':'cyan'}
def security_scan():
 events=[]
 def add(t,m,s='medium'): events.append({'id':str(len(events)+1),'timestamp':datetime.datetime.now().isoformat(),'type':t,'message':m,'severity':s})
 relay=run(['postconf','-h','smtpd_relay_restrictions'],check=False).stdout
 if 'reject_unauth_destination' not in relay and 'defer_unauth_destination' not in relay: add('AUTH_FAIL','Postfix relay restrictions may be unsafe','high')
 if run(['systemctl','is-active','--quiet','fail2ban'],check=False).returncode: add('AUTH_FAIL','Fail2ban is not active','medium')
 for p in ['/etc/postfix/sasl_passwd']:
  if os.path.exists(p) and os.stat(p).st_mode & 0o077: add('AUTH_FAIL',p+' permissions are too broad','high')
 if not certs(): add('DNS_WARN','No MailStack-managed TLS certificate found','medium')
 return {'score':max(0,100-len(events)*12),'events':events}

SETUP_CONFIG=ETC/'setup.json'
def valid_ip(value):
 try: return str(ipaddress.ip_address(str(value)))
 except Exception: raise ValueError('invalid server IP address')
def setup_identity(data):
 domain=str(data.get('domain','')).strip().lower(); host=str(data.get('mailHost','')).strip().lower(); ip=valid_ip(data.get('serverIp',''))
 if not DOMAIN_RE.fullmatch(domain) or not DOMAIN_RE.fullmatch(host) or not host.endswith('.'+domain): raise ValueError('invalid domain or mail hostname')
 run(['postconf','-e',f'myhostname = {host}']); run(['postconf','-e',f'mydomain = {domain}']); run(['postfix','check']); run(['systemctl','reload','postfix'])
 keydir=pathlib.Path('/etc/opendkim/keys')/domain; keydir.mkdir(parents=True,exist_ok=True)
 pub=''
 if run(['which','opendkim-genkey'],check=False).returncode==0:
  run(['opendkim-genkey','-b','2048','-D',str(keydir),'-d',domain,'-s','mail']); os.chmod(keydir/'mail.private',0o600)
  raw=(keydir/'mail.txt').read_text(); match=re.search(r'p=([^"\s)]+)',raw); pub=match.group(1) if match else ''
 cfg={'domain':domain,'mailHost':host,'serverIp':ip,'postmaster':str(data.get('postmaster') or 'postmaster@'+domain),'dkimSelector':'mail','updatedAt':datetime.datetime.now().isoformat()}
 atomic(SETUP_CONFIG,json.dumps(cfg,indent=2)+'\n',0o600); return {'applied':True,'identity':cfg,'dkimPublicKey':pub}
def dig(name,typ):
 p=run(['dig','+short',typ,name],check=False,timeout=15); return [x.strip().strip('"') for x in p.stdout.splitlines() if x.strip()]
def setup_dns_verify(data):
 domain=str(data.get('domain','')).lower(); host=str(data.get('mailHost','')).lower(); ip=valid_ip(data.get('serverIp','')); selector=str(data.get('dkimSelector','mail'))
 if not DOMAIN_RE.fullmatch(domain) or not DOMAIN_RE.fullmatch(host): raise ValueError('invalid domain')
 expected_spf=str(data.get('expectedSpf','')).strip(); relay=str(data.get('selectedRelay','direct')); ses_from=str(data.get('sesMailFrom','')); ses_region=str(data.get('sesRegion','us-east-1'))
 observed={'a':dig(host,'A'),'mx':dig(domain,'MX'),'spf':dig(domain,'TXT'),'dkim':dig(f'{selector}._domainkey.{domain}','TXT'),'dmarc':dig(f'_dmarc.{domain}','TXT')}
 spf_records=[x for x in observed['spf'] if x.startswith('v=spf1')]
 checks={'a':ip in observed['a'],'mx':any(host in x for x in observed['mx']),'spfSingle':len(spf_records)==1,'spfExpected':bool(expected_spf) and expected_spf in spf_records,'dkim':any('v=DKIM1' in x and re.search(r'p=[A-Za-z0-9+/]{100,}={0,2}',x) for x in observed['dkim']),'dmarc':any(x.startswith('v=DMARC1') and 'rua=mailto:' in x for x in observed['dmarc'])}
 if relay=='ses':
  observed['sesMx']=dig(ses_from,'MX'); observed['sesSpf']=dig(ses_from,'TXT'); ses_spf=[x for x in observed['sesSpf'] if x.startswith('v=spf1')]
  checks['sesMailFromMx']=any(f'feedback-smtp.{ses_region}.amazonses.com' in x for x in observed['sesMx']); checks['sesMailFromSpf']=len(ses_spf)==1 and 'include:amazonses.com' in ses_spf[0]
 return {'verified':all(checks.values()),'checks':checks,'observed':observed,'spfRecordCount':len(spf_records)}
def setup_relay(data):
 import smtplib
 host=str(data.get('host','')).strip(); port=int(data.get('port',587)); user=str(data.get('username','')); password=str(data.get('password',''))
 if not host or port not in (25,465,587,2525): raise ValueError('invalid relay endpoint')
 if port==465:
  client=smtplib.SMTP_SSL(host,port,timeout=20,context=ssl.create_default_context())
 else:
  client=smtplib.SMTP(host,port,timeout=20); client.ehlo()
  if port in (587,2525): client.starttls(context=ssl.create_default_context()); client.ehlo()
 try:
  if user or password: client.login(user,password)
  code,msg=client.noop()
 finally: client.quit()
 return {'connected':200 <= int(code) < 400,'code':int(code),'message':msg.decode(errors='replace') if isinstance(msg,bytes) else str(msg)}
def setup_relay_apply(data):
 host=str(data.get('host','')).strip(); port=int(data.get('port',587)); user=str(data.get('username','')); password=str(data.get('password',''))
 setup_relay(data)
 relay=f'[{host}]:{port}'; secret=f'{relay} {user}:{password}\n'; atomic('/etc/postfix/sasl_passwd',secret,0o600); run(['postmap','/etc/postfix/sasl_passwd'])
 for item in [f'relayhost = {relay}','smtp_sasl_auth_enable = yes','smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd','smtp_sasl_security_options = noanonymous','smtp_tls_security_level = encrypt']:
  run(['postconf','-e',item])
 run(['postfix','check']); run(['systemctl','reload','postfix']); return {'applied':True,'relayhost':relay}
def setup_cert_issue(data):
 domain=str(data.get('mailHost','')).lower(); email=str(data.get('email','')).strip()
 if not DOMAIN_RE.fullmatch(domain) or '@' not in email: raise ValueError('invalid certificate domain or email')
 acme='/root/.acme.sh/acme.sh'
 if not os.path.exists(acme): raise RuntimeError('acme.sh is not installed; install it before issuing a certificate')
 run([acme,'--issue','--standalone','-d',domain,'--accountemail',email],timeout=240)
 target=ETC/'tls'/domain; target.mkdir(parents=True,exist_ok=True)
 run([acme,'--install-cert','-d',domain,'--key-file',str(target/'privkey.pem'),'--fullchain-file',str(target/'fullchain.pem'),'--reloadcmd','systemctl reload postfix dovecot'],timeout=120)
 return {'issued':True,'domain':domain}
def setup_send_test(data):
 sender=str(data.get('sender','')); recipient=str(data.get('recipient','')); username=str(data.get('username','')); password=str(data.get('password','')); display=str(data.get('displayName','MailStack Administrator'))[:80]
 if not ADDRESS_RE.fullmatch(sender) or not ADDRESS_RE.fullmatch(recipient) or not USER_RE.fullmatch(username) or len(password)<12: raise ValueError('invalid mailbox or weak password')
 try: pwd.getpwnam(username)
 except KeyError:
  shell=run(['which','nologin'],check=False).stdout.strip() or '/usr/sbin/nologin'; run(['useradd','-m','-c',display,'-s',shell,username]); run(['chpasswd'],input=username+':'+password+'\n')
 body='From: '+sender+'\nTo: '+recipient+'\nSubject: MailStack connectivity test\n\nThis message was sent by MailStack setup verification.\n'
 p=run(['/usr/sbin/sendmail','-f',sender,'--',recipient],input=body,timeout=30,check=False)
 if p.returncode: raise RuntimeError((p.stderr or p.stdout or 'sendmail failed')[-1000:])
 return {'queued':True,'sender':sender,'recipient':recipient}
def setup_status():
 try: cfg=json.loads(SETUP_CONFIG.read_text())
 except Exception: cfg={}
 return {'identityConfigured':bool(cfg),'identity':cfg,'postfixActive':run(['systemctl','is-active','--quiet','postfix'],check=False).returncode==0,'dovecotActive':run(['systemctl','is-active','--quiet','dovecot'],check=False).returncode==0}

def main(req):
 action=req.get('action'); data=req.get('data') or {}
 if action=='snapshot': return status()
 if action=='setup.status': return setup_status()
 if action=='setup.identity.apply': return setup_identity(data)
 if action=='setup.dns.verify': return setup_dns_verify(data)
 if action=='setup.relay.test': return setup_relay(data)
 if action=='setup.relay.apply': return setup_relay_apply(data)
 if action=='setup.cert.issue': return setup_cert_issue(data)
 if action=='setup.mail.test': return setup_send_test(data)
 if action=='domains.list': return domain_list()
 if action=='domains.add':
  d=str(data.get('name','')).lower();
  if not DOMAIN_RE.fullmatch(d): raise ValueError('invalid domain')
  rr=rows(DOM); atomic(DOM,'\n'.join(' '.join(x) for x in rr if x[0]!=d)+('\n' if rr else '')+d+' OK\n'); postmap(DOM); return domain_list()
 if action=='domains.delete':
  d=str(data.get('id','')).lower();
  if not DOMAIN_RE.fullmatch(d): raise ValueError('invalid domain')
  atomic(DOM,'\n'.join(' '.join(x) for x in rows(DOM) if x[0]!=d)+'\n'); atomic(ALS,'\n'.join(' '.join(x) for x in rows(ALS) if not x[0].endswith('@'+d))+'\n'); postmap(DOM); postmap(ALS); return domain_list()
 if action=='users.add':
  u=str(data.get('username','')); password=str(data.get('password',''))
  if not USER_RE.fullmatch(u) or len(password)<12: raise ValueError('invalid username or weak password')
  run(['useradd','-m','-s',run(['which','nologin']).stdout.strip() or '/usr/sbin/nologin',u]); run(['chpasswd'],input=u+':'+password+'\n'); return users()
 if action=='users.delete':
  u=str(data.get('id',''));
  if not USER_RE.fullmatch(u): raise ValueError('invalid user')
  run(['userdel',u]); return users()
 if action=='aliases.add':
  src=str(data.get('source','')).lower(); dests=data.get('destinations') or []
  m=ADDRESS_RE.fullmatch(src)
  if not m or not DOMAIN_RE.fullmatch(m.group(1)) or not all(USER_RE.fullmatch(x) for x in dests): raise ValueError('invalid alias')
  rr=[x for x in rows(ALS) if x[0]!=src]; rr.append([src]+dests); atomic(ALS,'\n'.join(' '.join(x) for x in rr)+'\n'); postmap(ALS); return aliases()
 if action=='aliases.delete':
  src=str(data.get('id','')).lower(); atomic(ALS,'\n'.join(' '.join(x) for x in rows(ALS) if x[0]!=src)+'\n'); postmap(ALS); return aliases()
 if action=='services.action':
  ident=str(data.get('id','')); verb=str(data.get('verb','restart'))
  if ident not in SERVICES or verb not in ('start','stop','restart','reload'): raise ValueError('invalid service action')
  run(['systemctl',verb,SERVICES[ident]]); return services()
 if action=='queue.action':
  qid=str(data.get('id','')).rstrip('*!'); verb=str(data.get('verb','retry'))
  if qid and not QUEUE_RE.fullmatch(qid): raise ValueError('invalid queue id')
  if verb=='retry': run(['postqueue','-i',qid])
  elif verb=='delete': run(['postsuper','-d',qid])
  elif verb=='flush': run(['postqueue','-f'])
  else: raise ValueError('invalid queue action')
  return queue()
 if action=='logs.list': return logs(data.get('limit',200))
 if action=='security.scan': return security_scan()
 if action=='certs.list': return certs()
 if action=='certs.renew': run(['/root/.acme.sh/acme.sh','--cron','--home','/root/.acme.sh'],timeout=180); return certs()
 if action=='admin.get': return admin_public()
 if action=='admin.set': return admin_set(data)
 if action=='ai.config.get': return ai_public_config()
 if action=='ai.config.set': return ai_save(data)
 if action=='ai.test': return {'reply':ai_request([{'role':'user','content':'Reply exactly: MailStack AI connection successful.'}],120,.0),'config':ai_public_config()}
 if action=='ai.chat':
  message=str(data.get('message',''))[:12000]; history=data.get('history') if isinstance(data.get('history'),list) else []
  if not message.strip(): raise ValueError('message is required')
  system={'role':'system','content':'You are MailStack AI, a concise email infrastructure assistant. Never claim a server change occurred. Provide safe guidance for Postfix, Dovecot, DNS, DKIM, DMARC, TLS and SMTP relay. Reply in the user language.'}
  return {'success':True,'reply':ai_request([system]+history[-10:]+[{'role':'user','content':message}])}
 if action=='ai.diagnose':
  prompt='Analyze this email DNS configuration and return JSON only with score number, grade string, summary string, items array containing category,title,status,impact,detail,recommendation, deliverabilityOutlook object, and keyRecommendations array. Never guarantee inbox delivery. Input: '+json.dumps(data,ensure_ascii=False)[:20000]
  text=ai_request([{'role':'system','content':'You are an email DNS security auditor. Output valid JSON only.'},{'role':'user','content':prompt}],1800,.1)
  try: diagnosis=json.loads(text.strip().removeprefix('```json').removesuffix('```').strip())
  except Exception: diagnosis={'score':70,'grade':'B','summary':text[:1200],'items':[],'deliverabilityOutlook':{'gmail':'Medium','outlook':'Medium','qq_163':'Medium','spamScore':'Not tested'},'keyRecommendations':['Verify MX, SPF, DKIM, DMARC and PTR with authoritative DNS queries.']}
  return {'success':True,'diagnosis':diagnosis}
 if action=='ai.parse':
  prompt='Parse this raw DNS or mail log input and return JSON only with detectedDomain, analysis, errorsFound array, extractedRecords array, recommendedFixes array. Input: '+json.dumps(data,ensure_ascii=False)[:20000]
  text=ai_request([{'role':'system','content':'Return valid JSON only. Never invent successful DNS observations.'},{'role':'user','content':prompt}],1800,.1)
  try: result=json.loads(text.strip().removeprefix('```json').removesuffix('```').strip())
  except Exception: result={'detectedDomain':data.get('domain',''),'analysis':text[:1200],'errorsFound':[],'extractedRecords':[],'recommendedFixes':[]}
  return {'success':True,'result':result}
 raise ValueError('unsupported action')
if __name__=='__main__':
 try: print(json.dumps({'ok':True,'data':main(json.load(sys.stdin))},ensure_ascii=False))
 except Exception as e: print(json.dumps({'ok':False,'error':str(e)},ensure_ascii=False)); sys.exit(1)
