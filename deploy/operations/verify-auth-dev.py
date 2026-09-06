import json,subprocess,urllib.request,urllib.parse,base64,os,pathlib
root=pathlib.Path('/var/lib/application-delivery/auth-dev-namespace-cutover')
def k(*a):return subprocess.check_output(['kubectl','--request-timeout=30s',*a],timeout=120)
def get(url):
 with urllib.request.urlopen(url,timeout=20) as r:return json.load(r)
issuer='https://auth-dev.calpolysoc.org';d=get(issuer+'/.well-known/openid-configuration');assert d['issuer']==issuer
for key in ['authorization_endpoint','token_endpoint','jwks_uri','end_session_endpoint']:assert d[key].startswith(issuer+'/')
keys=get(d['jwks_uri'])['keys'];old=json.load(open(root/'uar-auth-runtime.json'));new=json.loads(k('-n','auth-dev','get','secret','uar-auth-runtime','-o','json'))
assert old['data']['AUTH_JWKS']==new['data']['AUTH_JWKS']
expected=json.loads(base64.b64decode(old['data']['AUTH_JWKS']))['keys'];public=['kty','kid','use','alg','n','e','crv','x','y']
for key in keys:assert any(all(key.get(f)==e.get(f) for f in public if f in key) for e in expected)
ip=json.loads(k('-n','auth-dev','get','svc','auth','-o','json'))['spec']['clusterIP']
code="(async()=>{const a=await require('dns').promises.lookup('auth');if(a.address!==process.argv[1])throw Error();const r=await fetch('http://auth:3003/.well-known/openid-configuration');if((await r.json()).issuer!=='https://auth-dev.calpolysoc.org')throw Error();process.exit(0)})().catch(()=>process.exit(1))"
k('-n','uar-dev','exec','deployment/portal','--','node','-e',code,ip)
code="(async()=>{const{prisma}=require('/app/dist/db.js');const{createClient}=require('redis');const r=createClient({url:process.env.AUTH_REDIS_URL||process.env.REDIS_URL});await r.connect();if(await r.ping()!=='PONG'||await prisma.oidcClient.count()<1)throw Error();await r.quit();await prisma.$disconnect();process.exit(0)})().catch(()=>process.exit(1))"
k('-n','auth-dev','exec','deployment/auth','--','node','-e',code)
proof={x:True for x in ['publicDiscovery','signingKeys','portalAlias','databaseRedis']};p=root/'cutover-verified.json';fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
with os.fdopen(fd,'w') as f:json.dump(proof,f)
print(json.dumps(proof))
