#!/usr/bin/env python3
"""Operator-run namespace cutover. Secret-bearing snapshots remain root-private."""
import argparse, base64, copy, json, os, pathlib, re, subprocess, urllib.parse, urllib.request
OLD = 'uar-dev'
NEW = 'auth-dev'
ROOT = pathlib.Path('/var/lib/application-delivery/auth-dev-namespace-cutover')

def command(args, **kw):
    return subprocess.check_output(args, timeout=180, **kw)

def kub(*args):
    return json.loads(command(['kubectl', '--request-timeout=40s', *args, '-o', 'json']))

def save(name, data):
    p = ROOT / name
    if not p.exists():
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)

def apply(obj):
    p = subprocess.run(['kubectl', '--request-timeout=40s', 'apply', '--server-side', '--field-manager=auth-dev-namespace', '-f', '-'], input=json.dumps(obj), text=True, capture_output=True, timeout=180)
    if p.returncode:
        raise RuntimeError('Kubernetes apply failed for ' + obj['kind'] + '/' + obj['metadata']['name'])

def clean(obj, namespace=NEW):
    obj = copy.deepcopy(obj)
    obj.pop('status', None)
    obj['metadata'] = {'name': obj['metadata']['name'], 'namespace': namespace, 'labels': {'app.kubernetes.io/part-of': 'auth-service'}}
    return obj

def policy(name, namespace, selector, direction, rules):
    return {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': {'name': name, 'namespace': namespace}, 'spec': {'podSelector': selector, 'policyTypes': [direction], direction.lower(): rules}}

def peer(ns, app):
    return {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': ns}}, 'podSelector': {'matchLabels': {'app': app}}}

def prepare():
    original_service = kub('-n', OLD, 'get', 'service', 'auth')
    if original_service['spec'].get('type') != 'ClusterIP':
        raise RuntimeError('Original Service is no longer ClusterIP; prepare cannot run after cutover')
    d = kub('-n', OLD, 'get', 'deployment', 'auth')
    save('deployment.json', d)
    if not d['spec']['template']['spec']['containers'][0]['image'].startswith('ghcr.io/xdkaine/auth-service@sha256:'):
        raise RuntimeError('Precondition failed')
    apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NEW, 'labels': {'app.kubernetes.io/part-of': 'auth-service', 'environment': 'dev', 'pod-security.kubernetes.io/enforce': 'baseline', 'pod-security.kubernetes.io/audit': 'restricted', 'pod-security.kubernetes.io/warn': 'restricted'}}})
    for kind, name in [('secret', 'uar-auth-runtime'), ('secret', 'uar-database-ca'), ('configmap', 'uar-auth-runtime-policy')]:
        original = kub('-n', OLD, 'get', kind, name)
        save(name + '.json', original)
        obj = clean(original)
        for key in ['REDIS_URL', 'AUTH_REDIS_URL']:
            if key not in obj.get('data', {}):
                continue
            value = obj['data'][key]
            if kind == 'secret':
                value = base64.b64decode(value).decode()
            u = urllib.parse.urlsplit(value)
            if u.hostname == 'redis':
                value = value.replace('://redis:', '://redis.uar-dev.svc.cluster.local:', 1)
            if urllib.parse.urlsplit(value).hostname not in ['redis.uar-dev.svc.cluster.local']:
                raise RuntimeError('Unexpected Redis host; review before moving')
            obj['data'][key] = base64.b64encode(value.encode()).decode() if kind == 'secret' else value
        apply(obj)
    policies = kub('-n', OLD, 'get', 'networkpolicy')['items']
    save('networkpolicies.json', policies)
    required_policies = {'default-deny', 'dns', 'auth-dependencies', 'auth-ingress', 'auth-public-https', 'configured-development-integrations'}
    if not required_policies.issubset({p['metadata']['name'] for p in policies}):
        raise RuntimeError('Missing required source network policies')
    for original in policies:
        name = original['metadata']['name']
        if name not in ['default-deny', 'dns', 'auth-dependencies', 'auth-ingress', 'auth-public-https', 'configured-development-integrations']:
            continue
        obj = clean(original)
        if name == 'configured-development-integrations':
            obj['spec']['podSelector'] = {'matchLabels': {'app': 'auth'}}
        if name in ['auth-dependencies', 'auth-ingress']:
            for rules in [obj['spec'].get('egress', []), obj['spec'].get('ingress', [])]:
                for rule in rules:
                    for p in rule.get('to', []) + rule.get('from', []):
                        if 'podSelector' in p and 'namespaceSelector' not in p:
                            p['namespaceSelector'] = {'matchLabels': {'kubernetes.io/metadata.name': OLD}}
        apply(obj)
    for app, port in [('postgres', 5432), ('redis', 6379)]:
        apply(policy('auth-dev-' + app, OLD, {'matchLabels': {'app': app}}, 'Ingress', [{'from': [peer(NEW, 'auth')], 'ports': [{'protocol': 'TCP', 'port': port}]}]))
    apply(policy('portal-to-auth-dev', OLD, {'matchLabels': {'app': 'portal'}}, 'Egress', [{'to': [peer(NEW, 'auth')], 'ports': [{'protocol': 'TCP', 'port': 3003}]}]))
    svc = original_service
    save('service.json', svc)
    svc = clean(svc)
    for key in ['clusterIP', 'clusterIPs', 'ipFamilies', 'ipFamilyPolicy', 'healthCheckNodePort']:
        svc['spec'].pop(key, None)
    apply(svc)
    apply(clean(d))
    command(['kubectl', '-n', NEW, 'rollout', 'status', 'deployment/auth', '--timeout=150s'])
    print('Auth deployment prepared in auth-dev; public traffic still uses original deployment')

def cutover():
    d = kub('-n', NEW, 'get', 'deployment', 'auth')
    if not d['status'].get('availableReplicas', 0) >= 1:
        raise RuntimeError('Precondition failed')
    svc = kub('-n', NEW, 'get', 'service', 'auth')
    ip = svc['spec']['clusterIP']
    with urllib.request.urlopen('http://' + ip + ':3003/healthz', timeout=20) as r:
        if not json.load(r)['ok']:
            raise RuntimeError('Precondition failed')
    path = pathlib.Path('/etc/nginx/sites-enabled/sdc_apps.conf').resolve()
    text = path.read_text()
    save('nginx.json', {'path': str(path), 'content': text})
    pattern = '(upstream auth_dev_backend\\s*\\{\\s*server )(?:10\\.43\\.10\\.3|' + re.escape(ip) + ')(:3003;)'
    changed, count = re.subn(pattern, lambda m: m[1] + ip + m[2], text)
    if not count == 1:
        raise RuntimeError('Auth development upstream must match expected original')
    path.write_text(changed)
    try:
        command(['nginx', '-t'], stderr=subprocess.STDOUT)
    except Exception:
        path.write_text(text)
        raise RuntimeError('Nginx validation failed; original restored')
    command(['systemctl', 'reload', 'nginx'])
    command(['kubectl', '-n', OLD, 'patch', 'service', 'auth', '--type=merge', '-p', json.dumps({'spec': {'type': 'ExternalName', 'externalName': 'auth.auth-dev.svc.cluster.local', 'selector': None, 'clusterIP': '', 'clusterIPs': None, 'ipFamilies': None, 'ipFamilyPolicy': None}})])
    for filename in ['config.json', 'all-environments.json']:
        p = pathlib.Path('/etc/application-delivery') / filename
        original = json.loads(p.read_text())
        save(filename, original)
        matches = [a for a in original['applications'] if a['id'] == 'auth-dev']
        if not len(matches) == 1:
            raise RuntimeError('Precondition failed')
        if not matches[0]['targets']['auth']['namespace'] in [OLD, NEW]:
            raise RuntimeError('Precondition failed')
        matches[0]['targets']['auth']['namespace'] = NEW
        temp = p.with_suffix('.namespace-new')
        temp.write_text(json.dumps(original, indent=2))
        temp.chmod(384)
        os.replace(temp, p)
    print('Public proxy, compatibility DNS and delivery target now point to auth-dev')

def snapshot():
    resources = [kub('get', 'namespace', NEW)]
    for kind in ['deployment', 'service', 'configmap', 'secret', 'networkpolicy']:
        for obj in kub('-n', NEW, 'get', kind)['items']:
            if kind in ['secret', 'configmap'] and obj['metadata']['name'] not in ['uar-auth-runtime', 'uar-database-ca', 'uar-auth-runtime-policy']:
                continue
            resources.append(clean(obj))
    resources[0] = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NEW, 'labels': resources[0]['metadata']['labels']}}
    for name in ['auth-dev-postgres', 'auth-dev-redis', 'portal-to-auth-dev']:
        resources.append(clean(kub('-n', OLD, 'get', 'networkpolicy', name), OLD))
    save('steady-state.json', resources)
    print('Cutover rollback snapshot saved privately')

def retire():
    if not (ROOT / 'steady-state.json').exists():
        raise RuntimeError('Snapshot required before retirement')
    proof = json.loads((ROOT / 'cutover-verified.json').read_text())
    if not all((proof.get(k) is True for k in ['publicDiscovery', 'signingKeys', 'portalAlias', 'databaseRedis', 'proxyRouting', 'deliveryTarget'])):
        raise RuntimeError('Precondition failed')
    d = kub('-n', NEW, 'get', 'deployment', 'auth')
    if not d['status'].get('availableReplicas', 0) >= 1:
        raise RuntimeError('Precondition failed')
    svc = kub('-n', OLD, 'get', 'service', 'auth')
    if not svc['spec']['type'] == 'ExternalName':
        raise RuntimeError('Precondition failed')
    with urllib.request.urlopen('https://auth-dev.calpolysoc.org/healthz', timeout=20) as r:
        if not json.load(r)['ok']:
            raise RuntimeError('Precondition failed')
    command(['kubectl', '-n', OLD, 'delete', 'deployment', 'auth', '--wait=true', '--timeout=120s'])
    print('Old Auth deployment removed; databases, Redis and volumes preserved')
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['prepare', 'cutover', 'snapshot', 'retire'])
    args = parser.parse_args()
    if not os.geteuid() == 0:
        raise RuntimeError('Run on the K3s host as root')
    ROOT.mkdir(mode=448, parents=True, exist_ok=True)
    if not ROOT.stat().st_mode & 63 == 0:
        raise RuntimeError('Precondition failed')
    globals()[args.phase]()
