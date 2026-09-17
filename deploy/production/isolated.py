#!/usr/bin/env python3
"""Fixed-target production deployment; never print secret-bearing documents."""
import base64, copy, hashlib, json, os, re, subprocess, sys, urllib.request
from pathlib import Path

TARGET = 'oa-verifier-production-20260917'
GROUP = 'oa-verifier'
DOMAIN = 'verifier-production-20260917.openanonymity.ai'
REVISION = '144865c7b3cd85b5625f7ad7546f5939e0ccd40d'
REGISTRY = 'https://18-211-179-1.sslip.io'
STAGING = 'oa-verifier-2'
PRIVATE = Path('.production-private')
RECORD = Path('production-record.json')
os.umask(0o077)

def az(*args):
    r = subprocess.run(['az', *args, '--only-show-errors', '-o', 'json'], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError('Azure operation failed: ' + ' '.join(args[:2]))
    return json.loads(r.stdout or 'null')

def private_write(name, data):
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    p = PRIVATE / name
    p.write_text(json.dumps(data)); p.chmod(0o600)
    return p

def cf(method, path, data=None):
    req = urllib.request.Request('https://api.cloudflare.com/client/v4/' + path,
        data=json.dumps(data).encode() if data is not None else None, method=method,
        headers={'Authorization': 'Bearer ' + os.environ['CF_DNS_API_TOKEN'], 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=30) as response: result = json.load(response)
    except Exception:
        raise RuntimeError('Cloudflare operation failed; private response suppressed') from None
    if not result.get('success'): raise RuntimeError('Cloudflare rejected scoped DNS operation')
    return result['result']

def zone():
    zones = cf('GET', 'zones?name=openanonymity.ai&status=active')
    if len(zones) != 1: raise RuntimeError('Expected one authorized openanonymity.ai zone')
    return zones[0]['id']

def staging_state():
    return az('container', 'show', '-g', GROUP, '-n', STAGING,
              '--query', '{id:id,image:containers[0].image,ip:ipAddress}')

def read_record(): return json.loads(RECORD.read_text())
def save_record(record): RECORD.write_text(json.dumps(record, indent=2) + '\n')

def preflight():
    assert os.environ['CONTAINER_NAME'] == TARGET
    assert os.environ['TLS_DOMAIN'] == DOMAIN
    assert os.environ['APP_REVISION'] == REVISION
    assert os.environ['REGISTRY_URL'] == REGISTRY
    assert len(os.environ.get('PRODUCTION_REGISTRY_SECRET', '')) >= 32
    if TARGET in az('container', 'list', '-g', GROUP, '--query', '[].name'):
        raise RuntimeError('Production target already exists; inspect before retry')
    zone_id = zone()
    if cf('GET', 'zones/' + zone_id + '/dns_records?name=' + DOMAIN):
        raise RuntimeError('Dedicated DNS name exists; refusing overwrite')
    req = urllib.request.Request(REGISTRY + '/verifier/registered_stations',
        headers={'Authorization': 'Bearer ' + os.environ['PRODUCTION_REGISTRY_SECRET']})
    with urllib.request.urlopen(req, timeout=15) as response:
        stations = json.load(response).get('stations', [])
    if not any(s.get('station_id') == 'oa-production-station' for s in stations):
        raise RuntimeError('New org registry does not contain production station')
    save_record({'source_revision': REVISION, 'container': TARGET, 'resource_group': GROUP,
                 'region': 'eastus', 'endpoint': 'https://' + DOMAIN, 'registry_url': REGISTRY,
                 'staging_before': staging_state(), 'workflow_run_id': os.environ['GITHUB_RUN_ID']})
    print('New target, dedicated DNS, and production registry preflight passed')

def provenance():
    match = re.search(r'tlog entry created with index: (\d+)', Path('cosign.log').read_text())
    if not match: raise RuntimeError('Cosign did not provide a transparency-log index')
    index = match.group(1)
    with urllib.request.urlopen('https://rekor.sigstore.dev/api/v1/log/entries?logIndex=' + index, timeout=30) as r:
        entry = next(iter(json.load(r).values()))
    h = json.loads(base64.b64decode(entry['body']))['spec']['data']['hash']
    record = read_record()
    record.update(image_ref=Path('image-ref.txt').read_text().strip(), rekor_log_index=index,
                  signing_payload_hash=h['algorithm'] + ':' + h['value'])
    save_record(record)

def prepare():
    record = read_record(); image = os.environ['IMAGE_REF']
    required = ['ACR_USERNAME', 'ACR_PASSWORD', 'PRODUCTION_REGISTRY_SECRET', 'CF_DNS_API_TOKEN', 'ACME_EMAIL']
    if not all(os.environ.get(k) for k in required): raise RuntimeError('Missing required deployment credential')
    assert image == record['image_ref']
    assert re.fullmatch(r'oaverifieracr\.azurecr\.io/oa-verifier-production-20260917@sha256:[a-f0-9]{64}', image)
    public = {
        'MAA_ENDPOINT': 'http://localhost:8080/attest/maa',
        'MAA_PROVIDER_URL': 'sharedeus.eus.attest.azure.net', 'STATION_REGISTRY_URL': REGISTRY,
        'CHALLENGE_MIN_INTERVAL': '300', 'CHALLENGE_MAX_INTERVAL': '600',
        'MAX_CONCURRENT_REQUESTS': '20', 'RATE_LIMIT_RPS': '10', 'RATE_LIMIT_BURST': '20',
        'SUBMIT_KEY_OWNERSHIP_GRACE_SECONDS': '60', 'STATION_FAILURE_GRACE_SECONDS': '600',
        'TLS_DOMAIN': DOMAIN, 'ACME_DNS_PROVIDER': 'cloudflare',
        'REKOR_LOG_INDEX': record['rekor_log_index'], 'SIGSTORE_PAYLOAD_HASH': record['signing_payload_hash'],
    }
    resource = {
        'type': 'Microsoft.ContainerInstance/containerGroups', 'apiVersion': '2023-05-01',
        'name': TARGET, 'location': 'eastus',
        'tags': {'Environment': TARGET, 'SourceRevision': REVISION, 'ManagedBy': 'codex'},
        'properties': {
            'sku': 'Confidential', 'osType': 'Linux', 'restartPolicy': 'Always',
            'containers': [
                {'name': 'oa-verifier', 'properties': {'image': image,
                    'ports': [{'port': 443, 'protocol': 'TCP'}],
                    'environmentVariables': [{'name': k, 'value': v} for k, v in public.items()],
                    'resources': {'requests': {'cpu': 1.0, 'memoryInGB': 2.0}}}},
                {'name': 'skr-sidecar', 'properties': {
                    'image': 'mcr.microsoft.com/aci/skr@sha256:baa6acf093c011cb26799187b6a535e32bd8248f52dd2cd9c606732b8a23c112',
                    'command': ['/skr.sh'], 'ports': [{'port': 8080, 'protocol': 'TCP'}],
                    'resources': {'requests': {'cpu': 0.5, 'memoryInGB': 1.0}}}},
            ],
            'imageRegistryCredentials': [{'server': 'oaverifieracr.azurecr.io',
                'username': os.environ['ACR_USERNAME'], 'password': os.environ['ACR_PASSWORD']}],
            'ipAddress': {'type': 'Public', 'ports': [{'port': 443, 'protocol': 'TCP'}], 'dnsNameLabel': TARGET},
            'confidentialComputeProperties': {'ccePolicy': ''},
        },
    }
    template = {'$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
                'contentVersion': '1.0.0.0', 'resources': [resource]}
    policy_path = private_write('policy-template.json', template)
    r = subprocess.run(['az', 'confcom', 'acipolicygen', '-a', str(policy_path), '--approve-wildcards'],
                       capture_output=True, text=True)
    if r.returncode: raise RuntimeError('CCE policy generation failed; private output suppressed')
    encoded = json.loads(policy_path.read_text())['resources'][0]['properties']['confidentialComputeProperties']['ccePolicy']
    policy = base64.b64decode(encoded).decode()
    match = re.search(r'containers := (\[.*?\])\s*\n\nallow_properties', policy, re.S)
    if not match: match = re.search(r'containers := (\[.*?\])(?=\s*\n\n|\s*$)', policy, re.S)
    if not match: raise RuntimeError('Unexpected policy structure')
    containers = json.loads(match.group(1))
    if not containers or 'env_rules' not in containers[0]: raise RuntimeError('Policy missing application environment rules')
    for name in ['STATION_REGISTRY_SECRET', 'CF_DNS_API_TOKEN', 'ACME_EMAIL', 'CCE_POLICY_B64']:
        containers[0]['env_rules'].append({'pattern': name + '=.+', 'strategy': 're2', 'required': True})
    policy = policy[:match.start(1)] + json.dumps(containers, separators=(',', ':')) + policy[match.end(1):]
    protected = [os.environ[k] for k in ['PRODUCTION_REGISTRY_SECRET', 'CF_DNS_API_TOKEN', 'ACR_PASSWORD', 'ACME_EMAIL']]
    if any(v and v in policy for v in protected): raise RuntimeError('Protected value in policy; refusing publication')
    Path('policy.rego').write_text(policy)
    encoded = base64.b64encode(policy.encode()).decode()
    deployment = copy.deepcopy(template); properties = deployment['resources'][0]['properties']
    parameter_values = {'acrUsername': os.environ['ACR_USERNAME'], 'acrPassword': os.environ['ACR_PASSWORD'],
                        'registrySecret': os.environ['PRODUCTION_REGISTRY_SECRET'],
                        'cfDnsToken': os.environ['CF_DNS_API_TOKEN'], 'acmeEmail': os.environ['ACME_EMAIL']}
    deployment['parameters'] = {k: {'type': 'secureString'} for k in parameter_values}
    properties['imageRegistryCredentials'][0].update(username="[parameters('acrUsername')]", password="[parameters('acrPassword')]")
    properties['confidentialComputeProperties']['ccePolicy'] = encoded
    properties['containers'][0]['properties']['environmentVariables'].extend([
        {'name': 'STATION_REGISTRY_SECRET', 'secureValue': "[parameters('registrySecret')]"},
        {'name': 'CF_DNS_API_TOKEN', 'secureValue': "[parameters('cfDnsToken')]"},
        {'name': 'ACME_EMAIL', 'secureValue': "[parameters('acmeEmail')]"},
        {'name': 'CCE_POLICY_B64', 'value': encoded},
    ])
    if any(v in json.dumps(deployment) for k,v in parameter_values.items() if k != 'acrUsername' and v):
        raise RuntimeError('Protected value in ARM template; refusing deployment')
    private_write('deployment.json', deployment)
    private_write('parameters.json', {'$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#',
                                     'contentVersion': '1.0.0.0', 'parameters': {k: {'value': v} for k,v in parameter_values.items()}})
    record['policy_sha256'] = hashlib.sha256(policy.encode()).hexdigest(); save_record(record)
    print('Confidential policy generated with no protected values embedded')

def deploy():
    if TARGET in az('container', 'list', '-g', GROUP, '--query', '[].name'):
        raise RuntimeError('Target appeared after preflight; refusing overwrite')
    az('deployment', 'group', 'create', '-g', GROUP, '-n', TARGET + '-' + os.environ['GITHUB_RUN_ID'],
       '--template-file', str(PRIVATE / 'deployment.json'), '--parameters', '@' + str(PRIVATE / 'parameters.json'))
    state = az('container', 'show', '-g', GROUP, '-n', TARGET,
               '--query', '{id:id,state:instanceView.state,ip:ipAddress,image:containers[0].image,sku:sku,tags:tags}')
    if state['image'] != read_record()['image_ref'] or state['sku'] != 'Confidential':
        raise RuntimeError('Deployed instance differs from pinned confidential image')
    fqdn = state['ip']['fqdn']
    if not fqdn.startswith(TARGET + '.') or not fqdn.endswith('.azurecontainer.io'):
        raise RuntimeError('Unexpected Azure DNS target')
    record = read_record(); record['azure'] = state; save_record(record)
    print('Created only the isolated confidential container')

def dns():
    record = read_record(); zone_id = zone()
    if cf('GET', 'zones/' + zone_id + '/dns_records?name=' + DOMAIN):
        raise RuntimeError('Dedicated DNS record appeared; refusing overwrite')
    result = cf('POST', 'zones/' + zone_id + '/dns_records',
                {'type': 'CNAME', 'name': DOMAIN, 'content': record['azure']['ip']['fqdn'],
                 'proxied': False, 'ttl': 300, 'comment': 'Isolated production OA verifier 20260917'})
    record['dns_record_id'] = result['id']; save_record(record)
    print('Created dedicated DNS-only CNAME; existing records unchanged')

def preserve():
    record = read_record()
    if staging_state() != record['staging_before']:
        raise RuntimeError('Existing verifier resource changed since preflight')
    record['staging_resource_unchanged'] = True; save_record(record)
    print('Existing verifier identity, image, and network configuration unchanged')

def cleanup():
    for name in ['policy-template.json', 'deployment.json', 'parameters.json']: (PRIVATE / name).unlink(missing_ok=True)
    if PRIVATE.exists(): PRIVATE.rmdir()
    print('Private deployment inputs removed')

if __name__ == '__main__':
    action = sys.argv[1]
    if action not in ['preflight', 'provenance', 'prepare', 'deploy', 'dns', 'preserve', 'cleanup']:
        raise SystemExit('Unknown fixed-target action')
    globals()[action]()
