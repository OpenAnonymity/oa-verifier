#!/usr/bin/env python3
"""Fixed production target, measured image, private rollback, fenced deployment.

Preparing a release does not restart a container or modify its key policy.
Only deploy consumes a pending, authenticated production dashboard request.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.request import Request, build_opener

from controls import NoRedirect

SUB = '839b147d-853e-4611-aaa9-f6c6fa4c14ad'
GROUP = 'oa-verifier'
TARGET = 'oa-verifier-production-20260917'
STAGING = 'oa-verifier-2'
DOMAIN = 'verifier-production-20260917.openanonymity.ai'
REGISTRY = 'https://org-live.openanonymity.ai'
REVISION = '4299cfa136c90550737dd46c89dba586c213159b'
BASE_IMAGE = 'oaverifieracr.azurecr.io/oa-verifier-production-20260917@sha256:55250fe5d9458f763231eb9867c8695f4b6cd508ac8d97551dbba5e1c5710791'
SIDECAR = 'mcr.microsoft.com/aci/skr@sha256:baa6acf093c011cb26799187b6a535e32bd8248f52dd2cd9c606732b8a23c112'
VAULT = 'oa-verifier-prod-sealed'
VAULT_URL = 'https://' + VAULT + '.vault.azure.net'
KEK = 'oa-verifier-prod-kek'
CLIENT_ID = '950c6ddd-b959-4ca1-98a8-ea90f32ddd69'
IDENTITY = '/subscriptions/' + SUB + '/resourcegroups/oa-verifier/providers/Microsoft.ManagedIdentity/userAssignedIdentities/' + VAULT
API = '2023-05-01'
RESOURCE_ID = '/subscriptions/' + SUB + '/resourceGroups/' + GROUP + '/providers/Microsoft.ContainerInstance/containerGroups/' + TARGET
PRIVATE = Path('.production-private')
RECORD = Path('production-record.json')
os.umask(0o077)


def run(args):
    result = subprocess.run(args, text=True, capture_output=True)
    if result.returncode:
        # Provider errors can echo submitted values. Keep them private.
        raise RuntimeError('Command failed: ' + ' '.join(args[:3]))
    return result.stdout


def az(*args):
    return json.loads(run(['az', *args, '--only-show-errors', '-o', 'json']) or 'null')


def private_write(name, data):
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    path = PRIVATE / name
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    return path


def read_record():
    return json.loads(RECORD.read_text())


def save_record(data):
    RECORD.write_text(json.dumps(data, indent=2) + '\n')


def fetch(url, secret=None):
    headers = {'User-Agent': 'Go-http-client/1.1'}
    if secret:
        headers['Authorization'] = 'Bearer ' + secret
    with build_opener(NoRedirect()).open(Request(url, headers=headers), timeout=25) as response:
        return json.load(response)


def current_resource():
    return az('rest', '--method', 'get', '--url', 'https://management.azure.com' + RESOURCE_ID + '?api-version=' + API)


def staging_state():
    return az('container', 'show', '-g', GROUP, '-n', STAGING,
              '--query', '{id:id,image:containers[0].image,ip:ipAddress,identity:identity}')


def resource_fingerprint(resource):
    """Exclude changing counters/IP status, retain all deployment configuration."""
    config = copy.deepcopy(resource)
    config.pop('systemData', None)
    p = config['properties']
    for field in ('instanceView', 'provisioningState'):
        p.pop(field, None)
    p.get('ipAddress', {}).pop('ip', None)
    for container in p['containers']:
        container['properties'].pop('instanceView', None)
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def validate_baseline(resource):
    if resource['id'].lower() != RESOURCE_ID.lower() or resource['location'] != 'eastus':
        raise ValueError('Wrong Azure production target')
    p = resource['properties']
    if p['sku'] != 'Confidential' or p['osType'] != 'Linux' or p['restartPolicy'] != 'Always':
        raise ValueError('Unexpected production platform configuration')
    containers = p['containers']
    if [c['name'] for c in containers] != ['oa-verifier', 'skr-sidecar']:
        raise ValueError('Unexpected container set')
    image = containers[0]['properties']['image']
    if image != BASE_IMAGE and resource.get('tags', {}).get('ResilienceRevision') != REVISION:
        raise ValueError('Unreviewed production source; stop before replacement')
    if containers[1]['properties']['image'] != SIDECAR:
        raise ValueError('Unexpected attestation sidecar')
    env = {e['name']: e.get('value') for e in containers[0]['properties']['environmentVariables']}
    if env.get('TLS_DOMAIN') != DOMAIN or env.get('STATION_REGISTRY_URL') not in (REGISTRY, 'https://18-211-179-1.sslip.io'):
        raise ValueError('Unexpected trust address or registry')
    if p['ipAddress']['dnsNameLabel'] != TARGET or p['ipAddress']['ports'] != [{'port': 443, 'protocol': 'TCP'}]:
        raise ValueError('Unexpected public network configuration')
    if p.get('volumes') or p.get('subnetIds'):
        raise ValueError('Unreviewed persistent volume or network configuration')
    if not p.get('confidentialComputeProperties', {}).get('ccePolicy'):
        raise ValueError('Missing current confidential policy')


def check_registry():
    secret = os.environ.get('PRODUCTION_REGISTRY_SECRET', '')
    if len(secret) < 32:
        raise ValueError('Production registry credential missing')
    stations = fetch(REGISTRY + '/verifier/registered_stations', secret).get('stations', [])
    if not any(s.get('station_id') == 'oa-production-station' for s in stations):
        raise ValueError('Production registry authorization or station registration failed')
    return len(stations)


def preflight():
    if az('account', 'show', '--query', 'id') != SUB:
        raise ValueError('Wrong Azure subscription')
    resource = current_resource()
    validate_baseline(resource)
    count = check_registry()
    identity = az('identity', 'show', '-g', GROUP, '-n', VAULT)
    if identity['clientId'] != CLIENT_ID or identity['id'].lower() != IDENTITY.lower():
        raise ValueError('Production storage identity mismatch')
    vault = az('keyvault', 'show', '-g', GROUP, '-n', VAULT)
    vp = vault['properties']
    if not vp['enablePurgeProtection'] or not vp['enableRbacAuthorization'] or vp['sku']['name'].lower() != 'premium':
        raise ValueError('Production vault protections missing')
    key = az('keyvault', 'key', 'show', '--vault-name', VAULT, '-n', KEK)
    if key['key']['kty'] != 'RSA-HSM' or key['attributes']['exportable'] is not True:
        raise ValueError('Wrong production sealing key')
    private_write('baseline.json', resource)
    save_record({'source_revision': REVISION, 'container': TARGET, 'resource_group': GROUP,
                 'endpoint': 'https://' + DOMAIN, 'registry_url': REGISTRY,
                 'baseline_fingerprint': resource_fingerprint(resource),
                 'baseline_image': resource['properties']['containers'][0]['properties']['image'],
                 'staging_before': staging_state(), 'registry_station_count': count,
                 'workflow_run_id': os.environ['GITHUB_RUN_ID'], 'prepared_at': int(time.time()),
                 'station_store': os.environ.get('STATION_STORE', 'keyvault-sealed')})
    print('Production resource, registry authorization, and separate vault preflight passed')


def provenance():
    matches = re.findall(r'tlog entry created with index: (\d+)', Path('cosign.log').read_text())
    if len(matches) != 1:
        raise ValueError('Expected one signed image transparency record')
    entry = next(iter(fetch('https://rekor.sigstore.dev/api/v1/log/entries?logIndex=' + matches[0]).values()))
    h = json.loads(base64.b64decode(entry['body']))['spec']['data']['hash']
    record = read_record()
    record.update(image_ref=Path('image-ref.txt').read_text().strip(), rekor_log_index=matches[0],
                  signing_payload_hash=h['algorithm'] + ':' + h['value'])
    save_record(record)


def public_environment(record):
    store = record['station_store']
    if store not in ('none', 'keyvault-sealed'):
        raise ValueError('Unsupported station store')
    return {
        'MAA_ENDPOINT': 'http://localhost:8080/attest/maa', 'MAA_PROVIDER_URL': 'sharedeus.eus.attest.azure.net',
        'STATION_REGISTRY_URL': REGISTRY, 'CHALLENGE_MIN_INTERVAL': '300', 'CHALLENGE_MAX_INTERVAL': '600',
        'MAX_CONCURRENT_REQUESTS': '20', 'RATE_LIMIT_RPS': '10', 'RATE_LIMIT_BURST': '20',
        'SUBMIT_KEY_OWNERSHIP_GRACE_SECONDS': '60', 'STATION_FAILURE_GRACE_SECONDS': '600',
        'TLS_DOMAIN': DOMAIN, 'ACME_DNS_PROVIDER': 'cloudflare', 'REGISTRY_WARMUP_SECONDS': '604800',
        'REKOR_LOG_INDEX': record['rekor_log_index'], 'SIGSTORE_PAYLOAD_HASH': record['signing_payload_hash'],
        'STATION_STATE_STORE': store, 'STATION_STATE_SECRET_NAME': 'oa-verifier-station-state',
        'TLS_CERT_STORE': 'keyvault-sealed', 'TLS_CERT_KEK_VAULT': VAULT_URL, 'TLS_CERT_KEK_NAME': KEK,
        'TLS_CERT_SECRET_VAULT': VAULT_URL, 'TLS_CERT_SECRET_NAME': 'oa-verifier-tls-bundle',
        'TLS_CERT_MSI_CLIENT_ID': CLIENT_ID,
    }


def base_template(image, public):
    if not re.fullmatch(r'oaverifieracr\.azurecr\.io/oa-verifier-production-20260917@sha256:[a-f0-9]{64}', image):
        raise ValueError('Image must be pinned to production repository digest')
    return {'$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
            'contentVersion': '1.0.0.0', 'resources': [{
                'type': 'Microsoft.ContainerInstance/containerGroups', 'apiVersion': API,
                'name': TARGET, 'location': 'eastus',
                'tags': {'Environment': TARGET, 'SourceRevision': REVISION, 'ResilienceRevision': REVISION},
                'identity': {'type': 'UserAssigned', 'userAssignedIdentities': {IDENTITY: {}}},
                'properties': {'sku': 'Confidential', 'osType': 'Linux', 'restartPolicy': 'Always',
                    'containers': [
                        {'name': 'oa-verifier', 'properties': {'image': image,
                            'ports': [{'port': 443, 'protocol': 'TCP'}],
                            'environmentVariables': [{'name': k, 'value': v} for k, v in public.items()],
                            'resources': {'requests': {'cpu': 1.0, 'memoryInGB': 2.0}}}},
                        {'name': 'skr-sidecar', 'properties': {'image': SIDECAR, 'command': ['/skr.sh'],
                            'ports': [{'port': 8080, 'protocol': 'TCP'}],
                            'resources': {'requests': {'cpu': 0.5, 'memoryInGB': 1.0}}}}],
                    'imageRegistryCredentials': [{'server': 'oaverifieracr.azurecr.io', 'identity': IDENTITY}],
                    'ipAddress': {'type': 'Public', 'ports': [{'port': 443, 'protocol': 'TCP'}], 'dnsNameLabel': TARGET},
                    'confidentialComputeProperties': {'ccePolicy': ''}}}]}


def protect_policy(policy):
    match = re.search(r'containers := (\[.*?\])(?=\s*\n\n|\s*$)', policy, re.S)
    if not match:
        raise ValueError('Unrecognized confidential policy format')
    containers = json.loads(match.group(1))
    if len(containers) != 2 or 'env_rules' not in containers[0]:
        raise ValueError('Unexpected measured containers; public structure=' + json.dumps([
            {'id': c.get('id'), 'keys': sorted(c)} for c in containers]))
    for name in ['STATION_REGISTRY_SECRET', 'CF_DNS_API_TOKEN', 'ACME_EMAIL', 'CCE_POLICY_B64']:
        containers[0]['env_rules'].append({'pattern': name + '=.+', 'strategy': 're2', 'required': True})
    # Platform-injected identity settings contain short-lived authentication data.
    for name in ['IDENTITY_ENDPOINT', 'IDENTITY_HEADER', 'IDENTITY_API_VERSION', 'IDENTITY_SERVER_THUMBPRINT']:
        containers[0]['env_rules'].append({'pattern': name + '=.*', 'strategy': 're2', 'required': False})
    return policy[:match.start(1)] + json.dumps(containers, separators=(',', ':')) + policy[match.end(1):]


def add_secrets(template):
    result = copy.deepcopy(template)
    values = {'registrySecret': os.environ['PRODUCTION_REGISTRY_SECRET'],
              'cfDnsToken': os.environ['CF_DNS_API_TOKEN'], 'acmeEmail': os.environ['ACME_EMAIL']}
    if not all(values.values()):
        raise ValueError('Missing deployment secret')
    result['parameters'] = {k: {'type': 'secureString'} for k in values}
    env = result['resources'][0]['properties']['containers'][0]['properties']['environmentVariables']
    env[:] = [e for e in env if e['name'] not in ('STATION_REGISTRY_SECRET', 'CF_DNS_API_TOKEN', 'ACME_EMAIL')]
    env.extend({'name': name, 'secureValue': "[parameters('" + parameter + "')]"}
               for name, parameter in [('STATION_REGISTRY_SECRET', 'registrySecret'), ('CF_DNS_API_TOKEN', 'cfDnsToken'), ('ACME_EMAIL', 'acmeEmail')])
    return result, values


def rollback_template(resource):
    """Keep the prior measured policy and runtime, substituting known secure inputs."""
    result = {k: copy.deepcopy(resource[k]) for k in ('name', 'location', 'type', 'properties')}
    result['apiVersion'] = API
    for k in ('tags', 'identity'):
        if resource.get(k):
            result[k] = copy.deepcopy(resource[k])
    p = result['properties']
    for k in ('provisioningState', 'instanceView', 'isCreatedFromStandbyPool'):
        p.pop(k, None)
    for k in ('ip', 'fqdn'):
        p['ipAddress'].pop(k, None)
    for c in p['containers']:
        c['properties'].pop('instanceView', None)
    template = {'$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
                'contentVersion': '1.0.0.0', 'resources': [result]}
    template, values = add_secrets(template)
    for cred in p.get('imageRegistryCredentials', []):
        if cred.get('identity'):
            continue
        if cred.get('server') != 'oaverifieracr.azurecr.io':
            raise ValueError('Unknown rollback registry credential')
        values['acrUsername'], values['acrPassword'] = os.environ['ACR_USERNAME'], os.environ['ACR_PASSWORD']
    # add_secrets copied the document; substitute on its actual resource.
    for cred in template['resources'][0]['properties'].get('imageRegistryCredentials', []):
        if not cred.get('identity'):
            cred['username'], cred['password'] = "[parameters('acrUsername')]", "[parameters('acrPassword')]"
    template['parameters'] = {k: {'type': 'secureString'} for k in values}
    return template, values


def write_parameters(name, values):
    private_write(name, {'$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#',
                        'contentVersion': '1.0.0.0', 'parameters': {k: {'value': v} for k, v in values.items()}})


def prepare():
    record = read_record()
    template = base_template(record['image_ref'], public_environment(record))
    path = private_write('policy-template.json', template)
    run(['az', 'confcom', 'acipolicygen', '-a', str(path), '--approve-wildcards'])
    encoded = json.loads(path.read_text())['resources'][0]['properties']['confidentialComputeProperties']['ccePolicy']
    base_policy = base64.b64decode(encoded).decode()
    # Generated only from fixed public env and identity-based image pull.
    Path('base-policy.rego').write_text(base_policy)
    policy = protect_policy(base_policy)
    protected = [os.environ[k] for k in ('PRODUCTION_REGISTRY_SECRET', 'CF_DNS_API_TOKEN', 'ACME_EMAIL', 'ACR_PASSWORD')]
    if any(value and value in policy for value in protected):
        raise ValueError('Protected value embedded in measured policy')
    Path('policy.rego').write_text(policy)
    encoded = base64.b64encode(policy.encode()).decode()
    p = template['resources'][0]['properties']
    p['confidentialComputeProperties']['ccePolicy'] = encoded
    p['containers'][0]['properties']['environmentVariables'].append({'name': 'CCE_POLICY_B64', 'value': encoded})
    deployment, values = add_secrets(template)
    rollback, rollback_values = rollback_template(json.loads((PRIVATE / 'baseline.json').read_text()))
    for doc in (deployment, rollback):
        if any(value and value in json.dumps(doc) for value in protected):
            raise ValueError('Protected value embedded in ARM template')
    private_write('deployment.json', deployment)
    private_write('rollback.json', rollback)
    write_parameters('parameters.json', values)
    write_parameters('rollback-parameters.json', rollback_values)
    # Cloud validation has no container mutation. Both directions must validate.
    for label in ('deployment', 'rollback'):
        params = 'parameters' if label == 'deployment' else 'rollback-parameters'
        az('deployment', 'group', 'validate', '-g', GROUP, '--template-file', str(PRIVATE / (label + '.json')),
           '--parameters', '@' + str(PRIVATE / (params + '.json')))
    record['policy_sha256'] = hashlib.sha256(policy.encode()).hexdigest()
    record['templates_validated'] = True
    save_record(record)
    print('Pinned production policy and rollback validated; running verifier unchanged')


def authorize_policy():
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
    from release_policy import decode_policy, merge, allows
    current = az('keyvault', 'key', 'show', '--vault-name', VAULT, '-n', KEK)
    old = decode_policy(current.get('releasePolicy', {}).get('encodedPolicy'))
    policy = merge(old, read_record()['policy_sha256'], 4)
    path = private_write('release-policy.json', policy)
    az('keyvault', 'key', 'set-attributes', '--vault-name', VAULT, '-n', KEK, '--policy', '@' + str(path))
    after = az('keyvault', 'key', 'show', '--vault-name', VAULT, '-n', KEK)
    if not allows(decode_policy(after.get('releasePolicy', {}).get('encodedPolicy')), read_record()['policy_sha256']):
        raise ValueError('Production key release policy not confirmed')


def apply(template, parameters):
    az('deployment', 'group', 'create', '-g', GROUP, '-n', 'prod-resilience-' + os.environ['GITHUB_RUN_ID'],
       '--template-file', str(PRIVATE / template), '--parameters', '@' + str(PRIVATE / parameters))


def deploy():
    import controls
    record = read_record()
    revision = int(os.environ['CONTROLS_REVISION'])
    if not record.get('templates_validated') or record['source_revision'] != REVISION:
        raise ValueError('Unvalidated production build')
    if resource_fingerprint(current_resource()) != record['baseline_fingerprint']:
        raise ValueError('Production changed during build; no deployment')
    check_registry()
    controls.claim(revision, record['station_store'])
    record['claimed_revision'] = revision
    save_record(record)
    authorize_policy()
    controls.check(revision, record['station_store'])
    # Final check occurs BEFORE deletion; no stale request can take prod offline.
    if resource_fingerprint(current_resource()) != record['baseline_fingerprint']:
        raise ValueError('Production changed after claim; no deployment')
    record['mutation_started'] = True
    save_record(record)
    try:
        az('container', 'delete', '-g', GROUP, '-n', TARGET, '--yes')
        apply('deployment.json', 'parameters.json')
        live = current_resource()
        if live['properties']['containers'][0]['properties']['image'] != record['image_ref']:
            raise ValueError('Production image does not match prepared digest')
        if live['properties']['ipAddress']['fqdn'] != TARGET + '.eastus.azurecontainer.io':
            raise ValueError('Production DNS identity changed')
        # TLS, fresh nonce, signed MAA measurement and channel binding are mandatory.
        run([sys.executable, str(Path(__file__).with_name('verify.py'))])
        health = fetch('https://' + DOMAIN + '/health')
        persistence = health.get('persistence', {})
        if persistence.get('store') != record['station_store'] or persistence.get('load_error') or persistence.get('save_error'):
            raise ValueError('Production persistence health did not pass')
        record['deployed'] = True
        record['staging_unchanged'] = staging_state() == record['staging_before']
        save_record(record)
    except Exception:
        record['rollback_attempted'] = True
        save_record(record)
        az('container', 'delete', '-g', GROUP, '-n', TARGET, '--yes')
        apply('rollback.json', 'rollback-parameters.json')
        record['rollback_resource_restored'] = current_resource()['properties']['containers'][0]['properties']['image'] == record['baseline_image']
        save_record(record)
        raise RuntimeError('Production validation failed; restored prior container configuration; verify recovery') from None
    # A reporting failure must not roll back a healthy verifier. Preserve the
    # run claim and evidence so an operator can reconcile it without a restart.
    controls.complete(revision, True)
    print('Production confidential deployment verified; station-login/restart acceptance remains separate')


def finish():
    import controls
    if not RECORD.exists():
        return
    record = read_record()
    if 'claimed_revision' in record and not record.get('deployed'):
        controls.complete(record['claimed_revision'], False)


def cleanup():
    if PRIVATE.exists():
        for path in PRIVATE.iterdir():
            path.unlink()
        PRIVATE.rmdir()


if __name__ == '__main__':
    action = sys.argv[1]
    if action not in ('preflight', 'provenance', 'prepare', 'deploy', 'finish', 'cleanup'):
        raise SystemExit('Unknown production action')
    try:
        globals()[action]()
    except Exception as error:
        print('Production action stopped: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
