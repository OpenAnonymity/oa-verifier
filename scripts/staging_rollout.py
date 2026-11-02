#!/usr/bin/env python3
"""Fixed staging target, private baseline, validated rollback and bounded recovery."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from urllib.request import urlopen

SUBSCRIPTION = '839b147d-853e-4611-aaa9-f6c6fa4c14ad'
GROUP = 'oa-verifier'
TARGET = 'oa-verifier-2'
PRODUCTION = 'oa-verifier-production-20260917'
DOMAIN = 'verifier2.openanonymity.ai'
REGISTRY = 'https://org-staging.openanonymity.ai'
API = '2023-05-01'
PRIVATE = Path('.staging-rollout-private')
RECORD = Path('staging-rollout.json')
os.umask(0o077)


def run(args):
    result = subprocess.run(args, text=True, capture_output=True)
    for _ in range(6):
        if (not result.returncode or args[:4] != ['az', 'deployment', 'group', 'create']
                or 'failedidentityoperation' not in result.stderr.lower()
                or 'pending' not in result.stderr.lower() or 'delet' not in result.stderr.lower()):
            break
        time.sleep(20)
        result = subprocess.run(args, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError('Azure command failed; private response withheld')
    return json.loads(result.stdout or 'null')


def az(*args):
    return run(['az', *args, '--only-show-errors', '-o', 'json'])


def write_private(name, value):
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    path = PRIVATE / name
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def write_record(record):
    RECORD.write_text(json.dumps(record, indent=2) + '\n')


def resource(target=TARGET):
    assert target in (TARGET, PRODUCTION)
    url = ('https://management.azure.com/subscriptions/' + SUBSCRIPTION + '/resourceGroups/' + GROUP
           + '/providers/Microsoft.ContainerInstance/containerGroups/' + target + '?api-version=' + API)
    return az('rest', '--method', 'get', '--url', url)


def fingerprint(value):
    value = copy.deepcopy(value)
    value.pop('systemData', None)
    props = value['properties']
    for key in ('instanceView', 'provisioningState'):
        props.pop(key, None)
    props.get('ipAddress', {}).pop('ip', None)
    for container in props['containers']:
        container['properties'].pop('instanceView', None)
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def environment(value):
    container = next(c for c in value['properties']['containers'] if c['name'] == 'oa-verifier')
    return {item['name']: item for item in container['properties']['environmentVariables']}


def assert_staging(value):
    if value['name'] != TARGET or value.get('location') != 'eastus':
        raise ValueError('Wrong staging deployment target')
    if value['properties'].get('sku') != 'Confidential':
        raise ValueError('Confidential staging runtime required')
    env = environment(value)
    if env['TLS_DOMAIN'].get('value') != DOMAIN or env['STATION_REGISTRY_URL'].get('value') != REGISTRY:
        raise ValueError('Wrong staging domain or registry')
    for name in ('STATION_STATE_STORE', 'TLS_CERT_STORE'):
        if env.get(name, {}).get('value') != 'keyvault-sealed':
            raise ValueError('Both existing encrypted stores must remain enabled')
    for name in ('TLS_CERT_KEK_VAULT', 'TLS_CERT_SECRET_VAULT'):
        if 'oa-verifier2-sealed' not in env.get(name, {}).get('value', ''):
            raise ValueError('Unexpected staging vault')


def rollback_template(live, candidate):
    assert_staging(live)
    assert_staging(candidate)
    result = {key: copy.deepcopy(live[key]) for key in ('name', 'location', 'type', 'properties')}
    result['apiVersion'] = API
    if live.get('tags'):
        result['tags'] = copy.deepcopy(live['tags'])
    if live.get('identity'):
        identity = live['identity']
        assigned = identity.get('userAssignedIdentities', {})
        if identity.get('type') != 'UserAssigned' or not assigned:
            raise ValueError('Unexpected existing identity')
        result['identity'] = {'type': 'UserAssigned', 'userAssignedIdentities': {key: {} for key in assigned}}
    props = result['properties']
    for key in ('provisioningState', 'instanceView', 'isCreatedFromStandbyPool', 'provisioningTimeoutInSeconds', 'isCustomProvisioningTimeout'):
        props.pop(key, None)
    for key in ('ip', 'fqdn'):
        props['ipAddress'].pop(key, None)
    for container in props['containers']:
        container['properties'].pop('instanceView', None)
        config = container['properties'].get('configMap')
        if config is not None and not config.get('keyValuePairs'):
            container['properties'].pop('configMap')
    logging = (props.get('diagnostics') or {}).get('logAnalytics')
    if logging is not None and not logging.get('workspaceKey'):
        replacement = (candidate['properties'].get('diagnostics') or {}).get('logAnalytics') or {}
        if not replacement.get('workspaceKey') or replacement.get('workspaceId') != logging.get('workspaceId'):
            raise ValueError('Cannot reconstruct existing logging credential')
        logging['workspaceKey'] = replacement['workspaceKey']
    replacements = environment(candidate)
    for item in environment(result).values():
        if 'value' in item or item.get('secureValue'):
            continue
        replacement = replacements.get(item['name'], {})
        if not replacement.get('secureValue'):
            raise ValueError('Cannot reconstruct an existing secure input')
        item['secureValue'] = replacement['secureValue']
    creds = props.get('imageRegistryCredentials', [])
    new_creds = candidate['properties'].get('imageRegistryCredentials', [])
    for cred in creds:
        if cred.get('identity'):
            continue
        match = next((x for x in new_creds if x.get('server') == cred.get('server') and x.get('username') == cred.get('username')), None)
        if not match or not match.get('password'):
            raise ValueError('Cannot reconstruct existing registry credential')
        cred['password'] = match['password']
    return {'$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
            'contentVersion': '1.0.0.0', 'resources': [result]}


def fetch(path):
    with urlopen('https://' + DOMAIN + path, timeout=15) as response:
        return json.load(response)


def approved_fingerprint():
    data = fetch('/broadcast')
    stations = sorted((row['station_id'], row['public_key'], row['registered_at']) for row in data.get('verified_stations', []))
    if not stations:
        raise ValueError('No approved staging station; do not replace runtime')
    return hashlib.sha256(json.dumps(stations).encode()).hexdigest()


def certificate(origin):
    context = ssl.create_default_context()
    with socket.create_connection((origin, 443), timeout=15) as connection:
        with context.wrap_socket(connection, server_hostname=DOMAIN) as secured:
            return hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest()


def validate(template):
    az('deployment', 'group', 'validate', '-g', GROUP, '--template-file', str(template))


def prepare():
    template = json.loads(Path('/tmp/aci-deploy.json').read_text())
    if len(template['resources']) != 1:
        raise ValueError('Only the staging container group may change')
    candidate = template['resources'][0]
    assert_staging(candidate)
    if environment(candidate).get('STATION_FAILURE_GRACE_SECONDS', {}).get('value') != '604800':
        raise ValueError('Seven-day provider protection required')
    live = resource()
    assert_staging(live)
    if set((live.get('identity') or {}).get('userAssignedIdentities', {})) != set((candidate.get('identity') or {}).get('userAssignedIdentities', {})):
        raise ValueError('Existing staging identity must be preserved')
    rollback = rollback_template(live, candidate)
    rollback_path = write_private('rollback.json', rollback)
    write_private('baseline.json', live)
    candidate_path = write_private('candidate.json', template)
    validate(rollback_path)
    validate(candidate_path)
    origin = live['properties']['ipAddress']['fqdn']
    record = {'target': TARGET, 'prepared': True, 'baseline_fingerprint': fingerprint(live),
              'production_fingerprint': fingerprint(resource(PRODUCTION)),
              'approved_station_fingerprint': approved_fingerprint(), 'origin': origin,
              'certificate_sha256': certificate(origin),
              'baseline_policy_sha256': hashlib.sha256(base64.b64decode(environment(live)['CCE_POLICY_B64']['value'], validate=True)).hexdigest(),
              'candidate_image': candidate['properties']['containers'][0]['properties']['image']}
    write_record(record)
    print('Staging replacement and rollback validated; running container untouched')


def apply(name):
    path = PRIVATE / name
    template = json.loads(path.read_text())
    assert len(template['resources']) == 1
    assert_staging(template['resources'][0])
    az('deployment', 'group', 'create', '-g', GROUP,
       '-n', 'staging-grace-' + os.environ['GITHUB_RUN_ID'], '--template-file', str(path))


def wait_ready(record, timeout=240):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            health = fetch('/health')
            state = health.get('persistence', {})
            current = resource()
            origin_ip = current['properties']['ipAddress']['ip']
            checks = {'healthy': health.get('status') == 'healthy',
                      'loaded': state.get('loaded') is True, 'sealed': state.get('store') == 'keyvault-sealed',
                      'no_storage_errors': not state.get('load_error') and not state.get('save_error'),
                      'approval_preserved': approved_fingerprint() == record['approved_station_fingerprint'],
                      'certificate_preserved': certificate(origin_ip) == record['certificate_sha256']}
            record['readiness_checks'] = checks
            record.pop('readiness_error_type', None)
            write_record(record)
            if all(checks.values()):
                return
        except Exception as error:
            record['readiness_error_type'] = type(error).__name__
            write_record(record)
        time.sleep(5)
    raise RuntimeError('Staging approval, encrypted restore or certificate validation failed')


def rollback():
    if not RECORD.exists():
        return
    record = json.loads(RECORD.read_text())
    if not record.get('mutation_started') or record.get('rollback_complete') or record.get('accepted'):
        return
    if not record.get('rollback_resource_restored'):
        az('container', 'delete', '-g', GROUP, '-n', TARGET, '--yes')
        apply('rollback.json')
        record['rollback_resource_restored'] = True
        write_record(record)
    wait_ready(record)
    record['rollback_complete'] = True
    write_record(record)
    print('Previous staging runtime, station registration and TLS certificate restored')


def deploy():
    record = json.loads(RECORD.read_text())
    if not record.get('prepared') or fingerprint(resource()) != record['baseline_fingerprint']:
        raise ValueError('Staging changed since validated baseline; no deployment')
    if fingerprint(resource(PRODUCTION)) != record['production_fingerprint']:
        raise ValueError('Production changed concurrently; inspect before staging rollout')
    record['mutation_started'] = True
    write_record(record)
    try:
        az('container', 'delete', '-g', GROUP, '-n', TARGET, '--yes')
        apply('candidate.json')
        wait_ready(record)
        current = resource()
        if current['properties']['containers'][0]['properties']['image'] != record['candidate_image']:
            raise ValueError('Staging image mismatch')
        if fingerprint(resource(PRODUCTION)) != record['production_fingerprint']:
            raise ValueError('Production configuration changed during staging rollout')
        record['runtime_restored'] = True
        write_record(record)
    except BaseException:
        rollback()
        raise
    print('Staging restored its approved station and original TLS certificate; attestation checks follow')


def main(mode):
    if mode == 'prepare':
        prepare()
    elif mode == 'deploy':
        deploy()
    elif mode == 'rollback':
        rollback()
    elif mode == 'accept':
        record = json.loads(RECORD.read_text())
        assert record.get('runtime_restored') and not record.get('rollback_complete')
        wait_ready(record, timeout=20)
        record['accepted'] = True
        write_record(record)
        print('Staging runtime, preserved approval/certificate, and workflow attestation checks accepted')
    elif mode == 'cleanup':
        if PRIVATE.exists():
            for path in PRIVATE.iterdir():
                path.unlink()
            PRIVATE.rmdir()
    else:
        raise ValueError('Unsupported staging rollout operation')


if __name__ == '__main__':
    try:
        main(sys.argv[1])
    except Exception as error:
        print('Staging rollout stopped (' + type(error).__name__ + '); no private inputs printed')
        raise SystemExit(1)
