"""Diagnose or restore one historical staging deployment; never expose its inputs."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

GROUP, TARGET = 'oa-verifier', 'oa-verifier-2'
SOURCE = 'staging-grace-41491594280'
POLICY = '954982a0766422d53757d7bd0890dfe1cd2b1e9f81a84e94bad1f3bf90b6f9c8'
DOMAIN = 'verifier2.openanonymity.ai'
CODES = ('FailedIdentityOperation', 'DeploymentActive', 'DeploymentFailed', 'InvalidTemplateDeployment',
         'InvalidTemplate', 'InvalidRequestContent', 'InvalidResourceIdentityTenantId',
         'InvalidResourceIdentityPrincipalId', 'InaccessibleImage', 'AuthorizationFailed',
         'ResourceNotFound', 'ContainerGroupStartFailed', 'InternalServerError', 'BadRequest')


def categories(text):
    lower = text.lower()
    return {'codes': [c for c in CODES if c.lower() in lower],
            'identity_deletion_pending': 'failedidentityoperation' in lower and 'delet' in lower and 'pending' in lower}


def az(*args, optional=False, retries=0):
    for attempt in range(retries + 1):
        result = subprocess.run(['az', *args, '--only-show-errors', '-o', 'json'], capture_output=True, text=True)
        if not result.returncode:
            return json.loads(result.stdout or 'null')
        diagnostic = categories(result.stderr)
        if diagnostic['identity_deletion_pending'] and attempt < retries:
            print(json.dumps({'operation': list(args[:3]), 'retry': attempt + 1, **diagnostic}), flush=True)
            time.sleep(20)
            continue
        if optional and 'ResourceNotFound' in diagnostic['codes']:
            return None
        print(json.dumps({'operation': list(args[:3]), **diagnostic}), flush=True)
        raise RuntimeError('Azure command failed; private response withheld')


def validate(template):
    resources = template.get('resources', [])
    if len(resources) != 1:
        raise ValueError('Only one staging resource may be restored')
    resource = resources[0]
    if resource.get('name') != TARGET or resource.get('location') != 'eastus':
        raise ValueError('Wrong staging target')
    if resource['properties'].get('sku') != 'Confidential':
        raise ValueError('Confidential runtime required')
    app = next(c for c in resource['properties']['containers'] if c['name'] == 'oa-verifier')
    env = {row['name']: row for row in app['properties']['environmentVariables']}
    if (env['TLS_DOMAIN'].get('value') != DOMAIN
            or env['STATION_REGISTRY_URL'].get('value') != 'https://org-staging.openanonymity.ai'
            or env['STATION_STATE_STORE'].get('value') != 'keyvault-sealed'
            or env['TLS_CERT_STORE'].get('value') != 'keyvault-sealed'):
        raise ValueError('Wrong staging identity or encrypted stores')
    digest = hashlib.sha256(base64.b64decode(env['CCE_POLICY_B64']['value'], validate=True)).hexdigest()
    if digest != POLICY:
        raise ValueError('Historical measured policy differs from saved baseline')
    image = app['properties']['image']
    if not re.fullmatch(r'oaverifieracr\.azurecr\.io/oa-verifier@sha256:[0-9a-f]{64}', image):
        raise ValueError('Immutable staging image required')
    return image


def restore_write_inputs(template, environ):
    result = copy.deepcopy(template)
    props = result['resources'][0]['properties']
    props.pop('isCustomProvisioningTimeout', None)
    for container in props['containers']:
        config = container['properties'].get('configMap')
        if config is not None and not config.get('keyValuePairs'):
            container['properties'].pop('configMap')
    logging = (props.get('diagnostics') or {}).get('logAnalytics')
    if logging is not None and not logging.get('workspaceKey'):
        if not environ.get('LOG_ANALYTICS_WORKSPACE_KEY'):
            raise ValueError('Existing logging credential required for restoration')
        if logging.get('workspaceId') != environ.get('LOG_ANALYTICS_WORKSPACE_ID'):
            raise ValueError('Logging workspace differs from configured staging workspace')
        logging['workspaceKey'] = environ['LOG_ANALYTICS_WORKSPACE_KEY']
    return result


def main(operation):
    if az('account', 'show').get('id') != '839b147d-853e-4611-aaa9-f6c6fa4c14ad':
        raise ValueError('Wrong subscription')
    group = az('container', 'show', '-g', GROUP, '-n', TARGET, optional=True)
    history = az('deployment', 'group', 'show', '-g', GROUP, '-n', SOURCE)
    operations = az('deployment', 'operation', 'group', 'list', '-g', GROUP, '-n', SOURCE, optional=True)
    diagnostic = categories(json.dumps({'error': (history.get('properties') or {}).get('error'), 'operations': operations}))
    template = az('deployment', 'group', 'export', '-g', GROUP, '-n', SOURCE)
    image = validate(template)
    props = template['resources'][0]['properties']
    app = next(c for c in props['containers'] if c['name'] == 'oa-verifier')
    null_env = [row['name'] for row in app['properties']['environmentVariables']
                if row.get('value') is None and not row.get('secureValue')]
    error_text = json.dumps({'error': (history.get('properties') or {}).get('error'), 'operations': operations}).lower()
    words = ('environment', 'variable', 'value', 'null', 'empty', 'required', 'password', 'username', 'configmap', 'keyvaluepairs', 'workspacekey', 'loganalytics', 'iscustomprovisioningtimeout',
             'identity', 'tenantid', 'principalid', 'provisioningtimeoutinseconds', 'iscreatedfromstandbypool',
             'dnsnamelabelreusepolicy', 'standbypoolprofile', 'subnet', 'confidential', 'security', 'policy',
             'extension', 'resource', 'cpu', 'memory', 'requests', 'limits', 'deserializ', 'unsupported',
             'invalid', 'not allowed', 'unknown', 'cannot', 'range', 'greater', 'less', 'zero')
    print(json.dumps({'diagnostic_categories': [word for word in words if word in error_text],
                      'property_names': list(props), 'null_environment_names': null_env,
                      'container_property_names': list(app['properties']), 'config_map_empty': not bool((app['properties'].get('configMap') or {}).get('keyValuePairs')), 'diagnostic_key_present': bool(((props.get('diagnostics') or {}).get('logAnalytics') or {}).get('workspaceKey')),
                      'pull_credential_shapes': [{'identity_present': bool(c.get('identity')), 'username_present': bool(c.get('username')), 'password_present': bool(c.get('password'))} for c in props.get('imageRegistryCredentials', [])]}), flush=True)
    print(json.dumps({'target': TARGET, 'operation': operation, 'group_exists': bool(group),
                      'provisioning_state': group.get('provisioningState') if group else None,
                      'history_error_categories': diagnostic, 'historical_image': image,
                      'historical_policy_matches': True}), flush=True)
    if operation == 'diagnose':
        return
    if operation != 'recover' or os.environ.get('CONFIRM_RECOVERY') != 'true':
        raise ValueError('Explicit recovery required')
    if group and group.get('provisioningState') != 'Failed':
        raise ValueError('Existing group is not explicitly failed; leave it untouched')
    template = restore_write_inputs(template, os.environ)
    if validate(template) != image:
        raise ValueError('Restoration changed historical image')
    if group:
        az('container', 'delete', '-g', GROUP, '-n', TARGET, '--yes')
    with tempfile.TemporaryDirectory(prefix='staging-recovery-') as directory:
        path = Path(directory) / 'recovery.json'
        path.write_text(json.dumps(template))
        path.chmod(0o600)
        az('deployment', 'group', 'validate', '-g', GROUP, '--template-file', str(path))
        az('deployment', 'group', 'create', '-g', GROUP, '-n', 'staging-recovery-' + os.environ['GITHUB_RUN_ID'],
           '--template-file', str(path), retries=6)
    restored = az('container', 'show', '-g', GROUP, '-n', TARGET)
    if next(c['image'] for c in restored['containers'] if c['name'] == 'oa-verifier') != image:
        raise ValueError('Restored image mismatch')
    print(json.dumps({'target': TARGET, 'historical_image_restored': True,
                      'provisioning_state': restored.get('provisioningState')}), flush=True)


if __name__ == '__main__':
    try:
        main(os.environ.get('RECOVERY_OPERATION', 'diagnose'))
    except Exception as error:
        print('Staging recovery stopped (' + type(error).__name__ + '); no credentials printed')
        raise SystemExit(1)
