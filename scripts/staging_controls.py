"""Read a fixed staging control endpoint; never accept an arbitrary target URL."""
import json
import os
import sys
from urllib.request import HTTPRedirectHandler, Request, build_opener

BASE = 'https://org-staging.openanonymity.ai'


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def validate(payload):
    if payload.get('environment') != 'staging' or payload.get('storage_control_ready') is not True:
        raise ValueError('Staging storage control is not ready')
    desired = payload.get('desired', {})
    revision = desired.get('revision')
    enabled = desired.get('encrypted_storage_enabled')
    if type(revision) is not int or revision < 0 or type(enabled) is not bool:
        raise ValueError('Invalid staging storage control')
    return revision, 'keyvault-sealed' if enabled else 'none'


def read():
    if os.environ.get('REGISTRY_BASE_URL', '').rstrip('/') != BASE:
        raise ValueError('Registry must be staging')
    credential = os.environ.get('REGISTRY_AUTH', '')
    if not credential:
        raise ValueError('Registry credential missing')
    request = Request(BASE + '/verifier/staging_resilience', headers={
        'Authorization': 'Bearer ' + credential, 'User-Agent': 'Go-http-client/1.1'})
    with build_opener(NoRedirect()).open(request, timeout=15) as response:
        return validate(json.load(response))


def claim(revision):
    request = Request(BASE + '/verifier/staging_resilience/claim', method='POST',
        data=json.dumps({'revision': revision}).encode(), headers={
            'Authorization': 'Bearer ' + os.environ['REGISTRY_AUTH'],
            'Content-Type': 'application/json', 'User-Agent': 'Go-http-client/1.1'})
    with build_opener(NoRedirect()).open(request, timeout=15) as response:
        return json.load(response).get('claimed') is True


def main():
    if os.environ.get('DASHBOARD_CONTROLS') != 'true':
        return
    revision, store = read()
    expected = os.environ.get('EXPECTED_CONTROLS_REVISION', '')
    if expected and str(revision) != expected:
        raise ValueError('Staging controls changed; deployment stopped')
    if os.environ.get('CONTROL_MODE') == 'check':
        if str(revision) != os.environ.get('RESILIENCE_REVISION'):
            raise ValueError('Staging controls changed while building; deployment stopped')
        return
    with open(os.environ['GITHUB_ENV'], 'a') as target:
        target.write(f'DASHBOARD_STATION_STATE_STORE={store}\nRESILIENCE_REVISION={revision}\n')
    print(f'Staging storage requested: {store}; revision {revision}')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # HTTP errors may contain sensitive server details: only the class.
        print('Staging control check failed: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
