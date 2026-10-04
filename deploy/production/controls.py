"""Production-only dashboard worker. No redirects or arbitrary destinations."""
import json
import os
import re
from urllib.request import HTTPRedirectHandler, Request, build_opener

BASE = 'https://org-live.openanonymity.ai/verifier/production_resilience'
VERIFIER = 'https://verifier-production-20260917.openanonymity.ai'


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(path='', data=None):
    secret = os.environ.get('PRODUCTION_RESILIENCE_WORKER_SECRET', '')
    if len(secret) < 32:
        raise ValueError('Production worker credential missing')
    req = Request(BASE + path, data=json.dumps(data).encode() if data is not None else None,
                  headers={'Authorization': 'Bearer ' + secret,
                           'Content-Type': 'application/json', 'User-Agent': 'Go-http-client/1.1'})
    with build_opener(NoRedirect()).open(req, timeout=20) as response:
        return json.load(response)


def validate(data):
    if data.get('environment') != 'production' or data.get('verifier_url', '').rstrip('/') != VERIFIER:
        raise ValueError('Wrong recovery-control environment')
    desired = data.get('desired', {})
    if (type(desired.get('revision')) is not int or desired['revision'] < 0
            or type(desired.get('encrypted_storage_enabled')) is not bool
            or type(desired.get('grace_enabled')) is not bool
            or desired.get('deployment', {}).get('phase') not in {'idle', 'pending', 'running', 'applied', 'failed'}):
        raise ValueError('Invalid production control record')
    return desired


def read():
    return validate(request())


def run_id():
    value = os.environ.get('GITHUB_RUN_ID', '')
    if not re.fullmatch(r'[0-9]{1,24}', value):
        raise ValueError('Invalid workflow run identifier')
    return value


def claim(revision, store):
    current = read()
    if (current['revision'] != revision or current['deployment']['phase'] != 'pending'
            or current['encrypted_storage_enabled'] != (store == 'keyvault-sealed')
            or current['grace_enabled'] is not True):
        raise ValueError('Request changed or grace disabled; no deployment')
    if request('/claim', {'revision': revision, 'run_id': run_id()}).get('claimed') is not True:
        raise ValueError('Production request was already claimed')


def check(revision, store):
    current = read()
    if (current['revision'] != revision or current['deployment'].get('run_id') != run_id()
            or current['deployment']['phase'] != 'running' or current['grace_enabled'] is not True
            or current['encrypted_storage_enabled'] != (store == 'keyvault-sealed')):
        raise ValueError('Production claim no longer matches; no mutation')


def complete(revision, success):
    if request('/complete', {'revision': revision, 'run_id': run_id(), 'success': success}).get('recorded') is not True:
        raise ValueError('Deployment result was not recorded')
