#!/usr/bin/env python3
"""Verify new endpoint against signed MAA claims and locally built CCE policy."""
import base64, hashlib, json, re, secrets, socket, ssl, time
from pathlib import Path
import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

record = json.loads(Path('production-record.json').read_text())
host = 'verifier-production-20260917.openanonymity.ai'
endpoint = 'https://' + host
nonce = secrets.token_hex(24)
attestation = None
for attempt in range(60):
    try:
        r = requests.get(endpoint + '/attestation', params={'nonce': nonce}, timeout=30)
        r.raise_for_status(); attestation = r.json()
        if attestation.get('token'): break
    except (requests.RequestException, ValueError): pass
    if attempt % 6 == 0: print('Waiting for trusted TLS and confidential attestation', flush=True)
    time.sleep(10)
if not attestation or not attestation.get('token'):
    raise RuntimeError('New endpoint did not return a trusted-TLS attestation')
token = attestation['token']; header = jwt.get_unverified_header(token)
key_url = header.get('jku') or attestation.get('verify_at')
if key_url != 'https://sharedeus.eus.attest.azure.net/certs':
    raise RuntimeError('Untrusted attestation signing-key endpoint')
if attestation.get('verify_at') and attestation['verify_at'] != key_url:
    raise RuntimeError('Signing-key URL mismatch')
if header.get('alg') not in ['RS256', 'RS384', 'RS512']:
    raise RuntimeError('Unexpected attestation signing algorithm')
keys = requests.get(key_url, timeout=30, allow_redirects=False); keys.raise_for_status()
if keys.status_code != 200: raise RuntimeError('Attestation JWK redirect or invalid response')
jwk = next(k for k in keys.json()['keys'] if k['kid'] == header['kid'])
claims = jwt.decode(token, jwt.PyJWK.from_dict(jwk).key, algorithms=[header['alg']],
    issuer=key_url.removesuffix('/certs'), options={'verify_aud': False, 'require': ['exp', 'iat', 'iss']}, leeway=30)
runtime = claims.get('x-ms-runtime', {})
if isinstance(runtime.get('client-payload'), dict): runtime = runtime['client-payload']
if runtime.get('nonce') != nonce: raise RuntimeError('Attestation freshness nonce mismatch')
if claims.get('x-ms-sevsnpvm-is-debuggable') is not False:
    raise RuntimeError('Confidential VM debug-disabled claim missing or false')
if claims.get('x-ms-attestation-type') != 'sevsnpvm' or claims.get('x-ms-compliance-status') != 'azure-compliant-uvm':
    raise RuntimeError('Expected Azure compliant confidential VM attestation')
policy_hash = hashlib.sha256(base64.b64decode(attestation['policy']['base64'])).hexdigest()
if policy_hash != record['policy_sha256'] or claims.get('x-ms-sevsnpvm-hostdata') != policy_hash:
    raise RuntimeError('Hardware policy measurement differs from built policy')
context = ssl.create_default_context()
with socket.create_connection((host, 443), timeout=30) as tcp:
    with context.wrap_socket(tcp, server_hostname=host) as tls:
        cert = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
key = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
tls_hash = hashlib.sha256(key).hexdigest()
if runtime.get('tls_hash') != tls_hash:
    raise RuntimeError('Signed attestation does not bind to live TLS key')
result = {'endpoint': endpoint, 'source_revision': record['source_revision'], 'image_ref': record['image_ref'],
    'policy_sha256': policy_hash, 'tls_spki_sha256': tls_hash, 'jwt_signature_verified': True,
    'jwt_time_claims_verified': True, 'fresh_nonce_verified': True, 'debug_disabled_verified': True,
    'source_policy_matches_hardware': True, 'tls_channel_binding_verified': True}
Path('verification-result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
