"""Restore the exact prior signed production deployment after failed recreation."""
import copy
import json
import os
from pathlib import Path
import subprocess
import rollout as r

assert os.environ['GITHUB_REF'] == 'refs/heads/release/verifier-provider-grace-20261026'
current = subprocess.run(['az','container','show','-g',r.GROUP,'-n',r.TARGET,'-o','json'], capture_output=True,text=True)
assert current.returncode != 0, 'Recovery only creates the absent fixed target'
template = r.az('deployment','group','export','-g',r.GROUP,'-n','prod-resilience-40347482903')
assert len(template['resources']) == 1
resource = template['resources'][0]
assert resource['name'] == r.TARGET and resource['properties']['sku'] == 'Confidential'
assert resource['properties']['containers'][0]['properties']['image'] == r.BASE_IMAGE
assert resource['properties']['containers'][1]['properties']['image'] == r.SIDECAR
assert resource['properties']['confidentialComputeProperties']['ccePolicy']
identity = resource['identity']
assert identity['type'] == 'UserAssigned' and set(identity['userAssignedIdentities']) == {r.IDENTITY}
resource['identity'] = {'type':'UserAssigned','userAssignedIdentities':{r.IDENTITY:{}}}
values = {'registrySecret':os.environ['PRODUCTION_REGISTRY_SECRET'],
 'cfDnsToken':os.environ['CF_DNS_API_TOKEN'],'acmeEmail':os.environ['ACME_EMAIL'],
 'acrUsername':os.environ['ACR_USERNAME'],'acrPassword':os.environ['ACR_PASSWORD']}
assert set(template['parameters']) <= set(values)
values = {k:values[k] for k in template['parameters']}
assert all(values.values())
path = r.private_write('recovery.json',template)
r.write_parameters('recovery-parameters.json',values)
try:
    r.az('deployment','group','validate','-g',r.GROUP,'--template-file',str(path),
      '--parameters','@'+str(r.PRIVATE/'recovery-parameters.json'))
    r.az('deployment','group','create','-g',r.GROUP,'-n','prod-recover-'+os.environ['GITHUB_RUN_ID'],
      '--template-file',str(path),'--parameters','@'+str(r.PRIVATE/'recovery-parameters.json'))
    live = r.current_resource()
    assert live['properties']['containers'][0]['properties']['image'] == r.BASE_IMAGE
    print('Prior signed production container restored; live recovery checks remain required')
finally:
    r.cleanup()
