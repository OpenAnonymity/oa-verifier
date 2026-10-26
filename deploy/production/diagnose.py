import json
import subprocess

def az(*args):
    p = subprocess.run(['az', *args, '-o', 'json'], capture_output=True, text=True)
    return json.loads(p.stdout) if p.returncode == 0 else None

def errors(obj):
    result = []
    if isinstance(obj, dict):
        if obj.get('code'):
            result.append({'code': obj['code']})
        for value in obj.values():
            result.extend(errors(value))
    elif isinstance(obj, list):
        for value in obj:
            result.extend(errors(value))
    return result

deployment = az('deployment', 'group', 'show', '-g', 'oa-verifier', '-n', 'prod-resilience-40347482903')
operations = az('deployment', 'operation', 'group', 'list', '-g', 'oa-verifier', '-n', 'prod-resilience-40347482903')
resource = az('container', 'show', '-g', 'oa-verifier', '-n', 'oa-verifier-production-20260917')
print(json.dumps({'deployment_error_codes':errors((deployment or {}).get('properties',{}).get('error')),
 'operation_error_codes':errors(operations),'resource_exists':resource is not None,
 'resource_state':(resource or {}).get('provisioningState'),
 'containers':[{'name':c.get('name'),'state':c.get('instanceView',{}).get('currentState',{}).get('state'),
  'events':[{'name':e.get('name'),'type':e.get('type')} for e in c.get('instanceView',{}).get('events',[])]} for c in (resource or {}).get('containers',[])]}))
