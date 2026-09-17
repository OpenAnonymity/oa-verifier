"""Read-only new-container diagnostics; raw log data never leaves this process."""
import json, os, re, subprocess
from pathlib import Path

command = ['az','container','logs','--resource-group','oa-verifier','--name','oa-verifier-production-20260917',
           '--container-name','oa-verifier','--only-show-errors']
result = subprocess.run(command, capture_output=True, text=True)
if result.returncode: raise SystemExit('Read-only isolated log retrieval failed; response suppressed')
logs = result.stdout
categories = [
    'registration request received', 'registration: cookie verified', 'three-way binding established',
    'registration rejected: failed to verify cookie', 'registration rejected: failed to fetch activity data',
    'registration rejected: failed to fetch registry', 'registration rejected: workspace data fetch failed',
    'registration rejected: FAILED privacy toggle check - BANNING', 'registration rejected: unable to verify privacy toggles',
    'failed cleanup of existing provisioning keys', 'failed to create provisioning key', 'created provisioning key',
    'station registered successfully', 'response missing data.key', 'response missing data.keys or data.total_count',
    'unexpected status', 'decode response', 'failed to notify org update', 'context deadline exceeded',
]
summary = {'target':'oa-verifier-production-20260917', 'line_count':len(logs.splitlines()),
           'event_counts':{category:logs.count(category) for category in categories if category in logs},
           'http_status_counts':{str(code):len(re.findall(r'(?:HTTP|status(?:_code)?)[\s=:]+"?'+str(code)+r'\b',logs)) for code in [400,401,403,404,409,422,429,500,502,503]},
           'configured_secret_occurrences':{key:logs.count(os.environ[key]) for key in ['ACR_PASSWORD','PRODUCTION_REGISTRY_SECRET','CF_DNS_API_TOKEN'] if os.environ.get(key)},
           'credential_pattern_counts':{'provider_key':len(re.findall(r'sk-or-v\d-[A-Za-z0-9_-]{16,}',logs)),
                                        'jwt':len(re.findall(r'eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}',logs))}}
Path('diagnostic-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
