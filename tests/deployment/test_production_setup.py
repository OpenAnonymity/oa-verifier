"""Scope guards run against a fake Azure CLI; never touch cloud resources."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/setup_production_encrypted_storage.sh'


class ProductionSetupGuards(unittest.TestCase):
    def reject(self, overrides):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root/'az'
            fake.write_text('''#!/usr/bin/env python3
import json,os,sys
with open(os.environ['AZ_CALLS'],'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')
args=sys.argv[1:]
if args[:2]==['account','show'] and '--query' in args and args[args.index('--query')+1]=='id':
 print(os.environ['FAKE_SUBSCRIPTION'])
elif args[:3]==['ad','signed-in-user','show']: print('synthetic-owner')
elif args[:3]==['ad','sp','list']: print('unexpected-principal')
''')
            fake.chmod(0o755)
            (root/'jq').write_text('#!/bin/sh\nexit 0\n');(root/'jq').chmod(0o755)
            env={**os.environ,'PATH':str(root)+':'+os.environ['PATH'],'AZ_CALLS':str(root/'calls'),
                 'FAKE_SUBSCRIPTION':'839b147d-853e-4611-aaa9-f6c6fa4c14ad',**overrides}
            result=subprocess.run(['bash',str(SCRIPT)],env=env,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            calls=[json.loads(x) for x in (root/'calls').read_text().splitlines()]
            self.assertFalse(any(set(x)&{'create','update','delete','purge','recover'} for x in calls))
            return result.stderr

    def test_wrong_subscription_stops_before_writes(self):
        self.assertIn('Wrong Azure subscription',self.reject({'FAKE_SUBSCRIPTION':'wrong'}))

    def test_staging_vault_override_stops_before_writes(self):
        self.assertIn('production-only',self.reject({'VAULT_NAME':'oa-verifier2-sealed'}))

    def test_wrong_deploy_principal_stops_before_writes(self):
        self.assertIn('Unexpected deployment principal',self.reject({}))

    def test_resource_setup_cannot_restart_or_delete_a_container(self):
        source=SCRIPT.read_text()
        self.assertNotIn('az container ',source)
        self.assertNotIn('az deployment ',source)
        self.assertNotIn('az keyvault delete ',source)
        self.assertIn('--enable-purge-protection true',source)
        self.assertIn('"$DEPLOY_SP_OBJECT_ID" "$KEK_RES"',source)
        self.assertIn('PROD_STATION_STATE_STORE',source)


if __name__=='__main__': unittest.main()
