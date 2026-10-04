"""Dispatch without claiming: the eventual deploy run owns the fenced claim."""
import json
import subprocess
import controls

REPO = 'OpenAnonymity/oa-verifier'
WORKFLOW = 'deploy-production-verifier.yml'


def main():
    desired = controls.read()
    if desired['deployment']['phase'] != 'pending':
        print('No pending production deployment request')
        return
    if desired['grace_enabled'] is not True:
        raise ValueError('Grace must be enabled before a production verifier deployment')
    runs = json.loads(subprocess.check_output([
        'gh', 'run', 'list', '-R', REPO, '--workflow', WORKFLOW,
        '--limit', '100', '--json', 'status'], text=True))
    if any(run['status'] != 'completed' for run in runs):
        print('Production preparation/deployment already running; no duplicate dispatch')
        return
    subprocess.run(['gh', 'workflow', 'run', WORKFLOW, '-R', REPO, '--ref', 'main',
                    '-f', 'operation=deploy', '-f', 'controls_revision=' + str(desired['revision']),
                    '-f', 'station_store=' + ('keyvault-sealed' if desired['encrypted_storage_enabled'] else 'none')], check=True)
    print('Production deployment dispatched; the deployment run will claim this exact revision')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('Production dispatcher stopped: ' + type(error).__name__) from None
