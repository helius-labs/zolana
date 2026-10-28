"""Exercise the actual reusable workflow worker against deployment API fixtures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import time
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/publish-client-policy.yml'
SCRIPT = textwrap.dedent(WORKFLOW.read_text().split("python3 - <<'PYCODE'\n", 1)[1].split('\n          PYCODE', 1)[0])


class ClientStatusWorker(unittest.TestCase):
    def run_worker(self, *, state='success', latest=42, actual_sha='a'*40):
        now=int(time.time());nonce='b'*64
        request={'version':1,'request_id':nonce,'cohort':'sdk','receipt_id':'c'*64,
                 'deployment':{'repository':'org/client','id':42,'sha':'a'*40,'environment':'production'},
                 'issued_at':now-5,'expires_at':now+895}
        fresh={'Key':'client-policy-checks/123/sdk/requests/'+nonce+'.json','LastModified':datetime.fromtimestamp(now,timezone.utc).isoformat()}
        historical={'Key':'client-policy-checks/123/sdk/requests/'+'d'*64+'.json','LastModified':datetime.fromtimestamp(now-3600,timezone.utc).isoformat()}
        gets=[]
        def output(args,**kwargs):
            if args[0]=='aws':return json.dumps({'Contents':[historical,fresh]})
            path=args[2]
            if '/deployments?' in path:return json.dumps([{'id':latest}] if latest else [])
            if path.endswith('/statuses'):return json.dumps([{'state':state}])
            return json.dumps({'sha':actual_sha,'environment':'production'})
        def run(args,**kwargs):
            if 'get-object' in args:
                key=args[args.index('--key')+1];gets.append(key)
                self.assertEqual(key,fresh['Key'],'Expired requests must not consume API work or delay fresh responses')
                Path(args[-1]).write_text(json.dumps(request))
                return subprocess.CompletedProcess(args,0,'','')
            return subprocess.CompletedProcess(args,254,'','404')
        with tempfile.TemporaryDirectory() as directory:
            env={'COHORT':'sdk','TARGET_ENVIRONMENT':'production','GITHUB_REPOSITORY':'org/client',
                 'GITHUB_REPOSITORY_ID':'123','RUNNER_TEMP':directory,'GITHUB_OUTPUT':directory+'/outputs'}
            with patch.dict(os.environ,env),patch('subprocess.check_output',side_effect=output),patch('subprocess.run',side_effect=run):
                exec(compile(SCRIPT,str(WORKFLOW),'exec'),{})
            response=json.loads((Path(directory)/'client-checks'/(nonce+'.json')).read_text())
            self.assertEqual(Path(directory,'outputs').read_text(),'any=true\n')
        self.assertEqual(gets,[fresh['Key']])
        self.assertEqual(response['request_digest'],hashlib.sha256(json.dumps(request,sort_keys=True,separators=(',',':')).encode()).hexdigest())
        return response

    def test_current_success_is_bound_to_the_request_and_history_is_not_replayed(self):
        self.assertTrue(self.run_worker()['current'])

    def test_failed_retired_newer_missing_and_wrong_commit_deployments_are_rejected(self):
        for edit in ({'state':'failure'},{'state':'inactive'},{'latest':43},{'latest':None},{'actual_sha':'e'*40}):
            with self.subTest(edit=edit):self.assertFalse(self.run_worker(**edit)['current'])
