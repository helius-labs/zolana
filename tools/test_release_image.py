import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT=Path(__file__).with_name('release-image.sh')
SHA='a'*40
DIGEST='sha256:'+'b'*64
FAKE=r'''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
name=Path(sys.argv[0]).name;args=sys.argv[1:]
with open(os.environ['CALL_LOG'],'a') as log:log.write(json.dumps([name,*args])+'\n')
if name=='gh':
    if args[:2]==['attestation','verify']:
        if args[2].startswith('oci://'):sys.exit(1)
        sys.exit(0 if os.environ.get('SIGNED_INTENT')=='true' else 1)
if name=='docker':
    if args[0]=='inspect':
        print('sha256:'+'c'*64 if '.Id' in args[2] else 'a'*40)
    sys.exit(0)
if name=='aws':
    if args[:2]==['ecr','describe-images']:print('sha256:'+'b'*64)
    elif args[:2]==['ecr','batch-get-image']:print('{}')
    elif args[:2]==['ecr','put-image']:sys.exit(1)
    elif args[:2]==['s3','cp']:
        Path(args[-1]).write_text(json.dumps({'config_digest':'sha256:'+'c'*64,'source_commit':'a'*40,'service':'photon'}))
    else:sys.exit(1)
'''


class PublishRecovery(unittest.TestCase):
    def run_case(self,mode,signed):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);binary=root/'bin';binary.mkdir()
            for tool in ('aws','gh','docker'):
                file=binary/tool;file.write_text(FAKE);file.chmod(0o755)
            env={**os.environ,'PATH':str(binary)+':'+os.environ['PATH'],'RUNNER_TEMP':directory,'GITHUB_OUTPUT':str(root/'output'),
                 'GITHUB_SHA':SHA,'GITHUB_REPOSITORY':'helius-labs/zolana','CALL_LOG':str(root/'calls'),
                 'SIGNED_INTENT':str(signed).lower(),'EXISTING_DIGEST':DIGEST}
            result=subprocess.run(['bash',str(SCRIPT),mode,'photon','zolana-photon','photon-zolana-'+SHA[:12],'publish-service-image.yml'],env=env,capture_output=True,text=True)
            output=(root/'output').read_text() if (root/'output').exists() else ''
            calls=[json.loads(line) for line in (root/'calls').read_text().splitlines()]
            return result,output,calls

    def test_push_succeeded_attestation_failed_retry_recovers_only_signed_config(self):
        result,output,calls=self.run_case('resolve',True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('needs_attestation=true',output);self.assertIn('digest='+DIGEST,output)
        self.assertFalse(any(call[:2]==['docker','push'] for call in calls))
        self.assertTrue(any(call[0]=='gh' and '--source-digest' in call and SHA in call for call in calls))

    def test_an_unsigned_image_cannot_be_adopted_or_reported_as_ready(self):
        result,output,calls=self.run_case('resolve',False)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('digest=',output)
        self.assertFalse(any(call[:2]==['docker','tag'] for call in calls))

    def test_retry_finishes_when_immutable_tag_already_names_the_same_image(self):
        result,output,calls=self.run_case('push',True)
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('digest='+DIGEST,output)
        self.assertFalse(any(call[:2]==['docker','push'] for call in calls))
