import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('native',Path(__file__).with_name('native-policy-checks.py'))
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)


class PolicyCodeBoundary(unittest.TestCase):
    def test_generated_policy_ci_cannot_execute_unrelated_pr_code(self):
        shas={'head':'a'*40,'base':'b'*40,'merge':'c'*40}
        for path in ('tools/release-client-policy.py','package.json','.github/workflows/async-prover.yml','sdk-libs/ts/src/client/client.ts'):
            def command(*args):return path if args[:2]==('git','diff') else ''
            with self.subTest(path=path),patch.object(native.policy,'command',side_effect=command),patch.object(native.policy,'qualified') as qualification,self.assertRaisesRegex(ValueError,'only generated policy'):
                native.validate(shas,'d'*64)
            qualification.assert_not_called()

    def test_stale_or_forked_policy_pr_cannot_be_validated(self):
        pr={'state':'open','head':{'sha':'a'*40,'ref':native.policy.BRANCH,'repo':{'full_name':native.REPO}},'base':{'ref':'main','sha':'b'*40},'mergeable':True,'merge_commit_sha':'c'*40}
        with patch.object(native,'api',return_value=pr),self.assertRaises(ValueError):native.identity('489','f'*40)
        pr['head']['repo']['full_name']='attacker/zolana'
        with patch.object(native,'api',return_value=pr),self.assertRaises(ValueError):native.identity('489','a'*40)
