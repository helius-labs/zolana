import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('catalog',Path(__file__).with_name('release-catalog.py'))
catalog=importlib.util.module_from_spec(spec);spec.loader.exec_module(catalog)


class ReleaseCatalog(unittest.TestCase):
    def test_client_policy_merge_does_not_rotate_measured_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):return subprocess.check_output(['git','-C',directory,*args],text=True).strip()
            git('init','-q');git('config','user.name','test');git('config','user.email','test@example.com');git('config','commit.gpgsign','false')
            root=Path(directory);(root/'prover/server').mkdir(parents=True);(root/'tools').mkdir()
            (root/'prover/server/main.go').write_text('package main\n');(root/'tools/images.json').write_text('{}')
            git('add','.');git('commit','-qm','measured inputs');initial=git('rev-parse','HEAD')
            config={'source_commit':initial,'client_prover':{'backend':'gnark','concurrency':2}}
            base={'nitro':{'measurements':{'indexer_url':'https://indexer.example'}}}
            def command(*args):return git(*args[1:])
            real_run=subprocess.run
            def run(args,**kwargs):
                if args[:2]==['git','merge-base']:kwargs['cwd']=directory
                return real_run(args,**kwargs)
            with patch.object(catalog,'command',side_effect=command),patch.object(catalog.subprocess,'run',side_effect=run):
                before=catalog.nitro_profile(config,base,initial)
                (root/'policy.json').write_text('new delivered client pins');git('add','.');git('commit','-qm','accept next identity')
                after=catalog.nitro_profile(config,base,git('rev-parse','HEAD'))
                self.assertEqual(before,after);self.assertEqual(catalog.digest(before),catalog.digest(after))
                (root/'prover/server/main.go').write_text('package main\n// real runtime change\n');git('add','.');git('commit','-qm','new server')
                self.assertNotEqual(before,catalog.nitro_profile(config,base,git('rev-parse','HEAD')))

    def test_partial_or_duplicate_release_is_never_deployable(self):
        base={'version':1,'id':'old','components':{'photon':{'image':'old'},'forester':{'image':'old'},'forester_prover':{'image':'old'}},'nitro':{},'source_commit':'old'}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);parts=root/'parts';parts.mkdir();quality=root/'quality.json';quality.write_text('{"passed":true,"runs":[1]}')
            (parts/'photon.json').write_text(json.dumps({'kind':'component','name':'photon','image':'new','source_commit':'a'*40}))
            environment={'GITHUB_SHA':'a'*40,'EXPECTED_SERVICES':'["photon","forester"]','EXPECTED_NITRO':'false','GITHUB_OUTPUT':str(root/'outputs')}
            with patch.dict(os.environ,environment),patch.object(catalog,'infra_file',return_value=copy.deepcopy(base)),self.assertRaisesRegex(ValueError,'Incomplete'):catalog.assemble(parts,'base',quality,root/'release.json')
            self.assertFalse((root/'release.json').exists())
            (parts/'duplicate.json').write_text((parts/'photon.json').read_text())
            with patch.dict(os.environ,environment),patch.object(catalog,'infra_file',return_value=copy.deepcopy(base)),self.assertRaisesRegex(ValueError,'Duplicate'):catalog.assemble(parts,'base',quality,root/'release.json')
            self.assertFalse((root/'release.json').exists())


class ProtocolPublicationGate(unittest.TestCase):
    def test_program_migration_blocks_publication_before_building(self):
        configuration={'source_commit':'a'*40,'compatible_protocol_builds':[{'protocol_source':'a'*40,'source_commit':'b'*40}]}
        with patch.object(catalog,'command',side_effect=['programs/shielded-pool/src/lib.rs','program-libs/interface/src/lib.rs']),self.assertRaisesRegex(ValueError,'protocol migration'):
            catalog.verify_protocol(configuration,'c'*40)
        with patch.object(catalog,'command',side_effect=['program-libs/tree/src/lib.rs','']):
            catalog.verify_protocol(configuration,'c'*40)
        unrelated={'source_commit':'a'*40,'compatible_protocol_builds':[{'protocol_source':'f'*40,'source_commit':'b'*40}]}
        with patch.object(catalog,'command',return_value='programs/shielded-pool/src/lib.rs') as command,self.assertRaises(ValueError):catalog.verify_protocol(unrelated,'c'*40)
        self.assertEqual(command.call_count,1)
