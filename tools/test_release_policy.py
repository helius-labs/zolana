import copy
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('policy',Path(__file__).with_name('release-client-policy.py'))
policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)


class PolicyRotation(unittest.TestCase):
    def test_rotation_keeps_old_pairs_and_is_idempotent(self):
        old={'platform':'aws-nitro','measurements':[{'pcr0':'a'*96,'pcr1':'b'*96,'pcr2':'c'*96}],'hpke_public_key':'d'*64,'gpu':'optional','max_age_secs':600}
        candidate={'nitro':{'measurements':{'PCR0':'e'*96,'PCR1':'f'*96,'PCR2':'1'*96},'hpke_public_key':'2'*64}}
        updated=policy.overlap(old,candidate)
        self.assertNotIn('hpke_public_key',updated)
        self.assertEqual(updated['measurements'][0],{**old['measurements'][0],'hpke_public_key':'d'*64})
        self.assertEqual(updated['measurements'][1],{'pcr0':'e'*96,'pcr1':'f'*96,'pcr2':'1'*96,'hpke_public_key':'2'*64})
        self.assertEqual(policy.overlap(updated,candidate),updated)
        self.assertEqual(old['hpke_public_key'],'d'*64)

    def test_conflicting_existing_global_and_per_image_keys_fail_closed(self):
        old={'platform':'aws-nitro','measurements':[{'pcr0':'a'*96,'pcr1':'b'*96,'pcr2':'c'*96,'hpke_public_key':'e'*64}],'hpke_public_key':'d'*64,'gpu':'optional','max_age_secs':600}
        with self.assertRaisesRegex(ValueError,'Conflicting'):
            policy.overlap(old,{'nitro':{'measurements':{},'hpke_public_key':'f'*64}})
