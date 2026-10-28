import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('release_changes', Path(__file__).with_name('release-changes.py'))
release_changes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_changes)


class ChangedServices(unittest.TestCase):
    def test_docs_do_not_publish(self):
        self.assertEqual(release_changes.changed_services(['README.md']), {'services': [], 'nitro': False})

    def test_shared_rust_dependencies_rebuild_both_rust_services(self):
        self.assertEqual(release_changes.changed_services(['program-libs/interface/src/lib.rs'])['services'], ['photon', 'forester'])

    def test_prover_changes_include_nitro(self):
        self.assertEqual(release_changes.changed_services(['prover/server/go.mod']), {'services': ['prover'], 'nitro': True})

    def test_photon_smoke_changes_are_not_missed(self):
        self.assertEqual(release_changes.changed_services(['tools/check-photon-image.sh'])['services'], ['photon'])

    def test_protocol_operations_changes_publish_forester_from_its_new_location(self):
        for path in ('protocol-ops/forester/src/run.rs','protocol-ops/instructions/src/lib.rs',
                     'protocol-ops/forester-prover/src/client.rs','protocol-ops/merkle-tree/src/lib.rs'):
            with self.subTest(path=path):
                self.assertEqual(release_changes.changed_services([path]), {'services':['forester'],'nitro':False})
