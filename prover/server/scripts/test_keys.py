"""Unit tests for keys.py. Offline: the object store and HTTP are faked.

    python3 -m unittest discover -s prover/server/scripts -p 'test_*.py'
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keys  # noqa: E402

REPO = keys.Repo(keys.REPO_ROOT)
LOCK_TEXT = REPO.path(keys.LOCK_REL).read_text()
LOCK = json.loads(LOCK_TEXT)
FINGERPRINT_SOURCE = REPO.path(keys.FINGERPRINT_REL).read_text()
TRANSFER_SHAPES = 11


def legacy_prefix(keys_map: dict, base: str = "proving-keys") -> str:
    """generate_lockfile.py's version hash, verbatim, as it was before keys.py."""
    canonical = json.dumps(
        {name: entry["sha256"] for name, entry in keys_map.items() if "source" not in entry},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    version = hashlib.sha256(canonical).hexdigest()[:16]
    return f"{base.rstrip('/')}/{version}"


class KeyTableTest(unittest.TestCase):
    def test_every_committed_key_derives(self):
        specs = keys.key_table(LOCK["keys"])
        groups = {}
        for spec in specs.values():
            groups[spec.group] = groups.get(spec.group, 0) + 1
        self.assertEqual(
            groups,
            {"transfer": 3 * TRANSFER_SHAPES + 4, "merge": 4, "batch": 2, "custom-ring": 6},
        )
        self.assertEqual(len(specs), len(LOCK["keys"]))

    def test_setup_commands(self):
        spec = keys.spec_for_name
        self.assertEqual(
            spec("transfer_p256_ring_36_2.key").setup,
            ("setup-transfer", "--circuit", "transfer-p256-ring", "--n-inputs", "36", "--n-outputs", "2"),
        )
        self.assertEqual(
            spec("transfer_ring_authority_4_4.key").setup[:3],
            ("setup-transfer", "--circuit", "transfer-ring-authority"),
        )
        self.assertEqual(
            spec("merge_ring_36_1.key").setup,
            ("setup-merge", "--circuit", "merge-ring", "--n-inputs", "36"),
        )
        self.assertEqual(
            spec("merge_8_1.key").setup,
            ("setup-merge", "--circuit", "merge", "--n-inputs", "8"),
        )
        self.assertEqual(
            spec("batch_address-append_40_250.key").setup,
            ("setup", "--circuit", "address-append", "--address-append-tree-height", "40",
             "--address-append-batch-size", "250"),
        )
        self.assertTrue(spec("batch_address-append_40_250.key").writes_vkey)
        self.assertEqual(spec("custom_ring_compressed_policy.key").setup, ("setup-custom-ring-compressed-policy",))
        self.assertFalse(spec("custom_ring_compressed_policy.key").writes_vkey)

    def test_verifying_key_paths(self):
        spec = keys.spec_for_name
        self.assertEqual(spec("transfer_ring_1_2.key").vk_path, keys.INTERFACE_VK_REL / "transfer_ring_1_2.rs")
        self.assertEqual(spec("merge_36_1.key").module_dir, keys.INTERFACE_VK_REL)
        self.assertEqual(
            spec("batch_address-append_40_10.key").vk_path,
            keys.TREE_VK_REL / "batch_address_append_40_10.rs",
        )
        self.assertEqual(
            spec("custom_ring_register_key.key").vk_path,
            keys.RING_VK_REL / "register_key_verifying_key.rs",
        )
        self.assertIsNone(spec("custom_ring_register_key.key").module_dir)

    def test_setup_commands_exist_in_the_prover(self):
        types = REPO.path("prover/server/prover/common/types.go").read_text()
        main = REPO.path("prover/server/main.go").read_text()
        circuits = set(re.findall(r'CircuitType = "([a-z0-9-]+)"', types))
        for spec in keys.key_table(LOCK["keys"]).values():
            if spec.group == "transfer":
                self.assertIn(spec.setup[2], circuits, spec.name)
            elif spec.group == "merge":
                self.assertIn(f'"{spec.setup[2]}"', main, spec.name)
            elif spec.group == "custom-ring":
                self.assertIn(spec.setup[0].removeprefix("setup-"), circuits, spec.name)
            else:
                self.assertEqual(spec.setup[:3], ("setup", "--circuit", "address-append"))
                self.assertIn('"address-append"', types)

    def test_unknown_names_are_rejected(self):
        for name in ("transfer_ring_1_2", "merge_8_2.key", "unknown_1_1.key", "custom_ring_.key"):
            with self.assertRaises(keys.KeysError, msg=name):
                keys.spec_for_name(name)

    def test_selection(self):
        names = LOCK["keys"]
        self.assertEqual(len(keys.select_keys(names, ["custom-ring"])), 6)
        self.assertEqual(
            keys.select_keys(names, ["merge"]),
            ["merge_36_1.key", "merge_8_1.key", "merge_ring_36_1.key", "merge_ring_8_1.key"],
        )
        self.assertEqual(keys.select_keys(names, ["merge-ring"]), ["merge_ring_36_1.key", "merge_ring_8_1.key"])
        self.assertEqual(len(keys.select_keys(names, ["transfer-ring"])), TRANSFER_SHAPES)
        self.assertEqual(keys.select_keys(names, keys=["transfer_ring_1_2"]), ["transfer_ring_1_2.key"])
        everything_but_base = keys.select_keys(names, ["all"], skips=["custom_ring_base"])
        self.assertEqual(len(everything_but_base), len(names) - 1)
        self.assertNotIn("custom_ring_base.key", everything_but_base)
        with self.assertRaises(keys.KeysError):
            keys.select_keys(names, ["nope"])
        with self.assertRaises(keys.KeysError):
            keys.select_keys(names, keys=["transfer_ring_6_2"])
        with self.assertRaises(keys.KeysError):
            keys.select_keys(names, ["merge"], skips=["transfer_ring_1_2"])
        self.assertEqual(
            keys.select_keys(names, keys=["transfer_ring_6_2"], allow_add=True), ["transfer_ring_6_2.key"]
        )


class LockfileTest(unittest.TestCase):
    def test_prefix_matches_generate_lockfile(self):
        self.assertEqual(keys.compute_prefix(LOCK["keys"]), legacy_prefix(LOCK["keys"]))
        self.assertEqual(keys.compute_prefix(LOCK["keys"]), LOCK["prefix"])

    def test_render_is_byte_identical(self):
        self.assertEqual(keys.render_lock(LOCK), LOCK_TEXT)

    def test_committed_lock_is_valid(self):
        self.assertEqual(keys.lock_errors(LOCK), [])

    def test_repository_check_passes(self):
        self.assertEqual(keys.check_repo(REPO), [])

    def test_regenerated_release_key_keeps_source_and_prefix(self):
        proposed = keys.propose_manifest(LOCK, {"custom_ring_policy.key": ("ab" * 32, 7)})
        self.assertEqual(proposed["keys"]["custom_ring_policy.key"], {"sha256": "ab" * 32, "size": 7, "source": "release"})
        self.assertEqual(proposed["prefix"], LOCK["prefix"])
        self.assertEqual(proposed["prefix"], legacy_prefix(proposed["keys"]))

    def test_regenerated_object_store_key_moves_prefix(self):
        proposed = keys.propose_manifest(LOCK, {"transfer_ring_1_2.key": ("cd" * 32, 9)})
        self.assertNotEqual(proposed["prefix"], LOCK["prefix"])
        self.assertEqual(proposed["prefix"], legacy_prefix(proposed["keys"]))
        self.assertEqual(keys.lock_errors(proposed), [])

    def test_schema_errors(self):
        def broken(mutate):
            manifest = json.loads(LOCK_TEXT)
            mutate(manifest)
            return keys.lock_errors(manifest)

        self.assertTrue(broken(lambda m: m["keys"]["merge_8_1.key"].update(sha256="XYZ")))
        self.assertTrue(broken(lambda m: m["keys"]["merge_8_1.key"].update(size=0)))
        self.assertTrue(broken(lambda m: m["keys"]["merge_8_1.key"].update(extra=1)))
        self.assertTrue(broken(lambda m: m["keys"]["merge_8_1.key"].update(source="s3")))
        self.assertTrue(broken(lambda m: m.update(prefix="proving-keys/0000000000000000")))
        self.assertTrue(broken(lambda m: m["keys"].update({"bogus.key": dict(LOCK["keys"]["merge_8_1.key"])})))
        self.assertTrue(broken(lambda m: m.update(extra=1)))


class FingerprintTest(unittest.TestCase):
    def setUp(self):
        self.pinned = keys.parse_fingerprints(FINGERPRINT_SOURCE)
        self.families = keys.fingerprint_families(self.pinned, LOCK["keys"])

    def test_families_are_derived_for_every_fingerprint(self):
        self.assertEqual(len(self.pinned), 13)
        self.assertEqual(set(self.families), set(self.pinned))
        self.assertEqual(self.families["merge_8_1"], {"merge_8_1.key", "merge_36_1.key"})
        self.assertEqual(self.families["merge_ring_8_1"], {"merge_ring_8_1.key", "merge_ring_36_1.key"})
        self.assertEqual(
            self.families["batch_address-append_40_10"],
            {"batch_address-append_40_10.key", "batch_address-append_40_250.key"},
        )
        self.assertEqual(len(self.families["transfer_ring_2_3"]), TRANSFER_SHAPES)
        self.assertEqual(len(self.families["transfer_ring_authority_2_2"]), 4)
        self.assertEqual(self.families["custom_ring_policy"], {"custom_ring_policy.key"})
        covered = set().union(*self.families.values())
        self.assertEqual(covered, set(LOCK["keys"]))

    def test_key_without_fingerprint_is_an_error(self):
        pinned = dict(self.pinned)
        del pinned["custom_ring_deposit"]
        with self.assertRaisesRegex(keys.KeysError, "custom_ring_deposit.key has no circuit fingerprint"):
            keys.fingerprint_families(pinned, LOCK["keys"])

    def test_unchanged_fingerprints_leave_the_source_alone(self):
        self.assertEqual(
            keys.update_fingerprints(FINGERPRINT_SOURCE, self.pinned, [], self.families), FINGERPRINT_SOURCE
        )

    def test_changed_circuit_requires_its_whole_family(self):
        actual = dict(self.pinned, merge_8_1=(1, 2))
        with self.assertRaisesRegex(keys.KeysError, "merge_36_1.key"):
            keys.update_fingerprints(FINGERPRINT_SOURCE, actual, ["merge_8_1.key"], self.families)
        updated = keys.update_fingerprints(
            FINGERPRINT_SOURCE, actual, ["merge_8_1.key", "merge_36_1.key"], self.families
        )
        self.assertIn('"merge_8_1":                     {constraints: 1, public: 2},', updated)
        self.assertEqual(keys.parse_fingerprints(updated), actual)
        self.assertEqual(len(updated.splitlines()), len(FINGERPRINT_SOURCE.splitlines()))

    def test_go_test_output_parses(self):
        output = '=== RUN   T\n\t"merge_8_1": {constraints: 177739, public: 2},\n--- SKIP: T\n'
        self.assertEqual(keys.parse_fingerprints(output), {"merge_8_1": (177739, 2)})

    def test_fingerprint_set_mismatch_is_an_error(self):
        actual = dict(self.pinned)
        del actual["merge_8_1"]
        with self.assertRaises(keys.KeysError):
            keys.update_fingerprints(FINGERPRINT_SOURCE, actual, [], self.families)


class ModuleListTest(unittest.TestCase):
    def test_committed_module_lists_render_unchanged(self):
        for module_dir, modules in keys.modules_by_dir(keys.key_table(LOCK["keys"])).items():
            text = REPO.path(module_dir / "mod.rs").read_text()
            self.assertEqual(keys.render_module_list(text, modules), text, module_dir)

    def test_new_module_is_inserted_in_order(self):
        text = REPO.path(keys.INTERFACE_VK_REL / "mod.rs").read_text()
        _, _, modules = keys.split_module_list(text)
        rendered = keys.render_module_list(text, modules + ["transfer_ring_6_2"])
        self.assertIn(
            'pub mod transfer_ring_5_4;\n#[cfg(feature = "verifying-keys")]\npub mod transfer_ring_6_2;\n',
            rendered,
        )
        self.assertTrue(rendered.startswith(text.split("#[cfg")[0]))

    def test_trailing_content_is_refused(self):
        with self.assertRaises(keys.KeysError):
            keys.split_module_list("pub mod a;\nfn main() {}\n")


# --- publishing with a fake bucket ------------------------------------------

BASE_URL = "https://cdn.test"


def entry(data: bytes, source: str | None = None) -> dict:
    value = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    if source:
        value["source"] = source
    return value


def manifest(entries: dict) -> dict:
    return {"keys": entries, "prefix": keys.compute_prefix(entries)}


class FakeBucket:
    def __init__(self, objects=None):
        self.objects = dict(objects or {})
        self.writes = []

    def size(self, prefix, name):
        data = self.objects.get(f"{prefix}/{name}")
        return None if data is None else len(data)

    def copy(self, source_prefix, prefix, name):
        self.writes.append(("copy", name))
        self.objects[f"{prefix}/{name}"] = self.objects[f"{source_prefix}/{name}"]

    def upload(self, path, prefix, name):
        self.writes.append(("upload", name))
        self.objects[f"{prefix}/{name}"] = Path(path).read_bytes()


class FakeHttp:
    """Serves the bucket at BASE_URL and a fixed map of other URLs."""

    def __init__(self, bucket, extra=None, corrupt=()):
        self.bucket, self.extra, self.corrupt = bucket, dict(extra or {}), set(corrupt)
        self.digested, self.headed = [], []

    def _data(self, url):
        if url in self.extra:
            data = self.extra[url]
        else:
            self.assert_prefix(url)
            data = self.bucket.objects.get(url[len(BASE_URL) + 1:])
        if data is not None and url.rsplit("/", 1)[1] in self.corrupt:
            data = data + b"!"
        return data

    @staticmethod
    def assert_prefix(url):
        if not url.startswith(BASE_URL + "/"):
            raise AssertionError(f"unexpected url {url}")

    def size(self, url):
        self.headed.append(url.rsplit("/", 1)[1])
        data = self._data(url)
        return None if data is None else len(data)

    def digest(self, url, sink=None):
        self.digested.append(url.rsplit("/", 1)[1])
        data = self._data(url)
        if data is None:
            raise keys.KeysError("HTTP 403")
        if sink:
            Path(sink).write_bytes(data)
        return len(data), hashlib.sha256(data).hexdigest()


OLD = {
    "transfer_ring_1_2.key": b"transfer 1x2",
    "transfer_ring_2_2.key": b"transfer 2x2 old",
    "merge_8_1.key": b"merge 8",
    "custom_ring_base.key": b"ring base",
}
NEW_2_2 = b"transfer 2x2 regenerated"


class PublishTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop("ZOLANA_PROVING_KEYS_URL", None)
        os.environ.pop("ZOLANA_RING_KEYS_URL", None)
        mock.patch.object(keys, "VERIFY_DELAY_SECONDS", 0).start()
        mock.patch.object(keys, "VERIFY_ATTEMPTS", 2).start()
        mock.patch("sys.stderr", io.StringIO()).start()
        self.addCleanup(mock.patch.stopall)

        self.repo_root = root / "repo"
        (self.repo_root / keys.DOWNLOADER_REL).parent.mkdir(parents=True)
        (self.repo_root / keys.DOWNLOADER_REL).write_text(f'defaultProvingKeysBaseURL = "{BASE_URL}"\n')
        self.repo = keys.Repo(self.repo_root)
        self.keys_dir = root / "live-keys"
        self.keys_dir.mkdir()

        self.base = manifest({
            name: entry(data, "release" if name.startswith("custom_ring") else None)
            for name, data in OLD.items()
        })
        self.write_repo_lock(self.base)
        self.old = self.base["prefix"]
        self.bucket = FakeBucket({
            f"{self.old}/transfer_ring_1_2.key": OLD["transfer_ring_1_2.key"],
            f"{self.old}/transfer_ring_2_2.key": OLD["transfer_ring_2_2.key"],
            f"{self.old}/merge_8_1.key": OLD["merge_8_1.key"],
        })

    def write_repo_lock(self, value):
        path = self.repo_root / keys.LOCK_REL
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(keys.render_lock(value))

    def repo_lock(self):
        return json.loads((self.repo_root / keys.LOCK_REL).read_text())

    def rotation(self, generated: dict[str, bytes], name="rotation"):
        directory = Path(self.tmp.name) / name
        for key, data in generated.items():
            (directory / "keys").mkdir(parents=True, exist_ok=True)
            (directory / "keys" / key).write_bytes(data)
        proposed = keys.propose_manifest(
            self.base, {k: (hashlib.sha256(d).hexdigest(), len(d)) for k, d in generated.items()}
        )
        rotation = keys.Rotation(directory, self.base, proposed, sorted(generated))
        rotation.stage(keys.LOCK_REL, keys.render_lock(proposed).encode())
        rotation.stage(Path("vk/transfer_ring_2_2.rs"), b"// new vk\n")
        rotation.save()
        return keys.Rotation.load(directory)

    def plan(self, rotation):
        return {a.name: a.kind for a in keys.plan_publish(rotation, self.bucket, [self.keys_dir])}

    def test_unchanged_keys_are_copied_and_regenerated_keys_uploaded(self):
        rotation = self.rotation({"transfer_ring_2_2.key": NEW_2_2})
        self.assertEqual(self.plan(rotation), {
            "transfer_ring_1_2.key": "copy",
            "transfer_ring_2_2.key": "upload",
            "merge_8_1.key": "copy",
            "custom_ring_base.key": "release",
        })

    def test_unchanged_key_missing_from_old_folder_uploads_a_verified_local_copy(self):
        del self.bucket.objects[f"{self.old}/merge_8_1.key"]
        rotation = self.rotation({"transfer_ring_2_2.key": NEW_2_2})
        with self.assertRaisesRegex(keys.KeysError, "merge_8_1.key: not in"):
            self.plan(rotation)
        (self.keys_dir / "merge_8_1.key").write_bytes(b"merge 8 but different")
        with self.assertRaisesRegex(keys.KeysError, "merge_8_1.key"):
            self.plan(rotation)
        (self.keys_dir / "merge_8_1.key").write_bytes(OLD["merge_8_1.key"])
        self.assertEqual(self.plan(rotation)["merge_8_1.key"], "upload")

    def test_stale_object_in_old_folder_is_not_copied(self):
        self.bucket.objects[f"{self.old}/merge_8_1.key"] = b"stale"
        rotation = self.rotation({"transfer_ring_2_2.key": NEW_2_2})
        with self.assertRaisesRegex(keys.KeysError, "merge_8_1.key"):
            self.plan(rotation)

    def test_interrupted_publish_resumes_and_never_overwrites(self):
        rotation = self.rotation({"transfer_ring_2_2.key": NEW_2_2})
        new = rotation.manifest["prefix"]
        self.bucket.objects[f"{new}/transfer_ring_1_2.key"] = OLD["transfer_ring_1_2.key"]
        self.assertEqual(self.plan(rotation)["transfer_ring_1_2.key"], "present")
        self.bucket.objects[f"{new}/transfer_ring_2_2.key"] = b"short"
        with self.assertRaisesRegex(keys.KeysError, "immutable"):
            self.plan(rotation)

    def test_release_only_rotation_keeps_the_folder(self):
        rotation = self.rotation({"custom_ring_base.key": b"ring base v2"})
        self.assertEqual(rotation.manifest["prefix"], self.old)
        self.assertEqual(rotation.manifest["keys"]["custom_ring_base.key"]["source"], "release")
        self.assertEqual(set(self.plan(rotation).values()), {"present", "release"})
        self.assertIn("gh release create", keys.release_instructions(rotation))

    def test_publish_uploads_verifies_then_updates_the_repository(self):
        rotation = self.rotation({"transfer_ring_2_2.key": NEW_2_2})
        http = FakeHttp(self.bucket)
        keys.publish(self.repo, rotation, self.bucket, http, self.keys_dir)
        new = rotation.manifest["prefix"]
        self.assertEqual(sorted(self.bucket.writes), [
            ("copy", "merge_8_1.key"), ("copy", "transfer_ring_1_2.key"), ("upload", "transfer_ring_2_2.key"),
        ])
        self.assertEqual(self.bucket.objects[f"{new}/transfer_ring_2_2.key"], NEW_2_2)
        # Uploaded bytes are hashed, copies are checked by size.
        self.assertEqual(http.digested, ["transfer_ring_2_2.key"])
        self.assertEqual(sorted(http.headed), ["merge_8_1.key", "transfer_ring_1_2.key"])
        self.assertEqual(self.repo_lock(), rotation.manifest)
        self.assertEqual((self.repo_root / "vk/transfer_ring_2_2.rs").read_bytes(), b"// new vk\n")
        self.assertEqual((self.keys_dir / "transfer_ring_2_2.key").read_bytes(), NEW_2_2)

    def test_failed_verification_leaves_the_repository_and_staging_alone(self):
        rotation = self.rotation({"transfer_ring_2_2.key": NEW_2_2})
        http = FakeHttp(self.bucket, corrupt={"transfer_ring_2_2.key"})
        with self.assertRaises(keys.KeysError):
            keys.publish(self.repo, rotation, self.bucket, http, self.keys_dir)
        self.assertEqual(self.repo_lock(), self.base)
        self.assertFalse((self.repo_root / "vk/transfer_ring_2_2.rs").exists())
        self.assertTrue((rotation.directory / keys.PLAN_FILE).exists())
        # Re-running once the object is served correctly finishes the job.
        keys.publish(self.repo, keys.Rotation.load(rotation.directory), self.bucket, FakeHttp(self.bucket), self.keys_dir)
        self.assertEqual(self.repo_lock(), rotation.manifest)

    def test_dry_run_writes_nothing(self):
        rotation = self.rotation({"transfer_ring_2_2.key": NEW_2_2})
        keys.publish(self.repo, rotation, self.bucket, FakeHttp(self.bucket), self.keys_dir, dry_run=True)
        self.assertEqual(self.bucket.writes, [])
        self.assertEqual(self.repo_lock(), self.base)

    def test_apply_refuses_a_moved_lockfile(self):
        rotation = self.rotation({"transfer_ring_2_2.key": NEW_2_2})
        moved = keys.propose_manifest(self.base, {"merge_8_1.key": ("ef" * 32, 3)})
        self.write_repo_lock(moved)
        with self.assertRaisesRegex(keys.KeysError, "changed since"):
            keys.apply_rotation(self.repo, rotation, None)

    def test_apply_is_idempotent_after_no_publish(self):
        rotation = self.rotation({"transfer_ring_2_2.key": NEW_2_2})
        keys.apply_rotation(self.repo, rotation, self.keys_dir)
        self.assertEqual(self.repo_lock(), rotation.manifest)
        keys.publish(self.repo, rotation, self.bucket, FakeHttp(self.bucket), self.keys_dir)
        self.assertEqual(self.repo_lock(), rotation.manifest)

    def test_install_survives_the_prover_replacing_the_live_key(self):
        rotation = self.rotation({"transfer_ring_2_2.key": NEW_2_2})
        keys.apply_rotation(self.repo, rotation, self.keys_dir)
        live = self.keys_dir / "transfer_ring_2_2.key"
        replacement = self.keys_dir / "transfer_ring_2_2.key.tmp"
        replacement.write_bytes(OLD["transfer_ring_2_2.key"])
        os.replace(replacement, live)
        self.assertEqual((rotation.keys_dir / "transfer_ring_2_2.key").read_bytes(), NEW_2_2)

    def test_migrating_release_keys_stages_a_folder_with_every_key(self):
        release = f"{keys.DEFAULT_RELEASE_URL}/custom_ring_base.key"
        http = FakeHttp(self.bucket, extra={release: OLD["custom_ring_base.key"]})
        args = SimpleNamespace(out=Path(self.tmp.name) / "migration", keys_dir=self.keys_dir)
        rotation = keys.migrate_release_keys(self.repo, args, http)
        self.assertTrue(all("source" not in e for e in rotation.manifest["keys"].values()))
        self.assertEqual(rotation.manifest["prefix"], legacy_prefix(rotation.manifest["keys"]))
        self.assertNotEqual(rotation.manifest["prefix"], self.old)
        self.assertEqual(self.plan(rotation), {
            "transfer_ring_1_2.key": "copy",
            "transfer_ring_2_2.key": "copy",
            "merge_8_1.key": "copy",
            "custom_ring_base.key": "upload",
        })
        keys.publish(self.repo, rotation, self.bucket, http, self.keys_dir)
        self.assertEqual(self.repo_lock(), rotation.manifest)
        self.assertEqual(http.digested[-1:], ["custom_ring_base.key"])

    def test_migration_refuses_a_bad_release_asset(self):
        release = f"{keys.DEFAULT_RELEASE_URL}/custom_ring_base.key"
        http = FakeHttp(self.bucket, extra={release: b"tampered"})
        args = SimpleNamespace(out=Path(self.tmp.name) / "migration", keys_dir=self.keys_dir)
        with self.assertRaisesRegex(keys.KeysError, "does not match"):
            keys.migrate_release_keys(self.repo, args, http)


if __name__ == "__main__":
    unittest.main()
