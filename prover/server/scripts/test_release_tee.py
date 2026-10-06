import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest

SCRIPTS = Path(__file__).resolve().parent
IMAGE = "registry.invalid/prover@sha256:" + "a" * 64
SNAPSHOT = b"trusted snapshot fixture"
DIGEST = hashlib.sha256(SNAPSHOT).hexdigest()


def plan(*args):
    return subprocess.run(
        ["bash", str(SCRIPTS / "release_tee.sh"), IMAGE, "fixture", "--photon", IMAGE,
         "--plan", *args], capture_output=True, text=True, timeout=10,
    )


def command(compose, service):
    match = re.search(r"^  " + service + r":\n(.*?)(?=^  \S|\Z)", compose, re.M | re.S)
    block = match[1].split("      - |\n", 1)[1].split("    volumes:", 1)[0]
    return textwrap.dedent(block).replace("$$", "$")


class SnapshotTests(unittest.TestCase):
    def run_service(self, service, digest, snapshot=None, url="", restored=None, fail=0):
        result = plan(*(["--photon-dump-sha256", digest] if digest else []))
        self.assertEqual(result.returncode, 0, result.stderr)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dump = root / "dump"
            dump.mkdir()
            if snapshot is not None:
                (dump / "photon.dump").write_bytes(snapshot)
            if restored is not None:
                (dump / "restored").write_text(restored)
            for name in ("curl", "pg_restore"):
                executable = root / name
                executable.write_text('#!/bin/sh\nprintf "%s\\n" called >> "$CALLED"\nexit "${FAIL:-0}"\n')
                executable.chmod(0o755)
            env = {"PATH": f"{root}:{os.environ['PATH']}", "CALLED": str(root / "called"),
                   "PHOTON_DUMP_URL": url, "PHOTON_DUMP_ID": DIGEST, "FAIL": str(fail)}
            ran = subprocess.run(
                ["sh", "-ec", command(result.stdout, service).replace("/dump", str(dump))],
                env=env, capture_output=True, text=True, timeout=10,
            )
            return ran.returncode, (root / "called").exists(), (
                (dump / "restored").read_text().strip() if (dump / "restored").exists() else None
            )

    def test_restore_rejects_unpinned_and_modified_snapshots(self):
        for digest, snapshot in (("", SNAPSHOT), (DIGEST, b"untrusted executable snapshot")):
            with self.subTest(digest=digest):
                code, called, restored = self.run_service("photon-restore", digest, snapshot)
                self.assertNotEqual(code, 0)
                self.assertFalse(called)
                self.assertIsNone(restored)

    def test_restore_accepts_only_the_measured_digest(self):
        code, called, restored = self.run_service("photon-restore", DIGEST, SNAPSHOT)
        self.assertEqual(code, 0)
        self.assertTrue(called)
        self.assertEqual(restored, DIGEST)

    def test_fetch_requires_a_pin_and_a_source(self):
        for digest, url in (("", "https://fixture.invalid/dump"), (DIGEST, "")):
            code, called, restored = self.run_service("photon-fetch", digest, url=url)
            self.assertNotEqual(code, 0)
            self.assertFalse(called)
            self.assertIsNone(restored)

    def test_completed_restore_does_not_fetch_again(self):
        code, called, restored = self.run_service("photon-fetch", DIGEST, restored=DIGEST)
        self.assertEqual(code, 0)
        self.assertFalse(called)
        self.assertEqual(restored, DIGEST)

    def test_failed_restore_never_marks_completion(self):
        code, called, restored = self.run_service("photon-restore", DIGEST, SNAPSHOT, fail=1)
        self.assertNotEqual(code, 0)
        self.assertTrue(called)
        self.assertIsNone(restored)

    def test_failed_download_stops_startup(self):
        code, called, restored = self.run_service(
            "photon-fetch", DIGEST, url="https://fixture.invalid/dump", fail=1,
        )
        self.assertNotEqual(code, 0)
        self.assertTrue(called)
        self.assertIsNone(restored)

    def test_digest_changes_measurement_and_database_volume(self):
        old = plan("--photon-dump-sha256", DIGEST).stdout
        new = plan("--photon-dump-sha256", "b" * 64).stdout
        empty = plan().stdout
        self.assertNotEqual(old, new)
        for compose, suffix in ((old, DIGEST), (new, "b" * 64), (empty, "chain")):
            self.assertIn(f"photon-db-{suffix}:/var/lib/postgresql/data", compose)
            self.assertIn(f"photon-dump-{suffix}:/dump", compose)
            self.assertNotIn("PHOTON_DUMP_ID", compose)

    def test_malformed_digest_is_rejected(self):
        for value in ("A" * 64, "x", "a" * 63, "a" * 65, "a\ncommand"):
            self.assertNotEqual(plan("--photon-dump-sha256", value).returncode, 0)


if __name__ == "__main__":
    unittest.main()
