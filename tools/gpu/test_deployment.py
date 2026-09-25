import json
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import unittest

from validate import database_identity

SCRIPTS = Path(__file__).resolve().parent


class DatabaseIsolationTests(unittest.TestCase):
    def test_rejects_remote_routes(self):
        for url in (
            "postgres://user@remote/database",
            "postgres://user@127.0.0.1/database?host=remote",
            "postgres://user@127.0.0.1/database?hostaddr=192.0.2.1",
            "postgres://user@127.0.0.1/database?service=devnet",
            "postgres://user@127.0.0.1/database#options",
            "postgres://user@127.0.0.1/database\n",
            "postgres://127.0.0.1/database",
            "postgres://user@127.0.0.1/",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                database_identity(url)

    def test_rotation_preserves_database_identity(self):
        identity = database_identity("postgres://user:old@127.0.0.1/database")
        self.assertEqual(identity, database_identity("postgres://user:new@127.0.0.1:5432/database"))
        for url in (
            "postgres://user@127.0.0.1:5433/database",
            "postgres://user@127.0.0.1/another",
            "postgres://another@127.0.0.1/database",
        ):
            with self.subTest(url=url):
                self.assertNotEqual(identity, database_identity(url))


class ServiceLaunchTests(unittest.TestCase):
    def test_migration_stops_with_service(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "current").mkdir()
            (root / "deployment.env").touch()
            migration = root / "current/photon-migration"
            migration.write_text(
                "#!/usr/bin/env python3\nimport json, os, signal\n"
                "print(json.dumps({'pid': os.getpid(), 'group': os.getpgrp()}), flush=True)\n"
                "signal.pause()\n"
            )
            migration.chmod(0o755)
            child = None
            process = subprocess.Popen(
                ["bash", str(SCRIPTS / "run-service.sh"), directory, "photon"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                start_new_session=True,
            )
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                self.assertTrue(ready, "migration did not start")
                child = json.loads(process.stdout.readline())
                self.assertEqual(child["group"], process.pid)
                os.killpg(process.pid, signal.SIGTERM)
                process.communicate(timeout=3)
            finally:
                for pid, kill in ((process.pid, os.killpg), (child["pid"] if child else None, os.kill)):
                    if pid is not None:
                        try:
                            kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                process.communicate(timeout=3)

    def test_prover_uses_local_indexer_without_empty_preload(self):
        for preload in ("", "merge:36:1"):
            with self.subTest(preload=preload), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "current").mkdir()
                (root / "deployment.env").write_text(
                    f"PHOTON_PORT=18884\nPROVER_PRELOAD_CIRCUITS='{preload}'\n"
                    "PROVER_INDEXER_URL=https://remote.invalid\n"
                )
                binary = root / "current/light-prover"
                binary.write_text("#!/usr/bin/env python3\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n")
                binary.chmod(0o755)
                result = subprocess.run(
                    ["bash", str(SCRIPTS / "run-service.sh"), directory, "prover"],
                    check=True, capture_output=True, text=True, env=os.environ.copy(),
                )
                args = json.loads(result.stdout)
                self.assertNotIn("", args)
                self.assertIn("--auto-download", args)
                self.assertEqual(args[args.index("--indexer-url") + 1], "http://127.0.0.1:18884")
                if preload:
                    self.assertEqual(args[args.index("--preload-circuits") + 1], preload)
                else:
                    self.assertNotIn("--preload-circuits", args)

    def test_photon_starts_only_after_successful_migration(self):
        for migration_status in (0, 1):
            with self.subTest(status=migration_status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "current").mkdir()
                (root / "deployment.env").write_text(
                    "PHOTON_RPC_URL=https://rpc.invalid\n"
                    "DATABASE_URL=postgres://user@127.0.0.1/photon\n"
                )
                migration = root / "current/photon-migration"
                migration.write_text(
                    "#!/usr/bin/env bash\nset -eu\n"
                    '[[ $1 == up && $DATABASE_URL == postgres://user@127.0.0.1/photon ]]\n'
                    'touch "$(dirname "$0")/migrated"\n'
                    f"exit {migration_status}\n"
                )
                photon = root / "current/photon"
                photon.write_text(
                    '#!/usr/bin/env bash\nset -eu\n[[ -f "$(dirname "$0")/migrated" ]]\n'
                    'touch "$(dirname "$0")/started"\n'
                )
                migration.chmod(0o755)
                photon.chmod(0o755)
                result = subprocess.run(
                    ["bash", str(SCRIPTS / "run-service.sh"), directory, "photon"],
                    capture_output=True, text=True, env=os.environ.copy(), timeout=10,
                )
                self.assertEqual(result.returncode, migration_status, result.stderr)
                self.assertTrue((root / "current/migrated").exists())
                self.assertEqual((root / "current/started").exists(), migration_status == 0)


if __name__ == "__main__":
    unittest.main()
