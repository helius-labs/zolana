import json
import os
from pathlib import Path
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
                self.assertEqual(args[args.index("--indexer-url") + 1], "http://127.0.0.1:18884")
                if preload:
                    self.assertEqual(args[args.index("--preload-circuits") + 1], preload)
                else:
                    self.assertNotIn("--preload-circuits", args)


if __name__ == "__main__":
    unittest.main()
