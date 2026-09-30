import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

import aws
import aws_host
from test_aws import config, host_install, stack_outputs
from validate import database_identity

SCRIPTS = Path(__file__).resolve().parent
SECRET = "fixture-secret"
DATABASE = f"postgres://photon:{SECRET}%2F@127.0.0.1:5432/photon_gpu"
RPC = f"https://rpc.invalid/?api-key={SECRET}"
PROVER = ["start", "--require-optimized-build", "--server-only", "--auto-download", "--preload-keys", "none"]
LOOPBACK = ["--prover-address", "127.0.0.1:3003", "--metrics-address", "127.0.0.1:9997",
            "--indexer-url", "http://127.0.0.1:8784"]
PROVER_ENV = {"PROVER_TRANSFER_CONCURRENCY": "2", "PROVER_REQUEST_TIMING": "true"}
PHOTON_ENV = {"TOKIO_WORKER_THREADS": "2"}
MIGRATION = ["--kill-after=10s", f"{aws_host.MIGRATION_SECONDS}s"]
OPERATOR = {"prover": {"GOGC": "50", "AEGLOS_MEMORY_LIMIT_BYTES": "1073741824", "CUDA_VISIBLE_DEVICES": "0"},
            "photon": {"RUST_LOG": "info"}}
# Photon accepts its database and RPC URLs only as flags.
PHOTON_URL_FLAGS = ("--db-url", "--rpc-url")
RECORDER = """#!/usr/bin/env python3
import json, os, sys
name = os.path.basename(sys.argv[0])
with open(os.environ["RECORD"], "a") as record:
    record.write(json.dumps({"argv": [name, *sys.argv[1:]], "env": dict(os.environ)}) + "\\n")
outputs = {"id": ["0", 0], "nvidia-smi": ["8.9", 0], "psql": ["0", 0], **json.loads(os.environ.get("FAKE_OUTPUTS", "{}"))}
text, code = outputs.get(name, ["", 0])
print(text)
sys.exit(code or name == "supervisorctl" and "pid" in sys.argv)
"""


def photon_args(database):
    return ["--port", "8784", "--rpc-url", RPC, "--db-url", database, "--max-db-conn", "20",
            "--max-concurrent-block-fetches", "10", "--logging-format", "json"]


def fake(path):
    path.write_text(RECORDER)
    path.chmod(0o755)


def record(directory, command, fakes, env=None):
    tools = directory / "bin"
    tools.mkdir()
    for name in fakes:
        fake(tools / name)
    log = directory / "record.jsonl"
    log.touch()
    subprocess.run(
        command, check=True, capture_output=True, text=True, timeout=60,
        env={**(env or {}), "PATH": f"{tools}:{os.environ['PATH']}", "RECORD": str(log)},
    )
    return [json.loads(line) for line in log.read_text().splitlines()]


def deployment_env(directory):
    settings = {"DEPLOYMENT_NAME": "fixture", "DATABASE_URL": DATABASE, "PHOTON_RPC_URL": RPC, "PROVER_API_KEY": SECRET,
                **OPERATOR["prover"], **OPERATOR["photon"]}
    (directory / "deployment.env").write_text("".join(f"{name}={value}\n" for name, value in settings.items()))


def service_records(directory, service):
    (directory / "current").mkdir(parents=True)
    deployment_env(directory)
    for name in ("photon-migration", "photon", "light-prover"):
        fake(directory / "current" / name)
    return record(directory, ["bash", str(SCRIPTS / "run-service.sh"), str(directory), service], ["timeout"])


def install_records(directory, outputs=None):
    bundle = directory / "bundle"
    bundle.mkdir(parents=True)
    deployment_env(bundle)
    for name in ("light-prover", "photon", "photon-migration"):
        fake(bundle / name)
    (bundle / "cuda-arch").write_text("sm_89\n")
    (bundle / "source-revision").write_text("c" * 40 + "\n")
    (bundle / "cache.dump").touch()
    (bundle / "validate.py").write_text((SCRIPTS / "validate.py").read_text())
    return record(
        directory, ["bash", str(SCRIPTS / "install.sh"), str(bundle), "vast"],
        ["id", "sha256sum", "nvidia-smi", "psql", "pg_restore", "install", "ln", "mv", "touch",
         "supervisorctl", "supervisord", "curl"],
        {"FAKE_OUTPUTS": json.dumps(outputs or {})},
    )


def aws_host_records(directory):
    directory.mkdir()
    calls = []
    host_install(directory, calls, secret=lambda arn, _: RPC if arn == config()["rpc_secret"] else SECRET)
    return calls


def export_records(directory):
    definitions = []

    def call(service, operation, **parameters):
        if operation == "register-task-definition":
            definitions.extend(parameters["ContainerDefinitions"])
            return {"taskDefinition": {"taskDefinitionArn": "export"}}
        if operation == "run-task":
            return {"tasks": [{"taskArn": "export"}]}
        if operation == "describe-tasks":
            return {"tasks": [{"lastStatus": "STOPPED", "containers": [{"exitCode": 0}]}]}
        return {}

    aws.export_cache(Mock(call=Mock(side_effect=call)), config(), stack_outputs(), "zolana-gpu-test")
    (definition,) = definitions
    env = {item["name"]: item["value"] for item in definition["environment"]}
    env["DATABASE_URL"] = f"postgres://reader:{SECRET}%2F@db.invalid:5432/photon"
    directory.mkdir()
    return record(directory, [*definition["entryPoint"], *definition["command"]], ["apt-get", "aws", "pg_dump"], env)


def started(records, name):
    return next(record for record in records if record["argv"][0] == name)


def container(records, name, image):
    argv, env = next(
        (record["argv"], record["env"]) for record in records
        if record["argv"][:2] == ["docker", "run"] and record["argv"][record["argv"].index("--name") + 1] == name
    )
    return {"command": argv[argv.index(image) + 1:], "env": env}


def secret_names(record):
    return sorted(name for name, value in record["env"].items() if SECRET in value)


def photon_launch(argv):
    return argv[0] == "photon" or argv[:2] == ["docker", "run"] and argv[argv.index("--name") + 1] == "photon"


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
            (root / "deployment.env").write_text("DATABASE_URL=postgres://user@127.0.0.1/photon\n")
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


class LauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.install = install_records(cls.root / "install")
        cls.photon = service_records(cls.root / "photon", "photon")
        cls.prover = service_records(cls.root / "prover", "prover")
        cls.host = aws_host_records(cls.root / "host")
        cls.export = export_records(cls.root / "export")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_launchers_share_service_arguments(self):
        dockerfile = (SCRIPTS.parents[1] / "prover/server/Dockerfile.aeglos").read_text()
        self.assertEqual(json.loads(re.search(r"^CMD (.+)$", dockerfile, re.M).group(1)),
                         [*PROVER, "--keys-dir", "/proving-keys"])
        prover = started(self.prover, "light-prover")
        self.assertEqual(prover["argv"][1:], [*PROVER, "--keys-dir", f"{self.root}/prover/keys", *LOOPBACK])
        self.assertLessEqual(PROVER_ENV.items(), prover["env"].items())
        host_prover = container(self.host, "prover", config()["prover_image"])
        self.assertEqual(host_prover["command"], [*PROVER, "--keys-dir", "/proving-keys", *LOOPBACK])
        self.assertLessEqual(PROVER_ENV.items(), host_prover["env"].items())
        migration = started(self.photon, "timeout")["argv"]
        self.assertEqual(migration[-4:], [*MIGRATION, f"{self.root}/photon/current/photon-migration", "up"])
        deadline = re.search(r"deadline=\$\(\(SECONDS \+ (\d+) \+ \d+\)\)", (SCRIPTS / "install.sh").read_text())
        self.assertEqual(int(deadline.group(1)), aws_host.MIGRATION_SECONDS)
        host_migration = container(self.host, "migration", config()["photon_image"])
        self.assertEqual(host_migration["command"][-4:], [*MIGRATION, "photon-migration", "up"])
        photon = started(self.photon, "photon")
        self.assertEqual(photon["argv"][1:], photon_args(DATABASE))
        self.assertLessEqual(PHOTON_ENV.items(), photon["env"].items())
        host_photon = container(self.host, "photon", config()["photon_image"])
        self.assertEqual(host_photon["command"],
                         ["photon", *photon_args(f"postgres://photon:{SECRET}@127.0.0.1:5432/photon")])
        self.assertLessEqual(PHOTON_ENV.items(), host_photon["env"].items())

    def test_launchers_keep_secrets_off_argv(self):
        for record in [*self.install, *self.photon, *self.prover, *self.host, *self.export]:
            argv = record["argv"]
            exempt = photon_launch(argv)
            shown = [value for i, value in enumerate(argv) if not (exempt and i and argv[i - 1] in PHOTON_URL_FLAGS)]
            self.assertNotIn(SECRET, " ".join(shown))
        libpq = [record for record in [*self.install, *self.export] if record["argv"][0] in ("psql", "pg_restore", "pg_dump")]
        self.assertEqual(sorted(record["argv"][0] for record in libpq), ["pg_dump", "pg_restore", "psql"])
        for record in libpq:
            self.assertEqual(record["env"]["PGPASSWORD"], SECRET + "/")
            self.assertEqual(secret_names(record), ["PGPASSWORD"])

    def test_environment_scopes_secrets_per_process(self):
        self.assertEqual(secret_names(started(self.install, "supervisord")), [])
        self.assertEqual(secret_names(started(self.photon, "timeout")), ["DATABASE_URL"])
        self.assertEqual(secret_names(started(self.photon, "photon")), [])
        self.assertEqual(secret_names(started(self.prover, "light-prover")), ["PROVER_API_KEY"])
        self.assertEqual(secret_names(started(self.export, "aws")), [])

    def test_services_receive_operator_settings(self):
        for records, name, settings in (
            (self.prover, "light-prover", OPERATOR["prover"]),
            (self.photon, "photon", OPERATOR["photon"]),
        ):
            with self.subTest(service=name):
                self.assertLessEqual(settings.items(), started(records, name)["env"].items())

    def test_install_stops_waiting_for_a_fatal_service(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(subprocess.CalledProcessError) as failed:
            install_records(Path(directory), {"curl": ["", 7], "supervisorctl": ["photon FATAL Exited too quickly", 3]})
        self.assertIn("Service readiness failed", failed.exception.stderr)

    def test_install_keeps_logs_root_owned(self):
        logs = next(record["argv"] for record in self.install
                    if record["argv"][0] == "install" and "/opt/zolana-gpu/fixture/logs" in record["argv"])
        self.assertEqual(logs[1:8], ["-d", "-m", "0750", "-o", "root", "-g", "zolana_gpu"])


if __name__ == "__main__":
    unittest.main()
