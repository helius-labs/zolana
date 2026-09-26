import argparse
import base64
import json
import re
import subprocess
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

import aws
import aws_host
import aws_stack

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/publish-gpu.yml"
PROVER = aws.tag_prefix("gpu", aws_host.CUDA_ARCH)
PREVIEW = aws.tag_prefix("gpu-preview", aws_host.CUDA_ARCH)


def config(with_indexer=True):
    result = {
        "region": "eu-central-1",
        "source_region": "eu-north-1",
        "image_region": "eu-north-1",
        "ami": "ami-1234567890abcdef0",
        "instance_type": "g6.2xlarge",
        "zone": "eu-central-1a",
        "disk_gb": 200,
        "cloudfront_prefix": "pl-12345678",
        "with_indexer": with_indexer,
        "image_repositories": [
            "arn:aws:ecr:eu-north-1:558215002830:repository/zolana-prover"
        ],
        "prover_image": "558215002830.dkr.ecr.eu-north-1.amazonaws.com/zolana-prover@sha256:"
        + "a" * 64,
        "photon_image": "558215002830.dkr.ecr.eu-north-1.amazonaws.com/zolana-photon@sha256:"
        + "b" * 64,
        "revision": "c" * 40,
        "prover_cpus": 6,
        "indexer_url": "http://127.0.0.1:8784"
        if with_indexer
        else "https://indexer.example.com",
        "indexer_key_secret": None,
    }
    if with_indexer:
        result["rpc_secret"] = (
            "arn:aws:secretsmanager:eu-north-1:558215002830:secret:"
            + aws.RPC_SECRET
            + "-123456"
        )
        result["source"] = {
            "cluster": "zolnet-devnet-c",
            "service": "photon",
            "database_secret": "arn:aws:secretsmanager:eu-north-1:558215002830:secret:database-123456",
            "network": {
                "awsvpcConfiguration": {
                    "subnets": ["subnet-12345678"],
                    "securityGroups": ["sg-12345678"],
                    "assignPublicIp": "DISABLED",
                }
            },
        }
    return result


def stack_outputs():
    return {
        "ExportExecutionRole": "arn:aws:iam::558215002830:role/isolated-export-execution",
        "ExportTaskRole": "arn:aws:iam::558215002830:role/isolated-export-task",
        "Bucket": "isolated-assets",
        "LogGroup": "isolated-logs",
        "ApiKeySecret": "isolated-api-key",
        "DatabaseSecret": "isolated-db-password",
        "InstanceId": "i-1234567890abcdef0",
        "Url": "https://example.cloudfront.net",
    }


def host_install(
    directory, calls, secret=lambda arn, region: "secret", migration="0", objects="0"
):
    (directory / "cache.dump").touch()

    def run(*args, **kwargs):
        env_file = (
            Path(args[args.index("--env-file") + 1]) if "--env-file" in args else None
        )
        calls.append(
            {
                "argv": list(args),
                "env": dict(
                    line.split("=", 1) for line in env_file.read_text().splitlines()
                )
                if env_file
                else {},
            }
        )
        if args[0] == "nvidia-smi":
            return f"{aws_host.CUDA_ARCH[3:-1]}.{aws_host.CUDA_ARCH[-1]}"
        if "psql" in args:
            return objects
        if args[:3] == ("docker", "wait", "migration"):
            return migration
        return ""

    with (
        patch.object(aws_host, "ROOT", directory),
        patch.object(aws_host, "run", side_effect=run),
        patch.object(aws_host, "secret", side_effect=secret),
        patch.object(aws_host, "healthy"),
        patch.object(aws_host.os, "chown"),
        patch.object(
            aws_host.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0),
        ),
    ):
        aws_host.install(dict(config(), outputs=stack_outputs()))


def workflow_step(name):
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index(f"      - name: {name}")
    run = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
    indent = len(lines[run]) - len(lines[run].lstrip()) + 2
    body = []
    for line in lines[run + 1 :]:
        if line.strip() and not line.startswith(" " * indent):
            break
        body.append(line[indent:])
    return "\n".join(body)


class StackTests(unittest.TestCase):
    def test_target_cannot_read_source_secrets(self):
        settings = config()
        resources = aws_stack.template(settings)["Resources"]
        statements = resources["HostRole"]["Properties"]["Policies"][0][
            "PolicyDocument"
        ]["Statement"]
        secrets = next(
            s["Resource"]
            for s in statements
            if s["Action"] == ["secretsmanager:GetSecretValue"]
        )
        self.assertEqual(
            secrets,
            [{"Ref": "ApiKey"}, settings["rpc_secret"], {"Ref": "DatabasePassword"}],
        )
        database = settings["source"]["database_secret"]
        self.assertIn(database, json.dumps(resources["ExportExecutionRole"]))
        self.assertNotIn(database, json.dumps(resources["ExportTaskRole"]))
        self.assertNotIn("s3:", json.dumps(resources["ExportExecutionRole"]))
        self.assertLess(len(json.dumps(settings, sort_keys=True)), 4096)

    def test_rpc_secret_resolves_dedicated_name(self):
        client = Mock(region="eu-north-1")
        client.call.return_value = {"ARN": config()["rpc_secret"]}
        self.assertEqual(aws.rpc_secret(client), config()["rpc_secret"])
        client.call.assert_called_once_with(
            "secretsmanager", "describe-secret", SecretId="zolana-gpu/photon-rpc-url"
        )
        client.call.side_effect = aws.AwsError("ResourceNotFoundException")
        with self.assertRaisesRegex(
            RuntimeError, "Create the zolana-gpu/photon-rpc-url"
        ):
            aws.rpc_secret(client)

    def test_only_gateway_accepts_ingress(self):
        resources = aws_stack.template(config())["Resources"]
        ingress = resources["SecurityGroup"]["Properties"]["SecurityGroupIngress"]
        self.assertEqual(
            ingress,
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3001,
                    "ToPort": 3001,
                    "SourcePrefixListId": "pl-12345678",
                }
            ],
        )
        host = resources["Instance"]["Properties"]
        self.assertTrue(host["BlockDeviceMappings"][0]["Ebs"]["Encrypted"])
        self.assertEqual(host["MetadataOptions"]["HttpTokens"], "required")
        self.assertNotIn("KeyName", host)
        cache = resources["Distribution"]["Properties"]["DistributionConfig"][
            "DefaultCacheBehavior"
        ]
        self.assertEqual(cache["ViewerProtocolPolicy"], "https-only")
        self.assertEqual(cache["CachePolicyId"], "4135ea2d-6df8-44a3-9df3-4b5a84be39ad")

    def test_prover_only_has_no_database_access(self):
        resources = aws_stack.template(config(False))["Resources"]
        self.assertNotIn("ExportRole", resources)
        self.assertNotIn("DatabasePassword", resources)
        self.assertNotIn("database", json.dumps(resources["HostRole"]).lower())


@patch.object(aws, "verify_attestations")
@patch.object(aws, "on_main", return_value=True)
class ImageTests(unittest.TestCase):
    def test_preview_images_require_explicit_selection(self, *_):
        revision, preview_revision = "a" * 40, "b" * 40
        client = Mock()
        client.call.return_value = {
            "imageDetails": [
                {
                    "imageTags": [PROVER + revision],
                    "imageDigest": "sha256:release",
                    "imagePushedAt": 1,
                },
                {
                    "imageTags": [PREVIEW + preview_revision],
                    "imageDigest": "sha256:preview",
                    "imagePushedAt": 2,
                },
            ]
        }
        self.assertEqual(aws.image_pair(client)["revision"], revision)
        self.assertEqual(
            aws.image_pair(client, preview_revision, preview=True)["revision"],
            preview_revision,
        )
        with self.assertRaisesRegex(RuntimeError, "No published"):
            aws.image_pair(client, preview_revision)

    def test_images_share_revision_and_pin_digests(self, _, verify):
        client = Mock()
        old, new = "a" * 40, "b" * 40
        client.call.side_effect = [
            {
                "imageDetails": [
                    {
                        "imageTags": [PROVER + old],
                        "imageDigest": "sha256:old",
                        "imagePushedAt": 1,
                    },
                    {
                        "imageTags": [PROVER + new],
                        "imageDigest": "sha256:new",
                        "imagePushedAt": 2,
                    },
                ]
            },
            {
                "imageDetails": [
                    {
                        "imageTags": [aws.tag_prefix("gpu") + old],
                        "imageDigest": "sha256:photon",
                        "imagePushedAt": 1,
                    }
                ]
            },
        ]
        result = aws.image_pair(client, with_indexer=True)
        self.assertEqual(result["revision"], old)
        self.assertTrue(result["prover_image"].endswith("@sha256:old"))
        self.assertTrue(result["photon_image"].endswith("@sha256:photon"))
        verify.assert_called_once_with(
            client,
            [result["prover_image"], result["photon_image"]],
            old,
            source_ref="refs/heads/main",
        )

    def test_release_must_be_on_main(self, on_main, verify):
        revision = "a" * 40
        client = Mock()
        client.call.return_value = {
            "imageDetails": [
                {
                    "imageTags": [
                        PROVER + revision,
                        PREVIEW + revision,
                    ],
                    "imageDigest": "sha256:branch",
                    "imagePushedAt": 1,
                }
            ]
        }
        on_main.return_value = False
        for selected in (None, revision):
            with self.assertRaisesRegex(RuntimeError, "not on origin/main"):
                aws.image_pair(client, selected)
        self.assertEqual(
            aws.image_pair(client, revision, preview=True)["revision"], revision
        )
        self.assertEqual(on_main.call_count, 2)
        verify.assert_called_once()
        self.assertEqual(verify.call_args.args[2], revision)
        self.assertIsNone(verify.call_args.kwargs["source_ref"])


class AttestationTests(unittest.TestCase):
    image = (
        "558215002830.dkr.ecr.eu-north-1.amazonaws.com/zolana-prover@sha256:" + "a" * 64
    )

    def verify(self, calls, source_ref=None, returncode=0):
        def gh(argv, env, **kwargs):
            config = Path(env["DOCKER_CONFIG"])
            calls.append(
                {
                    "argv": argv,
                    "config": config,
                    "auths": json.loads((config / "config.json").read_text())["auths"],
                }
            )
            return subprocess.CompletedProcess(argv, returncode, "", "denied")

        client = Mock()
        client.command.return_value = "ecr-token\n"
        with (
            patch.object(aws.shutil, "which", return_value="/usr/bin/gh"),
            patch.object(aws.subprocess, "run", side_effect=gh),
        ):
            aws.verify_attestations(
                client, [self.image], "c" * 40, source_ref=source_ref
            )
        return client

    def test_release_attestation_binds_main_commit(self):
        calls = []
        client = self.verify(calls, source_ref="refs/heads/main")
        client.command.assert_called_once_with("ecr", "get-login-password")
        (call,) = calls
        argv = call["argv"]
        self.assertEqual(
            argv[:4], ["/usr/bin/gh", "attestation", "verify", "oci://" + self.image]
        )
        for flag, value in (
            ("--repo", "helius-labs/zolana"),
            (
                "--signer-workflow",
                "helius-labs/zolana/.github/workflows/publish-gpu.yml",
            ),
            ("--source-ref", "refs/heads/main"),
            ("--source-digest", "c" * 40),
        ):
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertNotIn("ecr-token", " ".join(argv))
        auth = call["auths"][self.image.split("/")[0]]["auth"]
        self.assertEqual(base64.b64decode(auth), b"AWS:ecr-token")
        self.assertFalse(call["config"].exists())

    def test_preview_attestation_binds_commit(self):
        calls = []
        self.verify(calls)
        argv = calls[0]["argv"]
        self.assertEqual(
            argv[argv.index("--signer-workflow") + 1],
            "helius-labs/zolana/.github/workflows/publish-gpu.yml",
        )
        self.assertEqual(argv[argv.index("--source-digest") + 1], "c" * 40)
        self.assertNotIn("--source-ref", argv)

    def test_unattested_image_is_rejected(self):
        calls = []
        with self.assertRaisesRegex(
            RuntimeError, "Could not verify a publish-gpu attestation"
        ):
            self.verify(calls, source_ref="refs/heads/main", returncode=1)
        self.assertFalse(calls[0]["config"].exists())

    def test_verification_requires_github_cli(self):
        with (
            patch.object(aws.shutil, "which", return_value=None),
            self.assertRaisesRegex(RuntimeError, "Install gh"),
        ):
            aws.verify_attestations(Mock(), [self.image], "c" * 40)


class DeployTests(unittest.TestCase):
    def test_main_ancestry_uses_git(self):
        revision = "a" * 40
        with patch.object(
            aws.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)
        ) as git:
            self.assertFalse(aws.on_main(revision))
        self.assertEqual(
            git.call_args.args[0][3:],
            ["merge-base", "--is-ancestor", revision, "origin/main"],
        )

    def test_api_input_casing(self):
        client = aws.Aws("eu-central-1")
        with patch.object(client, "command", return_value="{}") as command:
            client.call("ecs", "run-task", Cluster="source", TaskDefinition="export")
            self.assertEqual(
                json.loads(command.call_args.args[3]),
                {"cluster": "source", "taskDefinition": "export"},
            )
            client.call("ecr", "describe-images", RepositoryName="repo")
            self.assertEqual(
                json.loads(command.call_args.args[3]), {"repositoryName": "repo"}
            )
            client.call("cloudformation", "describe-stacks", StackName="target")
            self.assertEqual(
                json.loads(command.call_args.args[3]), {"StackName": "target"}
            )

    def test_source_discovery_reads_only_metadata(self):
        client = Mock()
        settings = config()
        source = settings["source"]
        devnet_rpc = "arn:aws:secretsmanager:eu-north-1:558215002830:secret:rpc-123456"
        client.call.side_effect = [
            {
                "services": [
                    {
                        "taskDefinition": "photon-task",
                        "networkConfiguration": source["network"],
                    }
                ]
            },
            {
                "taskDefinition": {
                    "containerDefinitions": [
                        {
                            "secrets": [
                                {
                                    "name": "DATABASE_URL",
                                    "valueFrom": source["database_secret"],
                                },
                                {
                                    "name": "PHOTON_RPC_URL",
                                    "valueFrom": devnet_rpc,
                                },
                            ]
                        }
                    ]
                }
            },
        ]
        self.assertEqual(
            aws.discover_source(client, source["cluster"], "photon"), source
        )
        self.assertEqual(
            [call.args[1] for call in client.call.call_args_list],
            ["describe-services", "describe-task-definition"],
        )

    def test_foreign_stack_is_rejected(self):
        client = Mock()
        client.call.return_value = {"Stacks": [{"Tags": []}]}
        with self.assertRaisesRegex(RuntimeError, "not owned"):
            aws.get_stack(client, "existing")

    def test_permissions_error_is_not_absence(self):
        client = Mock()
        client.call.side_effect = aws.AwsError("AccessDenied")
        with self.assertRaises(aws.AwsError):
            aws.get_stack(client, "target")
        with self.assertRaises(aws.AwsError):
            aws.object_exists(client, "target", "cache")

    def test_plan_never_creates_resources(self):
        client = Mock()
        args = argparse.Namespace(plan=True, name="zolana-gpu-test")
        with (
            patch.object(aws, "configuration", return_value=config()),
            patch("builtins.print"),
        ):
            aws.deploy(args, client, None)
        self.assertEqual(
            [call.args[1] for call in client.call.call_args_list], ["validate-template"]
        )

    def test_completed_resume_does_not_export_or_reinstall(self):
        settings = config()
        out = stack_outputs()
        stack = {
            "StackName": "zolana-gpu-test",
            "StackStatus": "CREATE_COMPLETE",
            "Parameters": [
                {"ParameterKey": "Config", "ParameterValue": json.dumps(settings)}
            ],
            "Outputs": [
                {"OutputKey": key, "OutputValue": value} for key, value in out.items()
            ],
        }
        args = argparse.Namespace(
            plan=False,
            name="zolana-gpu-test",
            profile=None,
            **{
                key: None
                for key in (
                    "instance_type",
                    "disk_gb",
                    "zone",
                    "revision",
                    "preview",
                    "with_indexer",
                    "indexer_url",
                    "indexer_key_secret",
                    "source_region",
                    "source_cluster",
                    "source_service",
                )
            },
        )
        with (
            patch.object(aws, "wait_stack", return_value=stack),
            patch.object(aws, "object_exists", return_value=True),
            patch.object(aws, "install") as install,
            patch.object(aws, "export_cache") as export,
            patch.object(aws, "check_gateway"),
            patch("builtins.print"),
        ):
            aws.deploy(args, Mock(), stack)
        install.assert_not_called()
        export.assert_not_called()

    def test_failed_export_stops_only_its_task(self):
        client = Mock()

        def call(service, operation, **parameters):
            if operation == "register-task-definition":
                self.assertEqual(
                    parameters["ExecutionRoleArn"],
                    stack_outputs()["ExportExecutionRole"],
                )
                self.assertEqual(
                    parameters["TaskRoleArn"], stack_outputs()["ExportTaskRole"]
                )
                script = parameters["ContainerDefinitions"][0]["command"][0]
                self.assertIn("default_transaction_read_only=on", script)
                self.assertIn('timeout 300 python3 -c "$VALIDATE" pg_dump', script)
                self.assertIn("--lock-wait-timeout=1s", script)
                return {"taskDefinition": {"taskDefinitionArn": "owned-definition"}}
            if operation == "run-task":
                self.assertEqual(
                    parameters["Tags"], [{"key": "zolana-tool", "value": "gpu-deploy"}]
                )
                return {"tasks": [{"taskArn": "owned-export"}]}
            if operation == "describe-tasks":
                return {
                    "tasks": [
                        {
                            "lastStatus": "STOPPED",
                            "containers": [{"exitCode": 1}],
                            "stoppedReason": "failed",
                        }
                    ]
                }
            return {}

        client.call.side_effect = call
        with self.assertRaisesRegex(RuntimeError, "export failed"):
            aws.export_cache(client, config(), stack_outputs(), "zolana-gpu-test")
        operations = [call.args[1] for call in client.call.call_args_list]
        self.assertEqual(operations[-2:], ["stop-task", "deregister-task-definition"])
        stop = client.call.call_args_list[-2]
        self.assertEqual(stop.kwargs["Task"], "owned-export")
        self.assertNotIn("update-service", operations)

    def test_gateway_rejects_public_access_and_checks_both_services(self):
        client = Mock()
        client.call.return_value = {"SecretString": "secret"}
        response = Mock()
        response.__enter__ = Mock(return_value=Mock(status=200))
        response.__exit__ = Mock(return_value=False)
        unauthorized = urllib.error.HTTPError(
            "https://gateway/ready", 401, "unauthorized", {}, None
        )
        with patch.object(
            aws.urllib.request,
            "urlopen",
            side_effect=[unauthorized, response, response],
        ) as get:
            aws.check_gateway(client, config(), stack_outputs())
            self.assertEqual(get.call_count, 3)
            self.assertEqual(
                get.call_args_list[-1].args[0].full_url,
                "https://example.cloudfront.net/indexer/readiness",
            )
        with (
            patch.object(aws.urllib.request, "urlopen", return_value=response),
            self.assertRaisesRegex(RuntimeError, "unauthenticated"),
        ):
            aws.check_gateway(client, config(), stack_outputs())


class HostTests(unittest.TestCase):
    def test_timeout_does_not_disclose_command_secrets(self):
        command = ["docker", "run", "photon", "--rpc-url", "https://secret.example"]
        with (
            patch.object(
                aws_host.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(command, 1),
            ),
            self.assertRaisesRegex(RuntimeError, "docker run timed out") as raised,
        ):
            aws_host.run(*command)
        self.assertNotIn("secret.example", str(raised.exception))

    def test_local_migrations_gate_photon_startup(self):
        for migration_status in ("0", "1"):
            with (
                self.subTest(migration_status=migration_status),
                tempfile.TemporaryDirectory() as directory,
            ):
                calls = []
                if migration_status == "0":
                    host_install(Path(directory), calls)
                else:
                    with self.assertRaisesRegex(RuntimeError, "migration failed"):
                        host_install(Path(directory), calls, migration="1")
                commands = [call["argv"] for call in calls]
                restore = next(
                    i for i, argv in enumerate(commands) if "pg_restore" in argv
                )
                migrate = next(
                    i for i, argv in enumerate(commands) if "photon-migration" in argv
                )
                self.assertLess(restore, migrate)
                photon = [i for i, argv in enumerate(commands) if "--db-url" in argv]
                self.assertEqual(len(photon), int(migration_status == "0"))
                if photon:
                    self.assertLess(migrate, photon[0])
                self.assertEqual(
                    calls[migrate]["env"],
                    {"DATABASE_URL": "postgres://photon:secret@127.0.0.1:5432/photon"},
                )
                self.assertEqual(list(Path(directory).glob("*.env")), [])
                self.assertTrue((Path(directory) / "restored").exists())

    def test_restore_rejects_nonempty_target_without_marker(self):
        calls = []
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(RuntimeError, "not empty"),
        ):
            host_install(Path(directory), calls, objects="1")
        self.assertFalse(any("pg_restore" in call["argv"] for call in calls))
        self.assertFalse(any("s3" in call["argv"] for call in calls))

    def test_environment_rejects_line_injection(self):
        with (
            self.assertRaisesRegex(ValueError, "one line"),
            aws_host.environment("secrets.env", {"KEY": "value\nINJECTED=1"}),
        ):
            pass

    def test_gateway_keeps_auth_internal_for_both_routes(self):
        text = aws_host.gateway(True)
        self.assertIn("auth_request /_authorize", text)
        self.assertIn("internal;", text)
        self.assertIn("proxy_pass http://127.0.0.1:3003/auth", text)
        self.assertIn("proxy_pass http://127.0.0.1:8784/", text)
        self.assertNotIn("8784", aws_host.gateway(False))

    def test_gateway_hands_the_query_key_to_the_prover_and_logs_no_query(self):
        text = aws_host.gateway(True)
        self.assertIn("proxy_pass http://127.0.0.1:3003/auth?$request_query;", text)
        self.assertEqual(
            re.findall(r"access_log .*", text), ["access_log /dev/stdout gateway;"]
        )
        self.assertEqual(
            re.findall(r"error_log .*", text), ["error_log /dev/stderr crit;"]
        )
        log_format = re.search(r"log_format gateway (.*)", text).group(1)
        self.assertFalse(
            set(re.findall(r"\$\w+", log_format))
            & {
                "$request",
                "$request_uri",
                "$args",
                "$query_string",
                "$request_query",
                "$query",
            }
        )


class WorkflowTests(unittest.TestCase):
    def test_published_tags_match_deployment_selection(self):
        self.assertEqual(
            re.findall(r"^\s+cuda-arch: (\S+)$", WORKFLOW.read_text(), re.M),
            [aws_host.CUDA_ARCH],
        )
        script = workflow_step("Resolve immutable image")
        revision = "c" * 40
        for service, cuda_arch, ref, prefix in (
            ("prover", aws_host.CUDA_ARCH, "refs/heads/main", PROVER),
            ("prover", aws_host.CUDA_ARCH, "refs/heads/feature", PREVIEW),
            ("photon", "", "refs/heads/main", aws.tag_prefix("gpu")),
        ):
            with (
                self.subTest(service=service, ref=ref),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                registry = root / "aws"
                registry.write_text("#!/bin/sh\necho ImageNotFoundException\nexit 1\n")
                registry.chmod(0o755)
                output = root / "output"
                subprocess.run(
                    ["bash", "-eo", "pipefail", "-c", script],
                    check=True,
                    capture_output=True,
                    timeout=30,
                    env={
                        "PATH": f"{root}:/usr/bin:/bin",
                        "SERVICE": service,
                        "CUDA_ARCH": cuda_arch,
                        "GITHUB_REF": ref,
                        "GITHUB_SHA": revision,
                        "GITHUB_OUTPUT": str(output),
                        "REGISTRY": "registry.invalid",
                    },
                )
                values = dict(
                    line.split("=", 1) for line in output.read_text().splitlines()
                )
                self.assertEqual(
                    values["tag"],
                    f"registry.invalid/zolana-{service}:{prefix}{revision}",
                )
                self.assertEqual(values["exists"], "false")


if __name__ == "__main__":
    unittest.main()
