import argparse
import json
import subprocess
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

import aws
import aws_host
import aws_stack


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
            "arn:aws:secretsmanager:eu-north-1:558215002830:secret:rpc-123456"
        )
        result["source"] = {
            "cluster": "zolnet-devnet-c",
            "service": "photon",
            "rpc_secret": result["rpc_secret"],
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
        "ExportRole": "arn:aws:iam::558215002830:role/isolated-export",
        "Bucket": "isolated-assets",
        "LogGroup": "isolated-logs",
        "ApiKeySecret": "isolated-api-key",
        "DatabaseSecret": "isolated-db-password",
        "InstanceId": "i-1234567890abcdef0",
        "Url": "https://example.cloudfront.net",
    }


class StackTests(unittest.TestCase):
    def test_target_cannot_read_source_database(self):
        settings = config()
        resources = aws_stack.template(settings)["Resources"]
        host = json.dumps(resources["HostRole"])
        self.assertNotIn(settings["source"]["database_secret"], host)
        self.assertIn(settings["rpc_secret"], host)
        self.assertIn(
            settings["source"]["database_secret"], json.dumps(resources["ExportRole"])
        )
        self.assertLess(len(json.dumps(settings, sort_keys=True)), 4096)

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


class DeployTests(unittest.TestCase):
    def test_preview_images_require_explicit_selection(self):
        revision, preview_revision = "a" * 40, "b" * 40
        client = Mock()
        client.call.return_value = {
            "imageDetails": [
                {
                    "imageTags": ["gpu-sm89-" + revision],
                    "imageDigest": "sha256:release",
                    "imagePushedAt": 1,
                },
                {
                    "imageTags": ["gpu-preview-sm89-" + preview_revision],
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

    def test_images_share_revision_and_pin_digests(self):
        client = Mock()
        old, new = "a" * 40, "b" * 40
        client.call.side_effect = [
            {
                "imageDetails": [
                    {
                        "imageTags": ["gpu-sm89-" + old],
                        "imageDigest": "sha256:old",
                        "imagePushedAt": 1,
                    },
                    {
                        "imageTags": ["gpu-sm89-" + new],
                        "imageDigest": "sha256:new",
                        "imagePushedAt": 2,
                    },
                ]
            },
            {
                "imageDetails": [
                    {
                        "imageTags": ["gpu-" + old],
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

    def test_source_discovery_reads_only_metadata(self):
        client = Mock()
        settings = config()
        source = settings["source"]
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
                                    "valueFrom": source["rpc_secret"],
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
                    parameters["ExecutionRoleArn"], stack_outputs()["ExportRole"]
                )
                script = parameters["ContainerDefinitions"][0]["command"][0]
                self.assertIn("default_transaction_read_only=on", script)
                self.assertIn("timeout 300 pg_dump", script)
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
                settings = dict(config(), outputs=stack_outputs())
                calls = []
                (Path(directory) / "cache.dump").touch()

                def run(
                    *args, calls=calls, migration_status=migration_status, **kwargs
                ):
                    calls.append(args)
                    if args[0] == "nvidia-smi":
                        return "8.9"
                    if "psql" in args:
                        return "0"
                    if args[:3] == ("docker", "wait", "migration"):
                        return migration_status
                    return ""

                with (
                    patch.object(aws_host, "ROOT", Path(directory)),
                    patch.object(aws_host, "run", side_effect=run),
                    patch.object(aws_host, "secret", return_value="secret"),
                    patch.object(aws_host, "healthy"),
                    patch.object(aws_host.os, "chown"),
                    patch.object(
                        aws_host.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess([], 0),
                    ),
                ):
                    if migration_status == "0":
                        aws_host.install(settings)
                    else:
                        with self.assertRaisesRegex(RuntimeError, "migration failed"):
                            aws_host.install(settings)
                restore = next(
                    i for i, call in enumerate(calls) if "pg_restore" in call
                )
                migrate = next(
                    i for i, call in enumerate(calls) if "photon-migration" in call
                )
                self.assertLess(restore, migrate)
                photon = [i for i, call in enumerate(calls) if "--db-url" in call]
                self.assertEqual(len(photon), int(migration_status == "0"))
                if photon:
                    self.assertLess(migrate, photon[0])
                    prover = next(call for call in calls if "--prover-address" in call)
                    self.assertIn("--auto-download", prover)
                migration_env = Path(directory, "migration.env").read_text()
                self.assertEqual(
                    migration_env,
                    "DATABASE_URL=postgres://photon:secret@127.0.0.1:5432/photon\n",
                )
                self.assertTrue((Path(directory) / "restored").exists())

    def test_restore_rejects_nonempty_target_without_marker(self):
        settings = dict(config(), outputs=stack_outputs())
        calls = []

        def run(*args, **kwargs):
            calls.append(args)
            if args[0] == "nvidia-smi":
                return "8.9"
            if "psql" in args:
                return "1"
            return ""

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(aws_host, "ROOT", Path(directory)),
            patch.object(aws_host, "run", side_effect=run),
            patch.object(aws_host, "secret", return_value="password"),
            patch.object(
                aws_host.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0),
            ),
            self.assertRaisesRegex(RuntimeError, "not empty"),
        ):
            aws_host.install(settings)
        self.assertFalse(any("pg_restore" in call for call in calls))
        self.assertFalse(any("s3" in call for call in calls))

    def test_environment_rejects_line_injection(self):
        with self.assertRaisesRegex(ValueError, "one line"):
            aws_host.environment("secrets.env", {"KEY": "value\nINJECTED=1"})

    def test_gateway_keeps_auth_internal_for_both_routes(self):
        text = aws_host.gateway(True)
        self.assertIn("auth_request /_authorize", text)
        self.assertIn("internal;", text)
        self.assertIn("proxy_pass http://127.0.0.1:3003/auth", text)
        self.assertIn("proxy_pass http://127.0.0.1:8784/", text)
        self.assertNotIn("8784", aws_host.gateway(False))


if __name__ == "__main__":
    unittest.main()
