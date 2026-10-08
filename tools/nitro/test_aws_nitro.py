import argparse
import base64
import fnmatch
import io
import json
import re
import socket
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

import aws_nitro
import aws_nitro_host as host

import aws_host

REPOSITORY = Path(__file__).resolve().parents[2]
SERVER = REPOSITORY / "prover/server"
ENTRYPOINT = (SERVER / "nitro/entrypoint.sh").read_text()
ROUTES = SERVER / "nitro/routes.sh"
DOWNLOADER = SERVER / "prover/common/key_downloader.go"
IMAGE = (
    "558215002830.dkr.ecr.eu-north-1.amazonaws.com/zolana-prover-nitro@sha256:"
    + "a" * 64
)
PCR = {name: str(index) * 96 for index, name in enumerate(host.PCRS)}
KMS_KEY = (
    "arn:aws:kms:eu-central-1:558215002830:key/"
    + "1" * 8
    + "-1111-1111-1111-"
    + "1" * 12
)
HOST_ROLE = "arn:aws:iam::558215002830:role/zolana-nitro-test-HostRole"
HPKE = "ab" * 32
CONTEXT = "5" * 64
ENCLAVES = [
    {"cpus": [*range(1, 24), *range(49, 72)], "memory_mib": 92546},
    {"cpus": [*range(24, 48), *range(72, 96)], "memory_mib": 92658},
]


def config():
    return {
        "region": "eu-central-1",
        "image_region": "eu-north-1",
        "instance_type": "m6i.4xlarge",
        "zone": "eu-central-1a",
        "ami": "ami-1234567890abcdef0",
        "cloudfront_prefix": "pl-12345678",
        "disk_gb": 30,
        "with_indexer": False,
        "image_repositories": [
            "arn:aws:ecr:eu-north-1:558215002830:repository/zolana-prover-nitro"
        ],
        "prover_image": IMAGE,
        "indexer_url": "",
        "enclave_cpus": 12,
        "enclave_memory_mib": 49152,
    }


def instance_type(**overrides):
    described = {
        "NitroEnclavesSupport": "supported",
        "ProcessorInfo": {"SupportedArchitectures": ["x86_64"]},
        "VCpuInfo": {"DefaultVCpus": 16, "DefaultThreadsPerCore": 2},
        "MemoryInfo": {"SizeInMiB": 65536},
    }
    described.update(overrides)
    return described


def routes(indexer=""):
    outcome = subprocess.run(
        ["sh", str(ROUTES), str(DOWNLOADER), indexer],
        capture_output=True,
        text=True,
        check=False,
    )
    return outcome.returncode, outcome.stdout, outcome.stderr


def resume(parent, expected=None, seed=True, aws=None, missing=()):
    if aws is None:
        aws = Mock()
        aws.call.return_value = {"SecretString": "secret"}
    out = {
        "Bucket": "b",
        "ApiKeySecret": "s",
        "Url": "https://x",
        "HostRole": HOST_ROLE,
    }
    stack = {
        "Parameters": [
            {"ParameterKey": "Config", "ParameterValue": json.dumps(config())}
        ]
    }
    args = argparse.Namespace(
        plan=False,
        name="zolana-nitro-test",
        image=None,
        indexer_url=None,
        instance_type=None,
        zone=None,
        expect_pcrs=expected or dict(PCR, kms_key=None, image=IMAGE),
    )
    try:
        with (
            patch.object(aws_nitro.gpu, "wait_stack", return_value={}),
            patch.object(aws_nitro.gpu, "outputs", return_value=out),
            patch.object(
                aws_nitro.gpu,
                "object_exists",
                side_effect=lambda _aws, _bucket, key: (
                    (seed or key != host.SEED_OBJECT) and key not in missing
                ),
            ),
            patch.object(aws_nitro, "offered_key", return_value=HPKE),
            patch.object(aws_nitro.gpu, "check_gateway"),
            patch.object(aws_nitro.gpu, "log"),
            patch.object(aws_nitro, "read_measurements", return_value=parent),
            patch.object(aws_nitro, "show"),
        ):
            aws_nitro.deploy(args, aws, stack)
    except Exception:
        aws.command.assert_not_called()
        raise
    marker = aws.command.call_args.args
    assert marker[:2] == ("s3", "cp") and marker[-2].endswith("/install/complete")
    return aws


class StackTests(unittest.TestCase):
    def test_instance_runs_enclaves_behind_cloudfront_only(self):
        resources = aws_nitro.template(config())["Resources"]
        instance = resources["Instance"]["Properties"]
        self.assertEqual(instance["EnclaveOptions"], {"Enabled": True})
        self.assertNotIn("KeyName", instance)
        self.assertNotIn("UserData", instance)
        self.assertEqual(instance["MetadataOptions"]["HttpTokens"], "required")
        self.assertEqual(
            resources["SecurityGroup"]["Properties"]["SecurityGroupIngress"],
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3001,
                    "ToPort": 3001,
                    "SourcePrefixListId": "pl-12345678",
                }
            ],
        )
        origin = resources["Distribution"]["Properties"]["DistributionConfig"]
        self.assertIn("VpcOriginConfig", origin["Origins"][0])
        self.assertEqual(origin["Origins"][0]["Id"], "gateway")
        self.assertEqual(origin["DefaultCacheBehavior"]["TargetOriginId"], "gateway")
        self.assertEqual(
            origin["DefaultCacheBehavior"]["ViewerProtocolPolicy"], "https-only"
        )

    def test_host_role_reads_only_the_api_key_and_writes_only_measurements(self):
        body = aws_nitro.template(config())
        statements = body["Resources"]["HostRole"]["Properties"]["Policies"][0][
            "PolicyDocument"
        ]["Statement"]
        by_action = {tuple(s["Action"]): s["Resource"] for s in statements}
        self.assertFalse(
            any(action.startswith("kms:") for s in statements for action in s["Action"])
        )
        self.assertFalse(
            any(r["Type"].startswith("AWS::KMS") for r in body["Resources"].values())
        )
        self.assertEqual(
            body["Outputs"]["HostRole"], {"Value": {"Fn::GetAtt": ["HostRole", "Arn"]}}
        )
        self.assertEqual(
            by_action[("secretsmanager:GetSecretValue",)], [{"Ref": "ApiKey"}]
        )
        self.assertEqual(
            by_action[("s3:PutObject",)],
            [{"Fn::Sub": "${Assets.Arn}/" + host.MEASUREMENTS}],
        )
        self.assertEqual(
            by_action[
                (
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchCheckLayerAvailability",
                )
            ],
            config()["image_repositories"],
        )
        self.assertLess(len(json.dumps(config(), sort_keys=True)), 4096)

    def test_enclave_size_leaves_the_parent_whole_cores(self):
        self.assertEqual(aws_nitro.enclave_size(instance_type()), (12, 49152))
        odd = instance_type(VCpuInfo={"DefaultVCpus": 9, "DefaultThreadsPerCore": 2})
        self.assertEqual(aws_nitro.enclave_size(odd)[0], 4)
        for described in (
            instance_type(NitroEnclavesSupport="unsupported"),
            instance_type(ProcessorInfo={"SupportedArchitectures": ["arm64"]}),
            instance_type(MemoryInfo={"SizeInMiB": 32768}),
            instance_type(VCpuInfo={"DefaultVCpus": 4, "DefaultThreadsPerCore": 2}),
        ):
            with self.subTest(described=described), self.assertRaises(ValueError):
                aws_nitro.enclave_size(described)

    def test_image_must_be_pinned_by_digest(self):
        for image in (
            IMAGE.split("@")[0] + ":latest",
            IMAGE.replace("558215002830", "111111111111"),
            IMAGE[:-1],
            None,
        ):
            args = argparse.Namespace(image=image, profile=None)
            with (
                self.subTest(image=image),
                self.assertRaisesRegex(ValueError, "digest"),
            ):
                aws_nitro.configuration(args, Mock())

    def test_configuration_checks_the_digest_and_sizes_the_enclave(self):
        aws = Mock()
        aws.call.return_value = {"InstanceTypes": [instance_type()]}
        registry = Mock()
        args = argparse.Namespace(
            image=IMAGE,
            profile=None,
            region="eu-central-1",
            instance_type=None,
            zone=None,
            indexer_url=None,
        )
        with (
            patch.object(aws_nitro.gpu, "Aws", return_value=registry) as client,
            patch.object(aws_nitro.gpu, "placement", return_value="eu-central-1a"),
            patch.object(aws_nitro.gpu, "parameter", return_value="ami-1"),
            patch.object(aws_nitro.gpu, "cloudfront_prefix", return_value="pl-1"),
        ):
            outcome = aws_nitro.configuration(args, aws)
        client.assert_called_once_with("eu-north-1", None)
        registry.call.assert_called_once_with(
            "ecr",
            "describe-images",
            RegistryId="558215002830",
            RepositoryName="zolana-prover-nitro",
            ImageIds=[{"imageDigest": "sha256:" + "a" * 64}],
        )
        self.assertEqual(outcome, dict(config(), ami="ami-1", cloudfront_prefix="pl-1"))

    def test_plan_never_creates_resources(self):
        client = Mock()
        args = argparse.Namespace(plan=True, name="zolana-nitro-test", expect_pcrs=None)
        with (
            patch.object(aws_nitro, "configuration", return_value=config()),
            patch("builtins.print"),
        ):
            aws_nitro.deploy(args, client, None)
        self.assertEqual(
            [call.args[1] for call in client.call.call_args_list], ["validate-template"]
        )

    def test_deploy_refuses_parent_measurements_that_differ_from_measure(self):
        parent = dict(PCR, PCR0="f" * 96, nitro_cli="Nitro CLI 9.9.9")
        with (
            patch.object(aws_nitro, "check_attestation") as attestation,
            self.assertRaisesRegex(RuntimeError, "MEASUREMENT MISMATCH(.|\n)*PCR0"),
        ):
            resume(parent)
        attestation.assert_not_called()

    def test_expected_pcrs_need_every_measure_pcr(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pcrs.json"
            measured = dict(
                PCR,
                HashAlgorithm="Sha512_48 { .. }",
                source="measure",
                kms_key=KMS_KEY,
                image=IMAGE,
            )
            path.write_text(json.dumps(measured))
            expected = dict(PCR, kms_key=KMS_KEY, image=IMAGE)
            self.assertEqual(aws_nitro.expected_pcrs(str(path)), expected)
            path.write_text(json.dumps(dict(measured, PCR1=PCR["PCR1"].upper())))
            self.assertEqual(aws_nitro.expected_pcrs(str(path)), expected)
            path.write_text(json.dumps(dict(measured, kms_key=None)))
            self.assertIsNone(aws_nitro.expected_pcrs(str(path))["kms_key"])
            for record in (
                dict(PCR, HashAlgorithm="Sha512_48 { .. }"),
                {k: v for k, v in measured.items() if k != "kms_key"},
                {k: v for k, v in measured.items() if k != "image"},
                {k: v for k, v in measured.items() if k != "PCR2"},
                dict(measured, PCR1="g" * 96),
                dict(measured, PCR0=PCR["PCR0"][:-2]),
            ):
                path.write_text(json.dumps(record))
                with (
                    self.subTest(record=record),
                    self.assertRaises(argparse.ArgumentTypeError),
                ):
                    aws_nitro.expected_pcrs(str(path))

    def test_deploy_requires_expected_pcrs(self):
        with (
            patch("sys.argv", ["aws_nitro.py", "deploy", "test", "--image", IMAGE]),
            patch.object(aws_nitro.gpu, "Aws") as client,
            patch("sys.stderr"),
            self.assertRaises(SystemExit),
        ):
            aws_nitro.main()
        client.assert_not_called()

    def test_measure_builds_in_the_pinned_container_with_the_host_script(self):
        record = json.dumps(dict(PCR, HashAlgorithm="Sha512_48 { .. }"))
        with (
            patch.object(aws_nitro, "docker", side_effect=["", record]) as docker,
            patch.object(
                aws_nitro, "image_files", return_value={"kms_key": KMS_KEY}
            ) as files,
        ):
            measured = aws_nitro.measure(IMAGE)
            self.assertEqual(measured["PCR0"], PCR["PCR0"])
            self.assertEqual(measured["source"], "measure")
            self.assertEqual(measured["kms_key"], KMS_KEY)
        files.assert_called_once_with(IMAGE)
        pull, build = (call.args for call in docker.call_args_list)
        self.assertEqual(pull, ("pull", "--platform", "linux/amd64", IMAGE))
        self.assertRegex(
            aws_nitro.MEASURE_IMAGE, r"^amazonlinux:2023@sha256:[0-9a-f]{64}$"
        )
        self.assertEqual(
            build[build.index(aws_nitro.MEASURE_IMAGE) :],
            (
                aws_nitro.MEASURE_IMAGE,
                "python3",
                "/tools/nitro/aws_nitro_host.py",
                "measure",
                IMAGE,
            ),
        )
        with self.assertRaisesRegex(ValueError, "digest"):
            aws_nitro.measure(IMAGE.split("@")[0] + ":latest")

    def test_resume_rejects_another_image(self):
        stack = {
            "Parameters": [
                {"ParameterKey": "Config", "ParameterValue": json.dumps(config())}
            ]
        }
        args = argparse.Namespace(
            plan=False,
            name="zolana-nitro-test",
            image=IMAGE[:-1] + "b",
            indexer_url=None,
            instance_type=None,
            zone=None,
            expect_pcrs=None,
        )
        with self.assertRaisesRegex(ValueError, "different settings"):
            aws_nitro.deploy(args, Mock(), stack)


class AttestationTests(unittest.TestCase):
    def verify(self, returncode):
        seen = {}

        def tee_check(command, **kwargs):
            seen.update(kwargs, command=command)
            seen["policy"] = json.loads(Path(command[-1]).read_text())
            return subprocess.CompletedProcess(command, returncode)

        with patch.object(aws_nitro.subprocess, "run", side_effect=tee_check):
            resume(dict(PCR, enclaves=1))
        return seen

    def test_deploy_marks_complete_only_after_tee_check_passes(self):
        with self.assertRaisesRegex(RuntimeError, "tee-check(.|\n)*repository root"):
            self.verify(1)
        self.verify(0)

    def test_policy_pins_exactly_the_expected_pcrs(self):
        self.assertEqual(
            self.verify(0)["policy"],
            {
                "platform": "aws-nitro",
                "measurements": [
                    {"pcr0": PCR["PCR0"], "pcr1": PCR["PCR1"], "pcr2": PCR["PCR2"]}
                ],
                "hpke_public_key": HPKE,
                "gpu": "optional",
                "max_age_secs": 600,
            },
        )

    def test_key_reaches_tee_check_only_through_the_environment(self):
        seen = self.verify(0)
        self.assertEqual(
            seen["command"][:-1],
            [*aws_nitro.TEE_CHECK, "https://x", "--policy"],
        )
        self.assertFalse(any("secret" in part for part in seen["command"]))
        self.assertEqual(seen["env"]["PROVER_API_KEY"], "secret")
        self.assertEqual(seen["cwd"], REPOSITORY)

    def test_missing_cargo_names_the_requirement(self):
        with (
            patch.object(aws_nitro.subprocess, "run", side_effect=FileNotFoundError),
            self.assertRaisesRegex(RuntimeError, "cargo(.|\n)*repository root"),
        ):
            resume(dict(PCR, enclaves=1))

    def test_every_enclave_must_offer_one_key_before_tee_check(self):
        aws = Mock()
        aws.call.return_value = {"SecretString": "secret"}
        out = {"ApiKeySecret": "s", "Url": "https://x"}
        with (
            patch.object(
                aws_nitro, "offered_key", side_effect=[HPKE, HPKE, "cd" * 32, HPKE]
            ),
            patch.object(aws_nitro.subprocess, "run") as tee_check,
            self.assertRaisesRegex(RuntimeError, "different HPKE keys"),
        ):
            aws_nitro.check_attestation(aws, out, PCR, 2)
        tee_check.assert_not_called()

    def test_tee_check_runs_twice_per_enclave_against_the_pinned_key(self):
        aws = Mock()
        aws.call.return_value = {"SecretString": "secret"}
        out = {"ApiKeySecret": "s", "Url": "https://x"}
        policies = []

        def tee_check(command, **kwargs):
            policies.append(json.loads(Path(command[-1]).read_text()))
            return subprocess.CompletedProcess(command, 0)

        with (
            patch.object(aws_nitro, "offered_key", return_value=HPKE) as offered,
            patch.object(aws_nitro.subprocess, "run", side_effect=tee_check),
        ):
            self.assertEqual(aws_nitro.check_attestation(aws, out, PCR, 2), HPKE)
        self.assertEqual(offered.call_count, 4)
        self.assertEqual(len(policies), 4)
        self.assertTrue(all(p["hpke_public_key"] == HPKE for p in policies))

    def test_offered_key_requires_a_hex_key(self):
        for body, ok in (
            ({"hpke_public_key": HPKE}, True),
            ({"hpke_public_key": HPKE.upper()}, False),
            ({"hpke_public_key": HPKE[:-2]}, False),
            ({}, False),
        ):
            response = Mock()
            response.__enter__ = Mock(
                return_value=io.BytesIO(json.dumps(body).encode())
            )
            response.__exit__ = Mock(return_value=False)
            with (
                self.subTest(body=body),
                patch.object(
                    aws_nitro.urllib.request, "urlopen", return_value=response
                ) as urlopen,
            ):
                if ok:
                    self.assertEqual(aws_nitro.offered_key("https://x", "secret"), HPKE)
                    request = urlopen.call_args.args[0]
                    self.assertRegex(
                        request.full_url,
                        r"^https://x/tee/v1/attestation\?nonce=[0-9a-f]{64}$",
                    )
                    self.assertEqual(request.get_header("X-api-key"), "secret")
                else:
                    with self.assertRaisesRegex(RuntimeError, "HPKE"):
                        aws_nitro.offered_key("https://x", "secret")


class KmsTests(unittest.TestCase):
    def test_attested_policy_releases_the_seed_only_to_the_measured_enclave(self):
        allow, *denies, _context = aws_nitro.attested(HOST_ROLE, PCR, CONTEXT)
        self.assertEqual(
            allow,
            {
                "Sid": "AttestedEnclave",
                "Effect": "Allow",
                "Principal": {"AWS": HOST_ROLE},
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {
                    "StringEqualsIgnoreCase": {
                        f"kms:RecipientAttestation:{name}": PCR[name]
                        for name in host.PCRS
                    },
                    "StringEquals": {"kms:EncryptionContext:zolana-seed": CONTEXT},
                },
            },
        )
        self.assertEqual(
            [
                (
                    deny["Sid"],
                    deny["Effect"],
                    deny["Principal"],
                    deny["Action"],
                    deny["Condition"],
                )
                for deny in denies
            ],
            [
                (
                    f"Attested{name}",
                    "Deny",
                    "*",
                    "kms:Decrypt",
                    {
                        "StringNotEqualsIgnoreCase": {
                            f"kms:RecipientAttestation:{name}": PCR[name]
                        }
                    },
                )
                for name in host.PCRS
            ],
        )

    def test_new_keys_deny_wrapping_and_every_decrypt(self):
        self.assertEqual(
            aws_nitro.sealed() + aws_nitro.unbound(),
            [
                {
                    "Sid": "SealedSeed",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": [
                        "kms:Encrypt",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey",
                        "kms:GenerateDataKeyPair*",
                    ],
                    "Resource": "*",
                },
                {
                    "Sid": "UnboundDecrypt",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "kms:Decrypt",
                    "Resource": "*",
                },
            ],
        )

    def owned(self, aws, state="Enabled", tags=None):
        answers = {
            "describe-key": {
                "KeyMetadata": {"KeyId": "k", "Arn": KMS_KEY, "KeyState": state}
            },
            "list-resource-tags": {
                "Tags": tags
                if tags is not None
                else [{"TagKey": "zolana-tool", "TagValue": "nitro-deploy"}]
            },
        }
        aws.call.side_effect = lambda _service, operation, **_: answers[operation]

    def test_kms_key_reuses_its_alias(self):
        aws = Mock()
        self.owned(aws)
        self.assertEqual(
            aws_nitro.create_kms_key(aws, "zolana-nitro-test", "558215002830"), KMS_KEY
        )
        self.assertNotIn(
            "create-key", [call.args[1] for call in aws.call.call_args_list]
        )
        aws.call.assert_any_call("kms", "describe-key", KeyId="alias/zolana-nitro-test")

    def test_kms_key_refuses_a_foreign_or_disabled_alias(self):
        for state, tags in (("Enabled", []), ("PendingDeletion", None)):
            aws = Mock()
            self.owned(aws, state, tags)
            with self.subTest(state=state), self.assertRaises(RuntimeError):
                aws_nitro.find_kms_key(aws, "zolana-nitro-test")

    def test_new_kms_key_starts_with_the_administrator_only(self):
        aws = Mock()
        calls = []

        def call(service, operation, **parameters):
            calls.append((operation, parameters))
            if operation == "describe-key":
                raise aws_nitro.gpu.AwsError("NotFoundException")
            if operation == "create-key":
                return {"KeyMetadata": {"KeyId": "k", "Arn": KMS_KEY}}
            if operation == "create-alias":
                raise aws_nitro.gpu.AwsError("LimitExceededException")
            return {}

        aws.call.side_effect = call
        with (
            patch.object(aws_nitro.gpu, "log"),
            self.assertRaisesRegex(aws_nitro.gpu.AwsError, "LimitExceeded"),
        ):
            aws_nitro.create_kms_key(aws, "zolana-nitro-test", "558215002830")
        created = dict(calls)["create-key"]
        self.assertEqual(
            json.loads(created["Policy"]),
            aws_nitro.key_policy(
                "558215002830", *aws_nitro.sealed(), *aws_nitro.unbound()
            ),
        )
        self.assertEqual(
            created["Tags"], [{"TagKey": "zolana-tool", "TagValue": "nitro-deploy"}]
        )
        self.assertEqual(
            dict(calls)["schedule-key-deletion"],
            {"KeyId": "k", "PendingWindowInDays": 7},
        )

    def expected(self, image_key=KMS_KEY):
        return dict(PCR, kms_key=image_key, image=IMAGE)

    def kms_deploy(self, seed, policy, grants=(), missing=()):
        operations, uploads = [], []

        def call(service, operation, **parameters):
            operations.append((operation, parameters))
            if operation == "generate-data-key-without-plaintext":
                return {"CiphertextBlob": base64.b64encode(b"blob").decode()}
            if operation == "get-key-policy":
                return {"Policy": json.dumps(policy)}
            if operation == "list-grants":
                return {"Grants": list(grants)}
            return {"SecretString": "secret"}

        def command(*args, **kwargs):
            if args[:2] == ("s3", "cp") and "hpke-seed" in args[2]:
                uploads.append((Path(args[2]).read_bytes(), args[3]))
            if args[:2] == ("s3", "rm"):
                operations.append(("s3 rm", args[2]))

        aws = Mock()
        aws.call.side_effect = call
        aws.command.side_effect = command
        with (
            patch.object(aws_nitro, "find_kms_key", return_value=KMS_KEY),
            patch.object(
                aws_nitro.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0),
            ),
        ):
            resume(
                dict(PCR, enclaves=2),
                self.expected(),
                seed=seed,
                aws=aws,
                missing=missing,
            )
        return operations, uploads

    def kms_names(self, operations):
        return [
            name
            for name, _ in operations
            if name not in ("get-secret-value", "get-key-policy", "list-grants")
        ]

    def test_deploy_binds_an_immutable_policy_then_seeds_fresh(self):
        created = aws_nitro.key_policy(
            "558215002830", *aws_nitro.sealed(), *aws_nitro.unbound()
        )
        contexts = set()
        for seed in (False, True):
            with self.subTest(seed=seed):
                operations, uploads = self.kms_deploy(seed=seed, policy=created)
                self.assertEqual(
                    self.kms_names(operations),
                    [
                        "s3 rm",
                        "s3 rm",
                        "put-key-policy",
                        "generate-data-key-without-plaintext",
                    ],
                )
                put = dict(operations)["put-key-policy"]
                policy = json.loads(put["Policy"])
                context = aws_nitro.bound_context(policy)
                self.assertRegex(context, "^[0-9a-f]{64}$")
                contexts.add(context)
                self.assertEqual(
                    policy,
                    aws_nitro.bound_policy("558215002830", HOST_ROLE, PCR, context),
                )
                self.assertIs(put["BypassPolicyLockoutSafetyCheck"], True)
                self.assertEqual(
                    dict(operations)["generate-data-key-without-plaintext"][
                        "EncryptionContext"
                    ],
                    {"zolana-seed": context},
                )
                self.assertEqual(
                    uploads,
                    [
                        (context.encode(), "s3://b/" + host.SEED_CONTEXT_OBJECT),
                        (b"blob", "s3://b/" + host.SEED_OBJECT),
                    ],
                )
        self.assertEqual(len(contexts), 2)

    def test_resume_keeps_the_bound_context_and_its_seed(self):
        bound = aws_nitro.bound_policy("558215002830", HOST_ROLE, PCR, CONTEXT)
        operations, uploads = self.kms_deploy(seed=True, policy=bound)
        self.assertEqual(self.kms_names(operations), [])
        self.assertEqual(uploads, [])
        operations, uploads = self.kms_deploy(seed=False, policy=bound)
        self.assertEqual(
            self.kms_names(operations), ["generate-data-key-without-plaintext"]
        )
        self.assertEqual(
            dict(operations)["generate-data-key-without-plaintext"][
                "EncryptionContext"
            ],
            {"zolana-seed": CONTEXT},
        )
        self.assertEqual(
            [target for _, target in uploads],
            ["s3://b/" + host.SEED_CONTEXT_OBJECT, "s3://b/" + host.SEED_OBJECT],
        )

    def test_resume_restores_a_missing_context_without_a_new_seed(self):
        bound = aws_nitro.bound_policy("558215002830", HOST_ROLE, PCR, CONTEXT)
        operations, uploads = self.kms_deploy(
            seed=True, policy=bound, missing=(host.SEED_CONTEXT_OBJECT,)
        )
        self.assertEqual(self.kms_names(operations), [])
        self.assertEqual(
            uploads, [(CONTEXT.encode(), "s3://b/" + host.SEED_CONTEXT_OBJECT)]
        )

    def test_bind_refuses_a_key_with_grants(self):
        created = aws_nitro.key_policy(
            "558215002830", *aws_nitro.sealed(), *aws_nitro.unbound()
        )
        with self.assertRaisesRegex(RuntimeError, "grants"):
            self.kms_deploy(seed=True, policy=created, grants=[{"GrantId": "g"}])

    def test_deploy_refuses_a_key_bound_to_another_policy(self):
        for other in (
            aws_nitro.bound_policy(
                "558215002830", HOST_ROLE, dict(PCR, PCR0="f" * 96), CONTEXT
            ),
            aws_nitro.key_policy("558215002830", *aws_nitro.sealed()),
        ):
            with (
                self.subTest(other=other),
                self.assertRaisesRegex(RuntimeError, "bound to another policy"),
            ):
                self.kms_deploy(seed=True, policy=other)

    def test_bound_policy_leaves_no_way_to_widen_it(self):
        operator, seeding, *rest = aws_nitro.bound_policy(
            "558215002830", HOST_ROLE, PCR, CONTEXT
        )["Statement"]
        root = {"AWS": "arn:aws:iam::558215002830:root"}
        self.assertEqual(operator["Principal"], root)
        for action in (
            "kms:*",
            "kms:PutKeyPolicy",
            "kms:CreateGrant",
            "kms:Decrypt",
            "kms:Encrypt",
            "kms:GenerateDataKey",
            "kms:GenerateDataKeyWithoutPlaintext",
        ):
            self.assertNotIn(action, operator["Action"])
        self.assertEqual(
            seeding,
            {
                "Sid": "BoundSeed",
                "Effect": "Allow",
                "Principal": root,
                "Action": "kms:GenerateDataKeyWithoutPlaintext",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"kms:EncryptionContext:zolana-seed": CONTEXT}
                },
            },
        )
        self.assertEqual(
            rest, aws_nitro.attested(HOST_ROLE, PCR, CONTEXT) + aws_nitro.sealed()
        )

    def test_decrypt_under_any_other_context_is_denied_over_grants(self):
        deny = aws_nitro.attested(HOST_ROLE, PCR, CONTEXT)[-1]
        self.assertEqual(
            deny,
            {
                "Sid": "AttestedContext",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {"kms:EncryptionContext:zolana-seed": CONTEXT}
                },
            },
        )

    def test_bound_context_reads_none_from_an_older_policy(self):
        older = aws_nitro.key_policy(
            "558215002830",
            {"Sid": "AttestedEnclave", "Condition": {"StringEqualsIgnoreCase": {}}},
        )
        self.assertIsNone(aws_nitro.bound_context(older))

    def test_seed_context_key_matches_the_enclave(self):
        source = (SERVER / "tee/nitro_kms.go").read_text()
        self.assertIn(f'seedContextKey = "{host.SEED_CONTEXT_KEY}"', source)

    def test_deploy_refuses_pcrs_of_another_image(self):
        with (
            patch.object(aws_nitro, "find_kms_key", return_value=KMS_KEY),
            self.assertRaisesRegex(ValueError, "another image"),
        ):
            resume(dict(PCR, enclaves=2), dict(self.expected(), image=IMAGE + "0"))

    def test_deploy_refuses_an_image_for_another_kms_key(self):
        aws = Mock()
        args = argparse.Namespace(
            plan=False,
            name="zolana-nitro-test",
            expect_pcrs=self.expected(KMS_KEY[:-1] + "2"),
        )
        for found in (KMS_KEY, None):
            with (
                self.subTest(found=found),
                patch.object(aws_nitro, "find_kms_key", return_value=found),
                self.assertRaisesRegex(ValueError, "another KMS key"),
            ):
                aws_nitro.deploy(args, aws, None)
        aws.call.assert_not_called()


class HostTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        artifacts = patch.object(host, "ARTIFACTS", Path(directory.name) / "artifacts")
        self.artifacts = artifacts.start()
        self.addCleanup(artifacts.stop)

    def test_every_nitro_cli_call_names_the_artifacts_folder(self):
        built = json.dumps({"Measurements": dict(PCR, HashAlgorithm="Sha512_48")})
        with patch.object(host, "run", side_effect=[built, built, "", "[]"]) as run:
            host.build_eif(IMAGE, Path("prover.eif"))
            host.enclave_state(f"{host.ENCLAVE}-0")
        self.assertEqual(
            [call.args[:2] for call in run.call_args_list],
            [
                ("nitro-cli", "build-enclave"),
                ("nitro-cli", "describe-eif"),
                ("nitro-cli", "--version"),
                ("nitro-cli", "describe-enclaves"),
            ],
        )
        for call in run.call_args_list:
            self.assertEqual(
                call.kwargs["env"]["NITRO_CLI_ARTIFACTS"], str(self.artifacts)
            )
        self.assertTrue(self.artifacts.is_dir())
        self.assertIn(
            f"Environment=NITRO_CLI_ARTIFACTS={host.ARTIFACTS}",
            host.units([], ENCLAVES, True)["zolana-enclave@.service"],
        )

    def test_host_and_measure_install_the_same_nitro_cli(self):
        with (
            patch.object(host, "run", return_value="") as run,
            patch.object(host, "build_eif", return_value=PCR),
            patch("builtins.print"),
        ):
            host.main(["aws_nitro_host.py", "measure", IMAGE])
        install = run.call_args_list[0].args
        self.assertEqual(install[:4], ("dnf", "install", "-y", "-q"))
        self.assertEqual(install[4:], host.NITRO_PACKAGES)
        self.assertTrue(
            all(name.endswith("-" + host.NITRO_CLI) for name in install[4:])
        )

    def test_supervise_survives_describe_failures_until_the_enclave_stops(self):
        name = f"{host.ENCLAVE}-1"
        running = json.dumps([{"EnclaveName": name, "State": "RUNNING"}])
        other = json.dumps([{"EnclaveName": f"{host.ENCLAVE}-0", "State": "RUNNING"}])
        answers = {
            "terminate-enclave": [RuntimeError("busy")],
            "run-enclave": [""],
            "describe-enclaves": [
                running,
                RuntimeError("nitro-cli describe-enclaves timed out"),
                "not json",
                running,
                other,
            ],
        }
        seen = []

        def nitro(*args, timeout=300):
            seen.append(args)
            answer = answers[args[0]].pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

        with (
            patch.object(host, "nitro", side_effect=nitro),
            patch("sys.stderr"),
            self.assertRaisesRegex(RuntimeError, "Enclave 1 is ABSENT"),
        ):
            host.supervise(ENCLAVES, 1, poll=0)
        self.assertEqual(answers["describe-enclaves"], [])
        self.assertEqual(seen[0], ("terminate-enclave", "--enclave-name", name))

    def sysfs(self, nodes, offline=""):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "cpu").mkdir()
        (root / "cpu/offline").write_text(offline + "\n")
        half = sum(len(host.cpu_list(cpus)) for cpus, _ in nodes) // 2
        for number, (cpus, kib) in enumerate(nodes):
            node = root / f"node/node{number}"
            node.mkdir(parents=True)
            (node / "cpulist").write_text(cpus + "\n")
            (node / "meminfo").write_text(f"Node {number} MemTotal:       {kib} kB\n")
            for cpu in host.cpu_list(cpus):
                topology = root / f"cpu/cpu{cpu}/topology"
                topology.mkdir(parents=True)
                low = cpu % half
                (topology / "thread_siblings_list").write_text(f"{low},{low + half}\n")
        return root

    def test_two_numa_nodes_get_one_enclave_each_without_cpu0_core(self):
        root = self.sysfs([("0-23,48-71", 96866164), ("24-47,72-95", 96979944)])
        settings = {"enclave_cpus": 92, "enclave_memory_mib": 180224}
        self.assertEqual(host.layout(host.topology(root), settings, True), ENCLAVES)
        self.assertEqual(
            host.layout(host.topology(root), settings, False), [ENCLAVES[1]]
        )

    def test_one_numa_node_keeps_the_instance_caps(self):
        root = self.sysfs([("0-15", 66060288)])
        (enclave,) = host.layout(host.topology(root), config(), True)
        self.assertEqual(enclave["memory_mib"], 49152)
        self.assertEqual(len(enclave["cpus"]), 12)
        self.assertNotIn(0, enclave["cpus"])
        self.assertNotIn(8, enclave["cpus"])
        self.assertEqual(
            {cpu % 8 for cpu in enclave["cpus"]},
            {cpu - 8 for cpu in enclave["cpus"] if cpu >= 8},
        )

    def test_layout_skips_a_node_without_two_usable_cpus(self):
        nodes = [([(1, 3)], 8192), ([], 8192)]
        settings = {"enclave_cpus": 64, "enclave_memory_mib": 65536}
        self.assertEqual(
            host.layout(nodes, settings, True), [{"cpus": [1, 3], "memory_mib": 6144}]
        )
        with self.assertRaisesRegex(RuntimeError, "No NUMA node"):
            host.layout([([], 8192)], settings, True)

    def test_topology_refuses_offline_cpus(self):
        root = self.sysfs([("0-3", 8388608)], offline="2-3")
        with self.assertRaisesRegex(RuntimeError, "offline"):
            host.topology(root)

    def test_allocator_runs_once_per_node_then_pools_every_cpu(self):
        configs = []

        def allocator(command, cwd, env, **kwargs):
            self.assertEqual(env["NITRO_CLI_INSTALL_DIR"], cwd)
            configs.append(Path(cwd, "etc/nitro_enclaves/allocator.yaml").read_text())
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as directory:
            pool = Path(directory) / "ne_cpus"
            with (
                patch.object(host, "CPU_POOL", pool),
                patch.object(host.subprocess, "run", side_effect=allocator),
            ):
                host.allocate(ENCLAVES)
            self.assertEqual(
                pool.read_text(),
                ",".join(map(str, ENCLAVES[0]["cpus"] + ENCLAVES[1]["cpus"])) + "\n",
            )
        self.assertEqual(
            configs,
            [
                f"---\nmemory_mib: {e['memory_mib']}\ncpu_pool: {','.join(map(str, e['cpus']))}\n"
                for e in ENCLAVES
            ],
        )
        with (
            patch.object(
                host.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 1),
            ),
            self.assertRaisesRegex(RuntimeError, "allocator failed"),
        ):
            host.allocate(ENCLAVES)

    def test_enclave_runs_on_its_node_and_never_debugs(self):
        command = host.enclave_command(ENCLAVES[1], 1)
        self.assertNotIn("--debug-mode", command)
        self.assertNotIn("--attach-console", command)
        self.assertNotIn("--cpu-count", command)
        start = command.index("--cpu-ids") + 1
        self.assertEqual(
            command[start : command.index("--memory")],
            [str(cpu) for cpu in ENCLAVES[1]["cpus"]],
        )
        self.assertEqual(command[command.index("--memory") + 1], "92658")
        self.assertEqual(command[command.index("--enclave-cid") + 1], "17")
        self.assertEqual(
            command[command.index("--enclave-name") + 1], f"{host.ENCLAVE}-1"
        )

    def test_proxy_allowlist_is_exactly_the_image_routes(self):
        code, text, _ = routes("https://indexer.example.com:8443/rpc")
        self.assertEqual(code, 0)
        parsed = host.parse_routes(text)
        self.assertEqual(
            json.loads(host.proxy_config(parsed)),
            {
                "allowlist": [
                    {"address": "d3gbdb0egjwcw9.cloudfront.net", "port": 443},
                    {"address": "indexer.example.com", "port": 8443},
                ]
            },
        )
        units = host.units(parsed, ENCLAVES, True)
        egress = {name: text for name, text in units.items() if "egress" in name}
        self.assertEqual(
            [
                line
                for text in egress.values()
                for line in text.splitlines()
                if line.startswith("ExecStart=")
            ],
            [
                f"ExecStart=/usr/bin/vsock-proxy --ipv4 --num_workers 64 --config {host.PROXY_CONFIG} 8001 d3gbdb0egjwcw9.cloudfront.net 443",
                f"ExecStart=/usr/bin/vsock-proxy --ipv4 --num_workers 64 --config {host.PROXY_CONFIG} 8002 indexer.example.com 8443",
            ],
        )

    def test_malformed_routes_are_rejected(self):
        for text in (
            "",
            "127.0.0.2 host.example.com 443 8001\n127.0.0.3 other.example.com 443 8001",
            "127.0.0.2 host.example.com 443 8001 --config /tmp/x",
            "127.0.0.2 host.example.com\nExecStart=/bin/sh 443 8001",
            "10.0.0.2 host.example.com 443 8001",
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                host.parse_routes(text)

    def test_each_ingress_reaches_its_enclave_listener(self):
        self.assertIn(f"VSOCK-LISTEN:{host.ENCLAVE_PORT},", ENTRYPOINT)
        self.assertIn(f"--prover-address 127.0.0.1:{host.ENCLAVE_PORT}", ENTRYPOINT)
        units = host.units([], ENCLAVES, True)
        for index, (port, cid) in enumerate(((3003, 16), (3005, 17))):
            self.assertIn(
                f"TCP-LISTEN:{port},bind=127.0.0.1,fork,reuseaddr VSOCK-CONNECT:{cid}:{host.ENCLAVE_PORT}",
                units[f"zolana-ingress-{index}.service"],
            )
        ports = {host.ingress_port(index) for index in range(8)}
        self.assertFalse(
            ports & {host.AUTHORIZER_PORT, host.GATEWAY_PORT, host.ENCLAVE_PORT}
        )

    def test_gateway_round_robins_over_every_ingress_with_keepalive(self):
        text = aws_host.gateway(
            False,
            authorizer=f"http://127.0.0.1:{host.AUTHORIZER_PORT}/auth",
            upstreams=["127.0.0.1:3003", "127.0.0.1:3005"],
        )
        pool = re.search(r"upstream prover \{([^}]*)\}", text).group(1)
        self.assertEqual(
            re.findall(r"server (\S+);", pool), ["127.0.0.1:3003", "127.0.0.1:3005"]
        )
        self.assertIn("keepalive", pool)
        self.assertEqual(text.count("proxy_pass http://prover;"), 2)
        self.assertIn('proxy_set_header Connection "";', text)
        self.assertNotIn("proxy_pass http://127.0.0.1:3003", text)

    def test_proxy_workers_exceed_the_indexer_concurrency(self):
        default = re.search(
            r'Name: "indexer-concurrency".*?Value: (\d+)',
            (SERVER / "main.go").read_text(),
        ).group(1)
        self.assertGreater(host.PROXY_WORKERS, int(default))

    def test_enclave_template_restarts_and_terminates_only_its_enclave(self):
        units = host.units([], ENCLAVES, True)
        unit = units["zolana-enclave@.service"]
        self.assertIn("Restart=always", unit)
        head, service = unit.split("[Service]")
        self.assertIn(f"Requires={host.ALLOCATOR_UNIT}", head)
        self.assertIn("zolana-kms.service", head)
        self.assertNotIn("Requires=", service)
        self.assertIn(
            f"ExecStart=/usr/bin/python3 {host.ROOT}/aws_nitro_host.py supervise {host.ROOT}/config.json %i",
            unit,
        )
        self.assertIn(
            f"ExecStopPost=-/usr/bin/nitro-cli terminate-enclave --enclave-name {host.ENCLAVE}-%i",
            unit,
        )
        allocator = units[host.ALLOCATOR_UNIT]
        self.assertIn("Type=oneshot", allocator)
        self.assertIn("RemainAfterExit=yes", allocator)
        self.assertNotIn("Restart=", allocator)
        self.assertNotIn(
            f"After=network-online.target {host.ALLOCATOR_UNIT}", allocator
        )
        for name, text in units.items():
            if name not in ("zolana-enclave@.service", host.ALLOCATOR_UNIT):
                self.assertIn("DynamicUser=yes", text)
        self.assertEqual(
            host.services(units, ENCLAVES)[-2:],
            ["zolana-enclave@0.service", "zolana-enclave@1.service"],
        )
        self.assertNotIn("zolana-enclave@.service", host.services(units, ENCLAVES))

    def test_kms_service_runs_only_for_a_shared_key(self):
        self.assertIn(
            f"/usr/bin/python3 {host.ROOT}/aws_nitro_host.py kms {host.ROOT}/config.json",
            host.units([], ENCLAVES, True)["zolana-kms.service"],
        )
        self.assertNotIn("zolana-kms.service", host.units([], ENCLAVES[:1], False))

    def test_gateway_enforces_the_key_and_passes_the_tee_headers(self):
        text = aws_host.gateway(
            False, authorizer=f"http://127.0.0.1:{host.AUTHORIZER_PORT}/auth"
        )
        self.assertIn(
            f"proxy_pass http://127.0.0.1:{host.AUTHORIZER_PORT}/auth?$request_query;",
            text,
        )
        self.assertNotIn(f"proxy_pass http://127.0.0.1:{host.INGRESS_PORT}/auth", text)
        allowed = re.search(r'Access-Control-Allow-Headers "([^"]*)"', text).group(1)
        exposed = re.search(r'Access-Control-Expose-Headers "([^"]*)"', text).group(1)
        for header in (
            "Zolana-Tee",
            "Zolana-Tee-Enc",
            "Zolana-Tee-Ciphertext",
            "X-API-Key",
            "Authorization",
        ):
            self.assertIn(header, allowed.split(","))
        self.assertIn("Zolana-Tee", exposed.split(","))
        self.assertNotIn("proxy_set_body", text)

    def test_measurements_require_matching_build_and_description(self):
        built = {"Measurements": dict(PCR, HashAlgorithm="Sha384 { ... }")}
        with patch.object(host, "run", return_value="Nitro CLI 1.5.0"):
            record = host.measurements(built, built, IMAGE)
            self.assertEqual(record["image"], IMAGE)
            self.assertEqual({name: record[name] for name in host.PCRS}, PCR)
            other = {"Measurements": dict(built["Measurements"], PCR1="f" * 96)}
            with self.assertRaisesRegex(RuntimeError, "disagrees"):
                host.measurements(built, other, IMAGE)

    def image(self, files):
        def run(*args, **kwargs):
            if args[:2] == ("docker", "cp"):
                for name, text in files.items():
                    Path(args[3], name).write_text(text)
            return "container"

        with patch.object(host, "run", side_effect=run):
            return host.image_files(IMAGE)

    def test_image_names_its_kms_key_only_with_the_kms_source(self):
        base = {"routes": "127.0.0.2 keys.example.com 443 8001\n", "indexer-url": "\n"}
        for extra, expected in (
            ({}, None),
            ({"key-source": "boot\n"}, None),
            ({"key-source": "kms\n", "kms-key": KMS_KEY + "\n"}, KMS_KEY),
        ):
            with self.subTest(extra=extra):
                files = self.image(base | extra)
                self.assertEqual(files["kms_key"], expected)
                self.assertEqual(files["indexer_url"], "")
        for extra in (
            {"key-source": "kms\n"},
            {"key-source": "kms\n", "kms-key": "\n"},
        ):
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "KMS"):
                self.image(base | extra)

    def test_install_rejects_an_image_for_another_indexer(self):
        settings = dict(
            config(), outputs={"Bucket": "b", "ApiKeySecret": "s", "LogGroup": "l"}
        )
        with (
            patch.object(host, "run", return_value=""),
            patch.object(host, "retire_units"),
            patch.object(host.aws_host, "pull") as pull,
            patch.object(host, "write"),
            patch.object(
                host,
                "image_files",
                return_value={
                    "routes": [],
                    "indexer_url": "https://other.example.com",
                    "kms_key": None,
                },
            ),
            patch("builtins.print"),
            self.assertRaisesRegex(ValueError, "another indexer"),
        ):
            host.install(settings)
        pull.assert_called_once_with(settings, (IMAGE, host.NGINX))


class KmsConfigTests(unittest.TestCase):
    CREDENTIALS = {
        "Code": "Success",
        "AccessKeyId": "ASIAEXAMPLE",
        "SecretAccessKey": "secret-key",
        "Token": "session-token",
        "Expiration": "2026-10-07T20:00:00Z",
    }

    def test_message_is_one_json_line_without_key_or_region(self):
        line = host.kms_config(b"\x00\xffblob", CONTEXT, self.CREDENTIALS)
        self.assertTrue(line.endswith(b"\n"))
        self.assertEqual(line.count(b"\n"), 1)
        self.assertEqual(
            list(json.loads(line).items()),
            [
                ("ciphertext", base64.b64encode(b"\x00\xffblob").decode()),
                ("access_key_id", "ASIAEXAMPLE"),
                ("secret_access_key", "secret-key"),
                ("session_token", "session-token"),
                ("seed_context", CONTEXT),
            ],
        )
        with self.assertRaisesRegex(ValueError, "limit"):
            host.kms_config(b"x" * host.KMS_LIMIT, CONTEXT, self.CREDENTIALS)

    def opener(self, answers, requests):
        def opener(request, timeout):
            requests.append(request)
            response = Mock()
            response.__enter__ = Mock(
                return_value=io.BytesIO(answers[request.full_url].encode())
            )
            response.__exit__ = Mock(return_value=False)
            return response

        return opener

    def imds(self, roles, record):
        base = host.IMDS + "/meta-data/iam/security-credentials/"
        return {
            host.IMDS + "/api/token": "token",
            base: roles,
            base + "zolana-host": json.dumps(record),
        }

    def test_credentials_come_from_imdsv2_for_the_one_role(self):
        requests = []
        credentials = host.role_credentials(
            self.opener(self.imds("zolana-host\n", self.CREDENTIALS), requests)
        )
        self.assertEqual(credentials, self.CREDENTIALS)
        token, *reads = requests
        self.assertEqual(token.get_method(), "PUT")
        self.assertEqual(token.get_header("X-aws-ec2-metadata-token-ttl-seconds"), "60")
        self.assertTrue(
            all(r.get_header("X-aws-ec2-metadata-token") == "token" for r in reads)
        )

    def test_credentials_refuse_a_failed_or_ambiguous_role(self):
        for roles, record in (
            ("zolana-host", dict(self.CREDENTIALS, Code="Expired")),
            ("zolana-host\nother", self.CREDENTIALS),
            ("", self.CREDENTIALS),
        ):
            with self.subTest(roles=roles), self.assertRaises(RuntimeError):
                host.role_credentials(self.opener(self.imds(roles, record), []))

    def exchange(self, peer, message):
        parent, enclave = socket.socketpair()
        with enclave:
            host.answer_kms(parent, peer, {16, 17}, message)
            received = b""
            while chunk := enclave.recv(4096):
                received += chunk
        return received

    def test_each_enclave_connection_gets_fresh_credentials(self):
        fetched = []

        def message():
            fetched.append(None)
            return host.kms_config(
                b"blob", CONTEXT, dict(self.CREDENTIALS, Token=str(len(fetched)))
            )

        tokens = [
            json.loads(self.exchange((cid, 5000), message))["session_token"]
            for cid in (16, 17)
        ]
        self.assertEqual(tokens, ["1", "2"])

    def test_another_peer_gets_nothing(self):
        message = Mock()
        self.assertEqual(self.exchange((3, 5000), message), b"")
        message.assert_not_called()

    def test_a_failed_credential_read_closes_without_an_answer(self):
        with patch("sys.stderr"):
            received = self.exchange(
                (16, 5000), Mock(side_effect=RuntimeError("no role"))
            )
        self.assertEqual(received, b"")


class AuthorizerTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), host.authorizer("secret"))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def status(self, path, headers=None, method="GET"):
        request = urllib.request.Request(
            self.base + path, headers=headers or {}, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status
        except urllib.error.HTTPError as error:
            error.close()
            return error.code

    def test_key_sources_match_the_prover(self):
        for path, headers, method, expected in (
            ("/auth", {}, "GET", 401),
            ("/auth", {"X-API-Key": "wrong"}, "GET", 401),
            ("/auth", {"X-API-Key": "secret"}, "GET", 204),
            ("/auth", {"X-API-Key": "secret"}, "POST", 204),
            ("/auth", {"Authorization": "Bearer secret"}, "GET", 204),
            ("/auth", {"Authorization": "Basic secret"}, "GET", 401),
            ("/auth?api-key=secret", {}, "GET", 204),
            ("/auth?api-key=wrong", {}, "GET", 401),
            ("/auth?api-keys=secret", {}, "GET", 401),
            ("/auth?api-key=secret", {"X-API-Key": "wrong"}, "GET", 401),
            ("/other?api-key=secret", {}, "GET", 401),
        ):
            with self.subTest(path=path, headers=headers, method=method):
                self.assertEqual(self.status(path, headers, method), expected)


class ImageTests(unittest.TestCase):
    def test_routes_derive_the_key_host_from_the_downloader(self):
        host_name = re.search(
            r'defaultProvingKeysBaseURL\s*=\s*"https://([^"/]+)"',
            DOWNLOADER.read_text(),
        ).group(1)
        self.assertEqual(routes(), (0, f"127.0.0.2 {host_name} 443 8001\n", ""))

    def test_routes_reject_unsafe_indexer_urls(self):
        for url in (
            "http://indexer.example.com",
            "https://user:pass@indexer.example.com",
            "https://indexer.example.com/?api-key=x",
            "https://indexer.example.com/#x",
            "https://INDEXER.example.com",
            "https://indexer.example.com:0",
            "https://indexer.example.com:70000",
            "https://127.0.0.1",
            "https://indexer.example.com evil",
        ):
            with self.subTest(url=url):
                self.assertNotEqual(routes(url)[0], 0)

    def test_key_tmpfs_holds_every_served_key_and_the_largest_partial(self):
        size = int(re.search(r"^keys_mib=(\d+)$", ENTRYPOINT, re.M).group(1)) * 2**20
        patterns = re.findall(r"--serve '([^']+)'", ENTRYPOINT)
        lock = json.loads((SERVER / "prover/provingkeys/proving-keys.lock").read_text())
        served = [
            entry["size"]
            for name, entry in lock["keys"].items()
            if any(fnmatch.fnmatchcase(name.removesuffix(".key"), p) for p in patterns)
        ]
        self.assertTrue(served)
        self.assertLessEqual(sum(served) + max(served), size)
        self.assertFalse(
            any(fnmatch.fnmatchcase("batch_address-append_40_250", p) for p in patterns)
        )

    def test_enclave_runs_the_nitro_tee_without_a_key_or_public_listener(self):
        self.assertIn("--tee nitro", ENTRYPOINT)
        self.assertNotIn("PROVER_API_KEY", ENTRYPOINT)
        self.assertNotIn("0.0.0.0", ENTRYPOINT)
        self.assertIn("ip link set lo up", ENTRYPOINT)
        bases = re.findall(
            r"^FROM (\S+)", (SERVER / "Dockerfile.nitro").read_text(), re.M
        )
        self.assertEqual(len(bases), 2)
        self.assertTrue(
            all(re.search(r"@sha256:[0-9a-f]{64}$", base) for base in bases)
        )


if __name__ == "__main__":
    unittest.main()
