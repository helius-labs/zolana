import argparse
import fnmatch
import json
import re
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
        statements = aws_nitro.template(config())["Resources"]["HostRole"][
            "Properties"
        ]["Policies"][0]["PolicyDocument"]["Statement"]
        by_action = {tuple(s["Action"]): s["Resource"] for s in statements}
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
        args = argparse.Namespace(plan=True, name="zolana-nitro-test")
        with (
            patch.object(aws_nitro, "configuration", return_value=config()),
            patch("builtins.print"),
        ):
            aws_nitro.deploy(args, client, None)
        self.assertEqual(
            [call.args[1] for call in client.call.call_args_list], ["validate-template"]
        )

    def test_deploy_refuses_parent_measurements_that_differ_from_measure(self):
        aws = Mock()
        out = {"Bucket": "b", "ApiKeySecret": "s", "Url": "https://x"}
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
            expect_pcrs=PCR,
        )
        parent = dict(PCR, PCR0="f" * 96, nitro_cli="Nitro CLI 9.9.9")
        with (
            patch.object(aws_nitro.gpu, "wait_stack", return_value={}),
            patch.object(aws_nitro.gpu, "outputs", return_value=out),
            patch.object(aws_nitro.gpu, "object_exists", return_value=True),
            patch.object(aws_nitro.gpu, "check_gateway"),
            patch.object(aws_nitro.gpu, "log"),
            patch.object(aws_nitro, "read_measurements", return_value=parent),
            patch.object(aws_nitro, "check_attestation") as attestation,
            self.assertRaisesRegex(RuntimeError, "MEASUREMENT MISMATCH(.|\n)*PCR0"),
        ):
            aws_nitro.deploy(args, aws, stack)
        attestation.assert_not_called()
        aws.command.assert_not_called()

    def test_expected_pcrs_need_every_measure_pcr(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pcrs.json"
            measured = dict(PCR, HashAlgorithm="Sha512_48 { .. }", source="measure")
            path.write_text(json.dumps(measured))
            self.assertEqual(aws_nitro.expected_pcrs(str(path)), PCR)
            path.write_text(json.dumps(dict(measured, PCR1=PCR["PCR1"].upper())))
            self.assertEqual(aws_nitro.expected_pcrs(str(path)), PCR)
            for record in (
                dict(PCR, HashAlgorithm="Sha512_48 { .. }"),
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
        with patch.object(aws_nitro, "docker", side_effect=["", record]) as docker:
            measured = aws_nitro.measure(IMAGE)
            self.assertEqual(measured["PCR0"], PCR["PCR0"])
            self.assertEqual(measured["source"], "measure")
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
        )
        with self.assertRaisesRegex(ValueError, "different settings"):
            aws_nitro.deploy(args, Mock(), stack)


class AttestationTests(unittest.TestCase):
    def check(self, attestation):
        aws = Mock()
        aws.call.return_value = {"SecretString": "secret"}
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps(attestation).encode()
        out = {"ApiKeySecret": "arn", "Url": "https://example.cloudfront.net"}
        with patch.object(
            aws_nitro.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            aws_nitro.check_attestation(aws, out, PCR)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("X-api-key"), "secret")
        self.assertRegex(request.full_url, r"/tee/v1/attestation\?nonce=[0-9a-f]{64}$")

    def test_document_must_carry_every_built_pcr(self):
        document = b"cbor" + b"".join(bytes.fromhex(value) for value in PCR.values())
        evidence = {"document": document.hex()}
        self.check({"platform": "aws-nitro", "gpu": None, "evidence": evidence})
        missing = {"document": document[:-1].hex()}
        with self.assertRaisesRegex(RuntimeError, "PCR2"):
            self.check({"platform": "aws-nitro", "gpu": None, "evidence": missing})
        with self.assertRaisesRegex(RuntimeError, "Nitro"):
            self.check({"platform": "dstack-tdx", "gpu": None, "evidence": evidence})


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
            host.enclave_state()
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
            host.units([])["zolana-enclave.service"],
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
        running = json.dumps([{"EnclaveName": host.ENCLAVE, "State": "RUNNING"}])
        other = json.dumps([{"EnclaveName": "other", "State": "RUNNING"}])
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

        def nitro(*args, timeout=300):
            answer = answers[args[0]].pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

        with (
            patch.object(host, "nitro", side_effect=nitro),
            patch("sys.stderr"),
            self.assertRaisesRegex(RuntimeError, "ABSENT"),
        ):
            host.supervise(config(), poll=0)
        self.assertEqual(answers["describe-enclaves"], [])

    def test_allocator_matches_the_enclave_run_and_never_debugs(self):
        settings = config()
        self.assertEqual(
            host.allocator(settings), "---\nmemory_mib: 49152\ncpu_count: 12\n"
        )
        command = host.enclave_command(settings)
        self.assertNotIn("--debug-mode", command)
        self.assertNotIn("--attach-console", command)
        self.assertEqual(command[command.index("--cpu-count") + 1], "12")
        self.assertEqual(command[command.index("--memory") + 1], "49152")
        self.assertEqual(
            command[command.index("--enclave-cid") + 1], str(host.ENCLAVE_CID)
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
        units = host.units(parsed)
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

    def test_ingress_reaches_the_enclave_listener(self):
        self.assertIn(f"VSOCK-LISTEN:{host.ENCLAVE_PORT},", ENTRYPOINT)
        self.assertIn(f"--prover-address 127.0.0.1:{host.ENCLAVE_PORT}", ENTRYPOINT)
        ingress = host.units([])["zolana-ingress.service"]
        self.assertIn(
            f"TCP-LISTEN:{host.INGRESS_PORT},bind=127.0.0.1,fork,reuseaddr VSOCK-CONNECT:{host.ENCLAVE_CID}:{host.ENCLAVE_PORT}",
            ingress,
        )
        self.assertIn(f"127.0.0.1:{host.INGRESS_PORT}", aws_host.gateway(False))

    def test_proxy_workers_exceed_the_indexer_concurrency(self):
        default = re.search(
            r'Name: "indexer-concurrency".*?Value: (\d+)',
            (SERVER / "main.go").read_text(),
        ).group(1)
        self.assertGreater(host.PROXY_WORKERS, int(default))

    def test_enclave_unit_restarts_and_terminates(self):
        unit = host.units([])["zolana-enclave.service"]
        self.assertIn("Restart=always", unit)
        head, service = unit.split("[Service]")
        self.assertIn("Requires=nitro-enclaves-allocator.service", head)
        self.assertNotIn("Requires=", service)
        self.assertIn(
            f"ExecStopPost=-/usr/bin/nitro-cli terminate-enclave --enclave-name {host.ENCLAVE}",
            unit,
        )
        self.assertNotIn("DynamicUser", unit)
        for name, text in host.units([]).items():
            if name != "zolana-enclave.service":
                self.assertIn("DynamicUser=yes", text)

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

    def test_install_rejects_an_image_for_another_indexer(self):
        settings = dict(
            config(), outputs={"Bucket": "b", "ApiKeySecret": "s", "LogGroup": "l"}
        )
        with (
            patch.object(host, "run", return_value=""),
            patch.object(host.aws_host, "pull") as pull,
            patch.object(host, "write"),
            patch.object(host.subprocess, "run"),
            patch.object(
                host, "image_files", return_value=([], "https://other.example.com")
            ),
            patch("builtins.print"),
            self.assertRaisesRegex(ValueError, "another indexer"),
        ):
            host.install(settings)
        pull.assert_called_once_with(settings, (IMAGE, host.NGINX))


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
