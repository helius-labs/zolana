#!/usr/bin/env python3
import argparse
import base64
import functools
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
GPU = HERE.parent / "gpu"
REPOSITORY = HERE.parents[1]
sys.path.append(str(GPU))

import aws as gpu  # noqa: E402
import aws_stack  # noqa: E402
from aws_nitro_host import (  # noqa: E402
    MEASUREMENTS,
    PCRS,
    ROOT,
    SEED_OBJECT,
    image_files,
)

OWNER = {"Key": "zolana-tool", "Value": "nitro-deploy"}
IMAGE = re.compile(
    re.escape(gpu.REGISTRY_ACCOUNT)
    + r"\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com/([a-z0-9][a-z0-9._/-]*)@sha256:[0-9a-f]{64}"
)
AMI = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
MEASURE_IMAGE = "amazonlinux:2023@sha256:8ed3c0a996841537f75607e7d1de2114d8150391f75792e8da9268738547e73f"
PCR = re.compile(r"[0-9a-f]{96}")
HPKE_KEY = re.compile(r"[0-9a-f]{64}")
INSTANCE_TYPE = "m6i.4xlarge"
DISK_GB = 30
# An enclave cannot take CPU 0's core.
PARENT_VCPUS = 4
PARENT_MIB = 16384
MIN_ENCLAVE_MIB = 24576
TEE_CHECK = ("cargo", "run", "-q", "-p", "xtask", "--", "tee-check")
VERIFY_TIMEOUT = 1800


def template(config):
    body = aws_stack.template(config)
    resources = body["Resources"]
    instance = resources["Instance"]["Properties"]
    instance["EnclaveOptions"] = {"Enabled": True}
    del instance["UserData"]
    resources["HostRole"]["Properties"]["Policies"][0]["PolicyDocument"][
        "Statement"
    ].append(
        aws_stack.policy(
            ["s3:PutObject"], [aws_stack.sub("${Assets.Arn}/" + MEASUREMENTS)]
        )
    )
    distribution = resources["Distribution"]["Properties"]["DistributionConfig"]
    distribution["Origins"][0]["Id"] = "gateway"
    distribution["DefaultCacheBehavior"]["TargetOriginId"] = "gateway"
    body["Outputs"]["HostRole"] = {"Value": aws_stack.attr("HostRole", "Arn")}
    body["Description"] = "Zolana Nitro Enclave prover"
    return body


# Only a logged PutKeyPolicy lifts the denies.
def key_policy(account, *statements):
    return aws_stack.document(
        [
            {
                "Sid": "Administrator",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            *statements,
        ]
    )


def sealed():
    return [
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
    ]


# Until deploy binds the PCRs no attestation decrypts.
def unbound():
    return [
        {
            "Sid": "UnboundDecrypt",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "kms:Decrypt",
            "Resource": "*",
        }
    ]


def attested(host_role, pcrs):
    return [
        {
            "Sid": "AttestedEnclave",
            "Effect": "Allow",
            "Principal": {"AWS": host_role},
            "Action": "kms:Decrypt",
            "Resource": "*",
            "Condition": {
                "StringEqualsIgnoreCase": {
                    f"kms:RecipientAttestation:{name}": pcrs[name] for name in PCRS
                }
            },
        },
        *(
            {
                "Sid": f"Attested{name}",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {
                    "StringNotEqualsIgnoreCase": {
                        f"kms:RecipientAttestation:{name}": pcrs[name]
                    }
                },
            }
            for name in PCRS
        ),
    ]


def find_kms_key(aws, name):
    try:
        metadata = aws.call("kms", "describe-key", KeyId=f"alias/{name}")["KeyMetadata"]
    except gpu.AwsError as error:
        if "NotFoundException" in str(error):
            return None
        raise
    tags = aws.call("kms", "list-resource-tags", KeyId=metadata["KeyId"])["Tags"]
    if {"TagKey": OWNER["Key"], "TagValue": OWNER["Value"]} not in tags:
        raise RuntimeError(f"alias/{name} is not owned by the deployment tool")
    if metadata["KeyState"] != "Enabled":
        raise RuntimeError(f"alias/{name} is {metadata['KeyState']}")
    return metadata["Arn"]


def create_kms_key(aws, name, account):
    arn = find_kms_key(aws, name)
    if arn:
        return arn
    metadata = aws.call(
        "kms",
        "create-key",
        Description=f"{name} HPKE seed",
        Policy=json.dumps(key_policy(account, *sealed(), *unbound())),
        Tags=[{"TagKey": OWNER["Key"], "TagValue": OWNER["Value"]}],
    )["KeyMetadata"]
    try:
        aws.call(
            "kms",
            "create-alias",
            AliasName=f"alias/{name}",
            TargetKeyId=metadata["KeyId"],
        )
    except (Exception, KeyboardInterrupt):
        delete_kms_key(aws, metadata["KeyId"])
        raise
    gpu.log(f"Created alias/{name}")
    return metadata["Arn"]


def delete_kms_key(aws, key):
    aws.call("kms", "schedule-key-deletion", KeyId=key, PendingWindowInDays=7)


# The PCRs are bound before any seed is generated.
def release_seed(aws, out, key, pcrs):
    aws.call(
        "kms",
        "put-key-policy",
        KeyId=key,
        PolicyName="default",
        Policy=json.dumps(
            key_policy(key.split(":")[4], *sealed(), *attested(out["HostRole"], pcrs))
        ),
    )
    if gpu.object_exists(aws, out["Bucket"], SEED_OBJECT):
        return
    blob = aws.call(
        "kms", "generate-data-key-without-plaintext", KeyId=key, KeySpec="AES_256"
    )["CiphertextBlob"]
    with tempfile.TemporaryDirectory() as directory:
        seed = Path(directory) / "hpke-seed.bin"
        seed.write_bytes(base64.b64decode(blob))
        aws.command(
            "s3",
            "cp",
            str(seed),
            f"s3://{out['Bucket']}/{SEED_OBJECT}",
            "--only-show-errors",
        )


def enclave_size(described):
    threads = described["VCpuInfo"].get("DefaultThreadsPerCore", 1)
    cpus = described["VCpuInfo"]["DefaultVCpus"] - PARENT_VCPUS
    cpus -= cpus % threads
    memory = described["MemoryInfo"]["SizeInMiB"] - PARENT_MIB
    if (
        described.get("NitroEnclavesSupport") != "supported"
        or "x86_64" not in described["ProcessorInfo"]["SupportedArchitectures"]
        or cpus < 2
        or memory < MIN_ENCLAVE_MIB
    ):
        raise ValueError(
            f"Select an x86 instance with Nitro Enclaves and at least {PARENT_VCPUS + 2} vCPUs and {(PARENT_MIB + MIN_ENCLAVE_MIB) // 1024} GiB"
        )
    return cpus, memory


def image_reference(image):
    match = IMAGE.fullmatch(image or "")
    if not match:
        raise ValueError(
            f"--image must be an ECR image in account {gpu.REGISTRY_ACCOUNT} pinned by @sha256 digest"
        )
    return match.groups()


def docker(*args, stdout=None, timeout=1800):
    result = subprocess.run(
        ["docker", *args], stdout=stdout, text=True, timeout=timeout, check=False
    )
    if result.returncode:
        raise RuntimeError(f"docker {args[0]} failed")
    return result.stdout


def measure(image):
    image_reference(image)
    docker("pull", "--platform", "linux/amd64", image, stdout=sys.stderr)
    record = json.loads(
        docker(
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-v",
            f"{HERE.parent}:/tools:ro",
            MEASURE_IMAGE,
            "python3",
            "/tools/nitro/aws_nitro_host.py",
            "measure",
            image,
            stdout=subprocess.PIPE,
        )
    )
    return record | {"kms_key": image_files(image)["kms_key"], "source": "measure"}


def expected_pcrs(path):
    record = json.loads(Path(path).read_text())
    pcrs = {
        name: value.lower() if isinstance(value := record.get(name), str) else value
        for name in PCRS
    }
    if (
        record.get("source") != "measure"
        or "kms_key" not in record
        or not isinstance(record.get("image"), str)
        or not all(
            isinstance(value, str) and PCR.fullmatch(value) for value in pcrs.values()
        )
    ):
        raise argparse.ArgumentTypeError(
            f"{path} needs PCR0, PCR1, PCR2, image and kms_key written by tools/nitro/aws_nitro.py measure"
        )
    return pcrs | {"kms_key": record["kms_key"], "image": record["image"]}


def configuration(args, aws):
    image_region, repository = image_reference(args.image)
    gpu.Aws(image_region, args.profile).call(
        "ecr",
        "describe-images",
        RegistryId=gpu.REGISTRY_ACCOUNT,
        RepositoryName=repository,
        ImageIds=[{"imageDigest": args.image.split("@", 1)[1]}],
    )
    instance_type = args.instance_type or INSTANCE_TYPE
    described = aws.call(
        "ec2", "describe-instance-types", InstanceTypes=[instance_type]
    )["InstanceTypes"][0]
    cpus, memory = enclave_size(described)
    return {
        "region": args.region,
        "image_region": image_region,
        "instance_type": instance_type,
        "zone": gpu.placement(aws, instance_type, args.zone),
        "ami": gpu.parameter(aws, AMI),
        "cloudfront_prefix": gpu.cloudfront_prefix(aws),
        "disk_gb": DISK_GB,
        "with_indexer": False,
        "image_repositories": [
            f"arn:aws:ecr:{image_region}:{gpu.REGISTRY_ACCOUNT}:repository/{repository}"
        ],
        "prover_image": args.image,
        "indexer_url": args.indexer_url or "",
        "enclave_cpus": cpus,
        "enclave_memory_mib": memory,
    }


def read_measurements(aws, out):
    if not gpu.object_exists(aws, out["Bucket"], MEASUREMENTS):
        return None
    return json.loads(
        aws.command("s3", "cp", f"s3://{out['Bucket']}/{MEASUREMENTS}", "-")
    )


def check_measurements(expected, measured):
    differ = [name for name in PCRS if measured.get(name) != expected[name]]
    if differ:
        lines = [
            f"{name} parent {measured.get(name)}, measure {expected[name]}"
            for name in differ
        ]
        raise RuntimeError(
            "MEASUREMENT MISMATCH. Do not pin this deployment.\n"
            + "\n".join(lines)
            + f"\nParent nitro-cli {measured.get('nitro_cli')}"
        )


def attestation_policy(measurements, hpke_public_key):
    return {
        "platform": "aws-nitro",
        "measurements": [{name.lower(): measurements[name] for name in PCRS}],
        "hpke_public_key": hpke_public_key,
        "gpu": "optional",
        "max_age_secs": 600,
    }


def offered_key(url, api_key):
    request = urllib.request.Request(
        f"{url}/tee/v1/attestation?nonce={secrets.token_hex(32)}",
        headers={"X-API-Key": api_key},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        key = json.loads(response.read()).get("hpke_public_key")
    if not isinstance(key, str) or not HPKE_KEY.fullmatch(key):
        raise RuntimeError("Attestation carries no HPKE key")
    return key


# Round robin sends consecutive requests to every enclave in turn.
def check_attestation(aws, out, measurements, enclaves):
    api_key = gpu.api_key(aws, out)
    rounds = 2 * enclaves
    offered = {offered_key(out["Url"], api_key) for _ in range(rounds)}
    if len(offered) != 1:
        raise RuntimeError(
            "Enclaves offer different HPKE keys. Do not pin this deployment."
        )
    (hpke_public_key,) = offered
    refused = (
        f"Enclave at {out['Url']} failed tee-check. Do not pin this deployment.\n"
        "Deploy verifies the enclave with cargo run -p xtask from the repository root"
    )
    with tempfile.TemporaryDirectory() as directory:
        policy = Path(directory) / "policy.json"
        policy.write_text(json.dumps(attestation_policy(measurements, hpke_public_key)))
        for _ in range(rounds):
            try:
                result = subprocess.run(
                    [*TEE_CHECK, out["Url"], "--policy", str(policy)],
                    cwd=REPOSITORY,
                    env=os.environ | {"PROVER_API_KEY": api_key},
                    # Deploy stdout carries only the JSON summary.
                    stdout=sys.stderr,
                    timeout=VERIFY_TIMEOUT,
                    check=False,
                )
            except FileNotFoundError as error:
                raise RuntimeError(refused) from error
            if result.returncode:
                raise RuntimeError(refused)
    return hpke_public_key


def show(stack, measurements=None, hpke_public_key=None):
    out = gpu.outputs(stack)
    config = json.loads(out.get("Config", "{}"))
    summary = {"stack": stack["StackName"], "status": stack["StackStatus"]}
    for name in ("Url", "InstanceId", "ApiKeySecret", "LogGroup"):
        if name in out:
            summary[name] = out[name]
    for name in ("prover_image", "indexer_url", "enclave_cpus", "enclave_memory_mib"):
        if name in config:
            summary[name] = config[name]
    if measurements:
        summary["measurements"] = measurements
    if hpke_public_key:
        summary["hpke_public_key"] = hpke_public_key
    print(json.dumps(summary, indent=2))


def deploy(args, aws, stack):
    kms_key = None
    if args.expect_pcrs and args.expect_pcrs["kms_key"]:
        kms_key = find_kms_key(aws, args.name)
        if args.expect_pcrs["kms_key"] != kms_key:
            raise ValueError(
                "The image names another KMS key than this deployment. Run kms-key and build the image with the ARN it prints"
            )
    if stack:
        if args.plan:
            print(json.dumps(stack, indent=2))
            return
        params = {
            item["ParameterKey"]: item["ParameterValue"] for item in stack["Parameters"]
        }
        config = json.loads(params["Config"])
        for name, key in (
            ("image", "prover_image"),
            ("indexer_url", "indexer_url"),
            ("instance_type", "instance_type"),
            ("zone", "zone"),
        ):
            value = getattr(args, name)
            if value is not None and value != config.get(key):
                raise ValueError(
                    "Existing deployment has different settings. Use another name"
                )
        gpu.log("Resuming " + args.name)
    else:
        config = configuration(args, aws)
        body = json.dumps(template(config))
        aws.call("cloudformation", "validate-template", TemplateBody=body)
        if args.plan:
            print(body)
            return
        aws.call(
            "cloudformation",
            "create-stack",
            StackName=args.name,
            TemplateBody=body,
            Capabilities=["CAPABILITY_IAM"],
            Tags=[OWNER],
            OnFailure="DELETE",
        )
        gpu.log(
            f"Creating {args.name} with {config['instance_type']} in {config['zone']}"
        )
    if args.expect_pcrs and args.expect_pcrs["image"] != config["prover_image"]:
        raise ValueError("The measured PCRs belong to another image")
    stack = gpu.wait_stack(aws, args.name, owner=OWNER)
    out = gpu.outputs(stack)
    if kms_key:
        release_seed(aws, out, kms_key, args.expect_pcrs)
    if not gpu.object_exists(aws, out["Bucket"], "install/complete"):
        gpu.install(
            aws,
            config,
            out,
            root=str(ROOT),
            scripts=(GPU / "aws_host.py", HERE / "aws_nitro_host.py"),
        )
    gpu.check_gateway(aws, config, out)
    measurements = read_measurements(aws, out)
    if measurements is None:
        raise RuntimeError("Installation recorded no enclave measurements")
    check_measurements(args.expect_pcrs, measurements)
    hpke_public_key = check_attestation(
        aws, out, args.expect_pcrs, measurements["enclaves"]
    )
    gpu.log(f"{measurements['enclaves']} enclaves attest HPKE key {hpke_public_key}")
    with tempfile.TemporaryDirectory() as directory:
        marker = Path(directory) / "complete"
        marker.write_text(config["prover_image"])
        aws.command(
            "s3",
            "cp",
            str(marker),
            f"s3://{out['Bucket']}/install/complete",
            "--only-show-errors",
        )
    show(stack, measurements, hpke_public_key)


def main():
    parser = argparse.ArgumentParser(
        description="Deploy the CPU prover in an AWS Nitro Enclave. Requires Python 3 and AWS CLI v2."
    )
    parser.add_argument(
        "action", choices=("kms-key", "measure", "deploy", "status", "destroy")
    )
    parser.add_argument(
        "name",
        nargs="?",
        type=functools.partial(gpu.stack_name, prefix="zolana-nitro-"),
    )
    parser.add_argument("--profile", default=os.environ.get("AWS_PROFILE"))
    parser.add_argument("--region", default="eu-central-1")
    parser.add_argument(
        "--image", help="Enclave image built from Dockerfile.nitro, pinned by digest"
    )
    parser.add_argument(
        "--indexer-url", help="Indexer URL the image was built with, default none"
    )
    parser.add_argument(
        "--instance-type", help=f"Default {INSTANCE_TYPE}, Nitro Enclaves capable x86"
    )
    parser.add_argument(
        "--zone", help="Availability zone, default first offering the instance type"
    )
    parser.add_argument(
        "--expect-pcrs",
        type=expected_pcrs,
        help="measure output for --image, deploy fails on other parent measurements",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Resolve and validate the stack without creating resources",
    )
    args = parser.parse_args()
    if args.action == "measure":
        print(json.dumps(measure(args.image), indent=2))
        return
    if args.name is None:
        parser.error(f"{args.action} requires a name")
    if args.plan and args.action != "deploy":
        parser.error("--plan requires deploy")
    if args.action == "deploy" and not args.plan and args.expect_pcrs is None:
        parser.error("deploy requires --expect-pcrs from measure")
    aws = gpu.Aws(args.region, args.profile)
    identity = aws.call("sts", "get-caller-identity")
    if identity["Account"] != gpu.REGISTRY_ACCOUNT:
        raise ValueError(f"Select an AWS profile in account {gpu.REGISTRY_ACCOUNT}")
    gpu.log(f"AWS account {identity['Account']}, region {args.region}")
    if args.action == "kms-key":
        print(create_kms_key(aws, args.name, identity["Account"]))
        return
    stack = gpu.get_stack(aws, args.name, OWNER)
    if args.action == "deploy":
        deploy(args, aws, stack)
    elif args.action == "status":
        if stack is None:
            raise ValueError("Deployment does not exist")
        show(stack, read_measurements(aws, gpu.outputs(stack)))
    else:
        kms_key = find_kms_key(aws, args.name)
        if stack is None and kms_key is None:
            raise ValueError("Deployment does not exist")
        if stack:
            gpu.destroy(aws, stack, owner=OWNER)
        if kms_key:
            aws.call("kms", "delete-alias", AliasName=f"alias/{args.name}")
            delete_kms_key(aws, kms_key)
            gpu.log(f"Scheduled deletion of alias/{args.name}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("Interrupted. Use status to inspect the deployment before retrying")
    except (
        RuntimeError,
        ValueError,
        KeyError,
        OSError,
        subprocess.TimeoutExpired,
    ) as error:
        sys.exit(str(error))
