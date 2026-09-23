#!/usr/bin/env python3
import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from aws_host import POSTGRES
from aws_stack import template

HERE = Path(__file__).resolve().parent
REGISTRY_ACCOUNT = "558215002830"
IMAGE_REGION = "eu-north-1"
OWNER = {"Key": "zolana-tool", "Value": "gpu-deploy"}


class AwsError(RuntimeError):
    pass


class Aws:
    def __init__(self, region, profile=None):
        self.region = region
        self.base = [
            "aws",
            "--no-cli-pager",
            "--region",
            region,
            "--cli-connect-timeout",
            "10",
            "--cli-read-timeout",
            "60",
        ]
        if profile:
            self.base += ["--profile", profile]

    def command(self, *args, timeout=90):
        result = subprocess.run(
            self.base + list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode:
            raise AwsError(result.stderr.strip())
        return result.stdout

    def call(self, service, operation, **parameters):
        if service in ("ecs", "ecr"):
            parameters = {
                key[0].lower() + key[1:]: value for key, value in parameters.items()
            }
        output = self.command(
            service,
            operation,
            "--cli-input-json",
            json.dumps(parameters),
            "--output",
            "json",
        )
        return json.loads(output) if output.strip() else {}


def log(message):
    print(message, file=sys.stderr, flush=True)


def stack_name(value):
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,23}", value):
        raise argparse.ArgumentTypeError(
            "Use a lowercase name with at most 24 letters, digits or hyphens"
        )
    return "zolana-gpu-" + value


def get_stack(aws, name):
    try:
        stack = aws.call("cloudformation", "describe-stacks", StackName=name)["Stacks"][
            0
        ]
    except AwsError as error:
        if "does not exist" in str(error):
            return None
        raise
    if OWNER not in stack.get("Tags", []):
        raise RuntimeError("Stack is not owned by the GPU deployment tool")
    return stack


def outputs(stack):
    return {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}


def wait_stack(aws, name, deleting=False):
    deadline = time.monotonic() + 2400
    previous = None
    while time.monotonic() < deadline:
        stack = get_stack(aws, name)
        if stack is None and deleting:
            return None
        if stack is None:
            raise RuntimeError("Deployment stack disappeared")
        status = stack["StackStatus"]
        events = aws.call("cloudformation", "describe-stack-events", StackName=name)[
            "StackEvents"
        ]
        event = events[0]
        progress = f"{event['LogicalResourceId']} {event['ResourceStatus']}"
        if progress != previous:
            log(progress)
            previous = progress
        if not deleting and status in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            return stack
        if "FAILED" in status or "ROLLBACK" in status:
            failures = [
                e.get("ResourceStatusReason", "")
                for e in events
                if "FAILED" in e["ResourceStatus"]
            ]
            raise RuntimeError(f"Stack {status}. " + "\n".join(failures[:4]))
        time.sleep(10)
    raise RuntimeError(
        "Stack wait timed out. Use status to inspect it or destroy to remove it"
    )


def image_pair(aws, revision=None, with_indexer=False, preview=False):
    def entries(repository, prefix):
        found = {}
        for image in aws.call(
            "ecr",
            "describe-images",
            RegistryId=REGISTRY_ACCOUNT,
            RepositoryName=repository,
            Filter={"tagStatus": "TAGGED"},
        ).get("imageDetails", []):
            for tag in image.get("imageTags", []):
                if re.fullmatch(re.escape(prefix) + r"[a-f0-9]{40}", tag):
                    found[tag[len(prefix) :]] = image
        return found

    prefix = "gpu-preview" if preview else "gpu"
    provers = entries("zolana-prover", prefix + "-sm89-")
    photons = entries("zolana-photon", prefix + "-") if with_indexer else {}
    candidates = set(provers) & set(photons) if with_indexer else set(provers)
    if revision:
        candidates &= {revision}
    if not candidates:
        raise RuntimeError(
            "No published GPU release found. Wait for publish-gpu on main to finish"
        )
    selected = max(candidates, key=lambda sha: provers[sha]["imagePushedAt"])
    registry = f"{REGISTRY_ACCOUNT}.dkr.ecr.{IMAGE_REGION}.amazonaws.com"
    result = {
        "revision": selected,
        "prover_image": f"{registry}/zolana-prover@{provers[selected]['imageDigest']}",
    }
    if with_indexer:
        result["photon_image"] = (
            f"{registry}/zolana-photon@{photons[selected]['imageDigest']}"
        )
    return result


def discover_source(aws, cluster, service):
    response = aws.call("ecs", "describe-services", Cluster=cluster, Services=[service])
    if response.get("failures") or len(response.get("services", [])) != 1:
        raise RuntimeError("Source Photon service was not found")
    source = response["services"][0]
    task = aws.call(
        "ecs", "describe-task-definition", TaskDefinition=source["taskDefinition"]
    )["taskDefinition"]
    for container in task["containerDefinitions"]:
        secrets = {
            item["name"]: item["valueFrom"] for item in container.get("secrets", [])
        }
        if {"DATABASE_URL", "PHOTON_RPC_URL"} <= secrets.keys():
            if any(
                len(secrets[key].split(":")) != 7
                or ":secretsmanager:" not in secrets[key]
                for key in ("DATABASE_URL", "PHOTON_RPC_URL")
            ):
                raise RuntimeError(
                    "Source must use Secrets Manager string secrets without JSON selectors"
                )
            return {
                "cluster": cluster,
                "service": service,
                "network": source["networkConfiguration"],
                "database_secret": secrets["DATABASE_URL"],
                "rpc_secret": secrets["PHOTON_RPC_URL"],
            }
    raise RuntimeError("Source task has no Photon database and RPC secrets")


def configuration(args, aws):
    with_indexer = bool(args.with_indexer)
    source_region = args.source_region or "eu-north-1"
    if with_indexer and (args.indexer_url or args.indexer_key_secret):
        raise ValueError("Use either --with-indexer or an external indexer")
    if not with_indexer:
        url = urllib.parse.urlsplit(args.indexer_url or "")
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError(
                "Prover-only deployments require --indexer-url with an HTTPS URL and no embedded credentials"
            )
    instance_type = args.instance_type or "g6.2xlarge"
    info = aws.call("ec2", "describe-instance-types", InstanceTypes=[instance_type])[
        "InstanceTypes"
    ][0]
    gpus = info.get("GpuInfo", {}).get("Gpus", [])
    if (
        not gpus
        or any(gpu["Name"] not in ("L4", "L40S") for gpu in gpus)
        or "x86_64" not in info["ProcessorInfo"]["SupportedArchitectures"]
    ):
        raise ValueError("Select an x86 EC2 instance with L4 or L40S GPUs")
    offers = aws.call(
        "ec2",
        "describe-instance-type-offerings",
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]
    zones = sorted(offer["Location"] for offer in offers)
    zone = args.zone or (zones[0] if zones else None)
    if zone not in zones:
        raise ValueError(
            "Instance type is not offered in the selected availability zone"
        )
    ami = aws.call(
        "ssm",
        "get-parameter",
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/gpu/recommended/image_id",
    )["Parameter"]["Value"]
    prefix = aws.call(
        "ec2",
        "describe-managed-prefix-lists",
        Filters=[
            {
                "Name": "prefix-list-name",
                "Values": ["com.amazonaws.global.cloudfront.origin-facing"],
            }
        ],
    )["PrefixLists"][0]["PrefixListId"]
    config = {
        "region": args.region,
        "image_region": IMAGE_REGION,
        "source_region": source_region,
        "preview": bool(args.preview),
        "instance_type": instance_type,
        "zone": zone,
        "ami": ami,
        "cloudfront_prefix": prefix,
        "disk_gb": args.disk_gb or 200,
        "with_indexer": with_indexer,
        "prover_cpus": max(
            1, info["VCpuInfo"]["DefaultVCpus"] - (2 if with_indexer else 0)
        ),
        "indexer_url": "http://127.0.0.1:8784" if with_indexer else args.indexer_url,
        "indexer_key_secret": args.indexer_key_secret,
        "image_repositories": [
            f"arn:aws:ecr:{IMAGE_REGION}:{REGISTRY_ACCOUNT}:repository/zolana-{name}"
            for name in ("prover", "photon")
        ],
    }
    config.update(
        image_pair(
            Aws(IMAGE_REGION, args.profile),
            args.revision,
            with_indexer,
            bool(args.preview),
        )
    )
    if with_indexer:
        config["source"] = discover_source(
            Aws(source_region, args.profile),
            args.source_cluster or "zolnet-devnet-c",
            args.source_service or "zolnet-devnet-c-photon-api",
        )
        config["rpc_secret"] = config["source"]["rpc_secret"]
    return config


def export_cache(aws, config, out, name):
    # 1. The source security group grants database ingress.
    source = config["source"]
    command = """set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends awscli ca-certificates >/dev/null
export PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=120000 -c lock_timeout=1000'
timeout 300 pg_dump "$DATABASE_URL" --format=custom --compress=1 --no-owner --no-privileges --lock-wait-timeout=1s --file=/tmp/photon.dump
unset DATABASE_URL PGOPTIONS
timeout 300 aws s3 cp /tmp/photon.dump "$DESTINATION" --region "$DESTINATION_REGION" --only-show-errors
"""
    definition = aws.call(
        "ecs",
        "register-task-definition",
        Family=name + "-export",
        NetworkMode="awsvpc",
        RequiresCompatibilities=["FARGATE"],
        Cpu="1024",
        Memory="2048",
        ExecutionRoleArn=out["ExportRole"],
        TaskRoleArn=out["ExportRole"],
        RuntimePlatform={"cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX"},
        ContainerDefinitions=[
            {
                "name": "export",
                "image": POSTGRES,
                "essential": True,
                "entryPoint": ["timeout", "--kill-after=10s", "780", "bash", "-c"],
                "command": [command],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-region": config["region"],
                        "awslogs-group": out["LogGroup"],
                        "awslogs-stream-prefix": "export",
                    },
                },
                "secrets": [
                    {"name": "DATABASE_URL", "valueFrom": source["database_secret"]}
                ],
                "environment": [
                    {
                        "name": "DESTINATION",
                        "value": f"s3://{out['Bucket']}/cache/photon.dump",
                    },
                    {"name": "DESTINATION_REGION", "value": config["region"]},
                ],
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    task_arn = None
    try:
        result = aws.call(
            "ecs",
            "run-task",
            Cluster=source["cluster"],
            TaskDefinition=definition,
            LaunchType="FARGATE",
            NetworkConfiguration=source["network"],
            StartedBy=name,
            Count=1,
            Tags=[{"key": OWNER["Key"], "value": OWNER["Value"]}],
        )
        if result.get("failures") or len(result.get("tasks", [])) != 1:
            raise RuntimeError(
                "Cache export could not start. "
                + json.dumps(result.get("failures", []))
            )
        task_arn = result["tasks"][0]["taskArn"]
        deadline = time.monotonic() + 900
        previous = None
        while time.monotonic() < deadline:
            task = aws.call(
                "ecs", "describe-tasks", Cluster=source["cluster"], Tasks=[task_arn]
            )["tasks"][0]
            status = task["lastStatus"]
            if status != previous:
                log("Cache export " + status)
                previous = status
            if status == "STOPPED":
                if any(c.get("exitCode") != 0 for c in task["containers"]):
                    raise RuntimeError(
                        "Cache export failed. " + task.get("stoppedReason", "")
                    )
                return
            time.sleep(5)
        raise RuntimeError("Cache export exceeded its time limit")
    finally:
        if task_arn:
            aws.call(
                "ecs",
                "stop-task",
                Cluster=source["cluster"],
                Task=task_arn,
                Reason="Deployment export finished",
            )
        aws.call("ecs", "deregister-task-definition", TaskDefinition=definition)


def installed(aws, instance):
    response = aws.call(
        "ssm",
        "describe-instance-information",
        Filters=[{"Key": "InstanceIds", "Values": [instance]}],
    )
    return any(
        item["PingStatus"] == "Online" for item in response["InstanceInformationList"]
    )


def install(aws, config, out):
    deadline = time.monotonic() + 600
    while not installed(aws, out["InstanceId"]):
        if time.monotonic() >= deadline:
            raise RuntimeError("SSM registration timed out")
        time.sleep(5)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(dict(config, outputs=out)))
        for local, remote in (
            (path, "config.json"),
            (HERE / "aws_host.py", "aws_host.py"),
        ):
            aws.command(
                "s3",
                "cp",
                str(local),
                f"s3://{out['Bucket']}/install/{remote}",
                "--only-show-errors",
            )
    region, bucket = shlex.quote(config["region"]), shlex.quote(out["Bucket"])
    commands = ["set -eu", "umask 077", "mkdir -p /opt/zolana-gpu"]
    for name in ("config.json", "aws_host.py"):
        commands.append(
            f"aws --region {region} s3 cp s3://{bucket}/install/{name} /opt/zolana-gpu/{name} --only-show-errors"
        )
    commands.append("python3 /opt/zolana-gpu/aws_host.py /opt/zolana-gpu/config.json")
    command_id = aws.call(
        "ssm",
        "send-command",
        InstanceIds=[out["InstanceId"]],
        DocumentName="AWS-RunShellScript",
        TimeoutSeconds=120,
        Parameters={"commands": ["\n".join(commands)], "executionTimeout": ["2700"]},
        CloudWatchOutputConfig={
            "CloudWatchLogGroupName": out["LogGroup"],
            "CloudWatchOutputEnabled": True,
        },
    )["Command"]["CommandId"]
    log(f"Installing via SSM {command_id}. Logs in {out['LogGroup']}")
    try:
        wait_installation(aws, command_id, out["InstanceId"])
    except (Exception, KeyboardInterrupt):
        aws.call(
            "ssm",
            "cancel-command",
            CommandId=command_id,
            InstanceIds=[out["InstanceId"]],
        )
        raise


def wait_installation(aws, command_id, instance):
    deadline = time.monotonic() + 2820
    previous = ""
    while time.monotonic() < deadline:
        try:
            invocation = aws.call(
                "ssm",
                "get-command-invocation",
                CommandId=command_id,
                InstanceId=instance,
            )
        except AwsError as error:
            if "InvocationDoesNotExist" not in str(error):
                raise
            time.sleep(3)
            continue
        progress = invocation.get("StandardOutputContent", "")
        if progress != previous:
            log(progress[len(previous) :].strip())
            previous = progress
        status = invocation["Status"]
        if status == "Success":
            return
        if status not in ("Pending", "InProgress", "Delayed"):
            raise RuntimeError(
                f"Installation {status}. {invocation.get('StandardErrorContent', '')}"
            )
        time.sleep(5)
    raise RuntimeError(
        "Installation wait timed out. Inspect the SSM command before retrying"
    )


def show(stack):
    out = outputs(stack)
    result = {"stack": stack["StackName"], "status": stack["StackStatus"]}
    for name in ("Url", "InstanceId", "ApiKeySecret", "LogGroup"):
        if name in out:
            result[name] = out[name]
    if "Config" in out and json.loads(out["Config"])["with_indexer"]:
        result["IndexerUrl"] = out["Url"] + "/indexer"
    print(json.dumps(result, indent=2))


def deploy(args, aws, stack):
    if stack:
        if args.plan:
            print(json.dumps(stack, indent=2))
            return
        params = {
            item["ParameterKey"]: item["ParameterValue"] for item in stack["Parameters"]
        }
        config = json.loads(params["Config"])
        saved = dict(
            config,
            source_cluster=config.get("source", {}).get("cluster"),
            source_service=config.get("source", {}).get("service"),
        )
        for name in (
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
        ):
            value = getattr(args, name)
            if value is not None and value != saved.get(name):
                raise ValueError(
                    "Existing deployment has different settings. Use another name"
                )
        log("Resuming " + args.name)
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
        log(f"Creating {args.name} with {config['instance_type']} in {config['zone']}")
    stack = wait_stack(aws, args.name)
    out = outputs(stack)
    if not object_exists(aws, out["Bucket"], "install/complete"):
        if config["with_indexer"] and not object_exists(
            aws, out["Bucket"], "cache/photon.dump"
        ):
            export_cache(
                Aws(config["source_region"], args.profile), config, out, args.name
            )
        install(aws, config, out)
    check_gateway(aws, config, out)
    with tempfile.TemporaryDirectory() as directory:
        marker = Path(directory) / "complete"
        marker.write_text(config["revision"])
        aws.command(
            "s3",
            "cp",
            str(marker),
            f"s3://{out['Bucket']}/install/complete",
            "--only-show-errors",
        )
    show(stack)


def object_exists(aws, bucket, key):
    try:
        aws.call("s3api", "head-object", Bucket=bucket, Key=key)
        return True
    except AwsError as error:
        if "404" in str(error) or "Not Found" in str(error):
            return False
        raise


def check_gateway(aws, config, out):
    try:
        with urllib.request.urlopen(out["Url"] + "/ready", timeout=15):
            raise RuntimeError("Public gateway accepted an unauthenticated request")
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise RuntimeError(f"Public gateway returned HTTP {error.code}") from error
    key = aws.call("secretsmanager", "get-secret-value", SecretId=out["ApiKeySecret"])[
        "SecretString"
    ]
    paths = ["/ready"] + (["/indexer/readiness"] if config["with_indexer"] else [])
    for path in paths:
        request = urllib.request.Request(out["Url"] + path, headers={"X-API-Key": key})
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise RuntimeError("Public readiness check failed")


def main():
    parser = argparse.ArgumentParser(
        description="Deploy an isolated Aeglos prover on AWS. Requires Python 3 and AWS CLI v2."
    )
    parser.add_argument("action", choices=("deploy", "status", "destroy"))
    parser.add_argument("name", type=stack_name)
    parser.add_argument("--profile", default=os.environ.get("AWS_PROFILE"))
    parser.add_argument("--region", default="eu-central-1")
    parser.add_argument(
        "--with-indexer",
        action="store_true",
        default=None,
        help="Copy devnet-c into local PostgreSQL and run Photon",
    )
    parser.add_argument(
        "--indexer-url", help="External HTTPS indexer for a prover-only deployment"
    )
    parser.add_argument(
        "--indexer-key-secret",
        help="Secrets Manager ARN containing the external indexer API key",
    )
    parser.add_argument("--instance-type", help="Default g6.2xlarge, L4 or L40S only")
    parser.add_argument(
        "--disk-gb", type=int, help="Encrypted gp3 volume, default 200 GiB"
    )
    parser.add_argument(
        "--zone", help="Availability zone, default first offering the instance type"
    )
    parser.add_argument(
        "--revision", help="Published main commit, default newest complete release"
    )
    parser.add_argument(
        "--preview",
        action="store_true",
        default=None,
        help="Use preview images with an explicit --revision",
    )
    parser.add_argument("--source-region", help="Source region, default eu-north-1")
    parser.add_argument(
        "--source-cluster", help="Source cluster, default zolnet-devnet-c"
    )
    parser.add_argument(
        "--source-service", help="Source service, default zolnet-devnet-c-photon-api"
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Resolve and validate the stack without creating resources",
    )
    args = parser.parse_args()
    if args.preview and not args.revision:
        parser.error("--preview requires --revision")
    if args.plan and args.action != "deploy":
        parser.error("--plan requires deploy")
    if args.disk_gb is not None and not 50 <= args.disk_gb <= 16384:
        parser.error("--disk-gb must be between 50 and 16384")
    aws = Aws(args.region, args.profile)
    identity = aws.call("sts", "get-caller-identity")
    if identity["Account"] != REGISTRY_ACCOUNT:
        raise ValueError(f"Select an AWS profile in account {REGISTRY_ACCOUNT}")
    log(f"AWS account {identity['Account']}, region {args.region}")
    stack = get_stack(aws, args.name)
    if args.action == "deploy":
        deploy(args, aws, stack)
    elif stack is None:
        raise ValueError("Deployment does not exist")
    elif args.action == "status":
        show(stack)
    else:
        out = outputs(stack)
        if "Bucket" in out:
            aws.command(
                "s3",
                "rm",
                f"s3://{out['Bucket']}",
                "--recursive",
                "--only-show-errors",
                timeout=600,
            )
        aws.call("cloudformation", "delete-stack", StackName=args.name)
        wait_stack(aws, args.name, deleting=True)
        log("Deleted " + args.name)


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
