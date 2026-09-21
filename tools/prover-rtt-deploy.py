#!/usr/bin/env python3
"""Deploy and inspect the isolated prover latency experiment."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import tempfile


STACK = "prover-rtt-optimize"
ACCOUNT = "558215002830"
REGION = "eu-north-1"
VPC = "vpc-0226e56161e816225"
PRIVATE_SUBNET = "subnet-01d0a4d27fb52d8d6"
PUBLIC_SUBNETS = ["subnet-07fced5e99eeca643", "subnet-0e9b6b37f4491a4e5"]
AMI = "ami-0c020a23b5dfdbd1b"
PHOTON = "https://d2xah7tnhdhcom.cloudfront.net"
TAGS = {"Stack": STACK, "ManagedBy": "prover-rtt-deploy"}
ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / "target/prover-rtt/deployment"
TAG_LIST = [{"Key": key, "Value": value} for key, value in TAGS.items()]
ECS_TAGS = [{"key": key, "value": value} for key, value in TAGS.items()]


class AwsError(RuntimeError):
    pass


class Deployment:
    def __init__(self, profile):
        STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        STATE_DIR.chmod(0o700)
        self.state_path = STATE_DIR / "state.json"
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {}
        self.command = ["aws", "--profile", profile, "--region", REGION, "--no-cli-pager"]
        identity = self.aws("sts", "get-caller-identity")
        if identity["Account"] != ACCOUNT:
            raise RuntimeError("AWS account does not match the experiment account")
        if self.state and self.state.get("stack") != STACK:
            raise RuntimeError("Deployment state belongs to another stack")
        self.state.update(stack=STACK, account=ACCOUNT, region=REGION)

    def aws(self, namespace, operation, *, extra=(), **payload):
        with tempfile.NamedTemporaryFile(mode="w", dir=STATE_DIR, suffix=".json") as request:
            json.dump(payload, request)
            request.flush()
            command = self.command + [namespace, operation, "--output", "json"]
            if payload:
                command += ["--cli-input-json", "file://" + request.name]
            result = subprocess.run(command + list(extra), capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise AwsError(f"{namespace} {operation} failed\n{result.stderr.strip()}")
        return json.loads(result.stdout) if result.stdout.strip() else {}

    def save(self):
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.state, indent=2) + "\n")
        temporary.chmod(0o600)
        temporary.replace(self.state_path)

    def once(self, key, create):
        if key not in self.state:
            self.state[key] = create()
            self.save()
            print(f"Created {key}", flush=True)
        return self.state[key]

    def role(self, suffix, principal, policy):
        name = STACK + "-" + suffix
        def create():
            result = self.aws("iam", "create-role", RoleName=name, Tags=TAG_LIST,
                              AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                                  {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]}))
            return result["Role"]["Arn"]
        arn = self.once(suffix + "_role", create)
        self.owned_role(name)
        self.aws("iam", "put-role-policy", RoleName=name, PolicyName=STACK,
                 PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy}))
        return arn

    def owned_role(self, name):
        self.owned(self.aws("iam", "get-role", RoleName=name)["Role"].get("Tags", []))

    def owned_cluster(self):
        self.owned(self.aws("ecs", "list-tags-for-resource", resourceArn=self.state["cluster"])["tags"])

    def owned_alb(self):
        arn = self.state["alb"]["LoadBalancerArn"]
        self.owned(self.aws("elbv2", "describe-tags", ResourceArns=[arn])["TagDescriptions"][0]["Tags"])

    def owned_bucket(self):
        self.owned(self.aws("s3api", "get-bucket-tagging", Bucket=self.state["bucket"])["TagSet"])

    def configure_target(self):
        self.owned(self.aws("elbv2", "describe-tags", ResourceArns=[self.state["target"]])["TagDescriptions"][0]["Tags"])
        self.aws("elbv2", "modify-target-group-attributes", TargetGroupArn=self.state["target"],
                 Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "5"}])

    @staticmethod
    def owned(tags):
        values = {item.get("Key", item.get("key")): item.get("Value", item.get("value")) for item in tags}
        if any(values.get(key) != value for key, value in TAGS.items()):
            raise RuntimeError("Resource lacks the exact experiment ownership tags")

    def infrastructure(self):
        bucket = STACK + "-" + ACCOUNT + "-" + REGION
        def create_bucket():
            self.aws("s3api", "create-bucket", Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": REGION})
            self.aws("s3api", "put-bucket-tagging", Bucket=bucket, Tagging={"TagSet": TAG_LIST})
            self.aws("s3api", "put-public-access-block", Bucket=bucket,
                     PublicAccessBlockConfiguration={key: True for key in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]})
            self.aws("s3api", "put-bucket-encryption", Bucket=bucket, ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
            return bucket
        self.once("bucket", create_bucket)
        self.once("repository", lambda: self.aws("ecr", "create-repository", repositoryName=STACK,
                  imageTagMutability="IMMUTABLE", imageScanningConfiguration={"scanOnPush": True}, tags=TAG_LIST)["repository"]["repositoryUri"])
        for suffix in ["prover", "metrics", "build"]:
            name = "/" + STACK + "/" + suffix
            self.once("log_" + suffix, lambda name=name: self.create_log_group(name))
        secret_file = STATE_DIR / "api-key"
        def create_secret():
            token = secrets.token_urlsafe(32)
            secret_file.write_text(token + "\n")
            secret_file.chmod(0o600)
            return self.aws("secretsmanager", "create-secret", Name=STACK + "/api-key",
                            SecretString=token, Tags=TAG_LIST)["ARN"]
        self.once("secret", create_secret)
        if not secret_file.exists():
            token = self.aws("secretsmanager", "get-secret-value", SecretId=self.state["secret"])["SecretString"]
            secret_file.write_text(token + "\n")
            secret_file.chmod(0o600)
        log_arn = f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/{STACK}/*"
        repository_arn = f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/{STACK}"
        ecr_read = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        logging = {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"], "Resource": log_arn}
        self.role("execution", "ecs-tasks.amazonaws.com", [logging,
            {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
            {"Effect": "Allow", "Action": ecr_read, "Resource": repository_arn},
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": self.state["secret"]}])
        self.role("task", "ecs-tasks.amazonaws.com", [logging,
            {"Effect": "Allow", "Action": ["ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["ec2:DescribeTags", "ecs:DescribeTasks", "ecs:ListTasks", "ecs:DescribeClusters"], "Resource": "*"}])
        self.role("instance", "ec2.amazonaws.com", [logging,
            {"Effect": "Allow", "Action": ["ecs:RegisterContainerInstance", "ecs:DeregisterContainerInstance", "ecs:DiscoverPollEndpoint", "ecs:Poll", "ecs:StartTelemetrySession", "ecs:UpdateContainerInstancesState", "ecs:Submit*", "ec2:DescribeTags"], "Resource": "*"},
            {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
            {"Effect": "Allow", "Action": ecr_read + ["ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage"], "Resource": repository_arn},
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}])
        self.aws("iam", "attach-role-policy", RoleName=STACK + "-instance", PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
        def instance_profile():
            name = STACK + "-instance"
            result = self.aws("iam", "create-instance-profile", InstanceProfileName=name, Tags=TAG_LIST)
            self.aws("iam", "add-role-to-instance-profile", InstanceProfileName=name, RoleName=name)
            return result["InstanceProfile"]["Arn"]
        self.once("instance_profile", instance_profile)
        for name in ["alb", "task", "host"]:
            self.once("sg_" + name, lambda name=name: self.aws("ec2", "create-security-group", GroupName=STACK + "-" + name,
                Description=STACK + " " + name, VpcId=VPC, TagSpecifications=[{"ResourceType": "security-group", "Tags": TAG_LIST}])["GroupId"])
        self.once("sg_rules", self.security_rules)
        self.once("cluster", lambda: self.aws("ecs", "create-cluster", clusterName=STACK, tags=ECS_TAGS,
            settings=[{"name": "containerInsights", "value": "enabled"}])["cluster"]["clusterArn"])
        def template():
            user_data = "#!/bin/bash\nset -eu\nmkdir -p /var/lib/" + STACK + "/keys\nchown 65532:65532 /var/lib/" + STACK + "/keys\n"
            user_data += "printf '%s\\n' 'ECS_CLUSTER=" + STACK + "' 'ECS_ENABLE_AWSLOGS_EXECUTIONROLE_OVERRIDE=true' >> /etc/ecs/ecs.config\n"
            user_data += "command -v aws >/dev/null || dnf install -y awscli2\n"
            result = self.aws("ec2", "create-launch-template", LaunchTemplateName=STACK,
                TagSpecifications=[{"ResourceType": "launch-template", "Tags": TAG_LIST}], LaunchTemplateData={
                    "ImageId": AMI, "InstanceType": "c7a.4xlarge", "SecurityGroupIds": [self.state["sg_host"]],
                    "IamInstanceProfile": {"Arn": self.state["instance_profile"]},
                    "UserData": base64.b64encode(user_data.encode()).decode(),
                    "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": 2},
                    "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 100, "VolumeType": "gp3", "Encrypted": True, "DeleteOnTermination": True}}],
                    "TagSpecifications": [{"ResourceType": kind, "Tags": TAG_LIST + [{"Key": "Name", "Value": STACK}]} for kind in ["instance", "volume"]]})
            return result["LaunchTemplate"]["LaunchTemplateId"]
        self.once("launch_template", template)
        def scaling_group():
            self.aws("autoscaling", "create-auto-scaling-group", AutoScalingGroupName=STACK,
                LaunchTemplate={"LaunchTemplateId": self.state["launch_template"], "Version": "1"},
                MinSize=1, MaxSize=1, DesiredCapacity=1, VPCZoneIdentifier=PRIVATE_SUBNET,
                Tags=[{**tag, "PropagateAtLaunch": True} for tag in TAG_LIST])
            return self.aws("autoscaling", "describe-auto-scaling-groups", AutoScalingGroupNames=[STACK])["AutoScalingGroups"][0]["AutoScalingGroupARN"]
        self.once("asg", scaling_group)
        self.once("capacity_provider", lambda: self.aws("ecs", "create-capacity-provider", name=STACK, tags=ECS_TAGS,
            autoScalingGroupProvider={"autoScalingGroupArn": self.state["asg"], "managedScaling": {"status": "DISABLED"},
                                     "managedTerminationProtection": "DISABLED", "managedDraining": "ENABLED"})["capacityProvider"]["capacityProviderArn"])
        self.owned_cluster()
        self.owned(self.aws("ecs", "list-tags-for-resource", resourceArn=self.state["capacity_provider"])["tags"])
        self.aws("ecs", "put-cluster-capacity-providers", cluster=self.state["cluster"], capacityProviders=[STACK],
                 defaultCapacityProviderStrategy=[{"capacityProvider": STACK, "weight": 1}])
        self.once("alb", lambda: self.aws("elbv2", "create-load-balancer", Name=STACK, Type="application", Scheme="internet-facing",
                  Subnets=PUBLIC_SUBNETS, SecurityGroups=[self.state["sg_alb"]], Tags=TAG_LIST)["LoadBalancers"][0])
        self.once("target", lambda: self.aws("elbv2", "create-target-group", Name=STACK, Protocol="HTTP", Port=3001, VpcId=VPC,
            TargetType="ip", HealthCheckProtocol="HTTP", HealthCheckPath="/ready", HealthCheckIntervalSeconds=15,
            HealthCheckTimeoutSeconds=5, HealthyThresholdCount=2, UnhealthyThresholdCount=3, Matcher={"HttpCode": "200"}, Tags=TAG_LIST)["TargetGroups"][0]["TargetGroupArn"])
        self.configure_target()
        self.owned_alb()
        self.aws("elbv2", "modify-load-balancer-attributes", LoadBalancerArn=self.state["alb"]["LoadBalancerArn"],
                 Attributes=[{"Key": "idle_timeout.timeout_seconds", "Value": "300"}])
        self.once("listener", lambda: self.aws("elbv2", "create-listener", LoadBalancerArn=self.state["alb"]["LoadBalancerArn"],
            Protocol="HTTP", Port=80, DefaultActions=[{"Type": "forward", "TargetGroupArn": self.state["target"]}], Tags=TAG_LIST)["Listeners"][0]["ListenerArn"])
        self.once("distribution", self.distribution)
        self.status()

    def create_log_group(self, name):
        self.aws("logs", "create-log-group", logGroupName=name, tags=TAGS)
        self.aws("logs", "put-retention-policy", logGroupName=name, retentionInDays=7)
        return name

    def security_rules(self):
        groups = self.aws("ec2", "describe-security-groups", GroupIds=[self.state["sg_alb"], self.state["sg_task"]])["SecurityGroups"]
        for group in groups:
            self.owned(group.get("Tags", []))
        self.aws("ec2", "authorize-security-group-ingress", GroupId=self.state["sg_alb"], IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "PrefixListIds": [{"PrefixListId": "pl-fab65393"}]}])
        self.aws("ec2", "authorize-security-group-ingress", GroupId=self.state["sg_task"], IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 3001, "ToPort": 3001, "UserIdGroupPairs": [{"GroupId": self.state["sg_alb"]}]}])
        return True

    def distribution(self):
        config = {"CallerReference": STACK, "Comment": STACK, "Enabled": True, "HttpVersion": "http2", "PriceClass": "PriceClass_100",
            "Origins": {"Quantity": 1, "Items": [{"Id": "prover", "DomainName": self.state["alb"]["DNSName"],
                "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "http-only",
                    "OriginReadTimeout": 60, "OriginKeepaliveTimeout": 60, "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]}}}]},
            "DefaultCacheBehavior": {"TargetOriginId": "prover", "ViewerProtocolPolicy": "https-only",
                "AllowedMethods": {"Quantity": 7, "Items": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"], "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}},
                "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad", "OriginRequestPolicyId": "b689b0a8-53d0-40ab-baf2-68738e2966ac", "Compress": False},
            "ViewerCertificate": {"CloudFrontDefaultCertificate": True}}
        result = self.aws("cloudfront", "create-distribution-with-tags", DistributionConfigWithTags={"DistributionConfig": config, "Tags": {"Items": TAG_LIST}})
        return {key: result["Distribution"][key] for key in ["Id", "ARN", "DomainName"]}

    def instance(self):
        groups = self.aws("autoscaling", "describe-auto-scaling-groups", AutoScalingGroupNames=[STACK])["AutoScalingGroups"]
        if not groups or not groups[0]["Instances"]:
            raise RuntimeError("Experiment instance is not available yet")
        instance_id = groups[0]["Instances"][0]["InstanceId"]
        instance = self.aws("ec2", "describe-instances", InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
        self.owned(instance.get("Tags", []))
        if instance["InstanceType"] != "c7a.4xlarge" or instance.get("InstanceLifecycle") == "spot":
            raise RuntimeError("Experiment instance is not the expected on-demand hardware")
        return instance_id

    def remote(self, commands):
        result = self.aws("ssm", "send-command", InstanceIds=[self.instance()], DocumentName="AWS-RunShellScript",
            TimeoutSeconds=60, Parameters={"commands": ["set -eu"] + commands, "executionTimeout": ["900"]},
            CloudWatchOutputConfig={"CloudWatchOutputEnabled": True, "CloudWatchLogGroupName": self.state["log_build"]})
        command_id = result["Command"]["CommandId"]
        self.state["command"] = command_id
        self.save()
        print("Remote command " + command_id)
        return command_id

    def build(self, archive, revision):
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise RuntimeError("Build revision must be a full commit hash")
        archive = archive.resolve(strict=True)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        key = "source/" + revision + ".tar.gz"
        self.owned_bucket()
        self.aws("s3api", "put-object", extra=["--body", str(archive)], Bucket=self.state["bucket"], Key=key,
                 ServerSideEncryption="AES256", Metadata={"sha256": digest, "revision": revision})
        image = self.state["repository"] + ":" + revision
        registry = self.state["repository"].split("/")[0]
        directory = "/var/lib/" + STACK + "/build-" + revision
        self.remote([
            "command -v aws >/dev/null || dnf install -y awscli2",
            "mkdir -p " + shlex.quote(directory),
            "aws s3 cp " + shlex.quote("s3://" + self.state["bucket"] + "/" + key) + " " + shlex.quote(directory + "/source.tar.gz") + " --only-show-errors",
            "cd " + shlex.quote(directory),
            "printf '%s  %s\\n' " + shlex.quote(digest) + " source.tar.gz | sha256sum -c -",
            "tar -xzf source.tar.gz",
            "docker build --progress=plain --platform linux/amd64 --build-arg GOAMD64=v1 --build-arg PROVER_PGO=off --label org.opencontainers.image.revision=" + revision + " -f prover/server/Dockerfile.light -t " + shlex.quote(image) + " prover/server",
            "aws ecr get-login-password --region " + REGION + " | docker login --username AWS --password-stdin " + shlex.quote(registry),
            "docker push " + shlex.quote(image),
            "docker logout " + shlex.quote(registry),
            "docker image inspect " + shlex.quote(image) + " --format '{{.Id}} {{.Architecture}}'",
        ])
        self.state.update(image=image, revision=revision, archive_sha256=digest)
        self.save()

    def keys(self):
        manifest = json.loads((ROOT / "prover/server/prover/provingkeys/proving-keys.lock").read_text())
        commands = ["install -d -o 65532 -g 65532 /var/lib/" + STACK + "/keys", "cd /var/lib/" + STACK + "/keys"]
        for name in ["custom_ring_base.key", "custom_ring_policy.key"]:
            entry = manifest["keys"][name]
            url = "https://github.com/helius-labs/zolana/releases/download/custom-ring-keys-v7/" + name
            commands.extend([
                "curl --silent --show-error --fail --location --connect-timeout 10 --max-time 120 " + shlex.quote(url) + " -o " + shlex.quote(name + ".part"),
                "test \"$(stat -c %s " + shlex.quote(name + ".part") + ")\" = " + str(entry["size"]),
                "printf '%s  %s\\n' " + shlex.quote(entry["sha256"]) + " " + shlex.quote(name + ".part") + " | sha256sum -c -",
                "chown 65532:65532 " + shlex.quote(name + ".part"), "mv " + shlex.quote(name + ".part") + " " + shlex.quote(name),
            ])
        self.remote(commands)

    def deploy(self, selectors):
        self.owned_cluster()
        self.configure_target()
        image = self.state.get("image")
        if not image:
            raise RuntimeError("Build an image from the committed archive first")
        description = self.aws("ecr", "describe-images", repositoryName=STACK, imageIds=[{"imageTag": self.state["revision"]}])
        image = self.state["repository"] + "@" + description["imageDetails"][0]["imageDigest"]
        command = ["start", "--require-optimized-build", "--keys-dir", "/proving-keys", "--prover-address", "0.0.0.0:3001",
                   "--metrics-address", "0.0.0.0:9998", "--auto-download", "--json-logging", "--circuit", "transfer", "--circuit", "custom-ring-policy"]
        for selector in selectors.split(","):
            command += ["--preload-circuits", selector]
        metrics = {"agent": {"debug": False}, "logs": {"force_flush_interval": 30, "metrics_collected": {"prometheus": {
            "prometheus_config_path": "env:PROMETHEUS_CONFIG_CONTENT", "log_group_name": self.state["log_metrics"],
            "emf_processor": {"metric_namespace": STACK, "metric_declaration": [{"source_labels": ["job"], "label_matcher": "^prover$",
                "dimensions": [["job"], ["job", "circuit_type"], ["job", "queue", "stage"]], "metric_selectors": ["^prover_.*$"]}]}}}}}
        def logs(name):
            return {"logDriver": "awslogs", "options": {"awslogs-group": self.state["log_prover"], "awslogs-region": REGION, "awslogs-stream-prefix": name}}
        result = self.aws("ecs", "register-task-definition", family=STACK, networkMode="awsvpc", requiresCompatibilities=["EC2"],
            cpu="15360", memory="30720", executionRoleArn=self.state["execution_role"], taskRoleArn=self.state["task_role"],
            runtimePlatform={"cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX"}, tags=ECS_TAGS,
            volumes=[{"name": "keys", "host": {"sourcePath": "/var/lib/" + STACK + "/keys"}}], containerDefinitions=[
                {"name": "redis", "image": "public.ecr.aws/docker/library/redis:7.4.4-alpine3.21", "essential": True, "memory": 512,
                 "command": ["redis-server", "--bind", "127.0.0.1", "--save", "", "--appendonly", "no"],
                 "healthCheck": {"command": ["CMD-SHELL", "redis-cli ping | grep -q PONG"], "interval": 5, "timeout": 2, "retries": 5}, "logConfiguration": logs("redis")},
                {"name": "prover", "image": image, "essential": True, "command": command,
                 "dependsOn": [{"containerName": "redis", "condition": "HEALTHY"}],
                 "mountPoints": [{"sourceVolume": "keys", "containerPath": "/proving-keys", "readOnly": False}],
                 "portMappings": [{"containerPort": 3001, "protocol": "tcp"}, {"containerPort": 9998, "protocol": "tcp"}],
                 "secrets": [{"name": "PROVER_API_KEY", "valueFrom": self.state["secret"]}],
                 "environment": [{"name": key, "value": value} for key, value in {"PROVER_INDEXER_URL": PHOTON, "PROVER_INDEXER_CONCURRENCY": "1", "PROVER_REQUEST_TIMING": "true",
                    "PROVER_TRANSFER_CONCURRENCY": "4", "PROVER_MAX_CONCURRENCY": "4", "CUSTOM_RING_WORKER_CONCURRENCY": "1", "REDIS_URL": "redis://127.0.0.1:6379", "SERVICE": STACK}.items()],
                 "logConfiguration": logs("prover"), "stopTimeout": 120},
                {"name": "cloudwatch-agent", "image": "public.ecr.aws/cloudwatch-agent/cloudwatch-agent:latest", "essential": False, "memory": 256,
                 "environment": [{"name": "CW_CONFIG_CONTENT", "value": json.dumps(metrics)}, {"name": "PROMETHEUS_CONFIG_CONTENT", "value": "global:\n  scrape_interval: 60s\n  scrape_timeout: 10s\nscrape_configs:\n  - job_name: prover\n    static_configs:\n      - targets: ['localhost:9998']\n"}], "logConfiguration": logs("metrics")},
            ])
        task = result["taskDefinition"]["taskDefinitionArn"]
        self.state["task_definition"] = task
        self.state.setdefault("task_definitions", []).append(task)
        self.state["image_digest"] = image
        self.save()
        if "service" in self.state:
            service = self.aws("ecs", "describe-services", cluster=self.state["cluster"], services=[self.state["service"]], include=["TAGS"])["services"][0]
            self.owned(service.get("tags", []))
            self.aws("ecs", "update-service", cluster=self.state["cluster"], service=self.state["service"], taskDefinition=task)
        else:
            result = self.aws("ecs", "create-service", cluster=self.state["cluster"], serviceName=STACK, taskDefinition=task, desiredCount=1,
                capacityProviderStrategy=[{"capacityProvider": STACK, "weight": 1}], tags=ECS_TAGS, enableExecuteCommand=True,
                deploymentConfiguration={"maximumPercent": 100, "minimumHealthyPercent": 0}, healthCheckGracePeriodSeconds=600,
                loadBalancers=[{"targetGroupArn": self.state["target"], "containerName": "prover", "containerPort": 3001}],
                networkConfiguration={"awsvpcConfiguration": {"subnets": [PRIVATE_SUBNET], "securityGroups": [self.state["sg_task"]], "assignPublicIp": "DISABLED"}})
            self.state["service"] = result["service"]["serviceArn"]
            self.save()
        print("Service uses " + image)
        self.status()

    def status(self):
        result = {key: self.state.get(key) for key in ["stack", "repository", "revision", "image_digest", "task_definition"]}
        if "distribution" in self.state:
            item = self.aws("cloudfront", "get-distribution", Id=self.state["distribution"]["Id"])["Distribution"]
            result.update(endpoint="https://" + item["DomainName"], distribution_status=item["Status"])
        if "asg" in self.state:
            result["instance"] = self.instance()
        if "service" in self.state:
            service = self.aws("ecs", "describe-services", cluster=self.state["cluster"], services=[self.state["service"]])["services"][0]
            result["service"] = {key: service.get(key) for key in ["status", "runningCount", "pendingCount", "desiredCount", "taskDefinition"]}
            result["targets"] = self.aws("elbv2", "describe-target-health", TargetGroupArn=self.state["target"])["TargetHealthDescriptions"]
            tasks = self.aws("ecs", "list-tasks", cluster=self.state["cluster"], serviceName=STACK)["taskArns"]
            if tasks:
                details = self.aws("ecs", "describe-tasks", cluster=self.state["cluster"], tasks=tasks)["tasks"]
                result["tasks"] = [{key: task.get(key) for key in ["taskArn", "lastStatus", "healthStatus", "stopCode", "stoppedReason"]} for task in details]
        if "command" in self.state:
            result["remote_command"] = self.aws("ssm", "list-command-invocations", CommandId=self.state["command"], Details=False)["CommandInvocations"]
        print(json.dumps(result, indent=2))

    def command_status(self, command_id):
        result = self.aws("ssm", "get-command-invocation", CommandId=command_id or self.state["command"], InstanceId=self.instance())
        print(json.dumps({key: result.get(key) for key in ["CommandId", "Status", "ResponseCode", "StandardOutputContent", "StandardErrorContent"]}, indent=2))

    def down(self):
        if "distribution" in self.state:
            item = self.state["distribution"]
            self.owned(self.aws("cloudfront", "list-tags-for-resource", Resource=item["ARN"])["Tags"]["Items"])
            current = self.aws("cloudfront", "get-distribution-config", Id=item["Id"])
            if current["DistributionConfig"]["Enabled"]:
                current["DistributionConfig"]["Enabled"] = False
                self.aws("cloudfront", "update-distribution", Id=item["Id"], IfMatch=current["ETag"], DistributionConfig=current["DistributionConfig"])
                raise RuntimeError("Distribution disabled. Run down again after its update completes")
            self.aws("cloudfront", "delete-distribution", Id=item["Id"], IfMatch=current["ETag"])
            del self.state["distribution"]
            self.save()
        if "service" in self.state:
            service = self.aws("ecs", "describe-services", cluster=self.state["cluster"], services=[self.state["service"]], include=["TAGS"])["services"][0]
            self.owned(service.get("tags", []))
            self.aws("ecs", "delete-service", cluster=self.state["cluster"], service=self.state["service"], force=True)
            del self.state["service"]
            self.save()
        if "asg" in self.state:
            group = self.aws("autoscaling", "describe-auto-scaling-groups", AutoScalingGroupNames=[STACK])["AutoScalingGroups"][0]
            self.owned(group["Tags"])
            self.aws("autoscaling", "delete-auto-scaling-group", AutoScalingGroupName=STACK, ForceDelete=True)
            del self.state["asg"]
            self.save()
        for task in self.state.get("task_definitions", []).copy():
            definition = self.aws("ecs", "describe-task-definition", taskDefinition=task, include=["TAGS"])
            self.owned(definition.get("tags", []))
            self.aws("ecs", "deregister-task-definition", taskDefinition=task)
            self.state["task_definitions"].remove(task)
            self.save()
        if "capacity_provider" in self.state:
            self.owned(self.aws("ecs", "list-tags-for-resource", resourceArn=self.state["cluster"])["tags"])
            self.owned(self.aws("ecs", "list-tags-for-resource", resourceArn=self.state["capacity_provider"])["tags"])
            self.aws("ecs", "put-cluster-capacity-providers", cluster=self.state["cluster"], capacityProviders=[], defaultCapacityProviderStrategy=[])
            self.aws("ecs", "delete-capacity-provider", capacityProvider=STACK)
            del self.state["capacity_provider"]
            self.save()
        if "cluster" in self.state:
            self.owned(self.aws("ecs", "list-tags-for-resource", resourceArn=self.state["cluster"])["tags"])
            self.aws("ecs", "delete-cluster", cluster=self.state["cluster"])
            del self.state["cluster"]
            self.save()
        for key, kind in [("listener", "listener"), ("alb", "load-balancer"), ("target", "target-group")]:
            if key in self.state:
                arn = self.state[key]["LoadBalancerArn"] if key == "alb" else self.state[key]
                self.owned(self.aws("elbv2", "describe-tags", ResourceArns=[arn])["TagDescriptions"][0]["Tags"])
                field = {"listener": "ListenerArn", "alb": "LoadBalancerArn", "target": "TargetGroupArn"}[key]
                self.aws("elbv2", "delete-" + kind, **{field: arn})
                del self.state[key]
                self.save()
        if "launch_template" in self.state:
            template = self.aws("ec2", "describe-launch-templates", LaunchTemplateIds=[self.state["launch_template"]])["LaunchTemplates"][0]
            self.owned(template["Tags"])
            self.aws("ec2", "delete-launch-template", LaunchTemplateId=self.state["launch_template"])
            del self.state["launch_template"]
            self.save()
        for key in ["sg_task", "sg_alb", "sg_host"]:
            if key in self.state:
                group = self.aws("ec2", "describe-security-groups", GroupIds=[self.state[key]])["SecurityGroups"][0]
                self.owned(group["Tags"])
                self.aws("ec2", "delete-security-group", GroupId=self.state[key])
                del self.state[key]
                self.save()
        if "instance_profile" in self.state:
            name = STACK + "-instance"
            profile = self.aws("iam", "get-instance-profile", InstanceProfileName=name)["InstanceProfile"]
            self.owned(profile["Tags"])
            self.aws("iam", "remove-role-from-instance-profile", InstanceProfileName=name, RoleName=name)
            self.aws("iam", "delete-instance-profile", InstanceProfileName=name)
            del self.state["instance_profile"]
            self.save()
        for suffix in ["instance", "execution", "task"]:
            key = suffix + "_role"
            if key in self.state:
                name = STACK + "-" + suffix
                self.owned_role(name)
                if suffix == "instance":
                    self.aws("iam", "detach-role-policy", RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
                self.aws("iam", "delete-role-policy", RoleName=name, PolicyName=STACK)
                self.aws("iam", "delete-role", RoleName=name)
                del self.state[key]
                self.save()
        if "secret" in self.state:
            item = self.aws("secretsmanager", "describe-secret", SecretId=self.state["secret"])
            self.owned(item["Tags"])
            self.aws("secretsmanager", "delete-secret", SecretId=self.state["secret"], RecoveryWindowInDays=7)
            del self.state["secret"]
            (STATE_DIR / "api-key").unlink(missing_ok=True)
            self.save()
        if "repository" in self.state:
            arn = f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/{STACK}"
            self.owned(self.aws("ecr", "list-tags-for-resource", resourceArn=arn)["tags"])
            self.aws("ecr", "delete-repository", repositoryName=STACK, force=True)
            del self.state["repository"]
            self.save()
        if "bucket" in self.state:
            bucket = self.state["bucket"]
            self.owned(self.aws("s3api", "get-bucket-tagging", Bucket=bucket)["TagSet"])
            while True:
                objects = self.aws("s3api", "list-objects-v2", Bucket=bucket, MaxKeys=1000).get("Contents", [])
                if not objects:
                    break
                self.aws("s3api", "delete-objects", Bucket=bucket, Delete={"Objects": [{"Key": item["Key"]} for item in objects]})
            self.aws("s3api", "delete-bucket", Bucket=bucket)
            del self.state["bucket"]
            self.save()
        for suffix in ["prover", "metrics", "build"]:
            key = "log_" + suffix
            if key in self.state:
                tags = self.aws("logs", "list-tags-log-group", logGroupName=self.state[key])["tags"]
                self.owned([{"Key": name, "Value": value} for name, value in tags.items()])
                self.aws("logs", "delete-log-group", logGroupName=self.state[key])
                del self.state[key]
                self.save()
        self.state_path.rename(STATE_DIR / "removed-state.json")
        print("Experiment resources removed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="AdministratorAccess-558215002830")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ["infra", "status", "keys", "down"]:
        commands.add_parser(name)
    build = commands.add_parser("build")
    build.add_argument("--archive", type=Path, required=True)
    build.add_argument("--revision", required=True)
    deploy = commands.add_parser("deploy")
    deploy.add_argument("--preload", required=True)
    command = commands.add_parser("command")
    command.add_argument("--id")
    args = parser.parse_args()
    deployment = Deployment(args.profile)
    actions = {
        "infra": deployment.infrastructure,
        "status": deployment.status,
        "keys": deployment.keys,
        "build": lambda: deployment.build(args.archive, args.revision),
        "deploy": lambda: deployment.deploy(args.preload),
        "command": lambda: deployment.command_status(args.id),
        "down": deployment.down,
    }
    actions[args.command]()


if __name__ == "__main__":
    try:
        main()
    except (AwsError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
