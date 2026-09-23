import json


def ref(name):
    return {"Ref": name}


def attr(name, field):
    return {"Fn::GetAtt": [name, field]}


def sub(value):
    return {"Fn::Sub": value}


def resource(kind, **properties):
    return {"Type": "AWS::" + kind, "Properties": properties}


def policy(actions, resources):
    return {"Effect": "Allow", "Action": actions, "Resource": resources}


def document(statements):
    return {"Version": "2012-10-17", "Statement": statements}


def role(service, statements, managed=()):
    return resource(
        "IAM::Role",
        AssumeRolePolicyDocument=document(
            [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": "sts:AssumeRole",
                }
            ]
        ),
        ManagedPolicyArns=list(managed),
        Policies=[{"PolicyName": "deployment", "PolicyDocument": document(statements)}],
    )


def template(config):
    secret_arns = [ref("ApiKey")]
    for name in ("rpc_secret", "indexer_key_secret"):
        if config.get(name):
            secret_arns.append(config[name])
    if config["with_indexer"]:
        secret_arns.append(ref("DatabasePassword"))
    bucket_objects = sub("${Assets.Arn}/*")
    resources = {
        "Vpc": resource(
            "EC2::VPC",
            CidrBlock="10.83.0.0/24",
            EnableDnsSupport=True,
            EnableDnsHostnames=True,
        ),
        "InternetGateway": resource("EC2::InternetGateway"),
        "GatewayAttachment": resource(
            "EC2::VPCGatewayAttachment",
            VpcId=ref("Vpc"),
            InternetGatewayId=ref("InternetGateway"),
        ),
        "Subnet": resource(
            "EC2::Subnet",
            VpcId=ref("Vpc"),
            CidrBlock="10.83.0.0/24",
            AvailabilityZone=ref("AvailabilityZone"),
            MapPublicIpOnLaunch=True,
        ),
        "RouteTable": resource("EC2::RouteTable", VpcId=ref("Vpc")),
        "Route": resource(
            "EC2::Route",
            RouteTableId=ref("RouteTable"),
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=ref("InternetGateway"),
        ),
        "RouteAssociation": resource(
            "EC2::SubnetRouteTableAssociation",
            SubnetId=ref("Subnet"),
            RouteTableId=ref("RouteTable"),
        ),
        "SecurityGroup": resource(
            "EC2::SecurityGroup",
            VpcId=ref("Vpc"),
            GroupDescription="CloudFront gateway",
            SecurityGroupIngress=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3001,
                    "ToPort": 3001,
                    "SourcePrefixListId": config["cloudfront_prefix"],
                }
            ],
        ),
        "Assets": resource(
            "S3::Bucket",
            PublicAccessBlockConfiguration={
                key: True
                for key in (
                    "BlockPublicAcls",
                    "BlockPublicPolicy",
                    "IgnorePublicAcls",
                    "RestrictPublicBuckets",
                )
            },
            BucketEncryption={
                "ServerSideEncryptionConfiguration": [
                    {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
            OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Id": "expire-exports",
                        "Status": "Enabled",
                        "Prefix": "cache/",
                        "ExpirationInDays": 7,
                        "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
                    }
                ]
            },
        ),
        "BucketPolicy": resource(
            "S3::BucketPolicy",
            Bucket=ref("Assets"),
            PolicyDocument=document(
                [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": [attr("Assets", "Arn"), bucket_objects],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }
                ]
            ),
        ),
        "ApiKey": resource(
            "SecretsManager::Secret",
            GenerateSecretString={"PasswordLength": 48, "ExcludePunctuation": True},
        ),
        "Logs": resource("Logs::LogGroup", RetentionInDays=7),
        "HostRole": role(
            "ec2.amazonaws.com",
            [
                policy(["s3:GetObject"], [bucket_objects]),
                policy(["ecr:GetAuthorizationToken"], ["*"]),
                policy(
                    [
                        "ecr:BatchGetImage",
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:BatchCheckLayerAvailability",
                    ],
                    config["image_repositories"],
                ),
                policy(["secretsmanager:GetSecretValue"], secret_arns),
                policy(
                    ["logs:CreateLogStream", "logs:PutLogEvents"], [attr("Logs", "Arn")]
                ),
            ],
            ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"],
        ),
        "Profile": resource("IAM::InstanceProfile", Roles=[ref("HostRole")]),
        "Instance": resource(
            "EC2::Instance",
            ImageId=config["ami"],
            InstanceType=config["instance_type"],
            IamInstanceProfile=ref("Profile"),
            SubnetId=ref("Subnet"),
            SecurityGroupIds=[ref("SecurityGroup")],
            MetadataOptions={"HttpTokens": "required", "HttpPutResponseHopLimit": 1},
            BlockDeviceMappings=[
                {
                    "DeviceName": "/dev/xvda",
                    "Ebs": {
                        "VolumeSize": config["disk_gb"],
                        "VolumeType": "gp3",
                        "Encrypted": True,
                        "DeleteOnTermination": True,
                    },
                }
            ],
            Tags=[{"Key": "Name", "Value": ref("AWS::StackName")}],
            UserData={
                "Fn::Base64": "#!/bin/bash\nset -eu\nsystemctl mask --now --no-block ecs\nsystemctl enable --now docker amazon-ssm-agent\n"
            },
        ),
        "Origin": resource(
            "CloudFront::VpcOrigin",
            VpcOriginEndpointConfig={
                "Name": ref("AWS::StackName"),
                "Arn": sub(
                    "arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:instance/${Instance}"
                ),
                "HTTPPort": 3001,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "http-only",
                "OriginSSLProtocols": ["TLSv1.2"],
            },
        ),
        "Distribution": resource(
            "CloudFront::Distribution",
            DistributionConfig={
                "Enabled": True,
                "Comment": ref("AWS::StackName"),
                "HttpVersion": "http2",
                "PriceClass": "PriceClass_100",
                "ViewerCertificate": {"CloudFrontDefaultCertificate": True},
                "Origins": [
                    {
                        "Id": "gpu",
                        "DomainName": attr("Instance", "PrivateDnsName"),
                        "VpcOriginConfig": {
                            "VpcOriginId": attr("Origin", "Id"),
                            "OriginReadTimeout": 60,
                            "OriginKeepaliveTimeout": 60,
                        },
                    }
                ],
                "DefaultCacheBehavior": {
                    "TargetOriginId": "gpu",
                    "ViewerProtocolPolicy": "https-only",
                    "Compress": False,
                    "AllowedMethods": [
                        "GET",
                        "HEAD",
                        "OPTIONS",
                        "PUT",
                        "POST",
                        "PATCH",
                        "DELETE",
                    ],
                    "CachedMethods": ["GET", "HEAD"],
                    "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
                    "OriginRequestPolicyId": "b689b0a8-53d0-40ab-baf2-68738e2966ac",
                },
                "CustomErrorResponses": [
                    {"ErrorCode": code, "ErrorCachingMinTTL": 0}
                    for code in (400, 403, 404, 405, 414, 416, 500, 501, 502, 503, 504)
                ],
            },
        ),
    }
    resources["Route"]["DependsOn"] = "GatewayAttachment"
    resources["Instance"]["DependsOn"] = ["Route", "RouteAssociation"]
    resources["Origin"]["DependsOn"] = "GatewayAttachment"
    if config["with_indexer"]:
        resources["DatabasePassword"] = resource(
            "SecretsManager::Secret",
            GenerateSecretString={"PasswordLength": 48, "ExcludePunctuation": True},
        )
        resources["ExportRole"] = role(
            "ecs-tasks.amazonaws.com",
            [
                policy(
                    ["s3:PutObject", "s3:AbortMultipartUpload"],
                    [sub("${Assets.Arn}/cache/*")],
                ),
                policy(
                    ["secretsmanager:GetSecretValue"],
                    [config["source"]["database_secret"]],
                ),
                policy(
                    ["logs:CreateLogStream", "logs:PutLogEvents"], [attr("Logs", "Arn")]
                ),
            ],
        )
    outputs = {
        "InstanceId": ref("Instance"),
        "Bucket": ref("Assets"),
        "ApiKeySecret": ref("ApiKey"),
        "Url": sub("https://${Distribution.DomainName}"),
        "LogGroup": ref("Logs"),
        "Config": ref("Config"),
    }
    if config["with_indexer"]:
        outputs.update(
            DatabaseSecret=ref("DatabasePassword"), ExportRole=attr("ExportRole", "Arn")
        )
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Zolana Aeglos prover",
        "Parameters": {
            "AvailabilityZone": {
                "Type": "AWS::EC2::AvailabilityZone::Name",
                "Default": config["zone"],
            },
            "Config": {"Type": "String", "Default": json.dumps(config, sort_keys=True)},
        },
        "Resources": resources,
        "Outputs": {key: {"Value": value} for key, value in outputs.items()},
    }
