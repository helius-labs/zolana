# Nitro Enclave prover

`aws_nitro.py` deploys the CPU prover inside an AWS Nitro Enclave behind CloudFront.
A client encrypts each request to a key that only the measured enclave holds.
The enclave image is `prover/server/Dockerfile.nitro`, and its startup script is `prover/server/nitro/entrypoint.sh`.
The SDK trusts the enclave image through its PCR0, PCR1 and PCR2 measurements, never the parent instance or the network.
The operator computes those measurements on their own machine, so the parent never decides them.

## Roles

The enclave image decides trust.
It holds the prover binary, the CA bundle, the startup script, the egress hosts and the indexer URL.
PCR0 to PCR2 measure all of them.
The image is public, so it holds no secret.
It names the deployment's KMS key, and PCR0 to PCR2 bind that name too.
The prover runs with `--tee nitro` and derives its HPKE key from a seed that KMS releases only to an attested enclave.
An image built without the KMS key source draws a new HPKE key at each boot instead.
It listens on enclave loopback only and runs without an API key.

The KMS key policy grants `kms:*` to the account root, so every IAM principal of the account that may call `kms:PutKeyPolicy` is a trust root.
The policy denies every principal a decrypt without the measured PCRs and any call that wraps a new seed.
A trust root can lift those denials only by rewriting the policy, and CloudTrail records that call.

The parent instance runs the enclave and carries traffic it cannot read.
It is an Amazon Linux 2023 EC2 instance with enclaves enabled.
Operators reach it through SSM only.
It builds the enclave image file (EIF) from the image digest with the pinned `nitro-cli` release and runs one enclave per NUMA node without debug mode.
It also runs the gateway that enforces the API key.

CloudFront is the only ingress.
Its VPC origin reaches the instance, and the security group admits only the CloudFront origin prefix list on port 3001.

The operator creates the KMS key, builds and pushes the image with its ARN, measures it locally, deploys it, and pins the measurements into the SDKs.

## Shared key

All enclaves of a deployment hold the same HPKE key, so the gateway can spread requests over them and a client can pin the key.
`kms-key` creates one symmetric KMS key per deployment under `alias/zolana-nitro-NAME`, with a policy that grants only the administrator.
The image carries the key ARN in `/etc/zolana-nitro/kms-key`, and `measure` reads it back with the PCRs.
Deploy refuses an image that names another key or measurements of another image.
When the stack bucket holds no seed, it resets the key policy to the administrator, calls `GenerateDataKeyWithoutPlaintext` and stores the encrypted 32 byte seed at `install/hpke-seed.bin`.
It then writes the key policy.
That policy lets the host role call `kms:Decrypt` only when the request carries an attestation whose PCR0, PCR1 and PCR2 equal the values from `measure`, and it denies new seeds from then on.
The deployment never handles the plaintext seed.

At boot each enclave connects to the parent on vsock CID 3, port 8200.
The `zolana-kms` service answers with one JSON line that holds the ciphertext and fresh instance role credentials from IMDSv2, then closes.
The enclave asks KMS to decrypt with its attestation document, so KMS encrypts the seed to a key that exists only inside that enclave.
The parent relays that answer without being able to read it.
The enclave fails to start when any step fails.
A parent that feeds another ciphertext gets a refusal from KMS, because the key ARN comes from the measured image.

## How it works

A request enters CloudFront over HTTPS and reaches the nginx gateway on port 3001.
The gateway checks the API key through a local authorizer on port 3004.
The authorizer reads the key from Secrets Manager and accepts it in `X-API-Key`, as a Bearer token, or as the `api-key` query parameter.
`/proving-keys` stays public, as on the prover.
The gateway keeps the path and the query, forwards the `Zolana-Tee`, `Zolana-Tee-Enc` and `Zolana-Tee-Ciphertext` headers, and passes bodies through unchanged.
For browsers it allows those headers in CORS preflight and exposes `Zolana-Tee`.
It proxies round robin with keepalive to one `socat` per enclave.
Enclave `i` has CID `16 + i`, and its `socat` listens on `127.0.0.1` port `3003 + 2i` and connects to vsock port 3001 of that CID.
Inside the enclave a second `socat` forwards vsock port 3001 to the prover on `127.0.0.1:3001`.

The enclave has no network of its own.
At boot the startup script maps each allowed host to its own loopback address in `/etc/hosts`.
A `socat` listener on that address forwards to the parent over vsock, starting at port 8001.
On the parent, one `vsock-proxy` per host forwards that port to the real host.
Its allowlist holds exactly the hosts the image names.
The image names the proving key host from `key_downloader.go`, the indexer host when built with one, and the KMS host of its key's region.
TLS terminates inside the enclave against the real hostname, so the parent relays only ciphertext.
Proving keys download on first use into a tmpfs in enclave memory and verify against the lockfile digest.

The parent cannot read an encrypted request or its answer.
It sees the request path, the query, the timing and the sizes.
The path names the proving key, so the parent learns the circuit shape of each proof.
A request without `Zolana-Tee` travels in plaintext, and the SDK policy decides whether a client refuses that.

## Sizing

The default instance is `m6i.4xlarge`.
Nitro confines an enclave to one NUMA node, so the parent runs one enclave per node that has at least 2 vCPUs outside the core of CPU 0.
Each enclave takes its node's vCPUs except that core, and its node's memory less 2 GiB.
No enclave exceeds the instance less 4 vCPUs and 16 GiB.
On `m6i.4xlarge`, one node, the enclave gets 12 vCPUs and 48 GiB.
On `c6a.24xlarge`, two nodes, the enclaves get 46 and 48 vCPUs and about 90 GiB each, and the parent keeps the core of CPU 0 and about 4 GiB.
An image without the KMS key source runs only the largest of those enclaves, because separate enclaves would hold separate keys.

The stock `nitro-enclaves-allocator` refuses a CPU pool that spans NUMA nodes.
The `zolana-allocator` unit runs it once per enclave, each run with its own config under `NITRO_CLI_INSTALL_DIR`, which reserves huge pages on that node.
It then writes the union of the enclave CPUs to the driver's pool.
Each enclave runs in its own `zolana-enclave@i` unit, which restarts only that enclave.
Inside the enclave the key tmpfs takes 6 GiB, and a test pins that it holds every served key plus the largest partial download.
The prover heap limit is the enclave memory less the tmpfs and 2 GiB for the kernel and root file system.
`--instance-type` accepts any x86 type with Nitro Enclaves support, 6 vCPUs and 40 GiB, and the enclave scales with it.

## Prerequisites

Use Python 3.9 or later, AWS CLI v2, Docker with `buildx`, and the Rust toolchain of this repository.
`measure` mounts `/var/run/docker.sock` into a container, so the Docker daemon must listen there.
The AWS profile must belong to account `558215002830`.
The `zolana-prover-nitro` ECR repository exists in `eu-north-1` with immutable tags.
`AdministratorAccess-558215002830` covers the image push and the deployment.
Log in with `aws sso login --profile AdministratorAccess-558215002830` when the session expires.

## Steps

1. Create the deployment's KMS key and keep the ARN it prints.
   A second run prints the same ARN.

   ```sh
   kms_key=$(AWS_PROFILE=AdministratorAccess-558215002830 tools/nitro/aws_nitro.py kms-key NAME)
   ```

2. Log in to the registry and build the image for `linux/amd64` with the repository root as context.
   The tag names the commit, and the repository refuses to overwrite a tag.
   This step locks in every byte the enclave measures, including the indexer URL and the KMS key.

   ```sh
   registry=558215002830.dkr.ecr.eu-north-1.amazonaws.com
   aws ecr get-login-password --profile AdministratorAccess-558215002830 --region eu-north-1 \
     | docker login --username AWS --password-stdin "$registry"
   docker buildx build --platform linux/amd64 -f prover/server/Dockerfile.nitro \
     --build-arg INDEXER_URL=https://INDEXER \
     --build-arg KEY_SOURCE=kms --build-arg KMS_KEY_ARN="$kms_key" \
     -t "$registry/zolana-prover-nitro:TAG" --push .
   ```

   Omit `INDEXER_URL` for clients that send their own proof data.

3. Resolve the pushed digest.
   The digest, not the tag, identifies the image from here on.

   ```sh
   digest=$(AWS_PROFILE=AdministratorAccess-558215002830 AWS_REGION=eu-north-1 \
     tools/gpu/ecr-digest.sh zolana-prover-nitro TAG)
   ```

4. Measure the image on your own machine.
   The command pulls the digest with your registry login and builds the EIF in a pinned Amazon Linux 2023 container.
   That container installs the same `nitro-cli` release as the parent, and prints `PCR0`, `PCR1`, `PCR2`, `HashAlgorithm`, `image` and `nitro_cli`.
   It adds the `kms_key` the image names, or `null` for an image without the KMS key source.
   This step locks in the measurements, and a second run on the same digest prints the same values.

   ```sh
   tools/nitro/aws_nitro.py measure --image "$registry/zolana-prover-nitro@$digest" > pcrs.json
   ```

5. Deploy with the measured PCRs.
   The command refuses an image whose `kms_key` is not the key of `NAME`.
   It creates the stack, stores the encrypted seed, writes the key policy for the PCRs of `pcrs.json`, installs the host through SSM, builds the EIF and starts the enclaves.
   It waits for readiness and checks that CloudFront refuses a request without the key.
   It fails with `MEASUREMENT MISMATCH` when the PCRs the parent built differ from `pcrs.json`, and the deployment stays unfinished.
   It then reads the offered HPKE key twice per enclave through the gateway and refuses the deployment unless every answer names the same key.
   It runs `cargo run -q -p xtask -- tee-check` from the repository root as many times, with a policy that pins the PCRs of `pcrs.json` and that key, and passes the API key in `PROVER_API_KEY`.
   `tee-check` verifies the attestation certificate chain to the AWS root, the PCRs, the nonce and the HPKE key binding.
   It then checks the proving keys over the encrypted channel.
   The deployment stays unfinished until every `tee-check` passes, so run deploy from a checkout of this repository with its Rust toolchain.
   Deploy prints the URL, the API key secret ARN, the instance, the log group, the PCRs, the enclave count and `hpke_public_key`.
   The parent PCRs also stay in the stack bucket under `install/measurements.json`.

   ```sh
   AWS_PROFILE=AdministratorAccess-558215002830 tools/nitro/aws_nitro.py deploy NAME \
     --image "$registry/zolana-prover-nitro@$digest" --indexer-url https://INDEXER \
     --expect-pcrs pcrs.json
   ```

   `--indexer-url` must equal the build argument, and the installer refuses an image built for another URL.
   `--plan` validates the stack without creating it and does not need `--expect-pcrs`.
   Repeat the command with the same arguments to resume a failed deployment.

6. Pin the live enclave into the SDKs.
   `tee-policy` reads the key from `PROVER_API_KEY`, which keeps it out of the process list.
   With `--expect-pcrs` it refuses a live enclave whose PCRs differ from `pcrs.json`.
   This step locks in the measurements every client accepts.
   On a KMS deployment `--pin-key` also pins the attested HPKE key, and a later run refuses a prover with another key until `--replace`.

   ```sh
   PROVER_API_KEY=$(aws secretsmanager get-secret-value --profile AdministratorAccess-558215002830 \
     --region eu-central-1 --secret-id SECRET_ARN --query SecretString --output text) \
     cargo run -p xtask -- tee-policy https://DISTRIBUTION.cloudfront.net --replace --expect-pcrs pcrs.json
   ```

7. Commit the policy files with the release.

## Limits

No log or metric leaves the enclave, because the image opens no channel for them.
Parent logs stay in the journal of each `zolana-*` unit and in the gateway log group.
Use SSM to read them.

The parent passes the enclave only the encrypted seed and role credentials, and the enclave trusts neither beyond what KMS proves.
An indexer that requires an API key does not work, because the parent could read it, so use a keyless indexer or client-supplied proof data.

The enclave serves the transfer, merge and custom ring keys.
It does not serve the batch address-append keys of the forester, because the key tmpfs and the heap are sized for client keys.

A new image, indexer or instance type requires a new deployment name, and so a new KMS key and a new build.
`status NAME` prints the deployment.
`destroy NAME` deletes it with its bucket and schedules deletion of its KMS key after 7 days.

## Pitfalls

The PCRs depend on the `nitro-cli` release as well as the image.
`NITRO_CLI` in `aws_nitro_host.py` pins the release for the parent and for `measure`.
A change of that pin can change the PCRs of an unchanged image, so measure and pin again.

The image pins its Alpine package versions, and Alpine keeps only the newest build of each package.
An old commit stops building when a pinned package gets an update, so move the pins in `Dockerfile.nitro`.
Measure and pin the pushed digest, never the commit.

The image names one KMS key, so build one image per deployment, after `kms-key`.
The key policy names the PCRs of one image.
An enclave of any other image gets a refusal from KMS and does not start.

An image without the KMS key source draws a new HPKE key at each enclave start.
A crash, a resumed deployment and a reboot all restart the enclave.
After an enclave restart the next call fails decryption, the SDK attests again and resends once.

The allocator runs only while no enclave runs.
Restart `zolana-allocator` after stopping every `zolana-enclave@` unit, never alone.

The first proof for a key downloads and loads that key.
A large key can exceed the 60 second CloudFront origin read timeout.
The load continues after the timeout, so retry the request.

The allocator reserves enclave memory as huge pages.
After long uptime it can fail to reserve them, so reboot the instance and repeat the deploy.

A debug enclave reports all-zero PCRs and fails attestation.
Debug the image under Docker with `--privileged` and a stand-in `/dev/nsm` device, where the prover serves but cannot attest.
Never use `--debug-mode` on a pinned deployment.
