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
The prover runs with `--tee nitro` and draws a new HPKE key at each boot.
It listens on enclave loopback only and runs without an API key.

The parent instance runs the enclave and carries traffic it cannot read.
It is an Amazon Linux 2023 EC2 instance with enclaves enabled.
Operators reach it through SSM only.
It builds the enclave image file (EIF) from the image digest with the pinned `nitro-cli` release and runs the enclave without debug mode.
It also runs the gateway that enforces the API key.

CloudFront is the only ingress.
Its VPC origin reaches the instance, and the security group admits only the CloudFront origin prefix list on port 3001.

The operator builds and pushes the image, measures it locally, deploys it, and pins the measurements into the SDKs.

## How it works

A request enters CloudFront over HTTPS and reaches the nginx gateway on port 3001.
The gateway checks the API key through a local authorizer on port 3004.
The authorizer reads the key from Secrets Manager and accepts it in `X-API-Key`, as a Bearer token, or as the `api-key` query parameter.
`/proving-keys` stays public, as on the prover.
The gateway keeps the path and the query, forwards the `Zolana-Tee`, `Zolana-Tee-Enc` and `Zolana-Tee-Ciphertext` headers, and passes bodies through unchanged.
For browsers it allows those headers in CORS preflight and exposes `Zolana-Tee`.
It proxies to `socat` on port 3003, and `socat` connects to vsock port 3001 of enclave CID 16.
Inside the enclave a second `socat` forwards vsock port 3001 to the prover on `127.0.0.1:3001`.

The enclave has no network of its own.
At boot the startup script maps each allowed host to its own loopback address in `/etc/hosts`.
A `socat` listener on that address forwards to the parent over vsock, starting at port 8001.
On the parent, one `vsock-proxy` per host forwards that port to the real host.
Its allowlist holds exactly the hosts the image names.
The image names the proving key host from `key_downloader.go` and, when built with one, the indexer host.
TLS terminates inside the enclave against the real hostname, so the parent relays only ciphertext.
Proving keys download on first use into a tmpfs in enclave memory and verify against the lockfile digest.

The parent cannot read an encrypted request or its answer.
It sees the request path, the query, the timing and the sizes.
The path names the proving key, so the parent learns the circuit shape of each proof.
A request without `Zolana-Tee` travels in plaintext, and the SDK policy decides whether a client refuses that.

## Sizing

The default instance is `m6i.4xlarge`.
The parent keeps 4 vCPUs and 16 GiB, and the enclave allocator reserves the rest.
On `m6i.4xlarge` the enclave gets 12 vCPUs and 48 GiB.
The parent keeps the core of CPU 0, which an enclave cannot take, plus room for Docker during the EIF build.
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

1. Log in to the registry and build the image for `linux/amd64` with the repository root as context.
   The tag names the commit, and the repository refuses to overwrite a tag.
   This step locks in every byte the enclave measures, including the indexer URL.

   ```sh
   registry=558215002830.dkr.ecr.eu-north-1.amazonaws.com
   aws ecr get-login-password --profile AdministratorAccess-558215002830 --region eu-north-1 \
     | docker login --username AWS --password-stdin "$registry"
   docker buildx build --platform linux/amd64 -f prover/server/Dockerfile.nitro \
     --build-arg INDEXER_URL=https://INDEXER \
     -t "$registry/zolana-prover-nitro:TAG" --push .
   ```

   Omit `INDEXER_URL` for clients that send their own proof data.

2. Resolve the pushed digest.
   The digest, not the tag, identifies the image from here on.

   ```sh
   digest=$(AWS_PROFILE=AdministratorAccess-558215002830 AWS_REGION=eu-north-1 \
     tools/gpu/ecr-digest.sh zolana-prover-nitro TAG)
   ```

3. Measure the image on your own machine.
   The command pulls the digest with your registry login and builds the EIF in a pinned Amazon Linux 2023 container.
   That container installs the same `nitro-cli` release as the parent, and prints `PCR0`, `PCR1`, `PCR2`, `HashAlgorithm`, `image` and `nitro_cli`.
   This step locks in the measurements, and a second run on the same digest prints the same values.

   ```sh
   tools/nitro/aws_nitro.py measure --image "$registry/zolana-prover-nitro@$digest" > pcrs.json
   ```

4. Deploy with the measured PCRs.
   The command creates the stack, installs the host through SSM, builds the EIF and starts the enclave.
   It waits for readiness and checks that CloudFront refuses a request without the key.
   It fails with `MEASUREMENT MISMATCH` when the PCRs the parent built differ from `pcrs.json`, and the deployment stays unfinished.
   It then runs `cargo run -q -p xtask -- tee-check` from the repository root with a policy that pins the PCRs of `pcrs.json`, and passes the API key in `PROVER_API_KEY`.
   `tee-check` verifies the attestation certificate chain to the AWS root, the PCRs, the nonce and the HPKE key binding.
   It then checks the proving keys over the encrypted channel.
   The deployment stays unfinished until `tee-check` passes, so run deploy from a checkout of this repository with its Rust toolchain.
   Deploy prints the URL, the API key secret ARN, the instance, the log group and the PCRs.
   The parent PCRs also stay in the stack bucket under `install/measurements.json`.

   ```sh
   AWS_PROFILE=AdministratorAccess-558215002830 tools/nitro/aws_nitro.py deploy NAME \
     --image "$registry/zolana-prover-nitro@$digest" --indexer-url https://INDEXER \
     --expect-pcrs pcrs.json
   ```

   `--indexer-url` must equal the build argument, and the installer refuses an image built for another URL.
   `--plan` validates the stack without creating it and does not need `--expect-pcrs`.
   Repeat the command with the same arguments to resume a failed deployment.

5. Pin the live enclave into the SDKs.
   `tee-policy` reads the key from `PROVER_API_KEY`, which keeps it out of the process list.
   With `--expect-pcrs` it refuses a live enclave whose PCRs differ from `pcrs.json`.
   This step locks in the measurements every client accepts.

   ```sh
   PROVER_API_KEY=$(aws secretsmanager get-secret-value --profile AdministratorAccess-558215002830 \
     --region eu-central-1 --secret-id SECRET_ARN --query SecretString --output text) \
     cargo run -p xtask -- tee-policy https://DISTRIBUTION.cloudfront.net --replace --expect-pcrs pcrs.json
   ```

6. Commit the policy files with the release.

## Limits

No log or metric leaves the enclave, because the image opens no channel for them.
Parent logs stay in the journal of each `zolana-*` unit and in the gateway log group.
Use SSM to read them.

The enclave receives no secret, because the parent can read anything it passes.
An indexer that requires an API key does not work, so use a keyless indexer or client-supplied proof data.

The enclave serves the transfer, merge and custom ring keys.
It does not serve the batch address-append keys of the forester, because the key tmpfs and the heap are sized for client keys.

A deployment runs one enclave.
A new image, indexer or instance type requires a new deployment name.
`status NAME` prints the deployment, and `destroy NAME` deletes it with its bucket.

## Pitfalls

The PCRs depend on the `nitro-cli` release as well as the image.
`NITRO_CLI` in `aws_nitro_host.py` pins the release for the parent and for `measure`.
A change of that pin can change the PCRs of an unchanged image, so measure and pin again.

The image pins its Alpine package versions, and Alpine keeps only the newest build of each package.
An old commit stops building when a pinned package gets an update, so move the pins in `Dockerfile.nitro`.
Measure and pin the pushed digest, never the commit.

Each enclave start draws a new HPKE key.
A crash, a resumed deployment and a reboot all restart the enclave.
After an enclave restart the next call fails decryption, the SDK attests again and resends once.

The first proof for a key downloads and loads that key.
A large key can exceed the 60 second CloudFront origin read timeout.
The load continues after the timeout, so retry the request.

The allocator reserves enclave memory as huge pages.
After long uptime it can fail to reserve them, so reboot the instance and repeat the deploy.

A debug enclave reports all-zero PCRs and fails attestation.
Debug the image under Docker with `--privileged` and a stand-in `/dev/nsm` device, where the prover serves but cannot attest.
Never use `--debug-mode` on a pinned deployment.
