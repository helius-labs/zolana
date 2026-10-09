# TEE prover

No audit report is checked in.

The TEE prover is the Go prover in an Intel TDX confidential VM on Phala Cloud. Proof requests are encrypted to a key that only the measured prover holds.
`prover/server/tee` serves the attestation and decrypts encrypted requests. The Rust and TypeScript SDKs verify the attestation and encrypt every call. `testdata` holds the vectors the three implementations share.
A client that requires a TEE sends a request only after an Intel-signed quote proves which image runs. Only the process that quote measures can read the request.

The same server also runs on the CPU in an AWS Nitro Enclave, deployed with `tools/nitro`, whose guide covers that platform. A policy names its platform, and both SDKs accept either.
The `tools/nitro` guide also gives the AWS KMS layout that lets all enclaves of a deployment share one HPKE key.
This guide covers the Phala dstack deployment.

## Threat

A prover request carries the secret inputs of a proof, and the host operator and the Phala gateway handle every request byte outside the CVM.
The design denies them the plaintext request and the plaintext answer.
The guarantee should hold provided that

a) Intel TDX isolates the CVM memory and the DCAP collateral reflects the current TCB,
b) the measured image never writes a request body to logs or storage,
c) the holder of the Phala API key deploys only reviewed compose files and trusted database snapshots under the app, and
d) the Phala KMS releases the app key only to CVMs of the app.

The HPKE key derives from the app key, so precondition c is the trust root.
Any compose the API key holder deploys under the same app derives the same key and can open captured traffic.

## Building on it

In Rust, `ProverClient::with_tee(TeePolicy::default_deployment()?)` and `AsyncProverClient::with_tee` make every call attested and encrypted, and `ZolanaClient::with_prover_tee` does the same for both of its prover clients.
`ProverClient::attest` returns the verified `AttestedProver` on demand.
The `zolana` commands that prove take `--prover-tee`, or `ZOLANA_PROVER_TEE`, and `zolana vks check --prover-url <url> --prover-tee` attests a prover before it checks its proving keys.
In TypeScript, `ZolanaClientConfig.proverTee` takes `defaultTeePolicy()`, and `ZolanaClient.attestProver` returns the verified prover.
Without a policy the clients send plaintext requests, which the server still accepts.

The SDK pins no default deployment, so TEE stays opt-in.
`deployments/nitro-c7a.json` pins the running prover, an AWS Nitro c7a.24xlarge enclave at `https://d3psb33kf6y5qv.cloudfront.net`.
Load a pin with `TeePolicy::from_file_json` in Rust or `teePolicyFromJson(pin.deployment)` in TypeScript, and give the client the prover URL with its `api-key` query parameter.
A TEE client calls the prover at its own URL, because attestation needs its `/tee/v1/attestation` route and encrypted calls need its `Zolana-Tee` headers.

## Roles

The prover operator holds the Phala API key and the prover API key, and runs `prover/server/scripts/release_tee.sh`.
The SDK release pins the deployment the operator released, in `sdk-libs/client/src/prover/tee/policy.json` and its TypeScript mirror `default.ts`.
The client verifies the attestation against that pin and encrypts each call.
Intel signs the quote, and NVIDIA's NRAS signs the GPU verdict.

## How it works

`light-prover start --tee dstack` asks the dstack guest agent for a KMS-derived secret, and RFC 9180 `DeriveKeyPair` turns it into an X25519 HPKE key.
Every instance of the app derives the same key.
[The wire contract](WIRE_CONTRACT.md) gives the attestation endpoint, report_data, the client checks and encryption.
A passed attestation caches the key for `max_age_secs`, and the next call after that attests again.
An encrypted body decrypts only on its own route, and an unencrypted failure still lets retries work.
TEE servers reject queue mode because job IDs do not authorize clients.

The GPU build, tag `aeglos` with `PROVER_BACKEND=aeglos`, collects GPU evidence through NVML for every attestation.
It refuses a GPU with confidential computing off or devtools on, then checks the NRAS signatures, nonce and overall result inside the TDX guest.
The client relies on that measured check and on the report_data digest.
A failed GPU check fails the attestation and never omits the evidence.

Photon runs in the same CVM by default, on its own Postgres, and the prover reaches it at `http://photon:8784` on the compose network.
No indexer outside the CVM learns the leaves a proof spends.
Photon resumes from the last slot in its database or indexes from an empty database.
A snapshot restore requires its SHA256 digest in the measured compose. The CVM checks the downloaded bytes before calling `pg_restore`.
A snapshot is executable code supplied by its source database administrators. Pin only a snapshot from a trusted source. A digest authenticates the bytes and does not make their code safe.
Each snapshot digest uses separate database and restore volumes. A changed digest requires a new compose pin.

## Prerequisites

- A Phala Cloud API key in `PHALA_KEY` and the prover API key in `PROVER_API_KEY`.
- A prover image pinned by digest. A GPU image for the H200 is built from `Dockerfile.aeglos` with `CUDA_ARCH=sm_90`.
- A Photon image pinned by digest, built from `services/photon/Dockerfile` at the repository root.
- A private registry for a GPU image, because it holds compiled Aeglos. `TEE_REGISTRY_HOST` names it, and both images live there.
- Pull credentials for that registry. On ECR they are the `TEE_AWS_ACCESS_KEY_ID` and `TEE_AWS_SECRET_ACCESS_KEY` of an IAM user that only pulls the two repositories. On another registry they are `TEE_REGISTRY_USERNAME` and a read-only `TEE_REGISTRY_TOKEN`. An organization that refuses classic tokens on GHCR needs ECR.
- A Solana RPC URL in `PHOTON_RPC_URL` for the co-hosted Photon. Without it Photon reads the public devnet endpoint.
- For a snapshot, a trusted custom-format `pg_dump` file, its SHA256 digest and a private HTTPS download URL.
- `npx`, `jq`, `curl` and `cargo` on the release machine.

## Steps

1. For a snapshot, export the trusted database first. Set `PHOTON_DUMP_URL` to its download URL and pass its digest with `--photon-dump-sha256`. Run `prover/server/scripts/release_tee.sh <prover-image@sha256:digest> <cvm-name> --photon <photon-image@sha256:digest>`, with `--gpu` for an H200 prover. The compose it deploys pins both images and every command in the measured compose hash, and `--plan` prints it without deploying.
2. Let the script finish its `tee-policy` xtask run. The live prover's app id, HPKE key, KMS root, OS image, measurements and compose hash land in both pin files. A second attestation and an encrypted proving key check must pass before the files are written.
3. Run `cargo run -p xtask -- tee-check <prover-url> --prove <request.json> <key name>` with `PROVER_API_KEY` set. It attests under the new pin, runs an encrypted proving key check and returns one encrypted proof through the gateway.
4. Commit `policy.json` and `default.ts` with the SDK release that ships them. Clients of that release then talk only to this deployment.
5. To refresh an expired download link, run `prover/server/scripts/ship_photon_db.sh <cvm-name> --dump-url <https-url>`. The CVM accepts only the snapshot already pinned in its compose. To import another snapshot, release a new compose with its digest and publish the matching SDK pin.
6. For a new image, rerun the release with `--update` on the same CVM name. The new compose hash joins the pin, the app id and key stay, and `--replace` starts a new pin for a new app.

The `deploy-tee` workflow runs the release from GitHub. It builds the sm_90 prover and Photon, publishes them to `ghcr.io/<owner>/zolana-prover-tee` and `zolana-photon-tee` with build provenance, deploys and uploads the pin files as an artifact. Its `tee-deploy` environment holds `AEGLOS_DEPLOY_KEY`, `PHALA_KEY`, `PROVER_API_KEY`, `PROVER_INDEXER_API_KEY`, `PHOTON_RPC_URL`, `PHOTON_DUMP_URL`, `TEE_REGISTRY_USERNAME`, `TEE_REGISTRY_TOKEN` and `PRIVATE_LIBS_TOKEN`. The workflow refuses to push until both packages exist and are private or internal.

## Limits

- An SDK with no deployment pin refuses `TeePolicy::default_deployment()` and `defaultTeePolicy()`. An explicit verified policy is required.
- Old SDK releases refuse an updated prover, because the update changes the compose hash they pin. Ship the SDK release that carries the new hash together with the update.
- The HPKE key has no forward secrecy, because it derives from the app key. Rotate by releasing a new app with `--replace` and a matching SDK release.
- The verifiers accept only dstack runtime events of the version 1 digest format, which the 0.5 OS images emit. An OS image that emits the version 2 format fails attestation.
- A newly revoked TCB shows only after the prover refreshes its collateral cache, because the client verifies the collateral the prover relays. A TCB status the pin does not list fails at once.
- A GPU prover cannot attest while NRAS is unreachable, because each attestation asks NRAS for a fresh verdict.

## Pitfalls

- A setting in the CVM environment is not measured. An indexer URL in the environment lets the API key holder redirect the leaves a proof spends. The indexer URL lives in the compose, and the env holds only keys, the RPC URL and the dump link.
- `ship_photon_db.sh` replaces the whole encrypted env, so a variable left out of the ship is gone after the restart. Pass the release's `PROVER_INDEXER_API_KEY`, `PHOTON_RPC_URL`, `TEE_REGISTRY_HOST` and pull credentials.
- Phala's `deploy` defaults to public logs. A log line holding a request body is then readable by anyone, so the script passes `--no-public-logs`.
- With public logs off, Phala serves no container logs to the owner either. Reading a fault takes a redeploy with `--public-logs`, and a release with logs off afterwards.
- A prover URL without `api-key` fails attestation, because the attestation route sits behind the prover API key like the proof routes.
- A client built without a policy sends plaintext to the same prover and sees no error. Set the policy where the client is built, not per call.
