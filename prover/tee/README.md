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

Rust and TypeScript clients require a caller-supplied policy for every remote
prover, the Helius gateway included, and encrypt every call to the attested key.
The SDK contains no deployed prover URLs or deployment policies. Supply the
prover URL and the reviewed policy together; selecting a different hostname or
path never selects or changes the policy.

In Rust, pass a `TeePolicy` to `ProverClient::with_tee` or
`AsyncProverClient::with_tee`. In TypeScript, pass `tee` to `ProverClient` or
`proverTee` to `ZolanaClient`. A missing policy fails before any remote HTTP
request. Only a loopback prover permits plaintext development; a Rust client
using a proxy requires a policy even for loopback. The forester's explicit
`for_tree_batches` mode permits plaintext nullifier-tree batch proofs, which
carry only public tree data, and refuses every other proof.

The CLI takes `--prover-tee-policy <file>`, accepting either a bare policy or
its `{ "deployment": ... }` file wrapper. `--prover-tee` also requires a supplied
policy. `xtask loadtest` accepts `--prover-tee-policy <file>` too, and refuses
a remote prover without one before loading wallets or starting workers.
`xtask tee-check <url> --policy <file>` attests and checks encrypted
proving-key digests. For a unified Helius API, callers may supply the same
`/v1/zolana` base URL for Photon and the prover, with the appropriate policy;
the SDK keeps its query authentication on the attestation and encrypted calls.

A server started with `--tee` rejects a plaintext request before reading its body, except on the attestation, `/auth`, `/ready`, `/health` and `/proving-keys` routes.

### Updating pins

Each deployment policy pins the enclave measurements and HPKE public key.
A new image or key rotation requires a new reviewed policy, supplied by the
application. Never obtain trust pins from the prover's own response.
`xtask tee-policy <url> --policy <file>` creates or extends the specified
standalone policy file after attestation and encrypted proving-key checks.
It never rewrites SDK code. The [Nitro guide](../../tools/nitro/README.md)
explains how to independently measure the enclave before pinning it.

Keep policies in `prover/tee/deployments` for code review. Publish reviewed
policies as versioned JSON assets on the corresponding GitHub release, together
with checksums and measured-build provenance. An application can download the
chosen policy from that release, verify its checksum and bundle it with its
configuration. The SDK never downloads a policy or follows a mutable latest pin.
A deployment policy can be used by an older SDK when its policy schema,
attestation protocol, wire format and circuit set remain compatible; an image
rebuild or key rotation alone does not require an SDK release.

### Several approved deployment generations

For explicit fleet pins, keep a reviewed file containing the complete policy
of each approved generation. The [fleet file format](WIRE_CONTRACT.md#explicit-fleet-policy-files)
pairs each generation's measurements with its HPKE key and requires an expiry.
It is independent of the prover URL.

In TypeScript:

```ts
import { ZolanaClient, teeFleetPolicyFromJson } from "@heliuslabs/zolana/client";
import fleetFile from "./mainnet-tee-fleet.json" with { type: "json" };

const client = new ZolanaClient({
  solanaRpcUrl: heliusRpcUrl,
  proverTee: teeFleetPolicyFromJson(fleetFile, "mainnet"),
});
await client.attestProver();
```

In Rust, configure either prover client with the same file:

```rust
use spr_client::prover::{tee::TeeFleetPolicy, ProverClient};

let fleet = TeeFleetPolicy::from_json(&std::fs::read_to_string(policy_path)?, "mainnet")?;
let prover = ProverClient::new(prover_url).with_tee_fleet(fleet);
prover.attest()?;
```

These parsers load explicit application-approved pins. They do not fetch or
authenticate updates; the revision field alone provides no rollback protection.
An expired fleet rejects requests even if a key is cached. The `network`
argument checks the file's label, not the Solana RPC's actual network.

Independent keys behind one URL still require recipient-aware routing. A fleet
does not add routing, a recipient header or failover. Existing
single-deployment APIs, CLI files and `xtask tee-policy` remain unchanged.

### Signed fleet policy sources

TypeScript Node clients can configure `tufTeePolicy` from
`@heliuslabs/zolana/tee/node` instead of supplying fleet JSON. The
[SDK example](../../sdk-libs/ts/README.md#endpoints) configures an independently
reviewed public root, static metadata/target URLs and a trusted persistent
cache. The provider uses the reference TUF client, serves the fixed
`<network>/fleet.json` target directly from top-level targets metadata, and
does not follow delegated target roles. Signing roots are separate from
regional enclave encryption keys.

Publish target payloads and versioned targets/snapshot/root metadata before
the timestamp that advertises them. With consistent snapshots enabled, serve
the policy under each advertised hash as `<network>/<hash>.fleet.json` (normally
SHA-256). Only SHA-256 and SHA-512 target hashes are accepted; at least one is
required. Keep signed versions immutable;
bump the fleet revision for any changed policy payload, including expiry
renewal. The client verifies the TUF trust chain and target hash/length,
then checks the fleet network, paired pins and revision floor. Its snapshot
validity is bounded by the earliest expiry of the fleet and all four metadata
roles. A successful refresh invalidates cached enclave keys if their entry or
approved measurements changed. Even a request already encrypted locally is
checked against the current approvals before transmission.

The provider performs bounded, cancellable downloads without forwarding
prover authentication, and persists rollback state across restarts. Its
dedicated cache uses an exclusive lock: a crash can leave that lock behind;
recover it only after confirming the previous writer is gone. Malformed
cached metadata fails closed; do not clear the cache on verification errors.
Do not share it over a network filesystem or delete it to recover from a
rollback rejection. Metadata storage is a trusted part of the client.

This adds no backend API service and changes no proving routes. It supplies
neither a production Helius signing root nor a deployed policy repository.
Browser clients retain the portable `TeePolicySource` interface for an
application-authorized authenticated loader; a built-in browser TUF verifier
and Rust source are still pending. Regional routing and failover remain
separate parts of PRI-285.

## Mainnet: v0.6.0-alpha

| Network | Photon RPC | Nitro prover |
| --- | --- | --- |
| Mainnet | `https://dgcj4pjarvo65.cloudfront.net` | `https://d3ky2kt0ntqxt1.cloudfront.net` |
| Devnet-e | `https://d34xe1hqb2ibg2.cloudfront.net` | `https://dd73hh473h6ha.cloudfront.net` |

[mainnet-v0.6.0-alpha.json](deployments/mainnet-v0.6.0-alpha.json) contains the
mainnet PCR0–PCR2 and HPKE key. The measurements come from
[publisher run 40780091744](https://github.com/helius-labs/zolana/actions/runs/40780091744),
job `publish / mainnet-tee-2`, rather than the prover response. The exact
[measurement record](deployments/mainnet-v0.6.0-alpha-measurements.json) includes
the image digest, EIF SHA256, measured Photon endpoint and build settings.
The publisher also created
[build provenance](https://github.com/helius-labs/zolana/attestations/61035258)
for the EIF and measurement record. Its source and build-tooling commit is
`8ae430a154e22bafa819a570d383d04e2046e802` (`v0.6.0-alpha`), using Aeglos CPU
with concurrency 8. The EIF SHA256 is
`be011b1ec314abd5fa4838bc43bdda8abe03fae261e3ecb7259d1db05a2505f7`.

Verify the checked-in measurement file against the publisher's signed
provenance with:

```sh
gh attestation verify prover/tee/deployments/mainnet-v0.6.0-alpha-measurements.json \
  --repo helius-labs/zolana \
  --signer-workflow helius-labs/zolana/.github/workflows/publish-nitro.yml
```

The HPKE key was taken from AWS-signed attestation only after verifying the
certificate chain, fresh nonce, key binding and independently measured PCRs.
The recorded attestation in `testdata/mainnet_tee_2_attestation.json` lets both
SDKs check those bindings offline. Live tests also attest and generate an
encrypted synthetic transfer proof using caller-supplied URLs and policy files.

Load the reviewed policy JSON and pass it to
`teePolicyFromJson`, then supply the result as `proverTee` (or `tee` on
`ProverClient`). Rust accepts the same file through `TeePolicy::from_file_json`
and `with_tee`. These parameters work with direct, unified API and proxy URLs;
no endpoint constants or network-specific policy selectors are built into the
SDK. The two published policies reject each other's enclave measurements and keys.

For source pinning, the core program release artifacts are recorded by
[`v0.6.0-alpha`](https://github.com/helius-labs/zolana/releases/tag/v0.6.0-alpha)
at `8ae430a154e22bafa819a570d383d04e2046e802`; their sizes and SHA256 digests
are in that release's manifest. `ts-sdk-v0.6.0-alpha` at
`62e8a4ac11362d7af6c308eabb38d58baa9b3e3f` identifies the TypeScript SDK source.
Publishing either release does not establish which program binary is deployed;
that requires comparing the deployed program to the release artifact.

## devnet-e: v0.6.0-alpha

[devnet-e-v0.6.0-alpha.json](deployments/devnet-e-v0.6.0-alpha.json) carries the
deployment's measurements and HPKE key for callers to supply.
The prover uses the source pinned by
[v0.6.0-alpha](https://github.com/helius-labs/zolana/releases/tag/v0.6.0-alpha).
Its client prover runs Aeglos CPU in a Nitro Enclave and fetches indexed proof
data from Photon. Supply this reviewed policy explicitly when using this deployment.

| Service | URL |
| --- | --- |
| Client TEE prover | `https://dd73hh473h6ha.cloudfront.net` |
| Photon JSON-RPC | `https://d34xe1hqb2ibg2.cloudfront.net` |

Supply the URL and reviewed policy. In Rust:

```rust
use spr_client::prover::{
    indexed::ProofDataSource, tee::TeePolicy, ProverClient,
};

let policy = TeePolicy::from_file_json(&std::fs::read_to_string(policy_path)?)?;
let prover = ProverClient::new(prover_url)
    .with_tee(policy)
    .with_proof_data_source(ProofDataSource::Prover);
prover.attest()?;
```

In TypeScript:

```ts
import { ZolanaClient, teePolicyFromJson } from "@heliuslabs/zolana/client";
import policyFile from "./prover-policy.json" with { type: "json" };

const client = new ZolanaClient({
  solanaRpcUrl: "https://api.devnet.solana.com",
  indexerUrl: "https://d34xe1hqb2ibg2.cloudfront.net",
  proverUrl: "https://dd73hh473h6ha.cloudfront.net",
  proverTee: teePolicyFromJson(policyFile),
  proofDataSource: "prover",
});
await client.attestProver();
```

The prover proof-data setting uses `/indexed`, including
`/prove/transfer_confidential_1_2/indexed`, so the prover fetches Merkle proofs.
From the repository root, check attestation and encrypted proving-key digests:

```sh
cargo run -p xtask -- tee-check https://dd73hh473h6ha.cloudfront.net \
  --policy prover/tee/deployments/devnet-e-v0.6.0-alpha.json
```

The policy matches the measured EIF from
[publisher run 40784786893](https://github.com/helius-labs/zolana/actions/runs/40784786893),
with EIF SHA256 `78355457ec0916ac00f6fd6c8f169997fccb5a3348613730d6cf3819511fc564`.
Live attestation, encrypted key checks and an encrypted indexed proof were
verified against it. A future enclave build requires newly measured and
reviewed deployment pins. Applications pass the reviewed policy
explicitly with `with_tee`, `proverTee`, or the xtask's `--policy` option.

## Roles

The prover operator holds the Phala API key and the prover API key, and runs `prover/server/scripts/release_tee.sh`.
The operator publishes the reviewed standalone policy with the deployment release. The application supplies that policy to the SDK.
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
2. Let the script finish its `tee-policy` xtask run. The app id, HPKE key, KMS root, OS image, measurements and compose hash land in `prover/tee/deployments/<cvm-name>.json`. A second attestation and an encrypted proving key check must pass before the file is written.
3. Run `cargo run -p xtask -- tee-check <prover-url> --policy <policy.json> --prove <request.json> <key name>` with `PROVER_API_KEY` set. It attests under the new pin, runs an encrypted proving key check and returns one encrypted proof through the gateway.
4. Review and commit the policy, then attach the versioned JSON, checksum and build provenance to the deployment release. Applications supply that file to their SDK.
5. To refresh an expired download link, run `prover/server/scripts/ship_photon_db.sh <cvm-name> --dump-url <https-url>`. The CVM accepts only the snapshot already pinned in its compose. To import another snapshot, release a new compose with its digest and publish the matching deployment policy.
6. For a new image, rerun the release with `--update` on the same CVM name. The new compose hash joins the pin, the app id and key stay, and `--replace` starts a new pin for a new app.

The `deploy-tee` workflow runs the release from GitHub. It builds the sm_90 prover and Photon, publishes them to `ghcr.io/<owner>/spr-prover-tee` and `zolana-photon-tee` with build provenance, deploys and uploads the pin files as an artifact. Its `tee-deploy` environment holds `AEGLOS_DEPLOY_KEY`, `PHALA_KEY`, `PROVER_API_KEY`, `PROVER_INDEXER_API_KEY`, `PHOTON_RPC_URL`, `PHOTON_DUMP_URL`, `TEE_REGISTRY_USERNAME`, `TEE_REGISTRY_TOKEN` and `PRIVATE_LIBS_TOKEN`. The workflow refuses to push until both packages exist and are private or internal.

## Limits

- A remote prover without a caller-supplied policy is refused before HTTP.
- An application using an old policy refuses an updated image or key. Supply the newly reviewed policy; upgrade the SDK only if its supported policy or protocol is incompatible.
- The HPKE key has no forward secrecy, because it derives from the app key. Rotate by releasing a new app with `--replace` and a matching reviewed policy.
- The verifiers accept only dstack runtime events of the version 1 digest format, which the 0.5 OS images emit. An OS image that emits the version 2 format fails attestation.
- A newly revoked TCB shows only after the prover refreshes its collateral cache, because the client verifies the collateral the prover relays. A TCB status the pin does not list fails at once.
- A GPU prover cannot attest while NRAS is unreachable, because each attestation asks NRAS for a fresh verdict.

## Pitfalls

- A setting in the CVM environment is not measured. An indexer URL in the environment lets the API key holder redirect the leaves a proof spends. The indexer URL lives in the compose, and the env holds only keys, the RPC URL and the dump link.
- `ship_photon_db.sh` replaces the whole encrypted env, so a variable left out of the ship is gone after the restart. Pass the release's `PROVER_INDEXER_API_KEY`, `PHOTON_RPC_URL`, `TEE_REGISTRY_HOST` and pull credentials.
- Phala's `deploy` defaults to public logs. A log line holding a request body is then readable by anyone, so the script passes `--no-public-logs`.
- With public logs off, Phala serves no container logs to the owner either. Reading a fault takes a redeploy with `--public-logs`, and a release with logs off afterwards.
- A prover URL without `api-key` fails attestation, because the attestation route sits behind the prover API key like the proof routes.
- A client without a TEE policy sends its witness in plaintext, and a TEE prover refuses it only after the gateway in front has read the body, so point only attesting clients at a TEE deployment.
