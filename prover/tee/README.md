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

Rust and TypeScript prover clients require every remote prover, the Helius gateway included, to attest to the bundled policy before it receives a witness, and encrypt every call to it.
Only a loopback prover takes plaintext, and a Rust client with a proxy attests a loopback prover too, because the proxy can carry the call off the host.
The one exception is the Rust `for_tree_batches` mode the forester uses. It sends nullifier-tree batch proofs in plaintext to any prover, as they carry only public tree data, and refuses every other proof.
In Rust, `ProverClient::with_tee` and `AsyncProverClient::with_tee` take another policy, and `attest` returns the verified `AttestedProver` on demand.
In TypeScript, `tee` on `ProverClient` and `proverTee` on `ZolanaClient` take another policy, and `attestProver` returns the verified prover on demand.
The `zolana` commands that prove take `--prover-tee` to require the pin from a loopback prover too, and `--prover-tee-policy <file>` for another pin.
`zolana vks check --prover-url <url>` attests a TEE prover before it checks its proving keys.

The SDK pins `devnet-d-tee-2`, the indexed devnet Nitro Enclave prover at `https://d1unet9hn0mci0.cloudfront.net` (`DEFAULT_PROVER_URL` in Rust, `DEFAULT_TEE_PROVER_ENDPOINT` in TypeScript), in `sdk-libs/prover-tee/src/policy.json` and its TypeScript mirror `default.ts`. The matching Photon endpoint is `https://d21d98xh5lgv3b.cloudfront.net`.
The enclave was built from prover source commit `81d8f9cefed610247c9bd4cf69c3cf8553e0b731`, with build tooling from `92a2e088c300f6b62722dd699b68288d6150332e`, in the [measured build](https://github.com/helius-labs/zolana/actions/runs/39738684498). Both SDKs pin its PCR0–PCR2 measurements and attested HPKE public key in the bundled default policy. Clients use this policy automatically; no caller-supplied policy is needed for this deployment.
A TEE client calls the prover at its own URL, because attestation needs its `/tee/v1/attestation` route and encrypted calls need its `Zolana-Tee` headers.

A TypeScript client given a Helius devnet RPC URL and no `proverUrl` proves through the pinned prover without forwarding the RPC API key.
The indexed enclave fetches proof data from Photon; the Helius gateway still uses client-side proof data.

A server started with `--tee` rejects a plaintext request before reading its body, except on the attestation, `/auth`, `/ready`, `/health` and `/proving-keys` routes.

### Updating pins

The bundled policy pins the measurements and the HPKE key of one deployment.
A new image changes the measurements, a key rotation changes the key pin, and a client refuses the changed prover until its policy carries the new pins.
Take new pins from a reviewed release, as an SDK release or an explicit policy, never from the prover's own answer.
`xtask tee-policy` writes both SDK policy files, and a test fails when they differ.
The [Nitro guide](../../tools/nitro/README.md) measures a deployment before it pins it.

## devnet-d: v0.5.0-alpha

[devnet-d-v0.5.0-alpha.json](deployments/devnet-d-v0.5.0-alpha.json) pins the
v0.5.0-alpha deployment measurements. Use the updated SDKs from
[v0.5.0-alpha](https://github.com/helius-labs/zolana/releases/tag/v0.5.0-alpha).
The deployed protocol programs use commit `81d8f9cefed610247c9bd4cf69c3cf8553e0b731`.
Its client prover runs Aeglos CPU in a Nitro Enclave and fetches indexed proof
data from Photon. The SDK's bundled default policy pins this deployment and its
attested HPKE key; an explicit policy override is optional.

| Service | URL |
| --- | --- |
| Client TEE prover | `https://d1unet9hn0mci0.cloudfront.net` |
| Photon JSON-RPC | `https://d21d98xh5lgv3b.cloudfront.net` |

Use the bundled default policy. In Rust:

```rust
use zolana_client::prover::{
    indexed::ProofDataSource, tee::DEFAULT_PROVER_URL, ProverClient,
};

let prover = ProverClient::new(DEFAULT_PROVER_URL.into())
    .with_proof_data_source(ProofDataSource::Prover);
prover.attest()?;
```

In TypeScript:

```ts
import { ZolanaClient } from "@heliuslabs/zolana/client";

const client = new ZolanaClient({
  solanaRpcUrl: "https://api.devnet.solana.com",
  indexerUrl: "https://d21d98xh5lgv3b.cloudfront.net",
  proverUrl: "https://d1unet9hn0mci0.cloudfront.net",
  proofDataSource: "prover",
});
await client.attestProver();
```

The prover proof-data setting uses `/indexed`, including
`/prove/transfer_confidential_1_2/indexed`, so the prover fetches Merkle proofs.
From the repository root, check attestation and encrypted proving-key digests:

```sh
cargo run -p xtask -- tee-check https://d1unet9hn0mci0.cloudfront.net
```

The policy matches the measured EIF from
[publisher run 39738684498](https://github.com/helius-labs/zolana/actions/runs/39738684498),
with EIF SHA256 `a8cf5a57439c4725fc5f7450a283550a5eac7a98e75bc35fe23d72bd93384166`.
Live attestation, encrypted key checks and an encrypted indexed proof were
verified against it. A future enclave build requires newly measured and
reviewed SDK pins. Applications selecting another reviewed policy can pass it
explicitly with `with_tee`, `proverTee`, or the xtask's `--policy` option.

## Roles

The prover operator holds the Phala API key and the prover API key, and runs `prover/server/scripts/release_tee.sh`.
The SDK release pins the deployment the operator released, in `sdk-libs/prover-tee/src/policy.json` and its TypeScript mirror `default.ts`.
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

- An SDK with no deployment pin refuses `TeePolicy::default_deployment()` and `defaultTeePolicy()`, and a remote prover then needs an explicit policy.
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
- A client without a TEE policy sends its witness in plaintext, and a TEE prover refuses it only after the gateway in front has read the body, so point only attesting clients at a TEE deployment.
