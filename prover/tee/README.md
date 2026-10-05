# TEE prover

No audit report is checked in.

The TEE prover is the Go prover in an Intel TDX confidential VM on Phala Cloud. Proof requests are sealed to a key that only the measured prover holds.
`prover/server/tee` serves the attestation and opens sealed requests. The Rust and TypeScript SDKs verify the attestation and seal every call. `testdata` holds the vectors the three implementations share.
A client that requires a TEE sends a request only after an Intel-signed quote proves which image runs. Only the process that quote measures can read the request.

## Threat

A prover request carries the secret inputs of a proof, and the host operator and the Phala gateway handle every request byte outside the CVM.
The design denies them the plaintext request and the plaintext answer.
The guarantee should hold provided that

a) Intel TDX isolates the CVM memory and the DCAP collateral reflects the current TCB,
b) the measured image never writes a request body to logs or storage,
c) the holder of the Phala API key deploys only reviewed compose files under the app, and
d) the Phala KMS releases the app key only to CVMs of the app.

The HPKE key derives from the app key, so precondition c is the trust root.
Any compose the API key holder deploys under the same app derives the same key and can open captured traffic.

## Building on it

In Rust, `ProverClient::with_tee(TeePolicy::pinned()?)` and `AsyncProverClient::with_tee` make every call attested and sealed, and `ZolanaClient::with_prover_tee` does the same for both of its prover clients.
`ProverClient::attest` returns the verified `AttestedProver` on demand.
The `zolana` commands that prove take `--prover-tee`, or `ZOLANA_PROVER_TEE`, and `zolana vks check --prover-url <url> --prover-tee` attests a prover before it checks its proving keys.
In TypeScript, `ZolanaClientConfig.proverTee` takes `pinnedTeePolicy()`, and `ZolanaClient.attestProver` returns the verified prover.
Without a policy the clients send plaintext requests, which the server still accepts.

## Roles

The prover operator holds the Phala API key and the prover API key, and runs `prover/server/scripts/release_tee.sh`.
The SDK release pins the deployment the operator released, in `sdk-libs/client/src/prover/tee/policy.json` and its TypeScript mirror `pinned.ts`.
The client verifies the attestation against that pin and seals each call.
Intel signs the quote, and NVIDIA's NRAS signs the GPU verdict.

## How it works

`light-prover start --tee dstack` asks the dstack guest agent for a KMS-derived secret, and RFC 9180 `DeriveKeyPair` turns it into an X25519 HPKE key.
Every instance of the app derives the same key.
`GET /tee/v1/attestation?nonce=<32 bytes hex>` answers with a TDX quote, the dstack event log, Intel collateral and the HPKE public key. A GPU prover adds the NRAS response.
The quote's report_data is:

```
SHA-512("zolana/prover-tee/v1/report" || nonce || hpke_public_key || gpu_digest)
```

`gpu_digest` is the SHA-256 of the NRAS response, or 32 zero bytes without a GPU.
The client first checks the Intel signature and collateral at the current time. Then it checks the TCB status, MRTD and RTMR0 to RTMR2, and the RTMR3 replay.
The replay recomputes each event digest from the event content, so swapped content fails even when the digests still replay.
The `app-id`, `compose-hash`, `os-image-hash` and `key-provider` events, the HPKE key, report_data and the GPU requirement follow.
A pass caches the key for `max_age_secs`, and the next call after that attests again.

A sealed request sets `Zolana-Tee` to `v1` and carries `Zolana-Tee-Enc`. Its body is HPKE base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM.
The AAD is the method and the raw request target, so a body sealed for one route or job does not open on another.
The answer is the status and body under AES-256-GCM, keyed by the request context's exporter, so only that request opens it.
The client refuses an unsealed success.
An unsealed failure passes through, so retries and queue fallback still work, but its body is unauthenticated.

The GPU build, tag `aeglos` with `PROVER_BACKEND=aeglos`, collects GPU evidence through NVML for every attestation.
It refuses a GPU with confidential computing off or devtools on, then checks the NRAS signatures, nonce and overall result inside the TDX guest.
The client relies on that measured check and on the report_data digest.
A failed GPU check fails the attestation and never omits the evidence.

Photon runs in the same CVM by default, on its own Postgres, and the prover reaches it at `http://photon:8784` on the compose network.
No indexer outside the CVM learns the leaves a proof spends.
Photon resumes from the last slot in its database, so a new CVM starts from a database shipped from a running Photon.
On boot the CVM fetches `PHOTON_DUMP_URL` and restores it when `PHOTON_DUMP_ID` differs from the last restore.
A shipped database affects only which proofs succeed, because the chain rejects a proof against a root it never had.

## Prerequisites

- A Phala Cloud API key in `PHALA_KEY` and the prover API key in `PROVER_API_KEY`.
- A prover image pinned by digest. A GPU image for the H200 is built from `Dockerfile.aeglos` with `CUDA_ARCH=sm_90`.
- A Photon image pinned by digest, built from `services/photon/Dockerfile` at the repository root.
- A private registry for a GPU image, because it holds compiled Aeglos. `TEE_REGISTRY_USERNAME` and a read-only `TEE_REGISTRY_TOKEN` let the CVM pull it.
- A Solana RPC URL in `PHOTON_RPC_URL` for the co-hosted Photon. Without it Photon reads the public devnet endpoint.
- The AWS CLI, `python3` and a profile in the account that runs the source Photon, for a database ship from an ECS service.
- `npx`, `jq`, `curl` and `cargo` on the release machine.

## Steps

1. Run `prover/server/scripts/release_tee.sh <prover-image@sha256:digest> <cvm-name> --photon <photon-image@sha256:digest>`, with `--gpu` for an H200 prover. The compose it deploys pins both images and every command in the measured compose hash, and `--plan` prints it without deploying.
2. Let the script finish its `tee-policy` xtask run. The live prover's app id, HPKE key, KMS root, OS image, measurements and compose hash land in both pin files. A second attestation under the new pin must pass.
3. Commit `policy.json` and `pinned.ts` with the SDK release that ships them. Clients of that release then talk only to this deployment.
4. Run `prover/server/scripts/ship_photon_db.sh <cvm-name>`. It dumps devnet-c into an export-only `tools/gpu` stack and seals a short-lived download link into the CVM env. The CVM restarts and its compose hash stays. `--source-cluster` and `--source-service` name another running Photon, and `--dump-url` ships any `pg_dump` custom-format file.
5. For a new image, rerun the release with `--update` on the same CVM name. The new compose hash joins the pin, the app id and key stay, and `--replace` starts a new pin for a new app.

The `deploy-tee` workflow runs the release from GitHub. It builds the sm_90 prover and Photon, publishes them to `ghcr.io/<owner>/zolana-prover-tee` and `zolana-photon-tee` with build provenance, deploys and uploads the pin files as an artifact. Its `tee-deploy` environment holds `AEGLOS_DEPLOY_KEY`, `PHALA_KEY`, `PROVER_API_KEY`, `PROVER_INDEXER_API_KEY`, `PHOTON_RPC_URL`, `TEE_REGISTRY_USERNAME`, `TEE_REGISTRY_TOKEN` and `PRIVATE_LIBS_TOKEN`. The workflow refuses to push until both packages exist and are private.

## Limits

- Old SDK releases refuse an updated prover, because the update changes the compose hash they pin. Ship the SDK release that carries the new hash together with the update.
- The HPKE key has no forward secrecy, because it derives from the app key. Rotate by releasing a new app with `--replace` and a matching SDK release.
- The verifiers accept only dstack runtime events of the version 1 digest format, which the 0.5 OS images emit. An OS image that emits the version 2 format fails attestation.
- A newly revoked TCB shows only after the prover refreshes its collateral cache, because the client verifies the collateral the prover relays. A TCB status the pin does not list fails at once.
- A GPU prover cannot attest while NRAS is unreachable, because each attestation asks NRAS for a fresh verdict.

## Pitfalls

- A setting in the CVM environment is not measured. An indexer URL in the environment lets the API key holder redirect the leaves a proof spends. The indexer URL lives in the compose, and the env holds only keys, the RPC URL and the dump link.
- `ship_photon_db.sh` replaces the whole sealed env, so a variable left out of the ship is gone after the restart. Pass the release's `PROVER_INDEXER_API_KEY`, `PHOTON_RPC_URL` and registry variables, and `TEE_REGISTRY_HOST` when the prover image is not on `ghcr.io`.
- Phala's `deploy` defaults to public logs. A log line holding a request body is then readable by anyone, so the script passes `--no-public-logs`.
- A prover URL without `api-key` fails attestation, because the attestation route sits behind the prover API key like the proof routes.
- A client built without a policy sends plaintext to the same prover and sees no error. Set the policy where the client is built, not per call.
