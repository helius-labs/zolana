# Squads Ring

The Squads ring is a policy ring on the Solana Privacy Program (SPP): it adds an
auditor encryption key for compliance, a co-signer, and smart-account support
(asynchronous execution and shared viewing keys). The protocol is specified in
[`docs/squads_policy_program.md`](../../docs/squads_policy_program.md); this
directory holds its on-chain program, client interface, SDK, backend client and
integration tests.

## Scope

This is a self-contained nested Cargo workspace with its own lockfile. The root
`Cargo.toml` excludes it (`exclude = ["rings/squads"]`); it depends on the main
repo's crates by path. The ring and key-encryption circuits live in
`prover/circuits` and are proved in process by `squads-prover`, on the shared
gnark FFI prover (`sdk-libs/gnark-ffi-prover`). The SPP proofs of a spend or
merge still come from the main prover server.

## Crates

| Crate | Path | Holds |
| --- | --- | --- |
| `zolana-squads-program` | `program/` | On-chain program. Verifies the ring proof, forwards SPP payloads through `ring_auth`-signed CPIs, manages ring accounts. |
| `zolana-squads-interface` | `interface/` | Instruction tags, builders, instruction data, account state, verifying keys. |
| `zolana-squads-sdk` | `sdk/` | Shared-viewing-key crypto, ciphertexts, proposals, and the `prover` feature: ring and key-encryption witnesses, and the paired ring + SPP spend and merge builders. |
| `zolana-squads-client` | `client/` | In-process backend: balances, proposals, `requestTransact`, and the settlement / merge crank. |
| `squads-prover` | `prover/` | Go ring and key-encryption circuits, their witness encoding, and the key setup binary. |
| `squads-test-prover-server` | `test-prover-server/` | Unix-socket server tests prove through, so every test binary shares its loaded proving keys. |
| `squads-ring-tests` | `integration-tests/` | LiteSVM tests and the keypair / smart-account BDD suites on a local validator. |

## SPP settlement

Spends and merges carry the full SPP payload (`ring_transact`,
`ring_authority_transact` or `merge_ring` instruction data) and the SPP account
list; the program checks the payload against its ring proof and forwards both
unchanged, signing SPP's `ring_config` (the ring's `[b"ring_auth"]` PDA).
Deposits are built on-chain from the recipient viewing key account and forwarded
as `ring_deposit`. An Ed25519 keypair owner settles on the `AnonymousRingEddsa`
rail by signing `sha256(private_tx_hash || external_data_hash)`; a smart-account owner settles on the
`RingAuthority` rail, which governance must enable for the ring
(`set_ring_activation`).

Viewing, recovery, and auditor keys use main's tagged X25519 encoding. The
circuits reuse main's X25519, AES-256-CTR, verifiable-encryption key schedule,
and canonical byte hashing. Shared-key and nullifier ciphertexts use distinct
encryption contexts. Ring proofs bind the external transaction data separately
from `private_tx_hash`.

The ring withdrawal proof has one input and one output. Its SPP proof uses
compact output padding for the supported 1-by-2 keypair or 2-by-2 authority
shape; an authority withdrawal also needs a dummy input and its non-inclusion
proof. Compact padding adds no published output.

## Proving keys

The squads keys are INSECURE TEST KEYS, UNSAFE FOR PRODUCTION: the setup draws
its randomness from a fixed public seed, so anyone can forge proofs against
them. The seed makes them deterministic, so `just ensure-squads-keys` generates
them locally into `build/gnark/<circuit>/{pk,vk}.bin` and checks them against
`squads-keys.CHECKSUM`, which pins them to the committed
`interface/src/verifying_keys`. Those only compile with the interface's
`insecure-test-setup` feature (on by default). `just regen-squads-keys`
regenerates keys, verifying keys and pins together after a circuit change.

Tests prove through `squads-test-prover-server`, which the first proof of a test
process starts (`just build-squads-prover-server` builds it; without it,
proofs run in process). Its socket is scoped by `ZOLANA_PORT_OFFSET`.
`just test-squads` also runs the Go circuit tests.

## Tests

```bash
just test-squads                     # host tests: interface, program, sdk, client
just test-squads-ring                # keypair BDD suite on a local validator
just test-squads-ring-smart-account  # smart-account BDD suite
```
