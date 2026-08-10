# Squads Zone

A policy zone over the shielded pool for Squads accounts: auditor encryption
keys, a co-signer, and smart-account support (asynchronous execution and shared
viewing keys). Protocol description and instruction catalogue live in
[`docs/SQUADS.md`](../../docs/SQUADS.md); the fold circuits that lift its width
caps in [`docs/RECURSION.md`](../../docs/RECURSION.md). This directory holds the
on-chain program, the client interface, and the SDK.

## Scope

A self-contained nested Cargo workspace with its own lockfile. It depends on
the main repo's crates by path (`zolana-interface`, `sdk-libs/keypair`,
`sdk-libs/transaction`, `sdk-libs/client`) and settles through the SPP program
by CPI. The ZK circuits and the prover server stay in
[`/prover`](../../prover); the SDK's `prover/` module only builds witnesses and
calls the existing lazy server.

Integration tests live under `integration-tests/` (`squads-zone-tests`) and
load the built SBF binary. Build it first, or every test fails:

```bash
cd zones/squads/program && cargo build-sbf --features bpf-entrypoint
cargo test --manifest-path zones/squads/Cargo.toml -p squads-zone-tests
```

## Crates

| Crate | Path | Holds |
| --- | --- | --- |
| `zolana-squads-program` | `program/` | On-chain program. Verifies the zone proof, CPIs SPP, manages zone accounts. Depends only on `interface` and low-level crates. |
| `zolana-squads-interface` | `interface/` | Instruction tags, builders, instruction-data structs, account state layouts, ciphertext types, verifying keys. Shared by program, SDK, and tests. |
| `zolana-squads-sdk` | `sdk/` | Client-side shared-viewing-key crypto, zone UTXO and ciphertext (de)serialization, proposal building, prover glue. Reuses `keypair`, `transaction`, and `client`. |
| `zolana-squads-client` | `client/` | Operator-side backend: balances, tags, transaction assembly, proposal scanning, and the settlement crank. |
| `squads-zone-tests` | `integration-tests/` | LiteSVM and localnet integration tests plus the shared harness. Not published. |

## Layout

```text
program/src/
  lib.rs                  entrypoint and tag dispatch
  shared/                 proof composition and verify, SPP CPI + zone_auth
                          signer, PDA create, account close, owner identity,
                          withdrawal settlement, supported shapes
  instructions/
    transact/                     the synchronous spend
    deposit.rs, fold_transact.rs, merge_transact.rs, full_withdrawal.rs
    proposal/                     create, cancel, execute
    viewing_key_account/          create, close, toggle
    key_update_proposal/          propose, fill, execute, cancel
    zone_config/                  create, update, init_spp_zone_config

interface/src/
  instruction/            tag.rs, builders/, instruction_data/
  state/                  ZoneConfig, ViewingKeyAccount, Proposal, KeyUpdateProposal
  verifying_keys/         zone + key encryption consts, xtask-generated

sdk/src/
  crypto.rs, viewing_key_account.rs, encrypted_utxo.rs, proposal.rs, intent.rs
  prover/                 proof input build per circuit, calls the Go server

client/src/               backend, balances, tags, transact, proposals, crank

integration-tests/
  src/harness.rs          LiteSVM harness over the prebuilt SBF binary
  tests/                  admin, account, keypair, and smart-account suites
```

Tags, accounts, and the settlement mapping to SPP instructions are in
[`docs/SQUADS.md`](../../docs/SQUADS.md); do not restate them here.

## Serialization

Instruction data and account state use `zolana-transaction` wincode
(`SchemaRead` / `SchemaWrite`), not Borsh. Length-prefix rule for wincode
`Vec`s: `Vec<u8>` (ciphertexts, `encrypted_utxos`) uses `FixIntLen<u16>`,
every other vector uses `FixIntLen<u8>`.

## Signing model

Authorization is account-signer-based, no eddsa signature in instruction data:

- Spends (`transact`, `fold_transact`, `execute_proposal`, `merge_transact`) —
  owner intent is carried by the zone proof; the co-signer and the relayer or
  payer sign as explicit signer accounts.
- `create_viewing_key_account` — the `owner` account is a signer only when
  registering recovery keys; absent means the account is auditor-only.
- Elsewhere `owner` (smart-account vault via the Squads CPI), `executor`,
  `authority`, and `merge_authority` sign as accounts.
- The SDK-level P256 `owner_signature` signs `transaction_type` + `intent` so a
  backend can build the transaction; it is not an on-chain instruction-data
  field.

## Workspace wiring

The root `Cargo.toml` must exclude these crates so cargo does not absorb the
nested workspace:

```toml
[workspace]
exclude = ["zones/squads"]
```
