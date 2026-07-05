# Squads Zone

The Squads zone configures a zone on The Solana Privacy Protocol (TSPP / SPP): it
adds an auditor encryption key for compliance, a co-signer, and smart-account
support (asynchronous execution and shared viewing keys). The protocol is
specified in [`docs/squads_policy_program.md`](../../docs/squads_policy_program.md);
this directory holds its on-chain program, client interface, and SDK.

## Scope

This is a self-contained nested Cargo workspace. It depends on the main repo's
crates by path (`zolana-interface`, `sdk-libs/keypair`, `sdk-libs/transaction`,
`sdk-libs/client`) and reuses the SPP program via CPI.

The ZK circuits and the prover server already live in
[`/prover`](../../prover) (Go) and **do not move**. The only Rust prover code
here is the thin glue that builds witnesses and calls the existing lazy server.

Integration tests live in this workspace under `integration-tests/`
(`squads-zone-tests`), loading the built SBF binary. Run them with
`cargo test --manifest-path zones/squads/Cargo.toml -p squads-zone-tests`.

## Layout

```text
zones/squads/
├── Cargo.toml                       # nested [workspace] — own lockfile; root repo excludes these crates
├── justfile                         # zone-local recipes (build/test/regen-vkeys) — optional
│
├── program/                         # on-chain Squads zone program (pinocchio; depends only on interface)
│   └── src/
│       ├── lib.rs                   # entrypoint
│       ├── processor.rs             # tag dispatch -> process_<name>_ix
│       ├── error.rs                 # SquadsZoneError + From<> for ProgramError
│       ├── shared/                  # cross-cutting helpers (see "Loaders" below)
│       │   ├── mod.rs
│       │   ├── viewing_key_loader.rs  # load_viewing_key_account + owner/state checks (read across groups)
│       │   ├── zone_config_loader.rs  # load_zone_config + co-signer / auditor / merge-authority checks
│       │   ├── proof.rs             # zone & key-encryption Groth16 verify + public-input hashing
│       │   ├── cpi.rs               # SPP CPI helpers + zone_auth PDA signer
│       │   ├── create_pda.rs        # PDA account creation (hot/cold path)
│       │   ├── close.rs             # account close + rent return to rent_payer
│       │   ├── spl.rs               # SPL interface interaction (deposit / withdrawal)
│       │   └── client_signature.rs  # owner P256/eddsa signature checks
│       └── instructions/
│           ├── mod.rs
│           ├── sync/                # transact (0, folder) · deposit (1, file) · loader.rs
│           ├── async_exec/          # create_proposal (11) · cancel_proposal (12) · execute_proposal (13, folder) · loader.rs
│           ├── viewing_key/         # create (5) · update (6) · fill (7) · execute (14) · cancel (15) · close (8) · loader.rs
│           ├── exit/                # toggle (9) · full_withdrawal (10) · loader.rs
│           └── admin/               # create_zone_config (3) · update_zone_config (4) · merge_transact (2) · loader.rs
│
├── interface/                       # shared client<->program surface (CT `confidential-token-interface` shape)
│   └── src/
│       ├── lib.rs                   # re-exports; SQUADS_ZONE_PROGRAM_ID
│       ├── constants.rs             # PROGRAM_ID_PUBKEY, seeds, fixed sizes
│       ├── domain.rs                # domain-separation tags / typed constants
│       ├── error.rs                 # feature-gated SquadsZoneInterfaceError
│       ├── shared.rs                # ProofBytes + field-element packing (split_33_bytes, split_32_bytes, pack_*)
│       ├── instruction/
│       │   ├── tag.rs               # dispatch tag constants (0..15)
│       │   ├── builders/            # struct-per-instruction (Transact { … }.instruction()); signers are explicit AccountMetas
│       │   └── instruction_data/    # *IxData structs (TransactIxData, …), wincode SchemaRead/SchemaWrite
│       ├── state/                   # dual structs per account: XxxRef (wincode SchemaRead, read) + Xxx (wincode SchemaWrite, write)
│       │   ├── discriminator.rs     # account-type tag constants
│       │   ├── zone_config.rs · viewing_key_account.rs · proposal.rs · key_update_proposal.rs
│       ├── ciphertext.rs            # SharedKey/Proposal/Sender/Recipient ciphertexts, EncryptedUtxos
│       ├── proof.rs                 # ZoneProof/MergeProof/SppProof, InputContext
│       └── verifying_keys/          # zone_proof.rs · key_encryption.rs (xtask-generated)
│
└── sdk/                             # client wallet/crypto/serialization + prover glue (feature-gated)
    └── src/
        ├── lib.rs                   # features: `encryption` (default), `rpc`, `prover`
        ├── constants.rs
        ├── shared_viewing_key.rs    # shared-key derivation, P256 ECDH, Poseidon KDF blinding chain
        ├── viewing_key_account.rs   # build/decrypt account, recover shared sk + nullifier secret per holder
        ├── encrypted_utxo.rs        # zone EncryptedUtxos (de)serialize + decrypt
        ├── proposal.rs              # proposal ciphertext + proposal_hash
        ├── key_update.rs            # rotation ciphertexts + key-encryption proof inputs
        ├── intent.rs                # PrivateTransactionIntent, TransactionType, OutputUtxo
        ├── backend.rs               # `rpc` feature: JSON-RPC types getBalances/getProposals/request*
        └── prover/                  # `prover` feature: witness build + call to existing Go server (does NOT move)
            ├── mod.rs
            ├── zone.rs              # squads zone-proof witness + ProverClient call
            └── key_encryption.rs    # key-encryption-proof witness + call
```

## Crates

| Crate | Path | Holds |
| --- | --- | --- |
| `zolana-squads-program` | `program/` | On-chain program. Verifies the zone proof, CPIs SPP, manages zone accounts. Depends only on `interface` and low-level crates. |
| `zolana-squads-interface` | `interface/` | Instruction tags, builders, instruction-data structs, account state layouts, ciphertext types, verifying keys. Shared by program, SDK, and tests. |
| `zolana-squads-sdk` | `sdk/` | Client-side shared-viewing-key crypto, zone UTXO/ciphertext (de)serialization, proposal building, and the prover glue. Reuses `keypair`, `transaction`, and `client`. |

## Serialization

Instruction data and account state use `zolana-transaction` **wincode**
(`SchemaRead` / `SchemaWrite`) for both reads and writes — not Borsh (CT writes
with Borsh; this is a deliberate zolana divergence). Length-prefix rule for
wincode `Vec`s: `Vec<u8>` (ciphertexts, `encrypted_utxos`) uses `FixIntLen<u16>`;
every other vector (recovery keys, recipient slots, input contexts) uses
`FixIntLen<u8>`.

## Signing model

Authorization is account-signer-based, not an embedded eddsa signature in
instruction data (CT's `SignerMode::ClientSignature` does **not** translate
here):

- **Spends** (`transact`, `execute_proposal`, `merge_transact`) — owner intent is
  carried by the **zone proof** ("zk proof that owner signed"); the **co-signer**
  and the **relayer/payer** sign as explicit signer accounts.
- **Optional owner signer** (`create_viewing_key_account`) — the `owner`
  `AccountMeta` is a signer only when registering recovery keys; absent → the
  account is auditor-only.
- **Account-driven signers** elsewhere — `owner` (smart-account vault via the
  Squads CPI), `executor`, `authority`, and `merge_authority` sign as accounts.
- **P256 `owner_signature: Option<[u8;64]>`** lives only in the SDK/backend layer
  (signs `transaction_type` + `intent` so the backend can build); it is not an
  on-chain instruction-data field (spec open question #1).

## Program instructions

Grouped as in the spec; tag in parentheses. Folder = multi-account/proof
instruction (`mod.rs` + `processor.rs` + `verify.rs`, plus `init.rs`/`apply.rs`
where needed); file = simple single-account instruction.

- **sync/** — `transact` (0), `deposit` (1)
- **async_exec/** — `create_proposal` (11), `cancel_proposal` (12), `execute_proposal` (13)
- **viewing_key/** — `create_viewing_key_account` (5), `update_viewing_key_account` (6), `fill_key_update` (7), `execute_key_update` (14), `cancel_key_update` (15), `close_viewing_key_account` (8)
- **exit/** — `toggle_viewing_key_account` (9), `full_withdrawal` (10)
- **admin/** — `create_zone_config` (3), `update_zone_config` (4), `merge_transact` (2)

## Loaders

Account loading follows the confidential-transfers convention, not a single
global `loader.rs`:

- **Per-group `loader.rs`** — each instruction-group folder (`sync/`,
  `async_exec/`, `viewing_key/`, `exit/`, `admin/`) owns a `loader.rs` with the
  `load_*` functions and `validate_*` / `check_*` helpers for the accounts that
  group touches. Each loader validates program ownership, length, and
  discriminator, then returns a `Ref<State>` via `bytemuck`; field validators
  (e.g. PDA / owner / expiry checks) live alongside.
- **`shared/`** — cross-cutting helpers reused across groups: loaders for the
  accounts read everywhere (`ViewingKeyAccount`, `ZoneConfig`), Groth16 proof
  verification, the SPP CPI + `zone_auth` signer, PDA creation, account close,
  SPL interface interaction, and client signature checks. Mirrors
  confidential-transfers' `src/shared/` module.

Every account that is read or written goes through a `load_*` function in one of
these, per the repo account rules.

## Accounts

| Account | Seed | Purpose |
| --- | --- | --- |
| `ZoneConfig` | `[b"zone_config"]` | One per program. Auditor keys, co-signer, authority, proposal-lifetime bound, merge authorities. |
| `ViewingKeyAccount` | `[b"viewing_key_account", owner]` | One per user. Shared viewing key + commitment, per-holder/auditor key ciphertexts, nullifier commitment and encrypted nullifier secret. |
| `Proposal` | `[b"proposal", owner, cipher_text[0..33]]` | Queued async withdrawal/transfer; `proposal_hash` binds the operation. |
| `KeyUpdateProposal` | `[b"key_update_proposal", target, domain]` | Queued recovery-key change or auditor update; buffers new shared-key ciphertexts. |

## ZK proofs

Both circuits already exist in [`/prover`](../../prover); the program verifies
them on-chain (Groth16) and the SDK builds their witnesses.

- **Zone proof** — verified by `transact` and `execute_proposal`. Enforces
  verifiable encryption of every output to its recipient's shared viewing key
  and the canonical sender change-blinding derivation.
- **Key encryption proof** — verified by `create_viewing_key_account` and
  `execute_key_update`. Proves the shared private key is correctly encrypted to
  every recovery and auditor key and bound to the stored commitment.

Verifying keys live in `interface/verifying_keys/`, regenerated with the same
`regenerate_all_vkeys.sh` / xtask `bsb22-vk` pipeline as the rest of the repo.

## Workspace wiring

`zones/squads/Cargo.toml` is its own `[workspace]` with its own lockfile. The
root `Cargo.toml` must **exclude** these crates so cargo does not absorb them:

```toml
[workspace]
exclude = ["zones/squads"]
```

Dependencies on the main repo's crates are path-based
(`path = "../../../sdk-libs/keypair"`, etc.). Nothing in `/prover` moves; the
SDK's `prover/` module reuses `sdk-libs/client`'s `ProverClient` / `spawn_prover`
and points at the existing `squads` Go circuits.
