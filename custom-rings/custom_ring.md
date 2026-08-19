# Minimal Custom Ring: Auditor Verifiable Encryption

Source of truth for this example's privacy model, instruction set, and circuit.

## Purpose

SPP already ships the full ring surface (`RingConfig` state, `RING_DEPOSIT` /
`RING_TRANSACT` tags, `transfer_ring_*` verifying keys, the `ring_auth` PDA).
What it has no implementation of is the reserved
`OutputDataEncoding::VerifiablyEncrypted` auditor flow. This example is the
smallest ring program that fills that gap: its single proof statement is that the
per-transaction viewing secret key of an SPP `transact` is correctly encrypted to
the auditor public key stored in the ring's config account.

Every user ciphertext in an SPP transaction is HPKE'd under the transaction
viewing key, so an auditor who recovers that one secret can decrypt everything
the recipients see. That is why the circuit needs no per-output witnesses and no
`PrivateTxHashCircuit`: `private_tx_hash` is a pass-through public input.

## Scope (deliberately minimal)

- Confidential transfers only.
- Solana eddsa signers only (`CircuitId::RingEddsa` -> SPP tag `RING_TRANSACT`).
  The program rejects `RingP256`.
- No smart-account support. The localnet harness loads the squads smart-account
  program for **protocol bootstrap only** (`CreateProtocolConfig` / `CreateTree`
  are `execute_sync_ix`-gated); the ring program itself never touches smart
  accounts.
- No user accounts: no viewing-key accounts, no proposals, no key rotation, no
  viewing-key lifecycle.
- One feature: verifiable encryption to the auditor. User-side encryption is not
  checked by the circuit.
- Config gating is the program's upgrade authority when the deployment names
  one, otherwise a plain authority signer. No key rotation yet.

## Program id

```
9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh
```

The default of a build-time input: `build.rs` reads `CUSTOM_RING_PROGRAM_ID` and
writes the `declare_id!` the crate includes, so a ring generated from
`templates/custom-ring` pins its own address through Cargo `[env]` without
editing sources. With the variable unset the example is provisioned like the
other `sdk-tests` examples: no keypair committed to the repository.
`cargo build-sbf` writes `target/deploy/custom_ring_program.so` plus a throwaway
`target/deploy/custom_ring_program-keypair.json` (both gitignored), and the
localnet harness deploys the `.so` at the `declare_id!` address rather than at the
generated keypair's address. A real deploy needs a keypair whose pubkey equals the
id above; this example never performs one.

## Crates

| Crate | Package | Role |
| --- | --- | --- |
| `program` | `custom-ring-program` | Pinocchio program: instructions, proof verification, verifying keys, instruction data, tags, errors, canonical public-input hashing. |
| `prover` | `custom-ring-prover` | Go gnark circuit, cgo bindings, proof-input containers, setup binary. |
| `sdk` | `custom-ring-sdk` | Instruction builders, proof-input builders, prover client, the audited transfer flow (`AuditedTransfer`, ring deposits, v0 send behind a lookup table). Re-exports the auditor encryption codec. |
| `cli` | `custom-ring-cli` | Operator commands a generated ring runs (`deploy` and upgrade, `authority transfer` and `renounce`, `init`, `transact`, `status`, `rpc-check`) over the sdk. |
| `test` | `custom-ring-test-validator` | Localnet end-to-end tests. |

### The auditor side lives outside the example

The auditor encryption codec, transaction viewing key recovery, indexer scanning
and the decrypted result types are the `zolana-ring-client` crate under
`sdk-libs/ring-client`, not an example crate: the Ring RPC service
(`services/ring-rpc`) and the end-to-end test both run it, so the assertions run
the same code path an external auditor would, and neither depends on test
utilities. `sdk` owns everything the sender needs (instruction and proof-input
construction) and re-exports the codec for the message it builds.

### Dependency lists

Dependencies are added task by task, only when code actually uses them: CI runs
`cargo machete` and `just clippy` with `-D warnings`, so a declared-but-unused
dependency is a red build. The skeleton starts with `pinocchio` +
`zolana-interface` (program), `bindgen` as a build dependency (prover),
`custom-ring-program` (sdk), and none for `test`.

## The Go circuits and `build.rs`

`prover/build.rs` compiles `prover/circuits/` to a cgo c-archive and runs
bindgen, like the swap prover's build script, with one addition: when
`circuits/main.go` does not exist it prints a `cargo:warning` and returns without
building. In that state it leaves `cfg(custom_ring_go_circuits)` unset (the cfg is
always declared through `cargo:rustc-check-cfg`), and the FFI surface is gated on
that cfg. So the crate compiles as a skeleton, and code that needs the proving
engine fails to compile rather than silently degrading. Once the Go sources land,
the script takes the normal path and a failing `go build` is a hard error.

## Instructions

Tags 1-3 are program-local. Ring deposits carry no proof and are forwarded to SPP
byte for byte, so the dispatcher matches SPP's own
`zolana_interface::instruction::tag::RING_DEPOSIT` (14) instead of allocating a
local tag: the client builds the SPP-shaped instruction with the existing
`RingDeposit` builder and only re-targets the program id.

### 1 `create_config`

Accounts `[payer(w,s), authority(s), config(w, PDA [b"config"]), system_program,
program, program_data]`; data `CreateConfigIxData { auditor_pubkey: [u8; 33] }`
(wincode). Validates both signers, the system program, the canonical config
bump, an SEC1 compressed prefix in `{2, 3}`, and that the account is not already
initialized. Creates the account at exactly `RingProgramConfig::SIZE`.

`program` and `program_data` gate the call on the deployment: when the loader-v3
`ProgramData` names an upgrade authority, `authority` must be that key. A
non-upgradeable deployment or an unset or zeroed authority skips the check, so
localnet `--bpf-program` deployments (zeroed authority) and the mollusk fixtures
that model an immutable program stay first-caller-wins. Forged or truncated
loader state fails closed. The sdk builder types the auditor key as `P256Pubkey`,
so an off-curve key never reaches the program.

### 2 `init_spp_ring_config`

Accounts `[payer(w,s), authority(s), config, protocol_config, ring_auth(w),
system_program, spp_program]`; no data. Requires the stored authority to sign,
then CPIs SPP `CREATE_RING_CONFIG` with `ring_auth` (`[b"ring_auth"]` under this
program) flipped to a signer and `ring_authority_transact_is_enabled: false`.

### 14 `deposit` (forwarded)

Proofless forwarder. Checks the SPP program account, requires `ring_auth` to be
present, flips it to a signer, and invokes SPP with the instruction data
unchanged (tag byte included; SPP's dispatcher strips it).

### 3 `transact`

Data `CustomRingTransactIxData { proof: AuditProof, transact: TransactIxData }`
(wincode). Accounts `[payer(w,s), config] ++ <RING_TRANSACT list with ring_config
unsigned>`. Flow: deserialize, load config, require `CircuitId::RingEddsa`, locate
the auditor message, recompute the public-input hash, verify the Groth16 proof,
then CPI SPP `RING_TRANSACT` with `ring_auth` as signer.

The auditor message is transported in SPP `transact` `messages`, which are folded
into `external_data_hash` and republished verbatim in `GeneralEvent` - the
ciphertext is bound by both the ring proof and the SPP proof.

```
MessageData {
  view_tag: auditor_pk.x(),                        // compressed key bytes 1..33
  data: eph_pk_compressed(33) || ciphertext(32),   // 65 bytes total
}
```

Program-defined convention: exactly one message carries the auditor view tag, and
it is the last entry of `messages`. Free-form messages before it stay allowed.

## Constants

```
AUDIT_ENC_INFO:    &[u8; 10] = b"CRING/adt1"
DOM_SEP_CR_SHARED: u32       = 0x43525f53   // "CR_S"
```

## Pinned public-input chain

The circuit comments and the Rust recomputation both refer to this numbering.

```
PublicInputHash = HashChain([
  1. private_tx_hash                          (pass-through public field)
  2. tx_viewing_pk_lo   3. tx_viewing_pk_hi   (pack33_to_2fe of the compressed pk;
                                               in-circuit from
                                               ScalarMulGenerator(tx_viewing_sk) -> Compress)
  4. auditor_pk_lo      5. auditor_pk_hi      (pack33_to_2fe; Compress(witnessed 65-byte pk))
  6. eph_pk_lo          7. eph_pk_hi          (pack33_to_2fe; ScalarMulGenerator(eph_sk))
  8. ct_hash = hash_bytes(ciphertext[32])
])

shared_secret = Poseidon(DOM_SEP_CR_SHARED, dh_lo, dh_hi, eph_pk_lo, eph_pk_hi,
                         auditor_pk_lo, auditor_pk_hi)
  where dh = ECDH(eph_sk, auditor_pk).x
key, nonce = KeySchedule(shared_secret, AUDIT_ENC_INFO, 10)
ct         = AES-256-CTR(key, nonce, tx_viewing_sk)
```

Cross-language pairings: `zolana_hasher::hash_chain::create_hash_chain_from_slice`
== Go `gadget.HashChain`; `zolana_hasher::primitives::hash_bytes` ==
`gadget.HashBytes`; host KDF `zolana_keypair::symmetric_apply`; host ECDH
`ViewingKey::ecdh`. No `sdk-libs` changes are needed.

An ephemeral key is required, not optional: encrypting the transaction viewing
secret key directly under `ECDH(tx_viewing_sk, auditor_pk)` would derive the
encryption key from the very secret being encrypted. The 33-byte compressed
ephemeral public key rides in the message data.

Scalar canonicality: the circuit binds `bytes mod n`, and the auditor client
reduces the recovered 32 bytes modulo the P256 group order. Every witnessed byte
is range-checked to 8 bits in-circuit, and the uncompressed auditor key is
constrained to start with `0x04`.

## Audit-coverage boundary

The recovered transaction viewing key opens **Confidential-scheme `transact`
output slots only**.

Ring **deposits** are not auditor-decryptable: `EncryptedRingDepositData` is keyed
to the recipient, not to the transaction viewing key. That loses nothing, because
deposit amounts are public on-chain - the auditor reads them from the deposit
instruction or event rather than by decryption.

Undecryptable output slots are recorded in the audit result, not treated as
failures.

## Error-location convention

Errors live in the program crate (`program/src/error.rs`), and the sdk re-exports
them. That follows `sdk-tests/zk-program-swap/CLAUDE.md` ("No separate interface
crate; the sdk re-exports from here"), which all three existing examples do. The
root `CLAUDE.md` rule that every program error belongs in
`program-libs/interface` with a code in the 7000 space applies to SPP itself, not
to the `sdk-tests`-style examples.

This example uses the `8100..=8115` range, verified collision-free against SPP
(7000-7047), the swap example (8005-8016), and the remaining examples (9xxx).
Every code is pinned in an `error_codes_are_stable` test.


## Auditor service and ring generator

Auditor service: `services/ring-rpc/README.md`. Ring generator (`just ring-new`
and the generated pipeline): `templates/README.md`.

## Future Work
- rust prover server to make local testing performant (keep it separate from go prover server)
- rotating auditor key with a key version in the public-input chain
- add custom ring program filter as option to GetRingsByTagsRequest
- signed `get_decrypted_*_by_owner` methods on the Ring RPC
