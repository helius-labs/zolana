# Squads policy zone

A policy zone over the shielded pool for Squads accounts. It owns UTXOs on the
SPP ring rail and settles every spend by CPI into SPP, so SPP holds the funds
and enforces the protocol while the zone enforces the policy.

Program id `62EpnphqgmKwc1x9nfnLVvxGBNF8cdkrfvWPnY5VECAo`. Source under
`zones/squads`, a nested workspace with its own lockfile that depends on the
main-repo crates by path.

## Why a zone

A Squads account has no signing key. Its vault is a PDA, so it cannot produce
the P256 signature an ordinary SPP spend proves in circuit. The zone answers
that by owning the UTXOs itself and authorizing spends two ways.

| Rail | Owner | Authorization |
|---|---|---|
| P256 | a keypair holder | the owner signs `sha256(private_tx_hash)`, proved in circuit, settled through SPP `ring_transact` |
| Smart account | a Squads vault | no signature. The zone signs for its `ring_auth` PDA and settles through SPP `ring_authority_transact` |

The zone exists for the smart-account rail. A proposal on that rail is approved
asynchronously and settled later by a crank, which no in-circuit signature
scheme could do.

## Registration

The zone registers with SPP once, through `init_spp_zone_config` (tag 16). SPP
creates a `RingConfig` at the zone's own `["zone_auth"]` PDA, so one account is
the zone's authority seen from SPP's side. Every later CPI signs for that PDA, so SPP knows
which ring a leg belongs to and binds `ring_program_id`.

`ring_authority_transact_is_enabled` is set at registration. Without it the
smart-account rail cannot settle.

## Accounts

| Account | Seeds | Holds |
|---|---|---|
| `ZoneConfig` | `["zone_config"]` | authority, co-signer, auditor key, pause flag |
| `zone_auth` | `["zone_auth"]` | nothing here. It is SPP's `RingConfig` and the CPI signer |
| `ViewingKeyAccount` | `["viewing_key_account", owner]` | shared viewing key, its commitment, nullifier pubkey, recovery and auditor key ciphertexts |
| `Proposal` | `["proposal", ..]` | a pending transfer or withdrawal, bound by `proposal_hash` |
| `KeyUpdateProposal` | `["key_update_proposal", ..]` | a pending rotation of the recovery or auditor set |

A `ViewingKeyAccount` is the zone's identity record. Its `owner_kind` selects
the settlement rail, and `Poseidon(owner, nullifier_pubkey)` is the UTXO owner
hash every zone UTXO carries, so the program derives a deposit's recipient on
chain rather than trusting the caller.

A key-rotation proof is bound to the account's canonical
[`key_rotation_commitment`](../zones/squads/interface/src/state/viewing_key_account.rs).
That implementation is the source of truth for its domain, field set, and
packing. Successful rotation increments the committed nonce, so the same proof
cannot authorize another rotation.

Recovery-key add, remove, and replace operations fail closed in the current
instruction version. They remain disabled until a versioned signed-intent flow
can authenticate the P256 owner. A Solana proposer signature is not treated as
owner approval. A single auditor update remains authorized by the zone
co-signer.

## Instructions

Tags are the zone's own, distinct from SPP's.

| Tag | Instruction | Effect |
|---|---|---|
| 0 | `transact` | synchronous transfer or withdrawal. Verifies the zone proof, forwards SPP `ring_transact` or `ring_authority_transact` |
| 1 | `deposit` | proofless. Derives the recipient owner from a `ViewingKeyAccount`, forwards SPP `ring_deposit` |
| 2 | `merge_transact` | consolidates one merge shape into a single UTXO through SPP `merge_ring` |
| 3, 4 | `create_zone_config`, `update_zone_config` | zone administration |
| 5 to 9 | viewing key account lifecycle | create, update, fill, close, toggle |
| 10 | `full_withdrawal` | withdraws an account's whole balance |
| 11 to 13 | `create_proposal`, `cancel_proposal`, `execute_proposal` | the async smart-account rail |
| 14, 15 | `execute_key_update`, `cancel_key_update` | recovery and auditor set rotation |
| 16 | `init_spp_zone_config` | one-time registration with SPP |
| 17 | `fold_transact` | several transfer legs of one account under one fold proof, one `ring_transact` per leg |

## Circuits

Under `prover/server/circuits/squads`. Both have one public input, the
statement hash the program recomputes.

`zone` proves a spend. Value conservation, the owner binding, and the AES-CTR
verifiable encryption of the sender change and the recipient output. Its shape
selects the key through `select_zone_vk`.

`key_encryption` proves the shared viewing secret was encrypted to every
recipient key. Its key is selected by the recipient count.

`zone_fold` and `key_encryption_fold` widen those two by verifying several of
their proofs inside one circuit. See [Width caps](#width-caps).

`circuits/squads/utils` holds the shared gadgets, the Poseidon KDF chain, the
emulated P256 ECDH, and the transaction fold. They are Squads-only.

## What settles where

The zone never touches funds. Each instruction builds SPP instruction data and
CPIs with the `zone_auth` PDA flipped to signer.

| Zone instruction | SPP instruction |
|---|---|
| `deposit` | `ring_deposit` (tag 14) |
| `transact`, `execute_proposal` on the P256 rail | `ring_transact` (tag 15) |
| `transact`, `execute_proposal` on the smart-account rail | `ring_authority_transact` (tag 17) |
| `merge_transact` | `merge_ring` (tag 16) |

A deposit publishes only `owner_utxo_hash`, so SPP never sees the recipient. The
zone computes that hash itself from the viewing key account and the blinding,
and that binds a deposit to its recipient.

A zone spend keeps `default_owner_tag` unset in its `CircuitId::RingP256`
selector. Publishing the P256 x-coordinate would deanonymize the owner, and
ownership is already proved inside the ring.

## Width caps

Each zone circuit has a fixed width, and `ViewingKeyAccount` holds more recovery
keys than the key-encryption circuit can prove, so the cap binds in practice.
[RECURSION.md](RECURSION.md#squads-folds) holds every cap, what a fold above it
reaches, what each fold proves, and the key catalogue. Both folds settle through
`fold_transact`, tag 17, which verifies the fold once and forwards one CPI per
leg.

## Tests

`zones/squads/integration-tests` runs against a fresh validator and Photon per
test, because the SPP protocol config is a singleton.

| Suite | Covers |
|---|---|
| `keypair_lifecycle` | the P256 rail end to end, deposit through transfer to withdrawal |
| `smart_account_lifecycle` | the smart-account rail, including crank-settled proposals |
| `account/*`, `admin/*` | per-instruction behaviour and failure cases |

The lifecycle suites drive the mock backend in `zones/squads/client`, which
holds the auditor key and reads every balance through it. They exist to prove
one property. An auditor recovers balances from on-chain data plus its own
secret, with no user viewing or nullifier secret.
