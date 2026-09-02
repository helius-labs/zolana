# Shielded Pool Invariants

Test-coverage checklist derived from the program source. Detailed invariants
live in the per-instruction files; `docs/spec.md` remains the protocol source
of truth.

Legend: PR164 = the circuit/protocol update, merged via PR171 (#171);
"post-PR164" below refers to that update. PR172 (signer-run authorization,
owner-hidden ring deposits, the RingP256 rail) has landed: the P256 N/A
entries are re-activated in their RingP256 scope (INV-TRANSACT-06, -11,
INV-RING-TRANSACT-06, INV-RING-AUTH-05, INV-XC-12), INV-XC-32 covers
retired-and-new wire formats, and new entries pin the signer-run model
(INV-TRANSACT-45), the RingP256ProofData payload (INV-XC-33), and the
signer-account owner rotation hardening (INV-UPDATE-ZC-OWNER-02/-05).

Marker legend: `- [x]` covered by tests on this branch; `- [ ]` partial or
uncovered; `- [~]` covered on a companion security branch (#175/#176) that
lands before this one (behavior and tests are reverted out of this branch
and return with that merge).

| File | Covers |
|---|---|
| `transact.md` | Transact, RingTransact, RingAuthorityTransact |
| `deposit.md` | Deposit, RingDeposit |
| `merge.md` | MergeTransact, RingMergeTransact |
| `tree.md` | CreateTree, BatchUpdateNullifierTree, PauseTree, CloseNullifierPdas, SetTreeFees, ClaimTreeLamports, nullifier PDAs created by the spend instructions |
| `protocol-config.md` | CreateProtocolConfig, UpdateProtocolConfig |
| `ring-config.md` | CreateRingConfig, UpdateRingConfig, UpdateRingConfigOwner |
| `spl.md` | CreateAssetCounter, CreateSplInterface |
| `event.md` | EmitEvent |
| `cross-cutting.md` | dispatch, rollback, expiry/pause, double-spend, proof rails, external_data_hash, lamports/PDAs, loaders, ring authorization, events, error codes |

ID prefixes: `INV-TRANSACT`, `INV-RING-TRANSACT`, `INV-RING-AUTH`, `INV-DEPOSIT`,
`INV-RING-DEPOSIT`, `INV-MERGE`, `INV-RING-MERGE`, `INV-CREATE-TREE`,
`INV-BATCH-NULL`, `INV-PAUSE-TREE`, `INV-CLOSE-PDA`, `INV-SET-FEES`,
`INV-CREATE-PC`, `INV-UPDATE-PC`, `INV-CREATE-ZC`, `INV-UPDATE-ZC`,
`INV-UPDATE-ZC-OWNER`, `INV-CREATE-AC`, `INV-CREATE-SPL`, `INV-EMIT-EVENT`,
`INV-XC`. IDs are stable once assigned -- never renumber.

`Transact`, `RingTransact`, and `RingAuthorityTransact` share one parser and core
(`process_transact_core`), so the shared `INV-TRANSACT-*` data/settlement/tree
invariants apply to all three (noted in `transact.md`); the matrix references them
from all three rows. The same holds for `Deposit`/`RingDeposit`
(`process_deposit_internal`) and `MergeTransact`/`RingMergeTransact`
(`process_merge_core`).

## Coverage Matrix

| Instruction | File | Accounts | Data | Authz | Success | Rollback | Frame |
|---|---|---|---|---|---|---|---|
| CreateProtocolConfig (0) | `protocol-config.md` | INV-CREATE-PC-03, INV-CREATE-PC-04 | INV-CREATE-PC-05 | INV-CREATE-PC-01, INV-CREATE-PC-02, INV-CREATE-PC-10 | INV-CREATE-PC-06..08 | INV-XC-04 | INV-CREATE-PC-09 |
| UpdateProtocolConfig (1) | `protocol-config.md` | INV-UPDATE-PC-03 | INV-UPDATE-PC-04 | INV-UPDATE-PC-01, INV-UPDATE-PC-02 | INV-UPDATE-PC-05, INV-UPDATE-PC-07 | INV-XC-04 | INV-UPDATE-PC-06 |
| CreateTree (2) | `tree.md` | INV-CREATE-TREE-03, INV-CREATE-TREE-04 | INV-CREATE-TREE-05, INV-CREATE-TREE-06, INV-CREATE-TREE-10 | INV-CREATE-TREE-01, INV-CREATE-TREE-02 | INV-CREATE-TREE-07, INV-CREATE-TREE-08, INV-CREATE-TREE-10 | INV-XC-04 | INV-CREATE-TREE-09 |
| PauseTree (3) | `tree.md` | INV-XC-24 | INV-PAUSE-TREE-02 | INV-PAUSE-TREE-01 | INV-PAUSE-TREE-03, INV-PAUSE-TREE-04 | INV-XC-04 | INV-PAUSE-TREE-05 |
| BatchUpdateNullifierTree (4) | `tree.md` | INV-XC-24, INV-XC-08 | INV-BATCH-NULL-03 | INV-BATCH-NULL-01, INV-BATCH-NULL-02 | INV-BATCH-NULL-05, INV-BATCH-NULL-08 | INV-BATCH-NULL-04, INV-XC-04 | INV-BATCH-NULL-06, INV-BATCH-NULL-09 |
| CreateAssetCounter (5) | `spl.md` | INV-CREATE-AC-03, INV-CREATE-AC-04 | INV-CREATE-AC-05 | INV-CREATE-AC-01, INV-CREATE-AC-02 | INV-CREATE-AC-06, INV-CREATE-AC-07 | INV-XC-04 | INV-CREATE-AC-08 |
| CreateSplInterface (6) | `spl.md` | INV-CREATE-SPL-03..05, INV-CREATE-SPL-08, INV-CREATE-SPL-13, INV-CREATE-SPL-14 | INV-CREATE-SPL-06 | INV-CREATE-SPL-01, INV-CREATE-SPL-02 | INV-CREATE-SPL-07, INV-CREATE-SPL-09..11 | INV-XC-04 | INV-CREATE-SPL-12 |
| CreateRingConfig (7) | `ring-config.md` | INV-CREATE-ZC-04, INV-CREATE-ZC-05 | INV-CREATE-ZC-06 | INV-CREATE-ZC-01..03 | INV-CREATE-ZC-07, INV-CREATE-ZC-08 | INV-XC-04 | INV-CREATE-ZC-09 |
| UpdateRingConfig (8) | `ring-config.md` | INV-UPDATE-ZC-02 | INV-UPDATE-ZC-06 | INV-UPDATE-ZC-01 | INV-UPDATE-ZC-03, INV-UPDATE-ZC-05 | INV-XC-04 | INV-UPDATE-ZC-04 |
| UpdateRingConfigOwner (9) | `ring-config.md` | INV-UPDATE-ZC-02 | INV-UPDATE-ZC-OWNER-05 | INV-UPDATE-ZC-OWNER-01, INV-UPDATE-ZC-OWNER-02 | INV-UPDATE-ZC-OWNER-03 | INV-XC-04 | INV-UPDATE-ZC-OWNER-04 |
| EmitEvent (10) | `event.md` | INV-EMIT-EVENT-03 | INV-EMIT-EVENT-02 | permissionless by design (INV-EMIT-EVENT-01 bounds the risk) | INV-EMIT-EVENT-02, INV-EMIT-EVENT-04 | INV-XC-04 | INV-EMIT-EVENT-01 |
| Deposit (11) | `deposit.md` | INV-DEPOSIT-01..09, INV-DEPOSIT-20, INV-DEPOSIT-23, INV-DEPOSIT-24 | INV-DEPOSIT-10, INV-DEPOSIT-11, INV-DEPOSIT-18, INV-DEPOSIT-19, INV-DEPOSIT-21, INV-DEPOSIT-22 | INV-DEPOSIT-01, INV-DEPOSIT-03, INV-DEPOSIT-05 | INV-DEPOSIT-12..16, INV-DEPOSIT-25 | INV-XC-04 | INV-DEPOSIT-17 |
| Transact (12) | `transact.md` | INV-TRANSACT-01..04, INV-TRANSACT-13..16, INV-TRANSACT-40, INV-TRANSACT-41, INV-TRANSACT-43, INV-TRANSACT-48, INV-XC-24 | INV-TRANSACT-07..12, INV-TRANSACT-31..38, INV-XC-02 | INV-TRANSACT-04..06, INV-TRANSACT-20, INV-TRANSACT-39 | INV-TRANSACT-23..28, INV-TRANSACT-42, INV-TRANSACT-44, INV-TRANSACT-46, INV-TRANSACT-47, INV-TRANSACT-49, INV-XC-18, INV-XC-27 | INV-XC-04, INV-XC-05, INV-TRANSACT-50 | INV-TRANSACT-29, INV-TRANSACT-30 |
| MergeTransact (13) | `merge.md` | INV-MERGE-01..03, INV-MERGE-17, INV-MERGE-18, INV-TRANSACT-48 | INV-MERGE-06, INV-MERGE-07, INV-MERGE-16 | INV-MERGE-02, INV-MERGE-04, INV-MERGE-05, INV-MERGE-08 | INV-MERGE-13, INV-MERGE-14, INV-MERGE-19, INV-TRANSACT-46, INV-TRANSACT-47, INV-TRANSACT-49 | INV-XC-04, INV-XC-05, INV-TRANSACT-50 | INV-MERGE-15 |
| RingDeposit (14) | `deposit.md` | INV-RING-DEPOSIT-01..04 | INV-RING-DEPOSIT-05, INV-DEPOSIT-11, INV-DEPOSIT-18..25 | INV-RING-DEPOSIT-01, INV-RING-DEPOSIT-03, INV-RING-DEPOSIT-09, INV-XC-26 | INV-RING-DEPOSIT-06..08, INV-RING-DEPOSIT-10 | INV-XC-04 | INV-DEPOSIT-17 |
| RingTransact (15) | `transact.md` | INV-RING-TRANSACT-01, INV-RING-TRANSACT-02, INV-TRANSACT-48 | INV-TRANSACT-07..12, INV-TRANSACT-31..38 | INV-RING-TRANSACT-01, INV-RING-TRANSACT-03, INV-RING-TRANSACT-07, INV-RING-TRANSACT-08, INV-XC-26 | INV-RING-TRANSACT-03..06, INV-TRANSACT-23..28 | INV-XC-04, INV-XC-05 | INV-TRANSACT-30 |
| RingMergeTransact (16) | `merge.md` | INV-RING-MERGE-01..03, INV-MERGE-18, INV-TRANSACT-48 | INV-RING-MERGE-05 | INV-RING-MERGE-01, INV-RING-MERGE-04, INV-RING-MERGE-14, INV-XC-26 | INV-RING-MERGE-09..13 | INV-XC-04, INV-XC-05 | INV-MERGE-15 |
| RingAuthorityTransact (17) | `transact.md` | INV-RING-AUTH-01, INV-RING-TRANSACT-02, INV-TRANSACT-48 | INV-TRANSACT-07..12, INV-TRANSACT-31..38 | INV-RING-AUTH-01..03, INV-XC-26 | INV-RING-AUTH-04..07, INV-TRANSACT-23..28, INV-TRANSACT-46, INV-TRANSACT-47, INV-TRANSACT-49 | INV-XC-04, INV-XC-05, INV-TRANSACT-50 | INV-TRANSACT-30 |
| CloseNullifierPdas (18) | `tree.md` | INV-CLOSE-PDA-03, INV-CLOSE-PDA-04, INV-CLOSE-PDA-05, INV-CLOSE-PDA-09 | INV-CLOSE-PDA-05 | INV-CLOSE-PDA-01 | INV-CLOSE-PDA-02, INV-CLOSE-PDA-06, INV-CLOSE-PDA-10 | INV-CLOSE-PDA-07, INV-XC-04 | INV-CLOSE-PDA-08 |
| SetTreeFees (19) | `tree.md` | INV-SET-FEES-01, INV-SET-FEES-03, INV-SET-FEES-04 | INV-SET-FEES-05, INV-SET-FEES-06 | INV-SET-FEES-02 | INV-SET-FEES-07 | INV-SET-FEES-08, INV-XC-04 | INV-SET-FEES-09 |
| ClaimTreeLamports (20) | `tree.md` | INV-CLAIM-01, INV-CLAIM-03, INV-CLAIM-04 | INV-CLAIM-05 | INV-CLAIM-02 | INV-CLAIM-06 | INV-XC-04, INV-CLAIM-07 | INV-CLAIM-07 |

Cross-cutting rows that apply to every proof-bearing instruction (Transact,
RingTransact, RingAuthorityTransact, MergeTransact, RingMergeTransact) and are not
repeated in each cell above: INV-XC-06/07 (expiry), INV-XC-08 (pause), INV-XC-09
(stale root), INV-XC-10 (double-spend), INV-XC-11..17 (proof system and
external_data_hash), INV-XC-19/20 (value binding), INV-XC-31 (TreeError
conversion), INV-XC-32 (retired wire formats fail closed). Dispatch invariants
INV-XC-01..03
apply to every row. Post-PR164, INV-XC-12 (P256 proof encoding) is not applicable.

## Summary

- Total invariants: 280
  - transact.md: 60 (Transact 45, RingTransact 8, RingAuthorityTransact 7)
  - deposit.md: 35 (Deposit 25, RingDeposit 10)
  - merge.md: 33 (MergeTransact 19, RingMergeTransact 14)
  - tree.md: 55 (CreateTree 10, BatchUpdateNullifierTree 9, PauseTree 5, nullifier PDAs INV-TRANSACT-46..50, CloseNullifierPdas 10, SetTreeFees 9, ClaimTreeLamports 7)
  - protocol-config.md: 18 (Create 10, Update 8)
  - ring-config.md: 20 (Create 9, UpdateOwner 5, Update 6)
  - spl.md: 22 (CreateAssetCounter 8, CreateSplInterface 14)
  - event.md: 4
  - cross-cutting.md: 33
- Critical (funds/double-spend/authority takeover): 101
- High: 99
- Medium: 75
- Not applicable post-PR164: 5 (the both-amounts gate (INV-TRANSACT-12) and the merge ciphertext/`merge_view_tag` entries; the P256 entries returned with PR172 and are re-scoped, not N/A; IDs retained, never renumbered)
- SPEC_DIVERGENCE items: all 8 originally flagged items were resolved by updating
  `docs/spec.md` to match the code (items 1 and 3 were re-corrected on 2026-07-28
  after an audit found the first resolution had not actually landed):
  1. Deposit/RingDeposit instruction data is a batch: `assets: Vec<DepositAssetKind>` declared in the instruction data plus `deposits: Vec<DepositEntry>`; each entry carries `amount`, `view_tag`, `UtxoData`, `memo`.
  2. Transact public amounts signed `Option<i64>`; exactly the absolute value settles (fee folded prover-side) (INV-XC-18).
  3. Merge fixed 8-in/1-out shape and a 128-byte vanilla Groth16 `a||b||c` proof (no BSB22 commitments); the merge is ciphertext-free.
  4. UTXO tree height 32.
  5. Duplicate `ring_deposit` row removed from the instruction table.
  6. `create_asset_counter` (tag 5) and `batch_update_nullifier_tree` (tag 4) added to the instruction table.
  7. UpdateProtocolConfig: one field per call plus new-authority co-signature.
  8. GeneralEvent `tx_viewing_pk`/`salt` non-optional (all-zero on proofless deposits); `OutputUtxo.view_tag` naming; `OutputDataEncoding` wrapper; `ProoflessOutput.owner` + `memo`.
- INSUFFICIENT_INFO items:
  1. RESOLVED (2026-07-28): `StateAppendFailed = 7004` fires when a UTXO-tree append hits a full tree (`tree_error` maps `TreeError::TreeIsFull` -- INV-XC-31, covered by `tree/contract.rs` `deposit_rejects_an_append_to_a_full_utxo_tree`), and `PublicSettlementFailed = 7010` fires when an SPL deposit CPI does not credit the vault exactly the leg amount (INV-TRANSACT-44). Both are reachable and now carry condition->error invariants (INV-XC-30).
  2. The shielded balance-conservation formula (sum of inputs = sum of outputs + public amount, per asset) is enforced in the Go circuits, not in the analyzed Rust source; on the Rust side only the public-input binding is testable (INV-XC-19).

## Test Coverage (last updated 2026-07-23, hardening pass)

### Backend coverage

The checklist below is the overall coverage view. `Covered by:` entries identify
the test backend. Localnet coverage does not count as LiteSVM coverage.

| Label | Meaning |
|---|---|
| LiteSVM | A passing test in `program-tests/shielded-pool/tests/` that runs through `Pool`/`ZolanaProgramTest` and asserts the invariant directly |
| Localnet | A validator/RPC/indexer test; complementary, not a LiteSVM substitute |
| Partial | The behavior is exercised, but an important postcondition, delta, rollback sweep, or backend leg is not asserted |
| Blocked | The current harness cannot exercise the invariant (for example, a real-proof SPL transact path or a second ring identity) |

Every invariant was mapped against the test suite (integration tests in
`program-tests/`, unit tests in `programs/shielded-pool` and `program-libs/`).
Ticked invariants carry a `Covered by:` line; the remaining ones carry a
`Partial coverage:` line stating what is still missing.

Tree fee-schedule sync (2026-09-02): the tree header gained a runtime
`TreeFeeSchedule` and `fee_balance`, `set_tree_fees` (tag 19) and
`protocol_config.fee_authority` were added, `batch_update_nullifier_tree` and
`close_nullifier_pdas` pay `min(owed, fee_balance)` to a non-program
`reimbursement_recipient` (7055), and the constant 20-lamport insertion fee is
gone. New entries: INV-SET-FEES-01..09, INV-CLOSE-PDA-09/-10,
INV-CREATE-TREE-10, INV-UPDATE-PC-08 (13, all covered); INV-BATCH-NULL-08,
INV-CLOSE-PDA-02/-05/-08, INV-TRANSACT-29/-30/-42/-49, INV-MERGE-15/-19,
INV-CREATE-PC-05..07, INV-UPDATE-PC-03/-05, INV-XC-03/-28/-29/-31 restated.
The counts below are updated for the 13 additions.

Post-PR172 sync (2026-07-31):

- Covered: 245 / 273
- Covered on companion security branches (#175, #176): 3 (the `- [~]` entries:
  INV-CREATE-PC-10, INV-CREATE-AC-07, INV-BATCH-NULL-07 — behavior and tests
  land with those branches)
- Partial: 19 (condition exercised, but the exact count/delta or the full-batch/localnet leg is not asserted)
- Pointer: 1 (INV-XC-30, by design: it documents reachability and defers to INV-XC-31 / INV-TRANSACT-44 for coverage; it is counted in cross-cutting's 6 partial+untested below)
- Not covered: 0

(245 + 3 + 19 + 1 + 5 = 273. The per-file partial+untested column sums to 21
because it includes the pointer.)

Per file (covered / partial+untested / companion / not-applicable):
transact 57/2/0/1, deposit 35/0/0/0, merge 23/6/0/4, tree 43/4/1/0,
protocol-config 17/0/1/0, ring-config 18/2/0/0, spl 21/0/1/0, event 4/0/0/0,
cross-cutting 27/6/0/0.

All added tests pass. Suites run green this pass:
`shielded-pool-tests` (216 hermetic) and `--features proofs` (incl. the new
`merge_functional` binary with a real on-chain merge proof), plus the
documented gates (fmt, clippy, workspace check, photon, xtask, Go prover).

### Remaining gaps

#### LiteSVM-focused follow-up

The feasible LiteSVM work is to strengthen existing focused tests with exact
postconditions, rather than duplicate the localnet flows:

- add full account/tree/nullifier rollback-frame checks for `INV-XC-04`;
- add exact tree deltas and event-field assertions wherever merge success is
  currently validator-only (`INV-MERGE-12/13/14`);
- add exhaustive public-input field tamper coverage where the current golden
  vectors cover only representative fields (`INV-XC-11`);
- keep the remaining infrastructure-dependent items explicitly marked as
  `Localnet` or `Blocked` below.

No invariant remains untested by design: INV-XC-30's formerly-"unreachable"
codes were shown reachable (7004 full-tree append, 7010 post-CPI settlement
delta) and are pinned by INV-XC-31 / INV-TRANSACT-44 with on-chain tests.

INV-MERGE-08 / INV-MERGE-09 (merge owner- and viewing-key substitution) were
closed this pass by `spp-test-validator/tests/lifecycle.rs`
`merge_rejects_a_proof_bound_to_a_foreign_user_record`: a proof bound to owner A
submitted with owner B's `user_record` fails with 7008, leaving the tree and the
fixture's spendable set unchanged.

21 invariants are PARTIAL -- their behavior is exercised end-to-end but an exact
count/delta assertion or the full-batch/localnet leg is missing. The notable ones:
INV-MERGE-12/13/14 (real localnet merges pass but do not assert the exact +8/+1
tree deltas or the event field-by-field), INV-BATCH-NULL-04/05/06 (the
tampered-proof-on-a-full-batch and success-path legs need 250 queued nullifiers via
the localnet forester), INV-XC-04 (rollback is asserted for most instructions but
not a full per-instruction account-equality sweep of all 18), and INV-XC-11
(golden vectors + tamper tests cover the public-input binding, but not an
exhaustive per-field bit-flip loop). Each PARTIAL row names precisely what is left.

## Security audit findings (2026-07)

Status of the audit findings against the current (post-PR164) tree:

- F-01 unconstrained padding-input nullifiers -> nullifier-queue brick: FIXED by
  PR164 (all-slot non-inclusion + circuit-derived nullifiers); regression tests
  `prover/server/circuits/spp_transaction/shared/nullifier_attack_test.go`
  (INV-TRANSACT-31, INV-TRANSACT-32).
- F-02 `merge_view_tag` >= p / zero / tree-resident queue poison: ELIMINATED
  (field removed; output indexed by first input nullifier -- INV-RING-MERGE-12).
- F-03 merge dummy-slot nullifier burn: FIXED by PR164 (`MergeDummyNullifier`
  derivation); regression tests
  `prover/server/circuits/spp_merge/dummy_nullifier_attack_test.go`
  (INV-MERGE-16).
- F-04 Photon indexes batch updates from instruction intent not outcome
  (permissionless indexer halt): FIXED. Photon's
  `nullifier_tree_batch_update_parser` now sources updates exclusively from the
  emitted `BatchAddressAppendEvent` (emitted only when an update actually
  applied), authenticated by stack-height parentage to a shielded-pool
  `BATCH_UPDATE_NULLIFIER_TREE` instruction -- forged tag-4 CPIs and no-op
  successes record nothing. Regression tests
  `services/photon/src/ingester/parser/nullifier_tree_batch_update_parser.rs`
  `drops_forged_batch_update_cpi_without_event`,
  `drops_successful_batch_update_without_event`,
  `drops_event_with_foreign_parent`,
  `drops_event_under_non_batch_update_parent`,
  `parses_batch_update_from_emitted_event`,
  `records_event_root_not_instruction_root` (INV-BATCH-NULL-07).
- F-05 `tx_viewing_pk`/`salt` unbound (relayer burns recipient outputs): FIXED by
  PR164 (bound in `ExternalDataHash` -- INV-XC-16).
- F-06 merge viewing-key canonicality: MOOT (the vulnerable flow is gone.
  PR164 merge outputs are ciphertext-free: `prover/server/circuits/spp_merge`
  contains no encryption or KDF over a recipient key, and the merge output is
  derived deterministically from the inputs so the owner needs no decryption.
  The surviving `verifiable-encryption` consumer
  (`sdk-tests/zk-program-swap/prover/circuits/take_verifiable_encryption/take.go`)
  derives its AES key from the order-UTXO blinding via Poseidon KDF, never from
  a recipient P-256 pubkey; `p256.CompressPubkey`/`ECDH` have no callers in the
  current tree).
- F-07 `create_protocol_config` front-runnable initializer: FIXED. The program
  now reads its own loader-v3 `ProgramData` and binds one-time initialization
  to the deploy upgrade authority
  (`programs/shielded-pool/src/instructions/protocol_config/create.rs` `check_initialization_authority`,
  INV-CREATE-PC-10); non-upgradeable deployments and an unset authority
  (localnet, LiteSVM, immutable programs) skip the check, and forged or
  truncated loader state fails closed. `xtask init-protocol` gained a
  two-step flow (create as the upgrade authority via `--upgrade-authority`,
  then rotate `protocol_authority` to the protocol vault). Regression tests
  `program-tests/shielded-pool/tests/protocol_config/contract.rs`
  `create_rejects_a_fee_payer_that_is_not_the_upgrade_authority` (red first:
  the attacker initialized successfully pre-fix),
  `create_accepts_the_upgrade_authority`,
  `create_skips_the_check_without_an_upgrade_authority`.
- F-08 ring-merge viewing-key binding: PARTIALLY addressed (output
  `ring_data_hash` now proof-bound; owner identity still omitted by design --
  INV-RING-MERGE-08, INV-RING-MERGE-12).
- F-09 `merge_view_tag` not proof-bound: MOOT (field removed).
- F-10 root-history zero-placeholder burn: FIXED by PR164. `append_batch`
  pushes only the batch-final root into the 200-slot history
  (`program-libs/tree/src/smt.rs:117-123`) and `root_by_index` rejects zero
  slots; a batch costs one history slot regardless of size. Regression test
  `program-libs/tree/tests/init.rs` `append_batch_matches_sequential` (pins the
  single-slot cursor advance and the absence of zero placeholders).
- F-11 deposit `data_hash` unverified: DESIGN-ACCEPTED. `docs/spec.md` (UTXO
  Hash) documents `data_hash` as "committed into `utxo_hash` unchecked": the
  hashing scheme is application-defined, so the program cannot recompute it,
  and the deposit event publishes both `data_hash` and `data` for consumers to
  verify. Deposit is authorized by the payer (or the ring config), so a
  mismatch is self-inflicted; the deposit path
  (`programs/shielded-pool/src/instructions/deposit/processor.rs:104-124`)
  still folds the supplied `data_hash` into the UTXO hash as specified.

Post-audit note: an attempted removal of `OutputDataEncoding::VerifiablyEncrypted`
(dead after PR164's ciphertext-free merge) was **reverted** — the variant is
reserved for upcoming auditor encryption flows (custom rings with auditor;
PR #177 review, ananas-block). The spec entry on `docs/spec-pr171-catchup`
documents it as reserved, not legacy.
