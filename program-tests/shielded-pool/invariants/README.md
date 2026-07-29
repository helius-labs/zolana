# Shielded Pool Invariants

Test-coverage checklist derived from the program source. Detailed invariants
live in the per-instruction files; `docs/spec.md` remains the protocol source
of truth.

Legend: PR164 = the circuit/protocol update, merged via PR171 (#171);
"post-PR164" below refers to that update. The P256 rail is being restored
via PR172: the P256-related N/A entries and INV-XC-32 ("retired wire formats
fail closed") must be re-activated / re-scoped when it lands.

| File | Covers |
|---|---|
| `transact.md` | Transact, ZoneTransact, ZoneAuthorityTransact |
| `deposit.md` | Deposit, ZoneDeposit |
| `merge.md` | MergeTransact, ZoneMergeTransact |
| `tree.md` | CreateTree, BatchUpdateNullifierTree, PauseTree |
| `protocol-config.md` | CreateProtocolConfig, UpdateProtocolConfig |
| `zone-config.md` | CreateZoneConfig, UpdateZoneConfig, UpdateZoneConfigOwner |
| `spl.md` | CreateAssetCounter, CreateSplInterface |
| `event.md` | EmitEvent |
| `cross-cutting.md` | dispatch, rollback, expiry/pause, double-spend, proof rails, external_data_hash, lamports/PDAs, loaders, zone authorization, events, error codes |

ID prefixes: `INV-TRANSACT`, `INV-ZONE-TRANSACT`, `INV-ZONE-AUTH`, `INV-DEPOSIT`,
`INV-ZONE-DEPOSIT`, `INV-MERGE`, `INV-ZONE-MERGE`, `INV-CREATE-TREE`,
`INV-BATCH-NULL`, `INV-PAUSE-TREE`, `INV-CREATE-PC`, `INV-UPDATE-PC`,
`INV-CREATE-ZC`, `INV-UPDATE-ZC`, `INV-UPDATE-ZC-OWNER`, `INV-CREATE-AC`,
`INV-CREATE-SPL`, `INV-EMIT-EVENT`, `INV-XC`. IDs are stable once assigned --
never renumber.

`Transact`, `ZoneTransact`, and `ZoneAuthorityTransact` share one parser and core
(`process_transact_core`), so the shared `INV-TRANSACT-*` data/settlement/tree
invariants apply to all three (noted in `transact.md`); the matrix references them
from all three rows. The same holds for `Deposit`/`ZoneDeposit`
(`process_deposit_internal`) and `MergeTransact`/`ZoneMergeTransact`
(`process_merge_core`).

## Coverage Matrix

| Instruction | File | Accounts | Data | Authz | Success | Rollback | Frame |
|---|---|---|---|---|---|---|---|
| EmitEvent (14) | `event.md` | INV-EMIT-EVENT-03 | INV-EMIT-EVENT-02 | permissionless by design (INV-EMIT-EVENT-01 bounds the risk) | INV-EMIT-EVENT-02, INV-EMIT-EVENT-04 | INV-XC-04 | INV-EMIT-EVENT-01 |
| Transact (0) | `transact.md` | INV-TRANSACT-01..04, INV-TRANSACT-13..16, INV-TRANSACT-40, INV-TRANSACT-41, INV-TRANSACT-43, INV-XC-24 | INV-TRANSACT-07..12, INV-TRANSACT-31..38, INV-XC-02 | INV-TRANSACT-04..06, INV-TRANSACT-20, INV-TRANSACT-39 | INV-TRANSACT-23..28, INV-TRANSACT-42, INV-TRANSACT-44, INV-XC-18, INV-XC-27 | INV-XC-04, INV-XC-05 | INV-TRANSACT-29, INV-TRANSACT-30 |
| ZoneTransact (2) | `transact.md` | INV-ZONE-TRANSACT-01, INV-ZONE-TRANSACT-02 | INV-TRANSACT-07..12, INV-TRANSACT-31..38 | INV-ZONE-TRANSACT-01, INV-ZONE-TRANSACT-03, INV-ZONE-TRANSACT-07, INV-XC-26 | INV-ZONE-TRANSACT-03..06, INV-TRANSACT-23..28 | INV-XC-04, INV-XC-05 | INV-TRANSACT-30 |
| ZoneAuthorityTransact (3) | `transact.md` | INV-ZONE-AUTH-01, INV-ZONE-TRANSACT-02 | INV-TRANSACT-07..12, INV-TRANSACT-31..38 | INV-ZONE-AUTH-01..03, INV-XC-26 | INV-ZONE-AUTH-04..07, INV-TRANSACT-23..28 | INV-XC-04, INV-XC-05 | INV-TRANSACT-30 |
| CreateTree (5) | `tree.md` | INV-CREATE-TREE-03, INV-CREATE-TREE-04 | INV-CREATE-TREE-05, INV-CREATE-TREE-06 | INV-CREATE-TREE-01, INV-CREATE-TREE-02 | INV-CREATE-TREE-07, INV-CREATE-TREE-08 | INV-XC-04 | INV-CREATE-TREE-09 |
| BatchUpdateNullifierTree (51) | `tree.md` | INV-XC-24, INV-XC-08 | INV-BATCH-NULL-03 | INV-BATCH-NULL-01, INV-BATCH-NULL-02 | INV-BATCH-NULL-05, INV-BATCH-NULL-08 | INV-BATCH-NULL-04, INV-XC-04 | INV-BATCH-NULL-06, INV-BATCH-NULL-09 |
| Deposit (1) | `deposit.md` | INV-DEPOSIT-01..09, INV-DEPOSIT-20, INV-DEPOSIT-23, INV-DEPOSIT-24 | INV-DEPOSIT-10, INV-DEPOSIT-11, INV-DEPOSIT-18, INV-DEPOSIT-19, INV-DEPOSIT-21, INV-DEPOSIT-22 | INV-DEPOSIT-01, INV-DEPOSIT-03, INV-DEPOSIT-05 | INV-DEPOSIT-12..16, INV-DEPOSIT-25 | INV-XC-04 | INV-DEPOSIT-17 |
| ZoneDeposit (15) | `deposit.md` | INV-ZONE-DEPOSIT-01..04 | INV-ZONE-DEPOSIT-05, INV-DEPOSIT-11, INV-DEPOSIT-18..25 | INV-ZONE-DEPOSIT-01, INV-ZONE-DEPOSIT-03, INV-XC-26 | INV-ZONE-DEPOSIT-06..09 | INV-XC-04 | INV-DEPOSIT-17 |
| CreateAssetCounter (16) | `spl.md` | INV-CREATE-AC-03, INV-CREATE-AC-04 | INV-CREATE-AC-05 | INV-CREATE-AC-01, INV-CREATE-AC-02 | INV-CREATE-AC-06, INV-CREATE-AC-07 | INV-XC-04 | INV-CREATE-AC-08 |
| CreateSplInterface (4) | `spl.md` | INV-CREATE-SPL-03..05, INV-CREATE-SPL-08, INV-CREATE-SPL-13, INV-CREATE-SPL-14 | INV-CREATE-SPL-06 | INV-CREATE-SPL-01, INV-CREATE-SPL-02 | INV-CREATE-SPL-07, INV-CREATE-SPL-09..11 | INV-XC-04 | INV-CREATE-SPL-12 |
| CreateProtocolConfig (6) | `protocol-config.md` | INV-CREATE-PC-03, INV-CREATE-PC-04 | INV-CREATE-PC-05 | INV-CREATE-PC-01, INV-CREATE-PC-02, INV-CREATE-PC-10 | INV-CREATE-PC-06..08 | INV-XC-04 | INV-CREATE-PC-09 |
| UpdateProtocolConfig (7) | `protocol-config.md` | INV-UPDATE-PC-03 | INV-UPDATE-PC-04 | INV-UPDATE-PC-01, INV-UPDATE-PC-02 | INV-UPDATE-PC-05, INV-UPDATE-PC-07 | INV-XC-04 | INV-UPDATE-PC-06 |
| PauseTree (8) | `tree.md` | INV-XC-24 | INV-PAUSE-TREE-02 | INV-PAUSE-TREE-01 | INV-PAUSE-TREE-03, INV-PAUSE-TREE-04 | INV-XC-04 | INV-PAUSE-TREE-05 |
| CreateZoneConfig (9) | `zone-config.md` | INV-CREATE-ZC-04, INV-CREATE-ZC-05 | INV-CREATE-ZC-06 | INV-CREATE-ZC-01..03 | INV-CREATE-ZC-07, INV-CREATE-ZC-08 | INV-XC-04 | INV-CREATE-ZC-09 |
| UpdateZoneConfigOwner (10) | `zone-config.md` | INV-UPDATE-ZC-02 | INV-UPDATE-ZC-OWNER-05 | INV-UPDATE-ZC-OWNER-01, INV-UPDATE-ZC-OWNER-02 | INV-UPDATE-ZC-OWNER-03 | INV-XC-04 | INV-UPDATE-ZC-OWNER-04 |
| UpdateZoneConfig (11) | `zone-config.md` | INV-UPDATE-ZC-02 | INV-UPDATE-ZC-06 | INV-UPDATE-ZC-01 | INV-UPDATE-ZC-03, INV-UPDATE-ZC-05 | INV-XC-04 | INV-UPDATE-ZC-04 |
| MergeTransact (12) | `merge.md` | INV-MERGE-01..03, INV-MERGE-17, INV-MERGE-18 | INV-MERGE-06, INV-MERGE-07, INV-MERGE-16 | INV-MERGE-02, INV-MERGE-04, INV-MERGE-05, INV-MERGE-08 | INV-MERGE-13, INV-MERGE-14, INV-MERGE-19 | INV-XC-04, INV-XC-05 | INV-MERGE-15 |
| ZoneMergeTransact (13) | `merge.md` | INV-ZONE-MERGE-01..03, INV-MERGE-18 | INV-ZONE-MERGE-05 | INV-ZONE-MERGE-01, INV-ZONE-MERGE-04, INV-XC-26 | INV-ZONE-MERGE-09..13 | INV-XC-04, INV-XC-05 | INV-MERGE-15 |

Cross-cutting rows that apply to every proof-bearing instruction (Transact,
ZoneTransact, ZoneAuthorityTransact, MergeTransact, ZoneMergeTransact) and are not
repeated in each cell above: INV-XC-06/07 (expiry), INV-XC-08 (pause), INV-XC-09
(stale root), INV-XC-10 (double-spend), INV-XC-11..17 (proof system and
external_data_hash), INV-XC-19/20 (value binding), INV-XC-31 (TreeError
conversion), INV-XC-32 (retired wire formats fail closed). Dispatch invariants
INV-XC-01..03
apply to every row. Post-PR164, INV-XC-12 (P256 proof encoding) is not applicable.

## Summary

- Total invariants: 242
  - transact.md: 58 (Transact 44, ZoneTransact 7, ZoneAuthorityTransact 7)
  - deposit.md: 34 (Deposit 25, ZoneDeposit 9)
  - merge.md: 32 (MergeTransact 19, ZoneMergeTransact 13)
  - tree.md: 23 (CreateTree 9, BatchUpdateNullifierTree 9, PauseTree 5)
  - protocol-config.md: 17 (Create 10, Update 7)
  - zone-config.md: 20 (Create 9, UpdateOwner 5, Update 6)
  - spl.md: 22 (CreateAssetCounter 8, CreateSplInterface 14)
  - event.md: 4
  - cross-cutting.md: 32
- Critical (funds/double-spend/authority takeover): 85
- High: 80
- Medium: 65
- Not applicable post-PR164: 12 (P256 rails and the `P256SigningKey` owner tag, both-amounts gate, `cpi_authority` field, merge ciphertext/`merge_view_tag`; IDs retained, never renumbered)
- SPEC_DIVERGENCE items: all 8 originally flagged items were resolved by updating
  `docs/spec.md` to match the code (items 1 and 3 were re-corrected on 2026-07-28
  after an audit found the first resolution had not actually landed):
  1. Deposit/ZoneDeposit instruction data is a batch: `assets: Vec<DepositAssetKind>` declared in the instruction data plus `deposits: Vec<DepositEntry>`; each entry carries `amount`, `view_tag`, `UtxoData`, `memo`.
  2. Transact public amounts signed `Option<i64>`; exactly the absolute value settles (fee folded prover-side) (INV-XC-18).
  3. Merge fixed 8-in/1-out shape and a 128-byte vanilla Groth16 `a||b||c` proof (no BSB22 commitments); the merge is ciphertext-free.
  4. UTXO tree height 32.
  5. Duplicate `zone_deposit` "Tag 1" row removed from the instruction table.
  6. `create_asset_counter` (tag 16) and `batch_update_nullifier_tree` (tag 51) added to the instruction table.
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
| Blocked | The current harness cannot exercise the invariant (for example, a real-proof SPL transact path or a second zone identity) |

Every invariant was mapped against the test suite (integration tests in
`program-tests/`, unit tests in `programs/shielded-pool` and `program-libs/`).
Ticked invariants carry a `Covered by:` line; the remaining ones carry a
`Partial coverage:` line stating what is still missing.

Post-PR171 sync (2026-07-28):

- Covered: 204 / 242
- Partial: 25 (condition exercised, but the exact count/delta or the full-batch/localnet leg is not asserted)
- Pointer: 1 (INV-XC-30, by design: it documents reachability and defers to INV-XC-31 / INV-TRANSACT-44 for coverage; it is counted in cross-cutting's 9 partial+untested below)
- Not covered: 0
- Not applicable post-PR164: 12

(204 + 25 + 1 + 12 = 242. The per-file partial+untested column sums to 26
because it includes the pointer.)

Per file (covered / partial+untested / not-applicable):
transact 48/3/7, deposit 33/1/0, merge 22/6/4, tree 19/4/0,
protocol-config 17/0/0, zone-config 18/2/0, spl 21/1/0, event 4/0/0,
cross-cutting 22/9/1.

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

25 invariants are PARTIAL -- their behavior is exercised end-to-end but an exact
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
  (field removed; output indexed by first input nullifier -- INV-ZONE-MERGE-12).
- F-03 merge dummy-slot nullifier burn: FIXED by PR164 (`MergeDummyNullifier`
  derivation); regression tests
  `prover/server/circuits/spp_merge/dummy_nullifier_attack_test.go`
  (INV-MERGE-16).
- F-04 Photon indexes batch updates from instruction intent not outcome
  (permissionless indexer halt): FIXED. Photon's
  `nullifier_tree_batch_update_parser` now sources updates exclusively from the
  emitted `BatchAddressAppendEvent` (emitted only when an update actually
  applied), authenticated by stack-height parentage to a shielded-pool
  `BATCH_UPDATE_NULLIFIER_TREE` instruction -- forged tag-51 CPIs and no-op
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
- F-08 zone-merge viewing-key binding: PARTIALLY addressed (output
  `zone_data_hash` now proof-bound; owner identity still omitted by design --
  INV-ZONE-MERGE-08, INV-ZONE-MERGE-12).
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
  verify. Deposit is authorized by the payer (or the zone config), so a
  mismatch is self-inflicted; the deposit path
  (`programs/shielded-pool/src/instructions/deposit/processor.rs:104-124`)
  still folds the supplied `data_hash` into the UTXO hash as specified.
