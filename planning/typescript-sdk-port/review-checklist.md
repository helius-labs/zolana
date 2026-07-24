# TypeScript SDK parity review checklist

Use this checklist to drive the production TypeScript SDK review. The end state
requires an independently supported `PARITY` verdict or a justified
`NOT_APPLICABLE` disposition for each of the 118 production Rust source
responsibilities below. Package and cross-package completion gates must also
pass. Completed rows alone do not support a full SDK parity claim.

`review-2026-07-24.md` is a frozen audit. Do not update it from this checklist.
Tests, manifests, generated verifying keys, fixtures, reports, and
`@zolana/test-kit` supply evidence or annex material. They are not primary
review iterations.

## Mutable baseline

Update this block at the start of each session.

- Branch: `ts-sdk-port`
- Review HEAD: `c01d5c7c1d6169140025233a610c4423633ad3f9`
- Fixture `frozenCommit`: `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`
- Canonical Rust drift since freeze: none in the nine scoped source trees
- Primary rows: `118`
- Progress: `3 done / 118 total`; `0 needs_re_review`; `0 in_progress`
- Exact next eligible row: `I01 program-libs/interface/src/error.rs`
- Active fixes: none
- Last session: `2026-07-24`

Refresh the HEAD, fixture commit, drift result, progress, active fixes, and exact
next row after each wake. Treat dirty evidence as uncommitted. Record the commit
that makes it available before re-review.

## Vocabulary

Assign one verdict after each review:

- `PARITY`: current public behavior has adequate independent evidence.
- `PARTIAL`: the main behavior exists, but a case, rail, runtime, or test class is missing.
- `MISSING`: required behavior has no TypeScript implementation.
- `DIVERGENT`: TypeScript conflicts with the spec or current Rust.
- `STALE`: evidence supports an older Rust revision.
- `NOT_APPLICABLE`: omission is valid and the row records the evidence.
- `BLOCKED`: available evidence cannot determine parity.

Use only these row statuses:

- `todo`: no current-Rust review has finished.
- `in_progress`: one named review or fix worker owns the row.
- `needs_fix`: an adverse verdict has a concrete smallest fix.
- `needs_re_review`: a fix or evidence commit exists and needs independent review.
- `done`: independent review supports `PARITY`, or accepts a justified `NOT_APPLICABLE`.

Use `none`, `proposed`, `authorized`, `in_flight`, or `committed` in the Fix
column. A `PARITY` verdict counts toward completion only when Status is `done`.

## One-file review workflow

Process one canonical Rust file per iteration.

1. Read `docs-humanizer`, `zolana-comments`, `code-simplifier`, and `review-ts`,
   including the required references. Read `CLAUDE.md`.
2. Refresh the mutable baseline. Check current HEAD, fixture `frozenCommit`,
   Rust drift, dirty paths, and commits for active fixes.
3. Select one eligible row with the deterministic rule below. Claim it by
   setting Status to `in_progress`.
4. Explain the Rust file's purpose, imports and dependencies, public exports,
   basic flows, key or capability separations, and governing Rust and
   TypeScript tests.
5. Follow Rust re-exports and the TypeScript package entry points. Audit public
   API and behavior. Apply the byte, numeric, error, key, privacy, environment,
   fixture, test, and drift checks from `review-ts`.
6. Assign exactly one verdict. Passing tests alone cannot establish `PARITY`.
7. For a non-`PARITY` verdict, name the exact path and symbol, the observed
   difference or missing evidence, and the smallest fix. A `NOT_APPLICABLE`
   verdict needs a concrete language, platform, visibility, or generated-code
   reason with evidence.
8. Update only the selected row, the mutable baseline, gates affected by
   evidence, and the append-only session log. Name the exact next file.

Review workers are read-only except for this checklist. Each review must be
independent of the implementation worker whose commit it evaluates.

## Fix and re-review workflow

Do not implement a finding unless the user authorizes fixes.

1. Start an authorized fix in a separate background agent. Another reviewer may
   continue on a row whose Rust and TypeScript paths do not overlap.
2. Require the fix agent to read `docs-humanizer`, `zolana-comments`,
   `code-simplifier`, `review-ts`, and `CLAUDE.md`.
3. Give the agent explicit, non-overlapping file ownership. It must preserve
   unrelated work and inspect the worktree before editing.
4. Require focused checks and the relevant package checks. Record commands and
   results in the row or session log.
5. Require a small selective checkpoint commit. Stage exact paths only. Do not
   amend, bypass hooks or signing, stage broad paths, or push.
6. After a successful fix commit, set Fix to `committed`, record the hash, and
   set Status to `needs_re_review`. Keep the adverse verdict until independent
   re-review replaces it.
7. Only an independent review may set Status to `done` and Verdict to `PARITY`.

If signing or hooks fail, leave the fix uncommitted, preserve its files, and
record the blocker. An active uncommitted fix remains `in_progress`.

## Deterministic selection

At each wake:

1. Refresh rows marked `in_progress`. If an authorized fix now has a commit,
   change it to `needs_re_review`. Skip rows still owned by an active worker.
2. Select the lowest queue ID marked `needs_re_review`.
3. If none exists, select the lowest queue ID marked `todo`.
4. If neither exists, evaluate package gates in package order, then full SDK
   gates in listed order. Reopen the lowest responsible row when a gate fails.
5. Stop only when each row is `done`, each package gate passes, and each full
   SDK gate passes.

Queue IDs encode dependency order:
interface, keypair, merkle-tree, indexer-api, smart-account-client, API,
transaction, client, wallet. Module and package export roots come last within
their dependency group. This rule produces one next row without agent choice.

## Primary queue

Columns:

- TS owner names the main TypeScript implementation. Follow consolidated
  responsibilities and re-exports during review.
- Gap / fix holds the concrete finding or re-review reason.
- Review and Fix commit record evidence revisions. Use `-` when absent.

### Interface, 37 rows

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| I01 | `program-libs/interface/src/error.rs` | `interface/src/errors.ts` | todo | - | none | - | - | - |
| I02 | `program-libs/interface/src/shape.rs` | `interface/src/internal.ts` | todo | - | none | - | - | - |
| I03 | `program-libs/interface/src/merge_utils.rs` | `interface/src/internal.ts` | todo | - | none | - | - | - |
| I04 | `program-libs/interface/src/pda.rs` | `interface/src/pda/index.ts` | todo | - | none | - | - | - |
| I05 | `program-libs/interface/src/instruction/instruction_data/batch_update_nullifier_tree.rs` | `interface/src/codecs/index.ts` | todo | - | none | - | - | - |
| I06 | `program-libs/interface/src/instruction/instruction_data/create_tree.rs` | `interface/src/codecs/index.ts` | todo | - | none | - | - | - |
| I07 | `program-libs/interface/src/instruction/instruction_data/deposit.rs` | `interface/src/codecs/index.ts` | todo | - | none | - | - | - |
| I08 | `program-libs/interface/src/instruction/instruction_data/merge_transact.rs` | `interface/src/codecs/index.ts` | todo | - | none | - | - | - |
| I09 | `program-libs/interface/src/instruction/instruction_data/merge_zone.rs` | `interface/src/codecs/index.ts` | todo | - | none | - | - | - |
| I10 | `program-libs/interface/src/instruction/instruction_data/protocol_config.rs` | `interface/src/codecs/index.ts` | todo | - | none | - | - | - |
| I11 | `program-libs/interface/src/instruction/instruction_data/transact.rs` | `interface/src/codecs/index.ts` | todo | - | none | - | - | - |
| I12 | `program-libs/interface/src/instruction/instruction_data/zone_config.rs` | `interface/src/codecs/index.ts` | todo | - | none | - | - | - |
| I13 | `program-libs/interface/src/instruction/instruction_data/mod.rs` | `interface/src/codecs/index.ts` | todo | - | none | - | - | - |
| I14 | `program-libs/interface/src/instruction/builders/batch_update_nullifier_tree.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I15 | `program-libs/interface/src/instruction/builders/create_asset_counter.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I16 | `program-libs/interface/src/instruction/builders/create_associated_token_account.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I17 | `program-libs/interface/src/instruction/builders/create_spl_interface.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I18 | `program-libs/interface/src/instruction/builders/create_tree.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I19 | `program-libs/interface/src/instruction/builders/deposit.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I20 | `program-libs/interface/src/instruction/builders/merge_transact.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I21 | `program-libs/interface/src/instruction/builders/merge_zone.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I22 | `program-libs/interface/src/instruction/builders/protocol_config/mod.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I23 | `program-libs/interface/src/instruction/builders/transact.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I24 | `program-libs/interface/src/instruction/builders/zone_authority_transact.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I25 | `program-libs/interface/src/instruction/builders/zone_config/mod.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I26 | `program-libs/interface/src/instruction/builders/zone_deposit.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I27 | `program-libs/interface/src/instruction/builders/zone_transact.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I28 | `program-libs/interface/src/instruction/builders/mod.rs` | `interface/src/instructions/index.ts` | todo | - | none | - | - | - |
| I29 | `program-libs/interface/src/instruction/mod.rs` | `interface/src/index.ts` | todo | - | none | - | - | - |
| I30 | `program-libs/interface/src/state/discriminator.rs` | `interface/src/internal.ts` | todo | - | none | - | - | - |
| I31 | `program-libs/interface/src/state/protocol_config.rs` | `interface/src/codecs/index.ts` | todo | - | none | - | - | - |
| I32 | `program-libs/interface/src/state/spl_asset_counter.rs` | `interface/src/codecs/index.ts` | todo | - | none | - | - | - |
| I33 | `program-libs/interface/src/state/spl_asset_registry.rs` | `interface/src/codecs/index.ts` | todo | - | none | - | - | - |
| I34 | `program-libs/interface/src/state/tree.rs` | `interface/src/index.ts` | todo | - | none | - | - | - |
| I35 | `program-libs/interface/src/state/zone_config.rs` | `interface/src/codecs/index.ts` | todo | - | none | - | - | - |
| I36 | `program-libs/interface/src/state/mod.rs` | `interface/src/index.ts` | todo | - | none | - | - | - |
| I37 | `program-libs/interface/src/lib.rs` | `interface/src/index.ts` | todo | - | none | - | - | - |

### Keypair, 14 rows

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| K01 | `sdk-libs/keypair/src/constants.rs` | `keypair/src/constants.ts` | todo | - | none | - | - | - |
| K02 | `sdk-libs/keypair/src/signing_key.rs` | `keypair/src/signing-key.ts` | todo | - | none | - | - | - |
| K03 | `sdk-libs/keypair/src/nullifier_key.rs` | `keypair/src/nullifier-key.ts` | todo | - | none | - | - | - |
| K04 | `sdk-libs/keypair/src/viewing_key.rs` | `keypair/src/viewing-key.ts` | todo | - | none | - | - | - |
| K05 | `sdk-libs/keypair/src/pubkey.rs` | `keypair/src/public-key.ts` | todo | - | none | - | - | - |
| K06 | `sdk-libs/keypair/src/shielded.rs` | `keypair/src/shielded.ts` | todo | - | none | - | - | - |
| K07 | `sdk-libs/keypair/src/hash.rs` | `keypair/src/hash.ts`, `hash/index.ts` | todo | - | none | - | - | - |
| K08 | `sdk-libs/keypair/src/encryption.rs` | `keypair/src/encryption.ts` | todo | - | none | - | - | - |
| K09 | `sdk-libs/keypair/src/merge.rs` | `keypair/src/merge/` | todo | - | none | - | - | - |
| K10 | `sdk-libs/keypair/src/error.rs` | `keypair/src/error.ts` | todo | - | none | - | - | - |
| K11 | `sdk-libs/keypair/src/traits/view_key.rs` | `keypair/src/viewing-key.ts` | todo | - | none | - | - | - |
| K12 | `sdk-libs/keypair/src/traits/shielded_keypair.rs` | `keypair/src/shielded.ts` | todo | - | none | - | - | - |
| K13 | `sdk-libs/keypair/src/traits/mod.rs` | `keypair/src/index.ts` | todo | - | none | - | - | - |
| K14 | `sdk-libs/keypair/src/lib.rs` | `keypair/src/index.ts` | todo | - | none | - | - | - |

### Merkle tree, 2 rows

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M01 | `sdk-libs/merkle-tree/src/indexed.rs` | `merkle-tree/src/indexed.ts` | todo | - | none | - | - | - |
| M02 | `sdk-libs/merkle-tree/src/lib.rs` | `merkle-tree/src/merkle-tree.ts`, `index.ts` | todo | - | none | - | - | - |

### Indexer API, 1 row

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| X01 | `sdk-libs/indexer-api/src/lib.rs` | `indexer-api/src/` | todo | - | none | - | - | - |

### Smart-account client, 1 row

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S01 | `sdk-libs/smart-account-client/src/lib.rs` | `smart-account-client/src/` | todo | - | none | - | - | - |

### API, 1 row

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A01 | `sdk-libs/zolana-api/src/lib.rs` | `api/src/index.ts` | done | PARITY | committed | The committed Rust transport oracle covers the five methods, both nullifier start-sequence paths, request bytes, decoded responses, limits, and shared errors. | 2026-07-24 re-review | `f5d698d9` |

### Transaction, 31 rows

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T01 | `sdk-libs/transaction/src/error.rs` | `transaction/src/error.ts` | todo | - | none | - | - | - |
| T02 | `sdk-libs/transaction/src/data.rs` | `transaction/src/data.ts` | todo | - | none | - | - | - |
| T03 | `sdk-libs/transaction/src/serialization/scheme.rs` | `transaction/src/serialization/codecs.ts` | todo | - | none | - | - | - |
| T04 | `sdk-libs/transaction/src/serialization/plaintext.rs` | `transaction/src/serialization/codecs.ts` | todo | - | none | - | - | - |
| T05 | `sdk-libs/transaction/src/serialization/confidential.rs` | `transaction/src/serialization/codecs.ts` | todo | - | none | - | - | - |
| T06 | `sdk-libs/transaction/src/serialization/anonymous.rs` | `transaction/src/serialization/codecs.ts` | todo | - | none | - | - | - |
| T07 | `sdk-libs/transaction/src/serialization/proofless.rs` | `transaction/src/serialization/codecs.ts` | todo | - | none | - | - | - |
| T08 | `sdk-libs/transaction/src/serialization/split.rs` | `transaction/src/serialization/codecs.ts` | todo | - | none | - | - | - |
| T09 | `sdk-libs/transaction/src/serialization/merge.rs` | `transaction/src/serialization/codecs.ts` | todo | - | none | - | - | - |
| T10 | `sdk-libs/transaction/src/serialization/mod.rs` | `transaction/src/serialization/index.ts` | todo | - | none | - | - | - |
| T11 | `sdk-libs/transaction/src/utxo.rs` | `transaction/src/utxo.ts` | todo | - | none | - | - | - |
| T12 | `sdk-libs/transaction/src/wallet/asset.rs` | `transaction/src/wallet/asset.ts` | todo | - | none | - | - | - |
| T13 | `sdk-libs/transaction/src/wallet/authority.rs` | `transaction/src/wallet/authority.ts` | todo | - | none | - | - | - |
| T14 | `sdk-libs/transaction/src/wallet/state.rs` | `transaction/src/wallet/state.ts` | todo | - | none | - | - | - |
| T15 | `sdk-libs/transaction/src/wallet/sync.rs` | `transaction/src/wallet/sync.ts` | todo | - | none | - | - | - |
| T16 | `sdk-libs/transaction/src/wallet/parallel.rs` | `transaction/src/wallet/sync.ts` | todo | - | none | - | - | - |
| T17 | `sdk-libs/transaction/src/wallet/mod.rs` | `transaction/src/wallet/index.ts` | todo | - | none | - | - | - |
| T18 | `sdk-libs/transaction/src/instructions/types.rs` | `transaction/src/instructions/index.ts`, `utxo.ts` | todo | - | none | - | - | - |
| T19 | `sdk-libs/transaction/src/instructions/transact/types.rs` | `transaction/src/instructions/transact.ts` | todo | - | none | - | - | - |
| T20 | `sdk-libs/transaction/src/instructions/transact/shape.rs` | `transaction/src/transact/index.ts` | todo | - | none | - | - | - |
| T21 | `sdk-libs/transaction/src/instructions/transact/external_data.rs` | `transaction/src/instructions/transact.ts` | todo | - | none | - | - | - |
| T22 | `sdk-libs/transaction/src/instructions/transact/slots.rs` | `transaction/src/instructions/transact.ts` | todo | - | none | - | - | - |
| T23 | `sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs` | `transaction/src/instructions/transact.ts` | todo | - | none | - | - | - |
| T24 | `sdk-libs/transaction/src/instructions/transact/split.rs` | `transaction/src/instructions/builders.ts` | todo | - | none | - | - | - |
| T25 | `sdk-libs/transaction/src/instructions/transact/transfer.rs` | `transaction/src/instructions/transact.ts` | todo | - | none | - | - | - |
| T26 | `sdk-libs/transaction/src/instructions/transact/mod.rs` | `transaction/src/transact/index.ts` | todo | - | none | - | - | - |
| T27 | `sdk-libs/transaction/src/instructions/merge.rs` | `transaction/src/instructions/builders.ts` | todo | - | none | - | - | - |
| T28 | `sdk-libs/transaction/src/instructions/merge_zone.rs` | `transaction/src/instructions/builders.ts` | todo | - | none | - | - | - |
| T29 | `sdk-libs/transaction/src/instructions/zone_authority.rs` | `transaction/src/instructions/builders.ts` | todo | - | none | - | - | - |
| T30 | `sdk-libs/transaction/src/instructions/mod.rs` | `transaction/src/instructions/index.ts` | todo | - | none | - | - | - |
| T31 | `sdk-libs/transaction/src/lib.rs` | `transaction/src/index.ts` | todo | - | none | - | - | - |

### Client, 22 rows

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| C01 | `sdk-libs/client/src/retry.rs` | `client/src/indexer.ts` | todo | - | none | - | - | - |
| C02 | `sdk-libs/client/src/error.rs` | `client/src/error.ts` | done | PARITY | committed | The closed TypeScript contract covers the 58 Rust variants, typed details, wrapped categories, throw translation, immutable diagnostics, sanitized causes, and package exports. | 2026-07-24 re-review | `7cb3acda` |
| C03 | `sdk-libs/client/src/rpc.rs` | `client/src/rpc.ts` | todo | - | none | - | - | - |
| C04 | `sdk-libs/client/src/indexer.rs` | `client/src/indexer.ts` | done | PARITY | committed | The asynchronous adapter preserves the four requests, owned conversions, block-time polling, bounded failures, browser operation, and Rust-only blocking disposition. | 2026-07-24 re-review | `7cb3acda` |
| C05 | `sdk-libs/client/src/solana_rpc.rs` | `client/src/solana-rpc.ts` | todo | - | none | - | - | - |
| C06 | `sdk-libs/client/src/prover/field.rs` | `client/src/internal.ts` | todo | - | none | - | - | - |
| C07 | `sdk-libs/client/src/prover/inputs.rs` | `client/src/prover/types.ts` | todo | - | none | - | - | - |
| C08 | `sdk-libs/client/src/prover/proof.rs` | `client/src/prover/proof.ts` | todo | - | none | - | - | - |
| C09 | `sdk-libs/client/src/prover/json.rs` | `client/src/prover/client.ts`, `merge.ts` | todo | - | none | - | - | - |
| C10 | `sdk-libs/client/src/prover/transact/witness.rs` | `client/src/prover/assembly.ts` | todo | - | none | - | - | - |
| C11 | `sdk-libs/client/src/prover/transact/eddsa.rs` | `client/src/prover/assembly.ts` | todo | - | none | - | - | - |
| C12 | `sdk-libs/client/src/prover/transact/p256_and_eddsa.rs` | `client/src/prover/assembly.ts` | todo | - | none | - | - | - |
| C13 | `sdk-libs/client/src/prover/transact/zone_eddsa.rs` | `client/src/prover/assembly.ts` | todo | - | none | - | - | - |
| C14 | `sdk-libs/client/src/prover/transact/zone_p256.rs` | `client/src/prover/assembly.ts` | todo | - | none | - | - | - |
| C15 | `sdk-libs/client/src/prover/transact/mod.rs` | `client/src/prover/index.ts` | todo | - | none | - | - | - |
| C16 | `sdk-libs/client/src/prover/merge.rs` | `client/src/prover/merge.ts` | todo | - | none | - | - | - |
| C17 | `sdk-libs/client/src/prover/merge_zone.rs` | `client/src/prover/merge.ts` | todo | - | none | - | - | - |
| C18 | `sdk-libs/client/src/prover/zone_authority.rs` | `client/src/prover/assembly.ts` | todo | - | none | - | - | - |
| C19 | `sdk-libs/client/src/prover/client.rs` | `client/src/prover/client.ts` | todo | - | none | - | - | - |
| C20 | `sdk-libs/client/src/prover/mod.rs` | `client/src/prover/index.ts` | todo | - | none | - | - | - |
| C21 | `sdk-libs/client/src/client.rs` | `client/src/client.ts` | todo | - | none | - | - | - |
| C22 | `sdk-libs/client/src/lib.rs` | `client/src/index.ts` | todo | - | none | - | - | - |

### Wallet, 9 rows

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| W01 | `sdk-libs/wallet/src/actions/create_associated_token_account.rs` | `wallet/src/actions.ts` | todo | - | none | - | - | - |
| W02 | `sdk-libs/wallet/src/actions/deposit.rs` | `wallet/src/deposit.ts` | todo | - | none | - | - | - |
| W03 | `sdk-libs/wallet/src/actions/submit.rs` | `wallet/src/submit.ts` | todo | - | none | - | - | - |
| W04 | `sdk-libs/wallet/src/actions/transaction.rs` | `wallet/src/private-transaction.ts`, `actions.ts` | todo | - | none | - | - | - |
| W05 | `sdk-libs/wallet/src/actions/mod.rs` | `wallet/src/actions/index.ts` | todo | - | none | - | - | - |
| W06 | `sdk-libs/wallet/src/wallet_authority.rs` | `wallet/src/wallet-authority.ts` | todo | - | none | - | - | - |
| W07 | `sdk-libs/wallet/src/user_registry.rs` | `wallet/src/registry.ts` | todo | - | none | - | - | - |
| W08 | `sdk-libs/wallet/src/wallet_sync.rs` | `wallet/src/sync.ts` | todo | - | none | - | - | - |
| W09 | `sdk-libs/wallet/src/lib.rs` | `wallet/src/index.ts` | todo | - | none | - | - | - |

## Scope reconciliation

| Package pair | Primary rows |
| --- | ---: |
| `program-libs/interface` to `@zolana/interface` | 37 |
| `sdk-libs/keypair` to `@zolana/keypair` | 14 |
| `sdk-libs/merkle-tree` to `@zolana/merkle-tree` | 2 |
| `sdk-libs/indexer-api` to `@zolana/indexer-api` | 1 |
| `sdk-libs/smart-account-client` to `@zolana/smart-account-client` | 1 |
| `sdk-libs/zolana-api` to `@zolana/api` | 1 |
| `sdk-libs/transaction` to `@zolana/transaction` | 31 |
| `sdk-libs/client` to `@zolana/client` | 22 |
| `sdk-libs/wallet` to `@zolana/wallet` | 9 |
| Total | 118 |

Annex evidence includes 47 files under
`program-libs/interface/src/verifying_keys/`, Rust and TypeScript tests,
manifests, fixtures, inventory and packet reports, full-stack checks, and
`@zolana/test-kit`. Review generated verifying-key provenance and rail coverage
through the relevant interface, transaction, client, and full SDK gates.

## Package completion gates

Apply these gates to each package. Record evidence beside a gate or in the
session log.

- [ ] Each package row is `done` with `PARITY` or justified `NOT_APPLICABLE`.
- [ ] The complete public Rust export set has a TypeScript disposition.
- [ ] Each TypeScript export traces to Rust or a documented, behavior-preserving adaptation.
- [ ] Inventory claims have evidence independent of the inventory.
- [ ] Fixture provenance is fresh for the reviewed Rust revision, and current Rust drift is reviewed.
- [ ] Deterministic instruction, proof-input, hash, key, ciphertext, and serialization bytes match current Rust where applicable.
- [ ] Non-deterministic behavior has invariant or property coverage.
- [ ] Rust rejection, malformed-input, and tamper behavior has TypeScript coverage.
- [ ] Errors preserve stable codes and structured details at the same boundary.
- [ ] Browser-safe entry points contain no Node-only imports, and Node-only behavior stays in documented entry points.
- [ ] Feature-gated behavior and each supported proof rail have a disposition.
- [ ] Relevant focused, package, browser, vector, property, export, dependency, and pack checks pass.
- [ ] No package row has `PARTIAL`, `MISSING`, `DIVERGENT`, `STALE`, or `BLOCKED`.

## Full SDK completion gates

A full SDK parity claim requires the gate set below. Per-file completion is one
input to this decision.

- [ ] Each of the nine packages passes its package gates.
- [ ] Cross-package public types, errors, dependencies, and capability boundaries match current Rust.
- [ ] Deposit, private transfer, withdraw, split, merge, registration, sync, and submission flows have current-Rust coverage without behavior-hiding stubs.
- [ ] Instruction bytes execute against same-revision Solana programs.
- [ ] Proof inputs work with the same-revision prover for each supported shape and rail.
- [ ] Indexer requests and responses match the same-revision live Photon contract.
- [ ] EdDSA and P256 rails cover the complete supported shape set.
- [ ] Zone transfer, zone authority, and merge-zone behavior has named positive and rejection coverage.
- [ ] Fixture provenance points to the reviewed Rust revision and covers deterministic success, rejection, and tamper cases where applicable.
- [ ] The public-export ledger has no unexplained difference.
- [ ] No row or package gate has an unresolved adverse verdict.

## Copy-paste `/loop` prompt

```text
/loop Review exactly one eligible production Rust source responsibility in
planning/typescript-sdk-port/review-checklist.md per wake.

Read and follow:
- /Users/tilohelius/.claude/skills/docs-humanizer/SKILL.md and its required references
- /Users/tilohelius/.claude/skills/zolana-comments/SKILL.md
- /Users/tilohelius/.claude/skills/code-simplifier/SKILL.md
- /Users/tilohelius/Workspace/zolana/.cursor/skills/review-ts/SKILL.md
- /Users/tilohelius/Workspace/zolana/CLAUDE.md

Keep review work read-only except for the checklist. Do not implement findings
unless the user explicitly authorizes fixes.

At each wake:
1. Refresh HEAD, fixture frozenCommit, Rust drift, dirty paths, active fix
   ownership, progress counts, and commits for in_progress rows.
2. When an in_progress fix has a selective commit, mark it needs_re_review.
   Skip a row while its worker still has uncommitted changes.
3. Select the lowest queue ID marked needs_re_review. If none exists, select the
   lowest queue ID marked todo. Process no other row.
4. Explain the canonical Rust file's purpose, imports/dependencies, public
   exports, basic flows, key or capability separations, and Rust/TypeScript test
   locations.
5. Follow re-exports and audit public and behavioral parity with review-ts.
   Assign exactly one allowed verdict. For any verdict other than PARITY, state
   the exact path and symbol, concrete reason, missing evidence, and smallest
   fix. Justify NOT_APPLICABLE with evidence.
6. Update only that row, the mutable baseline, affected gates, and one
   append-only session-log entry. State the exact next file.
7. A fixed row becomes done only after independent re-review supports PARITY.
8. After no row is eligible, check package gates in package order and full SDK
   gates in listed order. Reopen the lowest responsible row for a failed gate.

Stop only when the 118 rows are done with PARITY or justified NOT_APPLICABLE,
each of the nine package gate sets passes, and the full SDK gate set passes.
Per-file completion alone must not produce a full SDK parity claim.
```

## Append-only session log

Copy this block for each wake. Do not rewrite earlier entries.

```markdown
### YYYY-MM-DD HH:MM UTC | ROW_ID | Rust path

- Baseline: HEAD `<hash>`; fixture `<hash>`; Rust drift `<none or paths>`
- Worker: `<review agent>`; implementation commit `<hash or none>`
- Explanation: `<purpose; imports/dependencies; exports; flow; capabilities; tests>`
- Evidence: `<spec sections; Rust tests; fixtures; TS tests; commands and results>`
- Verdict: `<one allowed verdict>`
- Gap and smallest fix: `<exact path/symbol and action, or none>`
- Row transition: `<old status> -> <new status>`
- Progress: `<done>/118`; package `<done>/<package total>`
- Exact next file: `<queue ID and Rust path, or first failing gate>`
- Full SDK parity claim: `<supported or unsupported, with failed gate>`
```

### 2026-07-24 16:46 UTC | A01 | `sdk-libs/zolana-api/src/lib.rs`

- Baseline: HEAD `7cb3acda65026c2dd1e0717d703e9880c28a8a12`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: GPT-5.6 Sol review subagent; implementation commit `f5d698d9`
- Explanation: The crate provides asynchronous and blocking Photon JSON-RPC transports. It depends on reqwest, serde, serde_json, serde_path_to_error, and zolana-indexer-api; its crate root exports both clients, ApiError, and selected indexer wire types. Each public method validates limits, builds a typed JSON-RPC request, posts to the method path, decodes the typed result, and separates transport, HTTP, JSON-RPC, invalid-request, and missing-result failures. The TypeScript root keeps the asynchronous capability, delegates schemas to `@zolana/indexer-api`, and omits the Rust blocking duplicate. It accepts no signing or viewing keys; its private API-key field and redacted errors keep transport credentials and response contents out of diagnostics. Rust unit tests cover URL parsing, blocking URL parity, and limits. TypeScript unit, response, transport, property, export, browser, and Rust-vector suites govern the port.
- Evidence: `docs/spec.md` has no transport contract; `sdk-libs/indexer-api/src/lib.rs` defines the current method and wire schema. The Rust source and this dependency have no drift from fixture commit `43fde8e4`. Fixture `api/transport-v1.json`, generated by `xtask/src/ts_fixtures_api.rs`, records six non-empty success exchanges and HTTP, JSON-RPC, missing-result, and limit failures; its committed SHA-256 is `9f4057f423bf7d24170a8ff734b961a637953fd3888343e02490bfde655141dc`. `cargo test -p zolana-api` passed 4 tests. The API build, typecheck, 52 unit tests, 11 vector tests, 2 property tests, 34 cross tests, browser check, and API check passed.
- Verdict: `PARITY`
- Gap and smallest fix: none
- Row transition: `needs_re_review -> done`
- Progress: `1/118`; package `1/1`
- Exact next file: `C02 sdk-libs/client/src/error.rs`
- Full SDK parity claim: unsupported; eight package row sets and the cross-package gates remain incomplete

### 2026-07-24 16:52 UTC | C02 | `sdk-libs/client/src/error.rs`

- Baseline: HEAD `d21f1c25607e5b194407f3e4adbe26947eeecc63`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: GPT-5.6 Sol review subagent; implementation commit `7cb3acda`
- Explanation: The public `ClientError` enum is the client crate's error boundary. It depends on `thiserror`, Solana address types, and the keypair, transaction, and hasher error enums; `sdk-libs/client/src/lib.rs` re-exports it from the crate root. Its 58 variants separate wrapped dependency failures, input and shape checks, transaction assembly, tree and proof validation, prover and RPC failures, indexer polling, merge and split checks, and deposit account checks. The TypeScript root exports `ClientError`, its closed code/details types, and the canonical Rust-code list. Client operations translate keypair and transaction failures at assembly boundaries and produce the hasher category at hashing boundaries. Causes retain category and public codes while filtering secret-named fields. This file accepts no keys and grants no signing, viewing, or nullifier capability.
- Evidence: `docs/spec.md` does not define the SDK error taxonomy. Current Rust `error.rs`, its wrapped error enums, and the nine scoped Rust source trees have no drift from fixture commit `43fde8e4`. Rust-generated fixture `client/errors-v1.json` is produced by the exhaustive `client_error_json` match in `xtask/src/ts_fixtures_client.rs`; its manifest SHA-256 is `49acb09fb6205e33efa8209263e6f83698a48ec72ca59bf5d5ef784156874d1d`. The fixture and `CANONICAL_CLIENT_ERROR_CODES` contain the same 58 variants in order. TypeScript tests cover the 58 codes, structured representative fields, keypair, transaction, and hasher translation, immutable details and causes, secret filtering, malformed external causes, and the closed compile-time union. Rust client library tests with crate features enabled passed 30 tests. Client build, typecheck, 99 unit tests, 30 vector tests, browser check, API scaffold check, export check, dependency check, pack check, and the 57-fixture and 182-inventory-row regeneration check passed.
- Verdict: `PARITY`
- Gap and smallest fix: none
- Row transition: `needs_re_review -> done`
- Progress: `2/118`; package `1/22`
- Exact next file: `C04 sdk-libs/client/src/indexer.rs`
- Full SDK parity claim: unsupported; eight package row sets, 21 client rows, and the cross-package gates remain incomplete

### 2026-07-24 16:56 UTC | C04 | `sdk-libs/client/src/indexer.rs`

- Baseline: HEAD `c01d5c7c1d6169140025233a610c4423633ad3f9`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: GPT-5.6 Sol review subagent; implementation commit `7cb3acda`
- Explanation: The feature-gated Rust module adapts `zolana-api` responses to the client RPC types and exports `ZolanaIndexer` plus `AsyncZolanaIndexer` through `sdk-libs/client/src/lib.rs`. It imports the API wire types, Solana addresses, transaction proof inputs, P256 public-key validation, client errors, retry configuration, RPC response types, and prover support. Its four RPC methods encode hashes, addresses, cursors, and limits; preserve response order; convert output slots, messages, nullifiers, Merkle proofs, and non-inclusion proofs; and optionally poll one captured Unix-second target against `context.block_time`. The TypeScript `ZolanaIndexer` is the JavaScript adaptation of `AsyncZolanaIndexer`: promises replace Rust's async trait, an injected `ZolanaApi` replaces `new` and `with_api`, and custom `fetch` supplies transport diagnostics in place of reqwest HTTP tracing. JavaScript has no useful blocking duplicate. The blocking Rust adapter's default 60-second Merkle-proof count loop is therefore outside the asynchronous disposition, while explicit block-time polling remains represented. The adapter accepts tags and public transaction-viewing keys but no signing, viewing, nullifier, or API-key material; `ZolanaApi` keeps its API key private, and translated errors retain safe codes and paths rather than response bodies or secrets. Rust unit tests govern the four request and conversion paths, malformed hashes, P256 decoding, JSON-RPC failures, and client confirmation. TypeScript parity, client integration, vector, browser, export, dependency, and package checks govern the adaptation.
- Evidence: `docs/spec.md` does not define this transport adapter. The current Rust file and its API, retry, RPC, and indexer schema dependencies have no drift from fixture commit `43fde8e4`. Rust-generated fixture `client/rpc-indexer-v1.json`, produced by `xtask/src/ts_fixtures_client.rs`, records current conversion values, fixed 32-byte hashes, a valid compressed 33-byte P256 point, a 16-byte salt, cursor bytes, ordered proofs, retry delays, attempts, and source limitations; the manifest pins SHA-256 `998eeb1e4ff49dccabdb543a7983e57a2a1e7fdfae00c35abddea036fe9513ab`. Independent source review confirmed one-request defaults, exact four-method request fields, stable response ordering, defensive byte copies, P256 curve validation, fixed-width rejection, one captured polling target, bounded attempts, cancellation, timeout translation, closed `ClientError` paths, and browser-safe imports. `cargo test -p zolana-client --lib --features indexer-api` passed 30 tests. The client build, typecheck, 99 unit tests, 30 vector tests, browser check, and API check passed. Export, dependency, pack, and fixture checks passed; fixture verification covered 57 fixtures and 182 inventory rows.
- Verdict: `PARITY`
- Gap and smallest fix: none
- Row transition: `needs_re_review -> in_progress -> done`
- Progress: `3/118`; package `2/22`
- Exact next file: `I01 program-libs/interface/src/error.rs`
- Full SDK parity claim: unsupported; eight package row sets, 20 client rows, and the cross-package gates remain incomplete
