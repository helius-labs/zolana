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
- Review HEAD: `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`
- Fixture `frozenCommit`: `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`
- Canonical Rust drift since freeze: `sdk-libs/merkle-tree/src/indexed.rs`
- Primary rows: `118`
- Progress: `31 done / 118 total`; `86 needs_fix`; `0 needs_re_review`; `1 todo`
- Exact next eligible row: `C21 sdk-libs/client/src/error.rs`
- Active reviews: `C05-C20` reviewed `2026-07-25`, sixteen `needs_fix`, so the client package gates stay unchecked; `C21, C22` deferred until the client retry and error fix commits
- Wallet package: `W01-W09` reviewed `2026-07-25`; all nine are `needs_fix`, so the wallet package gates stay unchecked. `W07` (sync-delegate viewing key), `W08` (missing shared-tag families), and `W04` (P256 rail source) are the blocking correctness findings
- Active fixes: `K01 proposed`; `K02 proposed`; `K03 proposed`
- Last session: `2026-07-25`

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

The loop has five phases:

1. Review the 118 primary rows.
2. Implement actionable findings and independently re-review their commits.
3. Resolve specification-authority blockers. Disputed behavior stays adverse
   until the designated protocol owner records a decision and the affected
   implementation and evidence agree.
4. Pass the package and full SDK gates.
5. Run [PKP-00 through PKP-08](proof-and-key-parity.md#implementation-work-packets).

The proof and key phase is a certification overlay, not another source-file
inventory. This checklist remains the authority for row verdicts.

The 26 cross-cutting findings in
[production-readiness-issues.md](production-readiness-issues.md#scheduling) are sequenced into these
same five phases. Its scheduling table names the owning document or packet and
the closing gate per finding. Three points of that schedule affect this loop:

- G9-1 and G9-2 head phase 2. Until a workflow runs the TypeScript scripts and
  the aggregate `check` script covers the cross-language and prover suites,
  a passing gate in phases 3 through 5 rests on one contributor's local shell
  and a reviewer cannot reproduce it. Both have gate lines below.
- G7-1 and G7-2 are authority rulings and belong to phase 3, beside the rows
  already held adverse by the owner-hash and proof-size conflicts.
- The findings that overlap PKP-01 through PKP-07 point at those packets. No
  finding creates a packet beside the PKP set.

During the row-review phase, at each wake:

1. Refresh rows marked `in_progress`. If an authorized fix now has a commit,
   change it to `needs_re_review`. Skip rows still owned by an active worker.
2. Select the lowest queue ID marked `needs_re_review`.
3. If none exists, select the lowest queue ID marked `todo`.
4. When no `todo` row remains, drain `needs_fix` rows in queue order. Implement
   authorized actionable findings with selective commits, then send each
   commit to an independent re-review. Keep unresolved authority conflicts
   adverse.
5. Evaluate package gates in package order, then full SDK gates in listed
   order. Reopen the lowest responsible row when a gate fails.
6. Start PKP-00 only after the 118 rows are `done` and the package and full SDK
   gates pass.

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
| I01 | `program-libs/interface/src/error.rs` | `interface/src/errors.ts`, `interface/src/index.ts` | done | PARITY | committed | The named 26-code map, structured decoder, unknown-code preservation, client translation, redaction, exports, and current-Rust evidence now align. | 2026-07-25 re-review | `e7fa785b` |
| I02 | `program-libs/interface/src/shape.rs` | `interface/src/internal.ts` | done | PARITY | committed | One deeply immutable interface shape authority now covers ordering, empty and boundary selection, unsupported pairs, malformed counts, reuse, exports, and current-Rust evidence. | 2026-07-25 re-review | `a384d9c1` |
| I03 | `program-libs/interface/src/merge_utils.rs` | `interface/src/internal.ts` | done | PARITY | committed | The canonical ciphertext hash is reused, and exact current-Rust oracles cover chunk boundaries, cardinality, prefixes, and rejection behavior. | 2026-07-25 re-review | `d7d228c6` |
| I04 | `program-libs/interface/src/pda.rs` | `interface/src/pda/index.ts` | done | PARITY | committed | Exact current-Rust oracles cover canonical PDA routes and bumps, nonzero inputs, malformed address positions, and rejection behavior. | 2026-07-25 re-review | `a41b85f8` |
| I05 | `program-libs/interface/src/instruction/instruction_data/batch_update_nullifier_tree.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | Public data and proof types, the exact codec, builder reuse, proof ordering, boundaries, malformed rejection, exports, and current-Rust evidence now align. | 2026-07-25 re-review | `a384d9c1` |
| I06 | `program-libs/interface/src/instruction/instruction_data/create_tree.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | The public create-tree data type and exact codec are reused by the builder and cover ownership, lengths, malformed addresses, browser behavior, and current-Rust bytes. | 2026-07-25 re-review | `a384d9c1` |
| I07 | `program-libs/interface/src/instruction/instruction_data/deposit.rs` | `interface/src/codecs/index.ts`, `interface/src/instructions/index.ts` | needs_fix | BLOCKED | proposed | Current Rust and locked TypeScript behavior conflict with authoritative `docs/spec.md` on deposit layouts and signing-tag semantics, so parity cannot be determined. Resolve the protocol authority before aligning codecs, builders, and evidence. | 2026-07-25 re-review | - |
| I08 | `program-libs/interface/src/instruction/instruction_data/merge_transact.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | Rust and TypeScript now reject non-`2` merge ciphertext prefixes, with exact current-Rust acceptance and rejection oracles. | 2026-07-25 re-review | `484ac5ed` |
| I09 | `program-libs/interface/src/instruction/instruction_data/merge_zone.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | Exact codec evidence and the dedicated merge-zone prove, assemble, submit, and wrong-path rejection flow now align. | 2026-07-25 re-review | `eed44013` |
| I10 | `program-libs/interface/src/instruction/instruction_data/protocol_config.rs` | `interface/src/codecs/index.ts` | needs_fix | BLOCKED | proposed | Current Rust and TypeScript update one selected protocol-config field, while authoritative `docs/spec.md` requires rewriting the owner, authority fields, and flags. Resolve that protocol conflict before completing codec parity. | 2026-07-25 re-review | - |
| I11 | `program-libs/interface/src/instruction/instruction_data/transact.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | Public canonical `externalDataHash` is reused by transaction code, and exact current-Rust tests change each input and assert the hash changes. | 2026-07-25 re-review | `abaa9984` |
| I12 | `program-libs/interface/src/instruction/instruction_data/zone_config.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | Test-kit returns canonical `zone_auth`, and exact current-Rust PDA, codec, and routing evidence aligns. | 2026-07-25 re-review | `a41b85f8` |
| I13 | `program-libs/interface/src/instruction/instruction_data/mod.rs` | `interface/src/codecs/index.ts` | needs_fix | PARTIAL | proposed | Most instruction-data counterparts and dispositions are present, but the aggregate inherits blocked deposit and protocol-config authority and still lacks a complete protocol-config codec. Resolve those dependencies and pin the export ledger. | 2026-07-25 re-review | - |
| I14 | `program-libs/interface/src/instruction/builders/batch_update_nullifier_tree.rs` | `interface/src/instructions/index.ts` | done | PARITY | committed | The builder reuses the canonical codec and exact current-Rust evidence covers program, bytes, account metas, boundaries, malformed input, and defensive ownership. | 2026-07-25 re-review | `a384d9c1` |
| I15 | `program-libs/interface/src/instruction/builders/create_asset_counter.rs` | `interface/src/instructions/index.ts` | done | PARITY | committed | Exact current-Rust bytes, account metas, malformed-address rejection, and defensive-copy evidence now align. | 2026-07-25 re-review | `8152a486` |
| I16 | `program-libs/interface/src/instruction/builders/create_associated_token_account.rs` | `interface/src/instructions/index.ts` | done | PARITY | none | The TypeScript builder preserves the legacy SPL associated-token derivation, canonical program IDs, six accounts and flags, and the one-byte idempotent discriminator. A current-Rust workflow fixture plus exact transaction and live repeated-call coverage supports parity. The planning fixture name has bookkeeping drift only. | 2026-07-25 review | - |
| I17 | `program-libs/interface/src/instruction/builders/create_spl_interface.rs` | `interface/src/instructions/index.ts` | done | PARITY | committed | Exact nonzero-mint current-Rust PDAs, account metas, malformed rejection, and defensive ownership evidence now align. | 2026-07-25 re-review | `8152a486` |
| I18 | `program-libs/interface/src/instruction/builders/create_tree.rs` | `interface/src/instructions/index.ts` | done | PARITY | committed | Default and custom nullifier-parameter paths, canonical codec reuse, exact bytes, account metas, rejection, and current-Rust fixtures now support parity. | 2026-07-25 re-review | `a384d9c1` |
| I19 | `program-libs/interface/src/instruction/builders/deposit.rs` | `interface/src/instructions/index.ts` | needs_fix | BLOCKED | proposed | Current Rust and TypeScript agree on covered SOL and SPL behavior, but authoritative `docs/spec.md` conflicts on accounts, payload, tag semantics, and the initial viewing-key tag. Resolve the protocol authority before completing evidence. | 2026-07-25 re-review | - |
| I20 | `program-libs/interface/src/instruction/builders/merge_transact.rs` | `interface/src/instructions/index.ts` | done | PARITY | committed | Exact current-Rust bytes, account routing, and shared malformed-prefix rejection now align. | 2026-07-25 re-review | `83b1f6b4` |
| I21 | `program-libs/interface/src/instruction/builders/merge_zone.rs` | `interface/src/instructions/index.ts` | done | PARITY | committed | Outer and CPI routing, exact current-Rust bytes, and shared malformed-prefix rejection now align. | 2026-07-25 re-review | `83b1f6b4` |
| I22 | `program-libs/interface/src/instruction/builders/protocol_config/mod.rs` | `interface/src/instructions/index.ts` | needs_fix | BLOCKED | proposed | Builder behavior follows current Rust, but the aggregate inherits I10's unresolved conflict with authoritative `docs/spec.md`. Resolve the protocol-config update contract before parity. | 2026-07-25 re-review | - |
| I23 | `program-libs/interface/src/instruction/builders/transact.rs` | `interface/src/instructions/index.ts` | done | PARITY | committed | Canonical builder reuse now preserves Rust's construction boundary, exact layouts, account metas, settlement errors, client integration, and current-Rust evidence. | 2026-07-25 re-review | `a384d9c1` |
| I24 | `program-libs/interface/src/instruction/builders/zone_authority_transact.rs` | `interface/src/instructions/index.ts` | done | PARITY | committed | Exact current-Rust SOL and SPL outer and CPI routes, account selection, and rejection behavior now align. | 2026-07-25 re-review | `83b1f6b4` |
| I25 | `program-libs/interface/src/instruction/builders/zone_config/mod.rs` | `interface/src/instructions/index.ts` | done | PARITY | committed | Canonical zone creation and update routing, exact account metas, rejection behavior, and exports now align. | 2026-07-25 re-review | `83b1f6b4` |
| I26 | `program-libs/interface/src/instruction/builders/zone_deposit.rs` | `interface/src/instructions/index.ts` | needs_fix | BLOCKED | proposed | Exact current-Rust SOL and SPL outer and CPI routing evidence is complete, but parity remains blocked by I07's unresolved zone-deposit layout and signing-semantics conflict with `docs/spec.md`. | 2026-07-25 re-review | - |
| I27 | `program-libs/interface/src/instruction/builders/zone_transact.rs` | `interface/src/instructions/index.ts` | done | PARITY | committed | Exact current-Rust SOL and SPL outer and CPI routing, withdrawal metas, owner index, and rejection behavior now align. | 2026-07-25 re-review | `83b1f6b4` |
| I28 | `program-libs/interface/src/instruction/builders/mod.rs` | `interface/src/instructions/index.ts` | needs_fix | BLOCKED | proposed | Prefix and routing evidence now align, but the aggregate inherits blocked I19, I22, and I26 builder children. Resolve their protocol authority before aggregate parity. | 2026-07-25 re-review | - |
| I29 | `program-libs/interface/src/instruction/mod.rs` | `interface/src/index.ts` | needs_fix | BLOCKED | proposed | The instruction aggregate inherits unresolved I07 and I10 protocol authority plus blocked builder children. Resolve those children before aggregate parity. | 2026-07-25 re-review | - |
| I30 | `program-libs/interface/src/state/discriminator.rs` | `interface/src/internal.ts` | done | PARITY | committed | One exported discriminator authority now includes the tree value, records reserved value `2`, is reused by codecs, and has complete current-Rust drift evidence. | 2026-07-25 re-review | `a384d9c1` |
| I31 | `program-libs/interface/src/state/protocol_config.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | The exact 132-byte layout, Rust nonzero-boolean decoding, size disposition, boundaries, malformed input, and current-Rust fixture now align. | 2026-07-25 re-review | `a384d9c1` |
| I32 | `program-libs/interface/src/state/spl_asset_counter.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | The exact codec, `FIRST_ASSET_ID`, reserved bytes, `u64` boundaries, initialization, allocation, overflow, and sequencing evidence now align. | 2026-07-25 re-review | `a384d9c1` |
| I33 | `program-libs/interface/src/state/spl_asset_registry.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | Exact registry bytes and boundaries align, and wallet sync now records, fetches, and retries unknown asset registries with current-Rust evidence. | 2026-07-25 re-review | `a19c99b3` |
| I34 | `program-libs/interface/src/state/tree.rs` | `interface/src/index.ts` | done | PARITY | committed | Public tree constants, nullifier parameters, account size, root offset, browser-safe exports, and current-Rust vectors now align. | 2026-07-25 re-review | `a384d9c1` |
| I35 | `program-libs/interface/src/state/zone_config.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | The exact 67-byte layout and canonical and noncanonical enabled-byte behavior now match current Rust with strict fixture evidence. | 2026-07-25 re-review | `a384d9c1` |
| I36 | `program-libs/interface/src/state/mod.rs` | `interface/src/index.ts` | done | PARITY | committed | The state root now reuses and exports canonical discriminators, asset constants, tree authorities, child codecs, and exact allowlist evidence. | 2026-07-25 re-review | `a384d9c1` |
| I37 | `program-libs/interface/src/lib.rs` | `interface/src/index.ts` | needs_fix | BLOCKED | proposed | The package root inherits blocked protocol children. The legacy frozen-revision fixture failure is package bookkeeping, not scoped evidence-blocking; its stale `sourceCommit` provenance remains for the fixture-gate worker. | 2026-07-25 re-review | - |

### Keypair, 14 rows

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| K01 | `sdk-libs/keypair/src/constants.rs` | `keypair/src/constants.ts` | needs_fix | PARTIAL | proposed | Seven Rust-public constants are hidden, the inventory incorrectly classifies them as internal, and direct constant evidence is incomplete. Export or record an exact JavaScript disposition for each public constant, correct the inventory, and add current-Rust evidence. | 2026-07-25 review | - |
| K02 | `sdk-libs/keypair/src/signing_key.rs` | `keypair/src/signing-key.ts` | needs_fix | DIVERGENT | proposed | The tagged public-key runtime encoding is 34 bytes while its TypeScript type says `Bytes33`, and the public `isEd25519` capability is missing. RNG failure, scalar rejection, signature boundaries, and secret inspection also lack evidence. Correct the type and adaptation, add `isEd25519`, and add current-Rust generation, signing, malformed-input, and secret-exposure tests. | 2026-07-25 review | - |
| K03 | `sdk-libs/keypair/src/nullifier_key.rs` | `keypair/src/nullifier-key.ts` | needs_fix | PARTIAL | proposed | Source behavior aligns, but malformed import, repeated derivation, capability separation, and secret-inspection vectors are incomplete. The inventory describes a leaf index instead of the blinding input, and fixture names and provenance point to the wrong responsibility. Correct the records and add exact current-Rust success, malformed-input, repeatability, capability, and inspection evidence. | 2026-07-25 review | - |
| K04 | `sdk-libs/keypair/src/viewing_key.rs` | `keypair/src/viewing-key.ts` | needs_fix | DIVERGENT | proposed | Valid cryptographic behavior and current-Rust vectors align, but zero-scalar is collapsed to invalid-secret, HKDF failures lack Rust error parity, and boundary, browser-runtime, inspection, adversarial, and temporary-cleanup evidence is incomplete. Preserve the aligned behavior, distinguish zero-scalar and HKDF failures, and add the missing evidence. | 2026-07-25 review | - |
| K05 | `sdk-libs/keypair/src/pubkey.rs` | `keypair/src/public-key.ts` | needs_fix | DIVERGENT | proposed | The Rust public key is a 34-byte tagged value, while TypeScript declares the runtime value as `Bytes33`. P256 decompression, canonical equality, and structured error behavior also differ or lack proof, and the public export ledger has no adversarial or browser evidence. Correct the tagged-key type and API, align decompression, equality, and errors, then add malformed, parity, export, and browser vectors from current Rust. | 2026-07-25 review | - |
| K06 | `sdk-libs/keypair/src/shielded.rs` | `keypair/src/shielded.ts` | needs_fix | DIVERGENT | proposed | The spec-authoritative P256 owner-hash construction conflicts with the current TypeScript path. Construction and facade APIs, compressed-address handling, ownership boundaries, and current-Rust evidence are also missing or divergent. Resolve the owner-hash conflict, align construction and ownership capabilities, expose the required facade and address behavior, and add exact fixtures plus malformed and capability-separation tests. | 2026-07-25 review | - |
| K07 | `sdk-libs/keypair/src/hash.rs` | `keypair/src/hash.ts`, `hash/index.ts` | needs_fix | DIVERGENT | proposed | Covered valid vectors match current Rust, but TypeScript omits the public Poseidon API, accepts malformed field widths and arities outside Rust's `1..=12`, and exposes extra unsafe hash helpers. Boundary, browser, and property evidence is incomplete, and owner hashing inherits the K06 spec conflict. Add the public Poseidon surface, enforce Rust widths and arities, remove or internalize unsafe helpers, resolve K06, and add exact rejection, boundary, browser, and property vectors. | 2026-07-25 review | - |
| K08 | `sdk-libs/keypair/src/encryption.rs` | `keypair/src/encryption.ts` | needs_fix | PARTIAL | proposed | TypeScript matches current Rust P256 ECDH, HKDF, and AES-CTR bytes, and the internal API disposition is valid. Shared-secret cleanup is not exception-safe, and current-Rust multi-block and counter, empty and boundary, malformed salt and slot, tamper, truncation, extension, defensive-copy, browser, security, and fixture-description evidence is incomplete. Make cleanup exception-safe and add exact current-Rust boundary, malformed, mutation, browser, and provenance fixtures. | 2026-07-25 review | - |
| K09 | `sdk-libs/keypair/src/merge.rs` | `keypair/src/merge/` | needs_fix | PARTIAL | proposed | Merge encryption and its frozen vector are byte-compatible, but the public Rust `symmetric_apply` capability is missing. Malformed-secret and structured-error behavior, info and chunk boundaries, temporary cleanup, exports, and provenance lack exact evidence. Fix Rust's info-length panic risk before porting unrestricted `symmetric_apply`, then add the API with bounded inputs, cleanup, and current-Rust rejection and boundary fixtures. | 2026-07-25 review | - |
| K10 | `sdk-libs/keypair/src/error.rs` | `keypair/src/error.ts` | needs_fix | DIVERGENT | proposed | TypeScript collapses or omits five Rust error distinctions, lacks code-indexed immutable diagnostics and exhaustive current-Rust evidence, and permits arbitrary enumerable causes or details to expose data. Define one-to-one closed codes and details, sanitize causes and redacted serialization, and add exhaustive current-Rust fixtures plus export and package tests. | 2026-07-25 review | - |
| K11 | `sdk-libs/keypair/src/traits/view_key.rs` | `keypair/src/viewing-key.ts` | needs_fix | PARTIAL | proposed | The 14 concrete operations exist on TypeScript `ViewingKey`, but public `ViewingKeyLike` exposes only two unused methods. `ShieldedKeypair` cannot substitute, higher packages require concrete `ViewingKey`, and trait declaration, facade, malformed-input, secret-exposure, browser, and current-Rust evidence is missing. Add the public trait adaptation and facade, accept the least-powerful capability in higher packages, and add the missing evidence. | 2026-07-25 review | - |
| K12 | `sdk-libs/keypair/src/traits/shielded_keypair.rs` | `keypair/src/shielded.ts` | needs_fix | PARTIAL | proposed | Concrete operations exist, but the generic interface omits six named capabilities, is unused, and lacks a workable async/HSM facade and evidence. Correct Rust's malformed-P256-sign panic and secret-returning nullifier trait method, then complete and consume the generic facade with current-Rust, malformed, capability, async/HSM, browser, and secret-exposure evidence. | 2026-07-25 review | - |
| K13 | `sdk-libs/keypair/src/traits/mod.rs` | `keypair/src/index.ts` | needs_fix | PARTIAL | proposed | Rust trait-module exports are represented only by incomplete root-level TypeScript interfaces; no documented traits subpath or counterpart and no trait-specific fixture exist. The declarations are accurate, but consumer, browser, and packed-package evidence does not exercise the interfaces. Add the documented traits surface and trait-specific fixture, then exercise the interfaces through consumer, browser, and packed-package tests. | 2026-07-25 review | - |
| K14 | `sdk-libs/keypair/src/lib.rs` | `keypair/src/index.ts` | needs_fix | DIVERGENT | proposed | The package export map and browser graph are coherent, but Rust-public constants, Poseidon, `symmetricApply`, `isEd25519`, `Signature`, compressed-address and traits surfaces are missing; `Bytes33` falsely declares a 34-byte key. The K06 owner-hash spec conflict, collapsed errors, stale metadata, and missing exact root, type, tarball, and consumer allowlists also prevent package parity. Complete and correct the package surface, resolve the inherited conflicts, refresh metadata, and add exact allowlist evidence. | 2026-07-25 review | - |

### Merkle tree, 2 rows

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M01 | `sdk-libs/merkle-tree/src/indexed.rs` | `merkle-tree/src/indexed.ts` | done | PARITY | committed | Canonical Rust and TypeScript now align on atomic indexed mutations, exclusive sentinels, trusted roots, exact proof lengths, public operations, errors, exports, browser behavior, package contents, and current-source fixtures. P06 records the requested gates passing without scoped drift or blockers. | 2026-07-25 re-review | `4e271aac` |
| M02 | `sdk-libs/merkle-tree/src/lib.rs` | `merkle-tree/src/merkle-tree.ts`, `index.ts` | done | PARITY | committed | Canonical Rust and TypeScript now align on atomic mutations, trusted roots, exact proof lengths, next-index and history behavior, public APIs, errors, exports, browser behavior, package contents, and current-source fixtures. P06 records the requested gates passing without scoped drift or blockers. | 2026-07-25 re-review | `4e271aac` |

### Indexer API, 1 row

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| X01 | `sdk-libs/indexer-api/src/lib.rs` | `indexer-api/src/` | needs_fix | DIVERGENT | proposed | TypeScript accurately follows current Rust and Photon, but authoritative `docs/spec.md` defines materially different indexer context, UTXO, transaction, and output schemas. Public base64-to-bytes and hash error distinctions are incomplete, the promised Rust fixture is absent, and exhaustive rejection and live-Photon evidence is missing. Resolve the Rust and Photon conflict with the spec, then align the TypeScript schema, public conversions, errors, fixtures, and evidence. | 2026-07-25 review | - |

### Smart-account client, 1 row

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S01 | `sdk-libs/smart-account-client/src/lib.rs` | `smart-account-client/src/` | needs_fix | DIVERGENT | proposed | Rust casts compiled account positions to `u8`, while TypeScript rejects indexes above 255, so the overflow policy conflicts. TypeScript also lacks equivalent enforcement and evidence for the 1232-byte transaction limit, an exact execute fixture, and the public export surface. Choose and enforce one index policy at the canonical boundary, add the size limit, and pin execute bytes and exports with current-Rust fixtures. | 2026-07-25 review | - |

### API, 1 row

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A01 | `sdk-libs/zolana-api/src/lib.rs` | `api/src/index.ts` | done | PARITY | committed | The committed Rust transport oracle covers the five methods, both nullifier start-sequence paths, request bytes, decoded responses, limits, and shared errors. | 2026-07-24 re-review | `f5d698d9` |

### Transaction, 31 rows

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T01 | `sdk-libs/transaction/src/error.rs` | `transaction/src/error.ts` | needs_fix | PARTIAL | committed | Re-review after the three fix commits: the code set is now closed, details are structured, messages are redacted, and cause categories keep keypair and authority failures apart. Residual: six declared codes have no producer (`TRANSACTION_UNKNOWN_ASSET_FIELD`, `TRANSACTION_INVALID_OUTPUT_POSITION`, `TRANSACTION_OUTPUT_AMOUNT_MISMATCH`, `TRANSACTION_OUTPUT_ASSET_MISMATCH`, `TRANSACTION_OUTPUT_BLINDING_MISMATCH`, `TRANSACTION_OUTPUT_OWNER_MISMATCH`) and no fixture derives the code set from the 59 current-Rust `TransactionError` variants. Smallest fix: raise or delete the six unused codes and add a variant-to-code fixture generated from current Rust. | 2026-07-25 re-review | `f0006e69`, `d413a8ff`, `9ed89b01` |
| T02 | `sdk-libs/transaction/src/data.rs` | `transaction/src/data.ts` | needs_fix | PARTIAL | committed | Re-review after `f0006e69`: malformed runtime kinds and byte values now raise `TRANSACTION_INVALID_DATA_RECORD`, the length boundary moved back to `encodeData`, and the codec is packed and exported. Residual: `Data` still accepts the `memo` record (tag `3`), which the `docs/spec.md` UTXO Data table does not define (it lists only `0x01 zone_data` and `0x02 utxo_data`); this is the same defect as T07. The `data-v1` fixture predates the current transaction crate. Smallest fix: drop `memo` together with T07 and regenerate `data-v1`. | 2026-07-25 re-review | `f0006e69` |
| T03 | `sdk-libs/transaction/src/serialization/scheme.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | PARTIAL | committed | Re-review after `a7fe607c`: `encryptedSchemeFromByte` exists, is exported from the package root, and rejects invalid values; scheme-to-encoding pairs are sealed and an empty blob reports exact details. Residual: Rust `EncryptedScheme::as_byte` has no named TypeScript counterpart, no allowlist proves the root export, and `values-and-errors-v1` predates the current crate. Smallest fix: add the named byte accessor, add the export-allowlist entry, and regenerate the fixture. | 2026-07-25 re-review | `a7fe607c` |
| T04 | `sdk-libs/transaction/src/serialization/plaintext.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | DIVERGENT | committed | Re-review after `7c697c2c` and `a7fe607c`: the Rust prerequisite is closed. `PlaintextTransfer::from_utxos` now takes the sender owner from the passed owner rather than the first UTXO, rejects duplicate and out-of-range recipient positions, and checks the asset per slot; TypeScript seals the discriminator and the scheme-to-encoding pairs. Residual: no exported TypeScript counterpart for `from_utxos`. The conversion stays inline and private inside `ts/transaction/src/wallet/sync.ts`, and `serialization-v1` predates the Rust owner change, so its bytes no longer prove the new rule. Smallest fix: export a `plaintextTransferFromUtxos` conversion and regenerate `serialization-v1`. | 2026-07-25 re-review | `7c697c2c`, `a7fe607c` |
| T05 | `sdk-libs/transaction/src/serialization/confidential.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | PARTIAL | committed | Re-review after `7c697c2c` and `a7fe607c`: the Rust cardinality prerequisite is closed (`from_utxos` requires exactly one UTXO), and TypeScript rejects malformed embedded P256 keys, packs `confidentialPlaintextFromUtxo`, and exports sender decryption. Residual: decryption failures still do not map onto the current-Rust `TransactionError::Decrypt` categories, and malformed-input and browser evidence plus a regenerated `serialization-v1` are missing. Smallest fix: map the failure categories and add the two test classes. | 2026-07-25 re-review | `7c697c2c`, `a7fe607c` |
| T06 | `sdk-libs/transaction/src/serialization/anonymous.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | DIVERGENT | committed | Re-review after `7c697c2c` and `d413a8ff`: the spec conflict is resolved. Rust now carries zone and program data through `AnonymousRecipient::from_utxos` and back through reconstruction, and TypeScript accepts the same bound data. Residual: no TypeScript counterpart for `AnonymousRecipient::from_utxos` or `AnonymousSenderBundle::from_utxos`, no shared-tag state progression, and `serialization-v1` predates the Rust data change. Smallest fix: export the two conversions, cover tag progression, and regenerate the fixture. | 2026-07-25 re-review | `7c697c2c`, `d413a8ff` |
| T07 | `sdk-libs/transaction/src/serialization/proofless.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | DIVERGENT | committed | Re-review after `7c697c2c`: `Proofless::from_utxos` now requires exactly one UTXO with a matching owner and zone context, and wallet sync checks the owner hash before accepting a decoded note (`ts/transaction/src/wallet/sync.ts`). Residual: the first named prerequisite is untouched. `DataRecord::Memo` (tag `3`) is still declared in `sdk-libs/transaction/src/data.rs` and mirrored in TypeScript, while the `docs/spec.md` UTXO Data table defines only `0x01 zone_data` and `0x02 utxo_data`, so both languages carry a record the protocol does not define. `decodeProofless` also stays private. Smallest fix: delete the memo record per spec, then export the proofless conversion. | 2026-07-25 re-review | `7c697c2c` |
| T08 | `sdk-libs/transaction/src/serialization/split.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | PARTIAL | committed | Re-review after `7c697c2c` and `a7fe607c`: the Rust prerequisite is closed (`Split::from_utxos` validates the input set, the owner, and the context), and TypeScript locks the split discriminator, carries zone context on `splitBundleUtxos`, and rejects cross-scheme input. Residual: `SplitEncryptedUtxos` is not exported from the `./serialization` subpath, no TypeScript counterpart exists for `Split::from_utxos`, and browser and export evidence plus a regenerated `serialization-v1` are missing. Smallest fix: export the type and the conversion, then add the two test classes. | 2026-07-25 re-review | `7c697c2c`, `a7fe607c` |
| T09 | `sdk-libs/transaction/src/serialization/merge.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | PARTIAL | committed | Re-review after `7c697c2c` and `a7fe607c`: the four Rust prerequisites are closed (one compatible UTXO, owner and data and zone validation, `zone_program_id` kept on reconstruction, structured `UnknownAssetField`), and TypeScript takes a `ViewingKey` instead of raw secret bytes, validates amount and blinding, and exports `mergeUtxo` and `mergePlaintextFromUtxo`. Residual: `mergeUtxo` raises `TRANSACTION_UNKNOWN_ASSET` where current Rust returns `UnknownAssetField`, and export, browser, and proof-contribution evidence is missing. Smallest fix: raise `TRANSACTION_UNKNOWN_ASSET_FIELD` at that call site and add the three test classes. | 2026-07-25 re-review | `7c697c2c`, `a7fe607c` |
| T10 | `sdk-libs/transaction/src/serialization/mod.rs` | `transaction/src/serialization/index.ts` | needs_fix | DIVERGENT | committed | Re-review after `a7fe607c`: scheme-to-encoding pairs are sealed and the family codecs are exported from the subpath. Residual: Rust `DecodeCx`, `OwnerCx`, and `UtxoSerialization` still have no TypeScript adaptation and no root export, so the aggregate capability contract is unrepresented; `SplitBundlePlaintext` names two different types, one declared in `wallet/authority.ts` and re-exported at the root and one declared in `serialization/codecs.ts` and re-exported from `./serialization`; declaration, runtime, tarball, browser, and consumer allowlists are absent. Smallest fix: adapt the three capabilities, rename one `SplitBundlePlaintext`, and add the allowlists. | 2026-07-25 re-review | `a7fe607c` |
| T11 | `sdk-libs/transaction/src/utxo.rs` | `transaction/src/utxo.ts` | needs_fix | PARTIAL | committed | Re-review after `6882ca25` and `f0006e69`: the spec-invalid pair is rejected on both sides. Rust `Utxo::with_zone` returns `MissingZoneProgramId` and TypeScript `commitmentFields` raises `TRANSACTION_MISSING_ZONE_PROGRAM_ID`; TypeScript also copies input arrays defensively. Residual: the Rust rule sits on `with_zone` rather than one canonical construction path, TypeScript still omits the field-encoded proof-input helpers and domain constants, and `utxo-v1` predates the Rust change. Smallest fix: route construction through a single validated path, add the field helpers, and regenerate `utxo-v1`. | 2026-07-25 re-review | `6882ca25`, `f0006e69` |
| T12 | `sdk-libs/transaction/src/wallet/asset.rs` | `transaction/src/wallet/asset.ts` | needs_fix | PARTIAL | committed | Re-review after `6882ca25`, `f0006e69`, and `9ed89b01`: both languages now reject an asset ID at or below `SOL_ASSET_ID`, which matches `docs/spec.md` (`1` for SOL, SPL registered at `asset_id >= 2`); TypeScript adds `addressForField`, runtime mint and lookup validation, and `clone()`. Residual: `entries()` still has no Rust counterpart and no recorded disposition, and property, error-detail, export, browser, and pack evidence plus a regenerated `asset-v1` are missing. Smallest fix: record or remove `entries()` and add the five test classes. | 2026-07-25 re-review | `6882ca25`, `f0006e69`, `9ed89b01` |
| T13 | `sdk-libs/transaction/src/wallet/authority.rs` | `transaction/src/wallet/authority.ts` | needs_fix | DIVERGENT | committed | Re-review after `9ed89b01` and `79b56f68`: TypeScript gained the anonymous-transfer capability (`encryptAnonymousTransfer`, `AnonymousRecipientSlot`) and a narrowed `SyncWalletAuthority`, so the sync path no longer needs the full authority. None of the four named Rust prerequisites is done: `wallet/authority.rs` still accepts a signing key on the wrong rail, its `ShieldedKeypair` implementation still returns `Address::default()` as an implicit zero Solana address instead of failing, and remote signatures and remote results are still returned unchecked. `WalletSyncMaterial` still carries the viewing and nullifier secrets in both languages, and `ApprovalRequest`, `LocalWalletAuthority`, and the encrypted-payload type have no TypeScript counterpart. Smallest fix: land the four Rust changes, then port the three types. | 2026-07-25 re-review | `9ed89b01`, `79b56f68` |
| T14 | `sdk-libs/transaction/src/wallet/state.rs` | `transaction/src/wallet/state.ts` | needs_fix | DIVERGENT | committed | Re-review after `3d444a6c`, `9ed89b01`, and `79b56f68`: both Rust prerequisites are closed. Balance and spent-total arithmetic is checked with `WalletBalanceOverflow`, and sync mutations stage before they apply. TypeScript now clones the registry, returns deep snapshot copies, and adds `checkedBalance`. Residual: the TypeScript `Wallet` still omits `ViewingKeyEntry`, `Balances`, `Filter`, the four `PrivateTransaction*` enums, `getPrivateTransactions`, `lastSynced`, and viewing-key history; `PrivateTransaction` lacks `asset`, `amount`, and the counterparty viewing key; `id.index` is `number` where Rust is `u64`; `balances(skipUtxos)` ignores its argument; and `_state`, `_replace`, and `registerAsset` have no Rust counterpart. Smallest fix: add the missing state API, widen the index to `bigint`, honor `skipUtxos`, and record the three extras. | 2026-07-25 re-review | `3d444a6c`, `9ed89b01`, `79b56f68` |
| T15 | `sdk-libs/transaction/src/wallet/sync.rs` | `transaction/src/wallet/sync.ts` | needs_fix | DIVERGENT | committed | Re-review after `3d444a6c`, `a7fe607c`, and `79b56f68`: four of the five Rust prerequisites are closed (counters resume from the stored offsets, a zero window raises `InvalidTagWindow`, `sync_with_material_in_place` stages the mutation, merge tags are scanned). TypeScript rejects the zero window, commits through a clone-then-replace path, and checks the proofless owner hash. Residual: TypeScript still performs no tag-window scan. `tagWindow` is validated and then unused while `syncWallet` walks each transaction against each slot, so counters, windows, and viewing epochs are absent; `Wallet::sync` and `sync_with_material` have no TypeScript counterpart; `SyncReport` fields differ. Rust still passes an `OwnerCx` without a zone program for the non-proofless schemes. Smallest fix: implement the tag-window scan with resumable counters, then align the report. | 2026-07-25 re-review | `3d444a6c`, `a7fe607c`, `79b56f68` |
| T16 | `sdk-libs/transaction/src/wallet/parallel.rs` | `transaction/src/wallet/sync.ts` | needs_fix | DIVERGENT | committed | Re-review after `3d444a6c`: the Rust parallel path now records confidential sends, sorts keys before merging, and resumes counters, so two of the four prerequisites are closed. Residual: `decryptTransactionsWorkerEquivalent` in `ts/transaction/src/wallet/sync.ts` still returns `decryptTransactions(input)` with no worker, cancellation, or secret-transfer behavior, so the row's core finding stands. The `parallel` feature tests still do not run in the normal gates and no test asserts that serial and parallel runs reach the same state. Smallest fix: add the feature to the gate command with the serial-parallel equality assertion, then implement the worker adaptation or record a platform disposition for the alias. | 2026-07-25 re-review | `3d444a6c` |
| T17 | `sdk-libs/transaction/src/wallet/mod.rs` | `transaction/src/wallet/index.ts` | needs_fix | DIVERGENT | committed | Re-review after `9ed89b01` and `79b56f68`: the wallet entry point gained `SyncWalletAuthority` and `AnonymousRecipientSlot`, and mutable internals are no longer handed out by reference. Residual: `ApprovalRequest`, `Balances`, `Filter`, `LocalWalletAuthority`, `ViewingKeyEntry`, `SyncConfig`, `decrypt_transactions_with_config`, and the four `PrivateTransaction*` enums are still absent from the TypeScript aggregate; the undeclared serial `decryptTransactionsWorkerEquivalent` alias is still exported; runtime, declaration, tarball, browser, named-consumer, and aggregate-fixture allowlists are missing. Smallest fix: add the named exports, record or remove the alias, and add the six allowlists. | 2026-07-25 re-review | `9ed89b01`, `79b56f68` |
| T18 | `sdk-libs/transaction/src/instructions/types.rs` | `transaction/src/instructions/index.ts`, `utxo.ts` | needs_fix | DIVERGENT | proposed | A TypeScript proof-input wrapper exists, but custom zero-owner inputs hash different fields, construction retains mutable UTXO and nullifier-key references instead of Rust ownership and clone semantics, the instructions subpath omits the mapped class, and inventory and evidence are stale. First make Rust reject noncanonical zero-owner dummies; meanwhile require TypeScript to match current-Rust hashing, then align ownership, exports, inventory, and evidence. | 2026-07-25 review | - |
| T19 | `sdk-libs/transaction/src/instructions/transact/types.rs` | `transaction/src/instructions/transact.ts` | needs_fix | DIVERGENT | proposed | TypeScript only partially covers the default private-hash and indexed-shape paths; it omits public Rust aggregate, builder, hash, and output-slot capabilities, runtime validation, owned copies, equality, root and instructions exports, fixtures for omitted capabilities, and adversarial cases. First require zero dummy hashes, address-hash cardinality equal to input cardinality, and a zone program when the zone hash is nonzero in Rust; then align the TypeScript surface and evidence while preserving T11 canonical UTXO and zone-validation ownership and T18 input construction, dummy, hash, nullifier, and ownership responsibility. | 2026-07-25 review | - |
| T20 | `sdk-libs/transaction/src/instructions/transact/shape.rs` | `transaction/src/transact/index.ts` | needs_fix | DIVERGENT | proposed | The canonical immutable interface shape table and TypeScript selection match Rust, but TypeScript conflates `TooManyOutputsForShape`, treats malformed falsy declarations as omission, and lacks exhaustive boundary, error, declaration, runtime, and pack evidence. Align those TypeScript semantics and evidence while preserving I02 interface shape ownership; no Rust implementation change is required, though direct Rust tests are missing. | 2026-07-25 review | - |
| T21 | `sdk-libs/transaction/src/instructions/transact/external_data.rs` | `transaction/src/instructions/transact.ts` | needs_fix | PARTIAL | proposed | The canonical hash preimage matches the spec and current interface, but TypeScript omits Rust constructor defaults, builders, and duplicate errors; retains optional hashes and arrays without complete defensive copies or freezing; has inconsistent malformed-input errors; and lacks root, subpath, export, boundary, property, tamper, and current-Rust fixture evidence. First replace Rust's unchecked `u16` casts with checked conversions and named errors, then align TypeScript and its evidence while preserving I11 ownership of canonical `externalDataHash`. | 2026-07-25 review | - |
| T22 | `sdk-libs/transaction/src/instructions/transact/slots.rs` | `transaction/src/instructions/transact.ts` | needs_fix | DIVERGENT | proposed | TypeScript has only an internal wallet adaptation and omits the public Rust slot struct and two helpers; runtime, copy, error, and export evidence is incomplete. Both implementations mirror one ciphertext per output, conflicting with `docs/spec.md` sender-bundle and recipient-ordinal mapping. First correct Rust's layout per spec, use checked slot conversion, and reject inconsistent hash-only output contexts; then align TypeScript without taking authority or serialization ownership from T13 or T03-T10. | 2026-07-25 review | - |
| T23 | `sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs` | `transaction/src/instructions/transact.ts` | needs_fix | DIVERGENT | proposed | Core current-Rust proof assembly and frozen prover vectors match, but the public helper and `PublicAmounts` API disposition is incomplete; constructor, signature, error, mutation, and real-before-dummy validation differ; and boundary, property, tamper, declaration, and pack evidence is incomplete. Resolve the `docs/spec.md` P256 input-owner conflict with Rust, Go, and TypeScript behavior and add canonical BN254 validation to Rust before aligning the TypeScript API and evidence, while preserving client/prover and T19 ownership. | 2026-07-25 review | - |
| T24 | `sdk-libs/transaction/src/instructions/transact/split.rs` | `transaction/src/instructions/builders.ts` | needs_fix | DIVERGENT | proposed | Valid fixed `1x8` split construction and bytes match, but Rust lacks required input-owner, nullifier, and dummy validation. TypeScript diverges in zone and amount error categories and details, public signing, fields, and `PreparedSplit.asset` surface, malformed prepared-state and ownership semantics, and evidence, export, and browser coverage. First add Rust ownership validation and named errors; then align TypeScript while preserving T08 serialization ownership. | 2026-07-25 review | - |
| T25 | `sdk-libs/transaction/src/instructions/transact/transfer.rs` | `transaction/src/instructions/transact.ts` | needs_fix | DIVERGENT | proposed | Valid transfer bytes and conservation match, but TypeScript pads during prepare rather than finalize, derives dummy tags from the sender rail, omits Rust public fields, types, direct signing, and chaining dispositions, and differs in ownership, withdrawal, amount, payload, error semantics, and evidence. Inherit T22's spec-conflicting ciphertext layout; first add Rust withdrawal-rail and range checks, excess-slot rejection, and checked recipient positions, then align TypeScript without taking T22 slot-layout or T23 proof-input ownership. | 2026-07-25 review | - |
| T26 | `sdk-libs/transaction/src/instructions/transact/mod.rs` | `transaction/src/transact/index.ts` | needs_fix | DIVERGENT | proposed | Rust exposes seven modules and 29 flattened symbols, while TypeScript offers a narrowed, orphaned surface with no transact subpath, incomplete capabilities, and no exact root, instructions, declaration, tarball, or packed-consumer aggregate evidence. The aggregate inherits T19-T25 defects without taking their ownership. | 2026-07-25 review | - |
| T27 | `sdk-libs/transaction/src/instructions/merge.rs` | `transaction/src/instructions/builders.ts` | needs_fix | DIVERGENT | proposed | TypeScript uses the wrong nullifier authority, reports zone failures under the wrong error category, and does not reproduce `PreparedMerge` revalidation. Expiry handling, constants, public API, secret boundaries, and exact current-Rust evidence are also incomplete. Require the Rust-equivalent nullifier capability, align zone errors and revalidation, expose the canonical expiry and constants, and add exact, stale, malformed, capability, and secret-exposure fixtures. | 2026-07-25 review | - |
| T28 | `sdk-libs/transaction/src/instructions/merge_zone.rs` | `transaction/src/instructions/builders.ts` | needs_fix | DIVERGENT | proposed | The TypeScript builder, prepared flow, and proof flow exist, but reject Rust-accepted `ZoneData` and `Memo`, omit expiry configuration, do not revalidate prepared zone consistency, and alias or defer zone-hash and address validation. Add the accepted payloads, configurable expiry, finalization revalidation, canonical validation, and boundary, property, tamper, browser, pack, and live merge-zone evidence while preserving T09 serialization and T27 merge ownership. | 2026-07-25 review | - |
| T29 | `sdk-libs/transaction/src/instructions/zone_authority.rs` | `transaction/src/instructions/builders.ts` | needs_fix | DIVERGENT | proposed | TypeScript omits `ExternalData`, shape and field-encoded public asset, and proof/finalization flow; changes optional-zone and public-amount semantics; uses noncanonical merge errors; aliases mutable inputs; and lacks direct fixture, malformed, tamper, browser, declaration, pack, and E2E evidence. First make Rust enforce canonical constructor and private invariants, a required nonzero zone, shape and tail padding, derived amounts and payer hash, and spec-required rejection of zone-authority withdrawals; then align TypeScript and add the missing evidence. | 2026-07-25 review | - |
| T30 | `sdk-libs/transaction/src/instructions/mod.rs` | `transaction/src/instructions/index.ts` | needs_fix | DIVERGENT | proposed | The TypeScript instructions entry point is a narrowed, undocumented aggregate that omits approved Rust capabilities and instruction input/output types, forwards inconsistently from the package root, leaves an orphan transact barrel, inherits T18-T29 defects, and lacks exact declaration, runtime, tarball, browser, packed-consumer, and aggregate-fixture allowlists. Expand and document the coherent aggregate and add exact allowlists while preserving child-row ownership. | 2026-07-25 review | - |
| T31 | `sdk-libs/transaction/src/lib.rs` | `transaction/src/index.ts` | needs_fix | DIVERGENT | proposed | The TypeScript root omits or remaps many Rust exports, exposes undocumented extras and a name collision, inherits T01-T30 gaps, and lacks exact declaration, runtime, tarball, browser, named-consumer, and root-fixture allowlists. Declare the direct Noble dependencies, complete license, repository, and package metadata, align and document the root surface, and add the missing allowlists while preserving child-row ownership. | 2026-07-25 review | - |

### Client, 22 rows

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| C01 | `sdk-libs/client/src/retry.rs` | `client/src/retry.ts`, `retry/index.ts` | needs_fix | DIVERGENT | proposed | The consolidated `retry.ts` closes the earlier surface, configuration, zero-delay, timer-bound, and attempt-count findings, and `expected.retry` in `rpc-indexer-v1.json` pins the capped schedule, but three differences remain. `retry.ts::retryErrorCause` can set `CLIENT_POLL_TIMED_OUT.details.lastCause` to `{category:"external"}` or `{category:"client"}` values that `PollTimedOut.last_cause: Option<RetryErrorCause>` cannot hold. `retry.ts::isRetryable` accepts `CLIENT_RPC`, which no `sdk-libs/ts` file constructs, and refuses `CLIENT_RPC_HTTP`, `CLIENT_RPC_JSON`, and `CLIENT_RPC_ENVELOPE`, the codes `solana-rpc.ts` actually raises for the transport failures Rust reports as the retryable `ClientError::Rpc`. `indexer.ts::pollIndexer` now swallows retryable failures and reports `CLIENT_INDEXER_NOT_CAUGHT_UP` with `latest` still at its `-(2n**63n)` seed, while `indexer.rs::wait_for_indexer` propagates each failure through `request()?` and can only report an observed `latest`. Restrict `retryErrorCause` to the three Rust causes, classify the codes the RPC adapter raises, and let `pollIndexer` propagate the exhausted cause instead of a lag report. `IndexerPollConfig::attempts` and `ClientError::retry_cause` also have no exported TypeScript counterpart. Rust moved again in `6d757791` after this re-review: `poll_until_async` was added, `wait_for_indexer` now routes through `poll_until` behind a `Lag` guard that reports `IndexerNotCaughtUp` only when the response count reaches the attempt count, and `ClientError::Indexer` became `{ method, retryable }` with `retry_cause` gated on `retryable`. That confirms the lag-report finding from the Rust side, leaves `canonicalSourceRevisions.client` (`3ba52785`) stale, and adds a fourth difference: `isRetryable` treats bare `CLIENT_INDEXER` as retryable while Rust now consults the flag. | 2026-07-25 re-review | `3ba52785`, `0a260feb`, `b230b314` |
| C02 | `sdk-libs/client/src/error.rs` | `client/src/error.ts` | needs_fix | PARTIAL | proposed | `validateClientError` closes the constructor against unknown codes, undeclared fields, wrong field kinds, and accessor-backed payloads; `copyAndFreeze` and `sanitizeDetails` give deep-copy, deep-freeze, and key-redaction evidence; `retry.ts` produces `CLIENT_POLL_TIMED_OUT`, and its `lastCause` field now agrees with the declared shape, closing the defect the C04 reviewer reported. Call-site reachability is still unproven: the producer-disposition test in `error.test.ts` only asserts that four hand-written sets partition `CANONICAL_CLIENT_ERROR_CODES`, so it cannot fail when a code loses its producer. A source scan finds no `new ClientError` site anywhere in `sdk-libs/ts` for `CLIENT_RPC`, `CLIENT_SOLANA_TRANSACTION_SIGNING`, `CLIENT_ACCOUNT_NOT_FOUND`, or `CLIENT_DEPOSIT_SENDER_NOT_SIGNER`, yet the test files them under `structuredTransport` and `rustWorkflowBoundary`, buckets that read as produced. Derive the produced set from the package sources and reclassify or add a producer for those four codes. | 2026-07-25 re-review | `3ba52785`, `0a260feb`, `b230b314` |
| C03 | `sdk-libs/client/src/rpc.rs` | `client/src/rpc.ts` | needs_fix | DIVERGENT | proposed | TypeScript `Rpc` exposes only 11 of 30 blocking capabilities, reduces account, send, and confirmation semantics, handles JSON integers, envelopes, and errors lossily, and incompletely decodes versioned transactions, loaded addresses, and outer and inner instructions. Retries, subscriptions, prove results, constants, root exports, and current fixture, declaration, browser, pack, and live evidence are missing. First use `Address` in Rust, make transaction construction fallible, and restore trait capability symmetry; then align the TypeScript surface, semantics, decoding, errors, exports, and evidence. | 2026-07-25 review | - |
| C04 | `sdk-libs/client/src/indexer.rs` | `client/src/indexer.ts` | needs_fix | DIVERGENT | proposed | Inherited C01 retry-contract divergence retries fatal indexer failures and converts exhausted transient causes into false lag reports; full-width `u64` responses are rejected; the API accessor and trace toggle are absent; fixture evidence predates the active retry integration. | 2026-07-25 re-review | `7cb3acda` |
| C05 | `sdk-libs/client/src/solana_rpc.rs` | `client/src/solana-rpc.ts` | needs_fix | DIVERGENT | proposed | `SolanaRpc.sendTransaction` returns before confirmation while Rust sends and confirms; `extractOutputViewTags` drops `meta.loadedAddresses`, scans the outer instructions ahead of the inner ones, and accepts transactions Rust rejects for missing inner-instruction metadata or an unmatched group index. The bounded confirmation retry, `assertExecutable`, `airdrop`, the confirmed-transaction and instruction-group accessors, and the promised `fixtures/client/solana_rpc.json` are absent. Confirm after send, append loaded addresses, restore per-group scan order and rejection rules, add the bounded retry, and pin the behavior with a current-Rust fixture. | 2026-07-25 review | - |
| C06 | `sdk-libs/client/src/prover/field.rs` | `client/src/internal.ts` | needs_fix | PARTIAL | proposed | Right-alignment and big-endian conversion behavior is reproduced by `internal.ts::{bytesField, bytesToBigInt}`, but the Rust module is public (`zolana_client::prover::field`) while the inventory records it as internal and points at a nonexistent `src/prover/field.ts`. The promised `fixtures/client/field.json` is absent and neither language tests the over-32-byte rejection. Record a disposition for the public Rust module, correct the inventory target, and add a current-Rust fixture covering alignment, the 32-byte boundary, and rejection. | 2026-07-25 review | - |
| C07 | `sdk-libs/client/src/prover/inputs.rs` | `client/src/prover/types.ts` | needs_fix | PARTIAL | proposed | The five transfer and merge witness types map field for field, but the crate-root `BatchAddressAppendInputs` has no TypeScript counterpart or recorded omission, `MergeInputs` is declared yet exported from no package subpath, and `TransferInput::new_dummy` has no public constructor. Add or justify the address-append type, export `MergeInputs` from `@zolana/client/prover`, and extend the `proof-input-v1` oracle beyond its single dummy case. | 2026-07-25 review | - |
| C08 | `sdk-libs/client/src/prover/proof.rs` | `client/src/prover/proof.ts` | needs_fix | DIVERGENT | proposed | The frozen valid and malformed proof vectors match, but `CompressedProof` has no `toP256Proof`, so the missing-commitment rejection that `proof-result-compression-v1.json` pins as `ProofParse` is raised from `client.ts` as `CLIENT_MERGE_PROOF_COMMITMENT`; `parseProof` rejects unprefixed, unparsable, and out-of-range coordinates and unknown fields that Rust accepts or silently zeroes; and `CLIENT_PROOF_POINT` and `CLIENT_PROOF_RAIL_MISMATCH` have no Rust variant. Add `toP256Proof` under the pinned code, decide which side owns coordinate strictness, and record the two added codes. | 2026-07-25 review | - |
| C09 | `sdk-libs/client/src/prover/json.rs` | `client/src/prover/client.ts`, `merge.ts` | needs_fix | PARTIAL | proposed | The two confidential request bodies match a Rust-generated oracle across 20 shape and rail cases, but `proverRequest` emits no `transfer-zone`, `transfer-p256-zone`, or `transfer-zone-authority` circuit type and nothing emits `address-append`, so four of the eight Rust request shapes have no TypeScript path. The merge body is checked against a hand-written key list on both sides rather than a shared oracle. Add the missing circuit types or record their omission, and capture a Rust merge request body as a fixture. | 2026-07-25 review | - |
| C10 | `sdk-libs/client/src/prover/transact/witness.rs` | `client/src/prover/assembly.ts` | needs_fix | DIVERGENT | proposed | The witness and instruction data agree on 20 frozen shape and rail cases, but `assembly.ts` takes the instruction's `p256SigningPkX` and the shared owner field from the caller's signature while `assemble` takes both from the first P256-owned input's owner, rejects a surplus proof that Rust ignores, reports a short proof list under a different code, and assigns the dummy signer index by a running real-input counter where Rust indexes by absolute slot. Derive the signing key from the input owner, align the two proof-count errors, and fix the slot indexing on the Rust side. | 2026-07-25 review | - |
| C11 | `sdk-libs/client/src/prover/transact/eddsa.rs` | `client/src/prover/assembly.ts` | needs_fix | PARTIAL | proposed | The Solana-only payload, its zeroed P256 members, and the public-input chain match a Rust-captured oracle across 10 shapes, but the public `TransferProver` and `TransferProofResult` have no TypeScript counterpart, so `nullifiers`, `outputHashes`, `privateTxHash`, `inputRootIndexes`, and `publicInputHash` are unreachable, and `CLIENT_EDDSA_INPUT_NOT_SOLANA_OWNED` is declared with no throw site. Expose the build result or record its omission, and either raise the declared code or drop it. | 2026-07-25 review | - |
| C12 | `sdk-libs/client/src/prover/transact/p256_and_eddsa.rs` | `client/src/prover/assembly.ts` | needs_fix | DIVERGENT | proposed | Input and output assembly, the five owner modes' observable branches, and the P256 payload match the Rust-captured oracle, but `assembly.ts::p256Y` recovers the y coordinate by modular square root without the curve check that `internal.ts::p256Coordinates` and `P256Owner::witness` both perform; `findPublicSplAsset` re-derives the public SPL asset with a local scan that skips dummy slots and omits the uniqueness check `public_amounts` performs; and `P256Owner`, `PublicAmounts`, `TransferSpendInput`, `TransferP256Prover`, and `TransferP256ProofResult` have no TypeScript counterpart. | 2026-07-25 review | - |
| C13 | `sdk-libs/client/src/prover/transact/zone_eddsa.rs` | `client/src/prover/assembly.ts` | needs_fix | MISSING | proposed | `ZoneTransferProver` and `ZoneTransferProofResult` have no TypeScript counterpart: `inventory.json` promises `src/prover/transact/zone-eddsa.ts` and `fixtures/client/zone_eddsa.json`, and neither exists. `proverRequest` cannot emit `transfer-zone`, and the anonymous 13-element public-input chain is implemented nowhere. Port the builder with its own chain and add the promised Rust-generated fixture, or downgrade the inventory disposition. | 2026-07-25 review | - |
| C14 | `sdk-libs/client/src/prover/transact/zone_p256.rs` | `client/src/prover/assembly.ts` | needs_fix | MISSING | proposed | `ZoneTransferP256Prover` and `ZoneTransferP256ProofResult` have no TypeScript counterpart: `inventory.json` promises `src/prover/transact/zone-p256.ts` and `fixtures/client/zone_p256.json`, and neither exists. Nothing emits `transfer-p256-zone`, and the `OwnerMode::Zone` sentinel that keeps P256 owners private is unimplemented. Port the builder with the zero-sentinel owner rule and add the promised fixture, or downgrade the inventory disposition. | 2026-07-25 review | - |
| C15 | `sdk-libs/client/src/prover/transact/mod.rs` | `client/src/prover/index.ts` | needs_fix | PARTIAL | proposed | Of the 16 symbols this module re-exports, 5 reach TypeScript (`assemble`, `intoProver`, `AssembledTransfer`, `ProverInputs`, `SpendProof`); the 11 prover and result types do not, the promised `src/prover/transact/index.ts` does not exist, and the queue points at `prover/index.ts` instead. Record a disposition per omitted symbol and correct the inventory target. | 2026-07-25 review | - |
| C16 | `sdk-libs/client/src/prover/merge.rs` | `client/src/prover/merge.ts` | needs_fix | PARTIAL | proposed | The merge payload, the verifiable encryption, the generator fallback, and the 11-element public-input chain match the frozen merge fixture, but `MergeAssembly` omits `publicInputHash`, `externalDataHash`, `ciphertext`, `txViewingPublicKey`, and `zoneInstructionData`, the per-input owner field is taken from the prepared signing key instead of each input's own owner as `OwnerMode::Merge` does, and the promised `fixtures/client/merge.json` is absent. Add the missing accessors, take the owner field per input, and generate the fixture. | 2026-07-25 review | - |
| C17 | `sdk-libs/client/src/prover/merge_zone.rs` | `client/src/prover/merge.ts` | needs_fix | PARTIAL | proposed | The zone branch of `merge.ts` reproduces the 10-element chain, the zone tag, and the zone payload member, but `MergeZoneProver` and `MergeZoneWitness` have no counterpart, the promised `src/prover/merge-zone.ts` and `fixtures/client/merge_zone.json` are absent, and `assembleMergeZoneWithProofs` skips the zone check that lives in `inputUtxoHashes`, where Rust stamps the zone on each proofed input and the output. Run the zone check on both entry points and add the fixture. | 2026-07-25 review | - |
| C18 | `sdk-libs/client/src/prover/zone_authority.rs` | `client/src/prover/assembly.ts` | needs_fix | MISSING | proposed | `ZoneAuthorityProver`, `ZoneAuthorityProofResult`, and `ZoneAuthorityWitness` have no TypeScript counterpart: the promised `src/prover/zone-authority.ts` and `fixtures/client/zone_authority.json` do not exist and nothing emits `transfer-zone-authority`. The transaction and interface packages already carry `PreparedZoneAuthority` and the instruction builder, so the pipeline stops at proving. Port the builder with the anonymous 12-element chain, or downgrade the inventory disposition. | 2026-07-25 review | - |
| C19 | `sdk-libs/client/src/prover/client.rs` | `client/src/prover/client.ts` | needs_fix | DIVERGENT | proposed | The request path, the 3-attempt retry, the job-handle detection, and the completed and failed status handling match, but TypeScript sets no request timeout where Rust caps a prove at 600 s, retries 408, 425, 429, and 5xx where Rust fails fast on any non-success status, exposes 2 of the 8 prove entry points, and drops `AsyncPollConfig`, `ProverClient.local()`, `SERVER_ADDRESS`, and `PROVE_PATH`. Add a default timeout, align the retry rule, and expose or record the six missing entry points. | 2026-07-25 review | - |
| C20 | `sdk-libs/client/src/prover/mod.rs` | `client/src/prover/index.ts` | needs_fix | PARTIAL | proposed | Of the 39 names this module re-exports, 10 reach `@zolana/client/prover`; the 29 absent ones are the prover, result, and witness types from C13 to C18, the transport constants, `MergeInputs`, `BatchAddressAppendInputs`, `Commitments`, `CompressedCommitments`, `SPP_SUPPORTED_SHAPES`, and `ProofInputUtxo`. The subpath has no export-vector fixture, so no frozen evidence would catch a dropped or added name, and `canonicalShape` and `resolveShape` are re-declared wrappers returning a widened shape type instead of `Shape`. Add an export-vector fixture for the subpath, record a disposition per absent name, and return `Shape` from the two wrappers. | 2026-07-25 review | - |
| C21 | `sdk-libs/client/src/client.rs` | `client/src/client.ts` | todo | - | none | - | - | - |
| C22 | `sdk-libs/client/src/lib.rs` | `client/src/index.ts` | needs_fix | DIVERGENT | proposed | The crate root re-exports `DEFAULT_TRANSACT_CU_LIMIT`, `RetryErrorCause`, the 42-name `pub use prover::{..}` block, `rpc::{OutputContext, OutputSlot, ProveResult, ShieldedTransaction, NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT}`, `solana_rpc::ConfirmedInstructionGroups`, and 17 `zolana_transaction` names; `index.ts` carries none of them. `DEFAULT_TRANSACT_CU_LIMIT` (`client.ts:42`), `MERGE_INPUTS` (`prover/merge.ts:31`), and both tree heights (`prover/assembly.ts:34-35`) exist as module-private constants, and the prover block is reachable only from `@zolana/client/prover`, so `import { ProverClient } from "@zolana/client"` fails where `use zolana_client::ProverClient` succeeds. In the other direction `index.ts` exports 19 names absent from `public-exports.md`, including `CANONICAL_CLIENT_ERROR_CODES`, `ClientErrorCause`, `ProvedMergeZone`, `RpcAccount`, and the nine retry names, and the ledger still declares `ClientError.code` as `` `CLIENT_${string}` `` with `cause?: unknown`. Nothing detects either direction: `test:exports` and `api:check` verify the export map and scaffolding rather than the symbol set, and the `fixtures/client/lib.json` that `inventory-client.md` requires does not exist. Re-export or record a disposition for each crate-root name, reconcile the ledger with the shipped surface, and generate the root export fixture with a test that asserts each entry. | 2026-07-25 review | - |

### Wallet, 9 rows

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| W01 | `sdk-libs/wallet/src/actions/create_associated_token_account.rs` | `wallet/src/submit.ts` | needs_fix | PARTIAL | proposed | Instruction bytes, the derived address, and the compiled message match the Rust-generated `wallet/create_associated_token_account.json` oracle, but the TS owner is `submit.ts`, not the `wallet/src/actions.ts` the queue and `inventory.json` name. `Transaction::new` panics when the payer does not cover every required signature while `createAssociatedTokenAccount` forwards whatever `payer.signNativeTransaction` returns unchecked, and `wrapWalletError("WALLET_CREATE_ASSOCIATED_TOKEN_ACCOUNT", ...)` buries the `ClientError` code one `cause` level deep where Rust returns it directly. Correct the inventory and queue path, reject a returned transaction whose signature set is incomplete before `sendTransaction`, and preserve the client error code on the wrapper. | 2026-07-25 review | - |
| W02 | `sdk-libs/wallet/src/actions/deposit.rs` | `wallet/src/deposit.ts` | needs_fix | DIVERGENT | proposed | `createDeposit` rejects inputs `Deposit::new` accepts: `WALLET_INVALID_AMOUNT` on `amount == 0` and `WALLET_UNEXPECTED_SPL_TOKEN_ACCOUNT` on a SOL deposit carrying a token account, which `spl_accounts` silently ignores. The public `deposit` (build, sign with payer and depositor, send) exported by `actions/mod.rs` has no TypeScript counterpart, and `deposit-vector.test.ts` constructs `Deposit` from `fixture.inputs.ownerBytes` and the expected hash instead of calling `createDeposit`, so `owner_hash` and `ProofInputUtxo::new(..).hash()` derivation has no oracle. Accept the Rust input domain, add or record a disposition for `deposit`, and drive the vector test through `createDeposit` from the recipient address. | 2026-07-25 review | - |
| W03 | `sdk-libs/wallet/src/actions/submit.rs` | `wallet/src/submit.ts` | needs_fix | PARTIAL | proposed | The merge submission flow, the `MERGE_CU_LIMIT` of `1_400_000`, and the merging-disabled rejection align, but `ensure_proofs_match_submit_tree` validates every indexer-returned proof's `state_tree` and `nullifier_tree` against the submit tree while `submitMergeTransaction` only compares its own configured tree, so a mismatched indexer response reaches the prover. `validate_merge_submission`'s distinct signing-curve, viewing-key, and nullifier-key rejections collapse into one `WALLET_MERGE_MATERIAL_MISMATCH`, `MergeMaterial` carries `nullifierKey` where the Rust struct deliberately holds no signing or viewing secret, and the declared `proverUrl` is unused. Validate the returned proof trees, split the mismatch codes, and remove the unused field and the widened secret. | 2026-07-25 review | - |
| W04 | `sdk-libs/wallet/src/actions/transaction.rs` | `wallet/src/private-transaction.ts`, `actions.ts` | needs_fix | DIVERGENT | proposed | `applyP256Signature` picks the rail from the input UTXO owners (`inputUtxos.some(... signatureType() === "p256")`) while `apply_p256_signature` picks it from the authority's own `address.signing_pubkey.signature_type()`, so a wallet spending notes on the other rail signs differently than Rust. `matchingInput` re-checks only the hash, nullifier, asset, amount, and blinding, while `validate_unsigned_inputs` compares the whole `Utxo` plus `data_hash` and `zone_data_hash`, so a substituted owner, zone program, or note payload survives the create-to-sign guard. `create_split` returns `SplitInputZoneMismatch` for a zone-bound note and `SplitInputHasData` for a data-carrying one; `createSplit` collapses both into `WALLET_SPLIT_INPUT_HAS_DATA`. `WALLET_MULTIPLE_INPUT_TREES` lists every tree address in `details` where `AmbiguousTree` reports a count. Take the rail from the authority address, compare the full note in the re-check, split the two rejections, and report a count. | 2026-07-25 review | - |
| W05 | `sdk-libs/wallet/src/actions/mod.rs` | `wallet/src/actions/index.ts` | needs_fix | PARTIAL | proposed | The `expected.exports` allowlist in `fixtures/wallet/mod.json` is a hand-curated nine of the thirty names `actions/mod.rs` re-exports, and `export-vector.test.ts` maps only those nine, so the frozen evidence cannot detect a dropped export. `actions/index.ts` omits `deposit`, `ResolvedAddress`, and the four `_sync` adapters, and adds `MergeMaterial` and `TransactionSigner`, which the Rust module does not export. The `expected.routing` block is never asserted. Regenerate `mod.json` from the actual re-export list, assert every entry, record a JavaScript disposition for the blocking adapters, and reconcile the two extra names. | 2026-07-25 review | - |
| W06 | `sdk-libs/wallet/src/wallet_authority.rs` | `wallet/src/wallet-authority.ts` | needs_fix | DIVERGENT | proposed | The Rust file only re-exports ten names from `zolana_transaction`. `wallet-authority.ts` instead declares `ApprovalRequest`, `WalletAuthority`, and `LocalWalletAuthority` inside `@zolana/wallet`, so `WalletAuthority` exists twice with two structurally similar declarations and `LocalWalletAuthority` is unreachable from `@zolana/transaction`, inverting the Rust ownership. `AnonymousRecipientSlot`, `EncryptedEnvelope`, `EncryptedSplit`, `EncryptedTransfer`, `P256Signature`, `SyncWalletAuthority`, and `WalletSyncMaterial` are absent from the wallet package. Re-export the ten names from `@zolana/transaction` and delete the duplicate declarations; the missing `encryptAnonymousTransfer` capability on both declarations is the already-recorded T13 gap. | 2026-07-25 review | - |
| W07 | `sdk-libs/wallet/src/user_registry.rs` | `wallet/src/registry.ts` | needs_fix | DIVERGENT | proposed | `resolveRegisteredAddress` reads `record.viewingPublicKey` directly, while `resolved_address_from_record` goes through `UserRecord::sender_viewing_pubkey()`, which returns the last `entries` viewing key whenever `sync_delegate` is set. A transfer to a recipient with an active sync delegate is therefore encrypted to a viewing key neither the delegate nor, per the Rust design, the recipient expects. Only four of the seventeen public Rust functions have counterparts: `ensure_registered`, `register_if_absent`, `fetch_user_record_checked`, `validate_registered_keypair`, `recipient_confidential_view_tag`, `resolved_address_from_record`, `decode_user_record_account`, and the `try_resolve_*` pair are absent, and `lib.rs` documents `try_resolve_registered_address_async` as the recommended explicit lookup. `registry.ts` also reimplements the curve check, the SHA-256 PDA derivation, the seed, and the program id instead of using the interface package. Route the viewing key through the delegate rule, add the missing functions, and derive the PDA from the interface helpers. | 2026-07-25 review | - |
| W08 | `sdk-libs/wallet/src/wallet_sync.rs` | `wallet/src/sync.ts` | needs_fix | DIVERGENT | proposed | `syncWallet` builds sender and recipient-request tags over `0..tagWindow` only, dropping the `tx_count` and `request_count` offsets `wallet_query_tags` adds, and omits `get_recipient_shared_view_tag` and `get_send_shared_view_tag` entirely, so paired-counter transfers are never queried and their notes stay invisible. It also skips Rust's proofless filter on `get_shielded_transactions_by_tags`, so a deposit surfaced by both indexer endpoints is collected twice under different keys; it feeds `decryptTransactions` in map-insertion order where Rust sorts by `(slot, signature)` then by first output tree and leaf index; `waitForIndexer` reduces to a no-op `continue` and no `IndexerPollConfig` reaches the indexer; and `positiveInteger` rejects configurations `normalized_config` clamps. Add the counter offsets and the two shared-tag families, restore the filter and the sort, wire the poll config, and clamp rather than reject. | 2026-07-25 review | - |
| W09 | `sdk-libs/wallet/src/lib.rs` | `wallet/src/index.ts` | needs_fix | PARTIAL | proposed | The documented five-step flow, the four module groupings, and the nested client-over-transaction error shape are represented and pinned by `fixtures/wallet/lib.json`. Of the fifty-two names the crate root re-exports, `index.ts` omits nine registry functions, seven authority types, `deposit`, and the seven `_sync` adapters, and adds `WalletError`, `MergeMaterial`, and `TransactionSigner`. `WalletError` is the package-level divergence behind several rows: Rust has no wallet error type and returns `ClientError` and `TransactionError` unchanged, while the TypeScript code prefixes its own `WALLET_${string}` template with no closed union and no canonical code list, so every wrapped call loses the original code to a `cause`. Publish a closed `WalletError` code union that preserves the wrapped code, and close the export gaps or record a disposition for each. | 2026-07-25 review | - |

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
- [ ] A browser-capable package executes its vector suites in a headless browser engine. The static
      forbidden-import scan in `browser-check.mjs` does not satisfy this gate
      ([G9-4](production-readiness-issues.md#g9-4-browser-support-is-checked-statically-not-in-a-browser-medium)).
- [ ] Each public accessor that returns secret-adjacent bytes has an aliasing test that mutates the
      returned buffer and asserts internal state is unchanged
      ([G6-2](production-readiness-issues.md#g6-2-defensive-copy-discipline-is-not-uniformly-verified-medium)).
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
- [ ] Full CI, fixture regeneration, browser, packed-package consumer, action
      E2E, and instruction E2E commands pass from a clean checkout.
- [ ] A repository workflow runs the TypeScript merge tier on pull requests. A gate in this section
      is not satisfied by a local run
      ([G9-1](production-readiness-issues.md#g9-1-no-workflow-runs-the-typescript-suite-blocker)).
- [ ] The merge tier runs the cross-language, prover, browser, fixture, packed-package, and
      package-lint suites, and the aggregate `check` script states the scope it actually has
      ([G9-2](production-readiness-issues.md#g9-2-the-aggregate-check-script-omits-most-certification-gates-blocker)).
- [ ] `sdk-libs/ts/fixtures/manifest.json` states a compatibility rule and a regeneration trigger per
      revision key, and a check rejects a fixture consumed against an incompatible pin
      ([G8-1](production-readiness-issues.md#g8-1-the-manifest-pins-multiple-source-revisions-high)).
- [ ] Each proof fixture records the verifying-key module and its SHA-256, and the gate fails when
      that identity differs from the key the verifier loads
      ([G8-2](production-readiness-issues.md#g8-2-verifying-key-provenance-is-not-tied-to-the-fixtures-high)).

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

Review work is read-only except for this checklist. This loop may implement
findings only when its invocation explicitly authorizes fixes. Fixes use the
selective commit and independent re-review workflow above.

At each wake:
1. Refresh HEAD, fixture frozenCommit, Rust drift, dirty paths, active fix
   ownership, progress counts, and commits for in_progress rows.
2. When an in_progress fix has a selective commit, mark it needs_re_review.
   Skip a row while its worker still has uncommitted changes.
3. Select the lowest queue ID marked needs_re_review. If none exists, select the
   lowest queue ID marked todo. Process no other review row.
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
8. After the 118 rows have been reviewed, implement authorized actionable
   needs_fix rows in queue order and independently re-review each commit.
   Resolve specification-authority blockers before changing their verdicts.
9. Check package gates in package order and full SDK gates in listed order,
   including full CI, fixture regeneration, browser, packed-package consumer,
   action E2E, and instruction E2E commands. Reopen the lowest responsible row
   for a failed gate.
10. After those gates pass, execute PKP-00 through PKP-08 from
    planning/typescript-sdk-port/proof-and-key-parity.md. Do not claim complete
    proof or key parity until native Rust verification and real
    TypeScript-driven prove-to-chain local-stack evidence pass.

Stop only when the 118 rows are done with PARITY or justified NOT_APPLICABLE,
each of the nine package gate sets passes, the full SDK gate set passes, and
PKP-00 through PKP-08 have reproducible evidence. Per-file completion alone
must not produce a full SDK, proof, or key-handling parity claim.
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

### 2026-07-24 17:00 UTC | I01 | `program-libs/interface/src/error.rs`

- Baseline: HEAD `30367f31136d7e9cf6aa3e5553ad32fa2769e934`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: GPT-5.6 Sol review subagent; implementation commit `none`
- Explanation: This public interface module defines caller-side `InterfaceError` values and the 26 `ShieldedPoolError` variants that the Solana program returns as `ProgramError::Custom(u32)`. It imports `solana_program_error`, `thiserror`, and feature-gated `zolana_tree`; `program-libs/interface/src/lib.rs` exposes the module as `zolana_interface::error`. The direct conversion preserves each numeric discriminant, while the `InterfaceError` and `TreeError` conversions select program categories used by account and tree flows. The TypeScript root exports its separate caller-side `InterfaceError` and a type-only `ShieldedPoolErrorCode`, but no runtime program-error value or decoder. The package grants no signing, viewing, or nullifier capability.
- Evidence: `docs/spec.md` does not define an error taxonomy, so `program-libs/interface/src/error.rs` is the canonical authority. The frozen and current Rust files have the same SHA-256, and no scoped Rust source changed after the fixture freeze. The Rust stability table pins each variant from `InvalidInstructionData = 7000` through `OwnerTagAccountMissing = 7025`; the TypeScript union contains exactly the same numeric range. `From<ShieldedPoolError> for ProgramError` casts the selected variant to `ProgramError::Custom`. Current workflow fixtures cover only `NullifierTreeUpdateFailed = 7002` and `InvalidSettlementAccounts = 7009`, and their TypeScript acceptance assertions also compare Rust display strings. No interface fixture or test pins the 26 named mappings, malformed input, or unknown custom codes. `SolanaRpc.#call` classifies JSON-RPC error envelopes as `CLIENT_RPC_ENVELOPE`, and `confirmTransaction` reduces status errors to `false`, so neither boundary exposes a shielded-pool code. The public TypeScript-only `InterfaceError` uses string codes and is not presented as a Solana program error. `rustup run 1.97.0 cargo test -p zolana-interface error_codes_are_stable` passed 1 test. Interface typecheck, API check, 15 unit tests, 1 vector test, and browser check passed.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/ts/interface/src/index.ts::ShieldedPoolErrorCode` is type-only, and `sdk-libs/ts/interface/src/errors.ts` has no named map, structured program-error type, guard, or strict decoder. Add those exports, generate a current-Rust fixture for the 26 name/code pairs, test malformed and unknown-code behavior, and update `sdk-libs/ts/client/src/solana-rpc.ts::SolanaRpc.#call` and confirmation handling to preserve recognized and raw unknown custom instruction codes without treating `InterfaceError` as a program error.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I02 program-libs/interface/src/shape.rs`
- Full SDK parity claim: unsupported; the interface error gate, eight package row sets, 20 client rows, and the cross-package gates remain incomplete

### 2026-07-24 17:21 UTC | I02 | `program-libs/interface/src/shape.rs`

- Baseline: HEAD `e035eb7127b36895e8c3d3423e1d8874bf55ced7`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`; the worktree was clean before the checklist claim
- Worker: GPT-5.6 Sol review subagent; implementation commit `none`
- Explanation: This dependency-free public module defines the `Shape` value, ten named constants, count accessors, and the ordered `SPP_SUPPORTED_SHAPES` authority. `program-libs/interface/src/lib.rs` exposes it as `zolana_interface::shape`; the transaction crate re-exports it and searches the list for the first shape whose capacities hold the real counts. The set is `1x1, 1x2, 2x2, 2x3, 3x3, 4x3, 4x4, 5x3, 5x4, 1x8`, with five as the largest input capacity and eight as the largest output capacity. Both EdDSA and P256 use this set, while proof encoding keeps standard Groth16 and BSB22 commitment data separate. `@zolana/interface` exports no shape API. `@zolana/transaction` contains a duplicate table and exposes lookup functions through its instruction and transact subpaths; its package root exposes the functions but omits the shape type and table.
- Evidence: `docs/spec.md` lists the same ten transaction shapes and both ownership rails. The Go `SupportedShapes` and prover `transferSupportedShapes` authorities match the Rust set and order; the verifier path named in contributor guidance does not exist, and the former `sdk-libs/client/src/shape.rs` authority now lives in interface and transaction. Go tests cover exact, empty, padded, boundary, unsupported, negative, and ordering cases. Rust `canonical_shape` selects `0x1 -> 1x1`, `0x2 -> 1x2`, `1x0 -> 1x1`, `0x8 -> 1x8`, and rejects pairs including `6x1`, `1x9`, `2x8`, and `5x5`; declared shapes return `UnsupportedShape`, `TooManyInputs`, or `TooManyOutputsForShape` with count details. TypeScript uses corresponding structured transaction codes for supported positive counts, but `checkedCount` rejects zero and the declared path does not validate negative or fractional real counts. The Rust-generated `client/prover-shapes-v1.json` fixture records the ten shapes in order for both rails, and its vector suite checks 20 complete proof-input and instruction-byte cases. Fixture regeneration is capable of detecting a stale table and passed against current Rust. The shape source has the same Git object as the frozen revision. Rust interface tests passed 25 tests, although none target `shape.rs`; the focused Rust transaction library command passed one matching test and exposed no selection test. Go protocol shape tests passed. Interface build, typecheck, 15 unit tests, one vector test, browser check, and API check passed. Transaction build, typecheck, 28 unit tests, five vector tests, browser check, and API check passed after dependencies were built. Client vectors passed 30 tests. Fixture verification passed 57 fixtures and 182 inventory rows. The checklist-only checkpoint failed because GPG signing required interactive pinentry; hooks and signing were not bypassed.
- Verdict: `DIVERGENT`
- Gap and smallest fix: `sdk-libs/ts/interface/src/index.ts` and `internal.ts` omit the public Rust `Shape` and `SPP_SUPPORTED_SHAPES` API. `sdk-libs/ts/transaction/src/instructions/transact.ts::SPP_SUPPORTED_SHAPES` duplicates that authority with mutable element objects, and `canonicalShape` conflicts with Rust on zero counts. Export one deeply immutable authority from interface, import it in transaction, accept safe non-negative counts including zero, validate declared-path counts, and pin exports, exact order, mutation resistance, empty and boundary lookup, unsupported pairs, and error details against a current-Rust fixture.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I03 program-libs/interface/src/merge_utils.rs`
- Full SDK parity claim: unsupported; I01 and I02 have adverse interface verdicts, eight package row sets remain incomplete, and cross-package gates have not passed

### 2026-07-24 23:38 UTC | I03 | `program-libs/interface/src/merge_utils.rs`

- Baseline: HEAD `9f00d180fa5cdea8128a9251aa2d91ec88781da1`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`; review began at `e035eb71`, then the signed checklist-only I02 checkpoint advanced HEAD without changing source evidence
- Worker: GPT-5.6 Sol review subagent; implementation commit `none`
- Explanation: This public, `no_std`-compatible interface module centralizes four merge proof field operations for the Solana program. It depends only on `zolana_hasher`'s Poseidon implementation and error type, and `program-libs/interface/src/lib.rs` exports it as `zolana_interface::merge_utils`. `pk_field_compressed` hashes the low and high 128-bit x-coordinate limbs and then includes the compressed key's y parity. `owner_pk_field_compressed` uses the same limb order but omits parity for the owner identity. Both accept a fixed 33-byte SEC1 encoding and reject prefixes other than `0x02` and `0x03`; they do not validate that x identifies a curve point. `pack33` splits a compressed key into a zero-prefixed 31-byte low limb and a two-byte high limb. `ciphertext_hash` right-aligns consecutive 16-byte big-endian chunks and hashes the resulting fields. The default and policy-zone merge verifier uses the packing and ciphertext hash; registry loading uses the parity-free owner field. The utility does not select input counts, assets, trees, or owner rails. Those checks belong to the merge instruction and circuit. The TypeScript keypair package consolidates the valid-flow field, packing, and ciphertext behavior, but the interface package exports none of these public Rust responsibilities.
- Evidence: `docs/spec.md` does not name these helper APIs. The current Rust file, scoped Rust trees, and relevant source dependencies have no drift from the fixture commit. The Go `Pack33To2FECircuit`, `PackBytesBE`, `OwnerPkField`, and `P256PkField` implementations confirm the byte order and parity split. Rust tests pin one 71-byte circuit ciphertext hash, one 33-byte split, bad prefixes, and parity separation; the focused command passed 4 tests. TypeScript's `ShieldedPublicKey.hash`, `ownerPublicKeyField`, `pack33`, and `mergeCiphertextHash` reproduce the valid-flow math. Keypair unit tests passed 26 tests and vectors passed 12. The merge fixture pins the 71-byte hash, packed viewing key, and one tampered hash, while the hash fixture pins one P256 owner field and public hash. Both fixtures cite keypair Rust sources, not `program-libs/interface/src/merge_utils.rs`. Interface typecheck and API checks passed, but the API report cannot cover omitted exports. No interface fixture or test covers these symbols, fixed-length rejection, both valid prefixes on the same x-coordinate, chunk lengths around 16 bytes, or the Rust Poseidon cardinality boundary. The public TypeScript `pack33` accepts arbitrary lengths through `subarray`, and its P256 object path validates the curve point, so neither is an exact raw-input substitute.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/ts/interface/src/internal.ts`, `index.ts`, and `package.json` expose no counterparts for `program-libs/interface/src/merge_utils.rs::{pk_field_compressed, owner_pk_field_compressed, pack33, ciphertext_hash}`. Add a browser-safe interface merge-utility entry point with structured interface errors and current-Rust vectors for the named success and rejection boundaries, then reuse that implementation from `sdk-libs/ts/keypair/src/hash.ts` and `merge/core.ts` so the protocol math has one TypeScript authority.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I04 program-libs/interface/src/pda.rs`
- Full SDK parity claim: unsupported; I01 through I03 have adverse interface verdicts, eight package row sets remain incomplete, and cross-package gates have not passed

### 2026-07-25 00:44 UTC | I04 | `program-libs/interface/src/pda.rs`

- Baseline: HEAD `d420822d0b1581d1295a84ded78e3c3d9b9c0145`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`; the worktree was clean before the checklist claim
- Worker: GPT-5.6 Sol review subagent; implementation commit `none`
- Explanation: This public interface module derives program and account addresses with `solana_pubkey::{Pubkey, PubkeyError}` and the IDs and seed bytes exported by `program-libs/interface/src/lib.rs`; `pub mod pda` exposes its public functions as `zolana_interface::pda::*`. The ID helpers convert the canonical SPP, CPI-authority, SPL Token, and Associated Token constants to 32-byte `Pubkey` values. The singleton flows derive protocol config from `["protocol_config"]`, SOL custody from `["sol_interface", [0]]`, and the asset counter from `["spl_asset_counter"]` under SPP. The CPI helper returns the pinned address whose defining constant uses `["cpi_authority"]` under SPP. Mint-keyed registry and vault flows append the mint's 32 address bytes. The associated-token flow uses `[owner, SPL Token program, mint]` under the Associated Token program. The SPP zone-config flow uses `["spp_zone_config", zone program]` under SPP, while the active zone authority and config account uses `["zone_auth"]` under the zone program. The two `_with_bump` helpers reconstruct either zone address with one supplied bump; account creation instead calls canonical `find_program_address`, and TypeScript accepts no user bump. These addresses separate signing capabilities: SPP can sign for its SOL custody, SPL vault, protocol, and CPI PDAs; a zone program can sign for its own `zone_auth` PDA; an associated token account is derived under the Associated Token program. The TypeScript `Address` brand is the JavaScript form of the current Rust 32-byte address value and rejects noncanonical base58 before parameterized derivation.
- Evidence: `docs/spec.md` contains no PDA contract, so the current interface constants, helper order, program creation checks, and builders govern this row. Current `pda.rs` and `lib.rs` have the same SHA-256 as fixture commit `43fde8e4`, and none of the nine scoped Rust source trees drifted after the freeze. `programs/shielded-pool/src/instructions/zone_config/create.rs` derives `zone_auth` canonically from the zone program, requires that PDA to sign creation, and stores its bump; settlement and SPL creation paths derive the SOL interface and mint-keyed vault with the same seed order. `@zolana/interface/pda` exports eight browser-safe helpers through its package subpath. Its root exports the four program or pinned-address constants in place of Rust's conversion-only ID helpers. It derives canonical bumps internally and exposes only the bump returned by `zoneConfigAddress`; the instruction module privately duplicates the missing `zone_auth` derivation. TypeScript unit tests pin the eight implemented outputs for the zero address and reject one malformed registry mint, but no fixture cites `program-libs/interface/src/pda.rs`. The frozen fixture set contains no PDA oracle. Focused Rust PDA tests passed 2 tests, covering only the SOL-interface constant and associated-token formula. Interface build and typecheck passed; 15 unit tests, 1 unrelated fixture vector, browser subpath bundling, API scaffold, and workspace export-map checks passed.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/ts/interface/src/pda/index.ts` has no public counterpart for `program-libs/interface/src/pda.rs::zone_auth`, while `sdk-libs/ts/interface/src/instructions/index.ts::zoneAuthorityAddress` privately duplicates the exact seed flow. Export `zoneAuthAddress(zoneProgram)` with its canonical bump and reuse it in the builders. Keep `zone_config_with_bump` and `zone_auth_with_bump` out of creation-facing TypeScript APIs so callers cannot select bumps. Add a current-Rust fixture that cites `pda.rs` and covers the nine address flows, exact bytes and bumps, nonzero mint, owner, and zone inputs, malformed address positions, and bump boundaries; the existing hard-coded zero-address tests cannot detect a plausible stale seed, program ID, or edge-case curve check.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I05 program-libs/interface/src/instruction/instruction_data/batch_update_nullifier_tree.rs`
- Full SDK parity claim: unsupported; I01 through I04 have adverse interface verdicts, eight package row sets remain incomplete, and cross-package gates have not passed

### 2026-07-25 00:45 UTC | I05 | `program-libs/interface/src/instruction/instruction_data/batch_update_nullifier_tree.rs`

- Baseline: HEAD `e39561f675f30aff5f7f958b16fac18045dc6d4f`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`; the worktree was clean, and I04's checklist checkpoint was commit `e39561f6`
- Worker: GPT-5.6 Sol review subagent; implementation commit `none`
- Explanation: This public instruction-data module defines `BatchUpdateNullifierTreeData` and `CompressedProof`. It uses Borsh to encode an exact 194-byte payload in this order: 32-byte new root, 32-byte old root, little-endian `u16` batch index, and proof arrays `a[32]`, `b[64]`, and `c[32]`. The Rust builder prepends tag 51 for a 195-byte instruction. Exact decoding rejects shorter or longer payloads. `CompressedProof::default()` returns a zero-filled proof, and `to_array()` preserves `a`, `b`, `c` order. The inline TypeScript builder has the valid encoding flow and input checks, but the mapped codec module and public data and proof representations are absent.
- Evidence: `docs/spec.md` SHA-256 `d962f3e871cf8edee67cfbfd2f59f88320e1615f175e99c53f8275268162550c` is current. The canonical Rust source SHA-256 is `682914730c69ffb749e56e9d566c0e0b4e53f06a66e06aac750d105f901fa736`, with no relevant Rust or spec drift from the fixture freeze. Rust functional and Photon evidence exercise the payload, and the TypeScript package remains browser-safe. TypeScript tests assert only tag 51. No current-Rust fixture or provenance covers offsets, endianness, proof order, exact lengths, boundaries, or malformed decoding. No live tests ran for this completed review.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/ts/interface/src/codecs/index.ts` is absent, while `sdk-libs/ts/interface/src/instructions/index.ts::batchUpdateNullifierTreeInstruction` contains only inline encoding. Add public data and proof types, an exact 194-byte encoder and strict decoder reused by the builder, a current-Rust fixture with exact and rejection tests, and a documented JavaScript equivalent for the zero default and `to_array` order.
- Row transition: `todo -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I06 program-libs/interface/src/instruction/instruction_data/create_tree.rs`
- Full SDK parity claim: unsupported; I01 through I05 have adverse interface verdicts, eight package row sets remain incomplete, and the cross-package gates have not passed

### 2026-07-24 23:49 UTC | I06 | `program-libs/interface/src/instruction/instruction_data/create_tree.rs`

- Baseline: HEAD `d420822d0b1581d1295a84ded78e3c3d9b9c0145`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed parallel review agent; implementation commit `none`
- Explanation: This public instruction-data module defines `CreateTreeData` as one 32-byte owner. The Rust default builder prepends tag 5 and produces exactly 33 bytes. The TypeScript `createTreeInstruction` produces those default bytes correctly but duplicates the encoding inline and exports no public data type or standalone codec. Optional builder parameters belong primarily to I18, while canonical tree constants belong to I34. This row adds no signing, viewing, or nullifier capability.
- Evidence: The reviewer found no source drift from fixture commit `43fde8e4`. Existing TypeScript tests assert only tag 5. No current-Rust fixture proves owner bytes, exact length, truncation or extension rejection, invalid-address details, defensive byte ownership, or browser behavior. The reviewer completed source and evidence checks without reporting a test run.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/ts/interface/src/codecs/index.ts` is absent, and `sdk-libs/ts/interface/src/instructions/index.ts::createTreeInstruction` encodes the owner inline. Add a public data type and exact 32-byte codec reused by the builder, then add current-Rust exact and rejection vectors for the named boundaries.
- Row transition: `todo -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I07 program-libs/interface/src/instruction/instruction_data/deposit.rs`
- Full SDK parity claim: unsupported; I01 through I06 have adverse interface verdicts, eight package row sets remain incomplete, and the cross-package gates have not passed

### 2026-07-24 23:49 UTC | I07 | `program-libs/interface/src/instruction/instruction_data/deposit.rs`

- Baseline: HEAD `e39561f675f30aff5f7f958b16fac18045dc6d4f`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed parallel review agent; implementation commit `none`
- Explanation: This public instruction-data module defines the plain and zone deposit payloads. Declaration order is exact; integers use little-endian `u64` and `u16`, options use one byte, and byte vectors use a `u16` length. The plain minimum is 105 bytes. The zone minimum is 139 bytes plus `zone_data`. SOL and SPL use the same payload. Deposit discovery uses the viewing-key x-coordinate tag, not the confidential-transfer signing tag. The plain TypeScript codec matches current Rust and is reused by the builder. `UtxoData` lacks a named export, while the public zone type and codec are absent and the zone builder duplicates encoding.
- Evidence: The reviewer found no source drift from fixture commit `43fde8e4`. Tests and fixtures do not cover UTXO data, zone data, maximum `u16` lengths, malformed options, truncation, or extension; the zone test checks only tag 15. The reviewer ran no tests. `docs/spec.md` conflicts with current Rust and locked behavior on deposit layouts and signing-tag wording. The authority order makes this conflict a blocker that requires resolution; this review does not assume Rust wins.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/ts/interface/src/index.ts` does not export `UtxoData` or a zone deposit data type, and `sdk-libs/ts/interface/src/instructions/index.ts` duplicates zone encoding without a codec. Resolve the spec conflict first. If current Rust becomes authoritative, export `UtxoData` and `ZoneDepositInstructionData`, add and reuse the zone codec, and add current-Rust success and rejection vectors for the named boundaries.
- Row transition: `todo -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I08 program-libs/interface/src/instruction/instruction_data/merge_transact.rs`
- Full SDK parity claim: unsupported; I01 through I07 have adverse interface verdicts, the I07 authority conflict is unresolved, eight package row sets remain incomplete, and the cross-package gates have not passed

### 2026-07-25 00:18 UTC | I08 | `program-libs/interface/src/instruction/instruction_data/merge_transact.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed parallel review agent; implementation commit `none`
- Explanation: This public instruction-data module defines default merge transaction bytes. The TypeScript encoder matches the 668-byte payload and 669-byte tagged instruction, including the eight-input P256 BSB22 proof structure. The package does not expose the corresponding codec, decoder, constants, or external-data hash authority.
- Evidence: The reviewer found no relevant canonical drift from the frozen commit. Existing evidence does not assert an exact frozen instruction fixture, distinguish malformed from trailing bytes, or prove the output scheme prefix. The reviewer reported no test run.
- Verdict: `PARTIAL`
- Gap and smallest fix: Add a public codec and decoder, `MERGE_INPUT_COUNT`, `MERGE_ENCRYPTED_UTXO_LEN`, and canonical `MergeExternalDataHash`; reuse the hash in the client and add exact and rejection tests for the named gaps.
- Row transition: `todo -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I09 program-libs/interface/src/instruction/instruction_data/merge_zone.rs`
- Full SDK parity claim: unsupported; I01 through I08 have adverse interface verdicts, the I07 authority conflict is unresolved, and package and cross-package gates have not passed

### 2026-07-25 00:18 UTC | I09 | `program-libs/interface/src/instruction/instruction_data/merge_zone.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed parallel review agent; implementation commit `none`
- Explanation: This public instruction-data module defines zone merge bytes. The TypeScript encoder matches the exact 700-byte payload and 701-byte tagged instruction, including the 32-byte `merge_view_tag` and account-derived zone identity. The default client prove and assembly path also accepts `PreparedMergeZone`.
- Evidence: The reviewer found no relevant canonical drift from the frozen commit. The package has no public codec, decoder, or exact fixture. The accepted client path silently selects the default merge circuit, tag 12, zero `zoneProgramId`, and default instruction. The reviewer reported no test run.
- Verdict: `PARTIAL`
- Gap and smallest fix: Add the public codec and exact evidence. Implement dedicated zone assembly, prover, and submission paths, and reject `PreparedMergeZone` from the default path until those paths exist.
- Row transition: `todo -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I10 program-libs/interface/src/instruction/instruction_data/protocol_config.rs`
- Full SDK parity claim: unsupported; I01 through I09 have adverse interface verdicts, the I07 authority conflict is unresolved, and package and cross-package gates have not passed

### 2026-07-25 00:18 UTC | I10 | `program-libs/interface/src/instruction/instruction_data/protocol_config.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed parallel review agent; implementation commit `none`
- Explanation: This public instruction-data module defines protocol-config create, update, and pause bytes. TypeScript matches the current Rust builders. `docs/spec.md` says update rewrites each authority and flag, while Rust and TypeScript update one selected field.
- Evidence: The reviewer found no relevant canonical drift from the frozen commit. Public types, codecs, decoders, and current-Rust exact and rejection fixtures for the variants are absent. The reviewer reported no test run.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Resolve the spec and implementation authority conflict first. Then add canonical public codecs for the selected contract, reuse them from the builders, and add exact and rejection fixtures for each variant.
- Row transition: `todo -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I11 program-libs/interface/src/instruction/instruction_data/transact.rs`
- Full SDK parity claim: unsupported; I07 and I10 have unresolved authority conflicts, the interface row set is incomplete, and package and cross-package gates have not passed

### 2026-07-25 00:18 UTC | I11 | `program-libs/interface/src/instruction/instruction_data/transact.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed parallel review agent; implementation commit `none`
- Explanation: This public instruction-data module defines transaction payload types, hashing, tag resolution, output handling, and ownership-rail proof layouts. The core TypeScript codec matches current Rust and has strong shape and workflow byte evidence. The public surface and canonical helper reuse remain incomplete.
- Evidence: The reviewer found no relevant canonical drift from the frozen commit. The interface omits `fetch_tag`, `ResolvedOutput`, `ExternalDataHash::hash`, P256 proof `LEN`, and named `MessageData` and `OutputUtxo` exports. Transaction and client duplicate hashing and tag resolution, nested bytes are not defensively copied, and focused owner-tag, message, prefix, mutation, and adversarial vectors are absent. The reviewer reported no test run.
- Verdict: `PARTIAL`
- Gap and smallest fix: Add the canonical helpers and types, reuse them across transaction and client, copy nested bytes, and add the named focused vectors. I01 and I02 remain dependencies.
- Row transition: `todo -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I12 program-libs/interface/src/instruction/instruction_data/zone_config.rs`
- Full SDK parity claim: unsupported; I07 and I10 have unresolved authority conflicts, I01 and I02 remain dependencies, and package and cross-package gates have not passed

### 2026-07-25 00:18 UTC | I12 | `program-libs/interface/src/instruction/instruction_data/zone_config.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed parallel review agent; implementation commit `none`
- Explanation: This public instruction-data module defines zone-config create, owner-update, and enabled-update bytes. The TypeScript builders match current Rust bytes and account metas, but they duplicate encoding and do not expose strict public codecs or decoders.
- Evidence: The reviewer found no relevant canonical drift from the frozen commit and no direct spec conflict because the spec omits this contract. Public types, strict codecs, decoders, current-Rust exact fixtures, and rejection fixtures are absent. `test-kit::createZoneConfig` returns the `spp_zone_config` PDA instead of the created `zone_auth` PDA. The reviewer reported no test run.
- Verdict: `PARTIAL`
- Gap and smallest fix: Add public types, strict codecs and decoders, reuse them from the builders, and add current-Rust exact and rejection fixtures. Correct the test-kit return value by reusing the I04 `zone_auth` PDA fix.
- Row transition: `todo -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I13 program-libs/interface/src/instruction/instruction_data/mod.rs`
- Full SDK parity claim: unsupported; 12 rows need fixes, I07 and I10 have unresolved authority conflicts, and package and cross-package gates have not passed

### 2026-07-25 00:39 UTC | I14 | `program-libs/interface/src/instruction/builders/batch_update_nullifier_tree.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This public builder creates the nullifier-tree batch-update instruction. TypeScript matches current Rust tag 51, the 194-byte payload and 195-byte instruction, canonical IDs, and the authority, protocol-config, tree, and SPP-program account order and flags. It duplicates the I05 encoding.
- Evidence: The TypeScript test asserts only tag 51. The claimed named fixture is absent, and no current-Rust evidence checks exact bytes, account metas, `u16` boundaries, malformed inputs, or defensive copies. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Reuse the I05 codec in `sdk-libs/ts/interface/src/instructions/index.ts::batchUpdateNullifierTreeInstruction`, then add a current-Rust fixture with exact instruction, account-meta, rejection, and copy tests.
- Row transition: `todo -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I13 program-libs/interface/src/instruction/instruction_data/mod.rs`
- Full SDK parity claim: unsupported; 13 rows need fixes, I07 and I10 have unresolved authority conflicts, and package and cross-package gates have not passed

### 2026-07-25 00:39 UTC | I15 | `program-libs/interface/src/instruction/builders/create_asset_counter.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This public builder creates the asset-counter instruction. TypeScript matches current Rust tag 16, the canonical program ID, and the authority, protocol-config, counter, and system-program account order and flags. The builder accepts no bump or defaults, and the processor derives the canonical PDA.
- Evidence: The claimed fixture and test do not exist. The only TypeScript test asserts tag 16, so it does not prove the exact program ID, data, or account metas. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Add a current-Rust fixture for `sdk-libs/ts/interface/src/instructions/index.ts::createAssetCounterInstruction` and test the exact program ID, data, and account metas.
- Row transition: `todo -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I13 program-libs/interface/src/instruction/instruction_data/mod.rs`
- Full SDK parity claim: unsupported; 14 rows need fixes, I07 and I10 have unresolved authority conflicts, and package and cross-package gates have not passed

### 2026-07-25 01:45 UTC | I13 | `program-libs/interface/src/instruction/instruction_data/mod.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This module is the public instruction-data export root. Rust exports 33 names. Eight have suitable TypeScript adaptations, six borrowed views need explicit JavaScript dispositions, and 19 public equivalents are missing.
- Evidence: The six borrowed views can be `NOT_APPLICABLE` only when strict owned decoders preserve their observable behavior. No relevant source changed from frozen commit `43fde8e4`. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Coordinate the child codecs, types, constants, hash helpers, and tag helpers; remove duplicate authorities; and record an exact export ledger with evidence. Resolve the I07 deposit and I10 protocol-config authority conflicts first.
- Row transition: `todo -> needs_fix`
- Progress: `3/118`; package `0/37`
- Exact next file: `I16 program-libs/interface/src/instruction/builders/create_associated_token_account.rs`
- Full SDK parity claim: unsupported; 15 rows need fixes, I07 and I10 have unresolved authority conflicts, and package and cross-package gates have not passed

### 2026-07-25 01:45 UTC | I16 | `program-libs/interface/src/instruction/builders/create_associated_token_account.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This builder derives the legacy SPL associated-token address and creates the idempotent instruction. TypeScript preserves the canonical program IDs, six accounts and flags, and one-byte discriminator `1`.
- Evidence: A current-Rust workflow fixture checks the derivation and exact transaction. Live coverage repeats the instruction and confirms idempotent behavior. The fixture-name difference in planning is bookkeeping drift, not an implementation or evidence gap. No tests ran for this recorder update.
- Verdict: `PARITY`
- Gap and smallest fix: none
- Row transition: `todo -> done`
- Progress: `4/118`; package `1/37`
- Exact next file: `I17 program-libs/interface/src/instruction/builders/create_spl_interface.rs`
- Full SDK parity claim: unsupported; 15 interface rows need fixes, eight package row sets remain incomplete, and cross-package gates have not passed

### 2026-07-25 01:45 UTC | I17 | `program-libs/interface/src/instruction/builders/create_spl_interface.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This builder creates the SPL interface instruction. TypeScript matches source tag 4, eight account metas, canonical PDAs, and the legacy token program.
- Evidence: Existing TypeScript evidence asserts only the tag, and the named fixture is absent. No relevant source changed from frozen commit `43fde8e4`. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Add a current-Rust fixture with a nonzero mint and assert the exact program, data, account metas, rejection behavior, and defensive copies.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I18 program-libs/interface/src/instruction/builders/create_tree.rs`
- Full SDK parity claim: unsupported; 16 interface rows need fixes, including the I07 and I10 authority conflicts, and package and cross-package gates have not passed

### 2026-07-25 01:45 UTC | I18 | `program-libs/interface/src/instruction/builders/create_tree.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This builder creates a tree with an owner and three account metas. The TypeScript default path matches tag 5, owner encoding, and those metas.
- Evidence: TypeScript omits the public custom nullifier-parameter path and Borsh encoder. No exact fixture covers the default or custom path, and rejection evidence is absent. No relevant source changed from the frozen commit. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Add the custom nullifier-parameter path and Borsh encoder with exact default and custom fixtures plus rejection tests. Coordinate I04 PDA derivation, I06 data encoding, and I34 tree constants.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I19 program-libs/interface/src/instruction/builders/deposit.rs`
- Full SDK parity claim: unsupported; 17 interface rows need fixes, including the I07 and I10 authority conflicts, and package and cross-package gates have not passed

### 2026-07-25 01:45 UTC | I19 | `program-libs/interface/src/instruction/builders/deposit.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: Current Rust and TypeScript produce the same SOL instruction, and the SPL source shape matches. The spec defines different deposit accounts, payload, tag semantics, and the initial viewing-key tag.
- Evidence: No exact SPL fixture exists. No relevant source changed from frozen commit `43fde8e4`. The spec conflict prevents a current parity finding. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Resolve the spec conflict first. If current Rust is retained, add an exact SPL fixture plus rejection and defensive-copy tests.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I20 program-libs/interface/src/instruction/builders/merge_transact.rs`
- Full SDK parity claim: unsupported; I07, I10, and I19 retain authority conflicts, and package and cross-package gates have not passed

### 2026-07-25 01:45 UTC | I20 | `program-libs/interface/src/instruction/builders/merge_transact.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This builder creates the default merge instruction. The TypeScript program ID, tag, four account metas, and frozen instruction match current Rust.
- Evidence: The builder duplicates the I08 merge encoder, and no direct test asserts the frozen builder output. No relevant source changed from the frozen commit. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Reuse the I08 codec and add an exact fixture assertion for the builder. I01 owns error behavior.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I21 program-libs/interface/src/instruction/builders/merge_zone.rs`
- Full SDK parity claim: unsupported; 19 interface rows need fixes, including three authority conflicts, and package and cross-package gates have not passed

### 2026-07-25 01:45 UTC | I21 | `program-libs/interface/src/instruction/builders/merge_zone.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: The TypeScript outer instruction and CPI behavior match current Rust, including tag 13, 701 instruction bytes, and four account metas.
- Evidence: The builder duplicates the I04 `zone_auth` PDA and I09 codec. No exact fixture covers both modes. The client's default-merge substitution remains a separate I09 and client gap. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Reuse the I04 PDA and I09 codec, then add an exact fixture for each mode.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I22 program-libs/interface/src/instruction/builders/protocol_config/mod.rs`
- Full SDK parity claim: unsupported; 20 interface rows need fixes, including three authority conflicts, and package and cross-package gates have not passed

### 2026-07-25 01:45 UTC | I22 | `program-libs/interface/src/instruction/builders/protocol_config/mod.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: Current Rust and TypeScript create, update, and pause structures and authority semantics match.
- Evidence: This row inherits the I10 spec conflict and duplicates its codecs. No exact current-Rust fixtures cover bytes, account metas, authority rotation, or rejection behavior. No relevant source changed from the frozen commit. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Resolve I10, reuse its codecs, and add exact current-Rust bytes, account-meta, authority-rotation, and rejection fixtures.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I23 program-libs/interface/src/instruction/builders/transact.rs`
- Full SDK parity claim: unsupported; 21 interface rows need fixes, I07, I10, and I19 retain authority conflicts, and package and cross-package gates have not passed

### 2026-07-25 02:46 UTC | I23 | `program-libs/interface/src/instruction/builders/transact.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This public builder creates the default transaction instruction. Valid TypeScript layouts and fixtures match current Rust. The client has a second copy of the builder.
- Evidence: TypeScript `validateSettlement` rejects malformed settlement combinations before it builds an instruction. Rust builds those combinations so the Solana program can return code 7023. No relevant source changed from frozen commit `43fde8e4`. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Remove the TypeScript-only semantic validation or change the canonical Rust boundary, then make the client reuse the interface builder.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I24 program-libs/interface/src/instruction/builders/zone_authority_transact.rs`
- Full SDK parity claim: unsupported; 22 interface rows need fixes, including the I23 error-boundary divergence, and package and cross-package gates have not passed

### 2026-07-25 02:46 UTC | I24 | `program-libs/interface/src/instruction/builders/zone_authority_transact.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This public builder supports outer and CPI zone-authority transactions for SOL and SPL assets. Valid account metas match current Rust.
- Evidence: No exact current-Rust fixture covers this builder. It shares I23's early settlement rejection boundary and privately duplicates I04's `zone_auth` derivation. No relevant source changed from frozen commit `43fde8e4`. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Resolve I23, reuse the I04 PDA helper, and add exact current-Rust outer and CPI fixtures for both assets.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I25 program-libs/interface/src/instruction/builders/zone_config/mod.rs`
- Full SDK parity claim: unsupported; 23 interface rows need fixes, including the shared settlement boundary, and package and cross-package gates have not passed

### 2026-07-25 02:46 UTC | I25 | `program-libs/interface/src/instruction/builders/zone_config/mod.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This module exports the create, owner-update, and enabled-update zone-config builders. Their TypeScript bytes, account metas, and authority semantics statically match current Rust.
- Evidence: No exact current-Rust fixture covers the three builders, and no evidence covers CPI creation routing. I04 and I12 own the shared PDA and codec work. No relevant source changed from frozen commit `43fde8e4`. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Reuse I04 and I12, then add exact fixtures for the three builders and evidence for CPI creation routing.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I26 program-libs/interface/src/instruction/builders/zone_deposit.rs`
- Full SDK parity claim: unsupported; 24 interface rows need fixes, and package and cross-package gates have not passed

### 2026-07-25 02:46 UTC | I26 | `program-libs/interface/src/instruction/builders/zone_deposit.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This public builder supports outer and CPI zone deposits for SOL and SPL assets. TypeScript matches current Rust modes, tag, PDA derivation, and account metas.
- Evidence: No exact outer or CPI fixture and no focused tests cover this builder. I04 and I07 own its duplicated PDA and codec, and the I07 deposit-spec conflict remains unresolved. No relevant source changed from frozen commit `43fde8e4`. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Reuse I04 and I07, retain the deposit authority conflict, and add exact mode and asset fixtures.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I27 program-libs/interface/src/instruction/builders/zone_transact.rs`
- Full SDK parity claim: unsupported; 25 interface rows need fixes, including the deposit-spec conflict, and package and cross-package gates have not passed

### 2026-07-25 02:46 UTC | I27 | `program-libs/interface/src/instruction/builders/zone_transact.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This public builder creates outer and CPI zone transactions. Valid TypeScript instructions match current Rust.
- Evidence: TypeScript applies I23's early settlement rejection and changes the Rust program-error boundary. No exact vectors cover both modes, withdrawals, or owner-index account selection. No relevant source changed from frozen commit `43fde8e4`. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Resolve the settlement boundary with I23, then add exact vectors for both modes, withdrawals, and owner-index selection.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I28 program-libs/interface/src/instruction/builders/mod.rs`
- Full SDK parity claim: unsupported; 26 interface rows need fixes, including two settlement-boundary divergences, and package and cross-package gates have not passed

### 2026-07-25 02:46 UTC | I30 | `program-libs/interface/src/state/discriminator.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This public state module defines account discriminator values. TypeScript embeds values 1, 3, 4, 5, and 6 across four codecs but omits the tree value.
- Evidence: TypeScript has no canonical exported table or fixture for the complete current-Rust set. Value 2 is reserved by protocol history. No relevant source changed from frozen commit `43fde8e4`. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Export and reuse one discriminator table, record value 2 as reserved history, include the tree discriminator, and add a complete drift fixture.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I28 program-libs/interface/src/instruction/builders/mod.rs`
- Full SDK parity claim: unsupported; 27 interface rows need fixes, I28 remains the lowest unrecorded row, and package and cross-package gates have not passed

### 2026-07-25 02:46 UTC | I31 | `program-libs/interface/src/state/protocol_config.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This public state type has an exact 132-byte layout. TypeScript matches the fields and offsets.
- Evidence: TypeScript `Reader.bool` rejects bytes 2 through 255, while Rust treats each nonzero byte as true. Exact, boundary, and `SIZE` evidence is absent. The I10 and I22 spec conflict remains. No relevant source changed from frozen commit `43fde8e4`. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Decode the flag as `u8 != 0`, add exact and boundary fixtures, record the `SIZE` disposition, and preserve the I10 and I22 conflict.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I28 program-libs/interface/src/instruction/builders/mod.rs`
- Full SDK parity claim: unsupported; 28 interface rows need fixes, including protocol-config behavior and spec conflicts, and package and cross-package gates have not passed

### 2026-07-25 02:46 UTC | I32 | `program-libs/interface/src/state/spl_asset_counter.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This public state type stores the next SPL asset ID in an exact 16-byte layout. The TypeScript codec matches its bytes.
- Evidence: `FIRST_ASSET_ID` has no TypeScript disposition. Evidence does not cover a current-Rust exact vector, `u64` boundaries, reserved bytes, initialization, allocation, overflow, or two registrations. No relevant source changed from frozen commit `43fde8e4`. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Export or document `FIRST_ASSET_ID` and add exact state plus allocation boundary evidence.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I28 program-libs/interface/src/instruction/builders/mod.rs`
- Full SDK parity claim: unsupported; 29 interface rows need fixes, I28 remains the lowest unrecorded row, and package and cross-package gates have not passed

### 2026-07-25 02:46 UTC | I33 | `program-libs/interface/src/state/spl_asset_registry.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This public state type maps an SPL mint to its asset ID in an exact 48-byte layout. The TypeScript codec matches the layout.
- Evidence: Current tests round-trip TypeScript values without an independent oracle; exact boundary and browser vectors are absent. Wallet sync creates `unknownAssetIds` without recording or fetching registry accounts and omits the Rust retry behavior. No relevant source changed from frozen commit `43fde8e4`. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Add exact boundary and browser vectors, then make wallet sync record, fetch, and retry unknown asset registry accounts as Rust does.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `I28 program-libs/interface/src/instruction/builders/mod.rs`
- Full SDK parity claim: unsupported; 30 interface rows need fixes, I28 remains the lowest unrecorded row, and package and cross-package gates have not passed

### 2026-07-25 05:21 UTC | I28 | `program-libs/interface/src/instruction/builders/mod.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`; the active interface worker owns the non-conflicting fixes
- Explanation: This module is the public builder export root. TypeScript represents each builder name with a JavaScript-appropriate API, but the aggregate inherits child divergences and duplicate authorities.
- Evidence: Custom tree parameters, canonical codec and PDA reuse, exact builder vectors, and runtime and declaration export allowlists remain incomplete. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Complete the non-conflicting child fixes, add the custom tree path, reuse canonical authorities, and pin exact builder exports and vectors.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `K05 sdk-libs/keypair/src/pubkey.rs`
- Full SDK parity claim: unsupported; the interface package retains adverse rows and package and cross-package gates have not passed

### 2026-07-25 05:21 UTC | I29 | `program-libs/interface/src/instruction/mod.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`; the active interface worker owns the non-conflicting fixes
- Explanation: This module is the public instruction root. TypeScript preserves the 18 tags and provides ergonomic builder adaptations.
- Evidence: Nineteen public instruction-data equivalents are missing. Child, spec, and settlement conflicts remain, and feature, helper, and export dispositions lack exact evidence. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Add the non-conflicting data and helper exports, record valid JavaScript dispositions, and pin root and subpath allowlists without hiding the unresolved conflicts.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `K05 sdk-libs/keypair/src/pubkey.rs`
- Full SDK parity claim: unsupported; instruction-root and child conflicts remain unresolved

### 2026-07-25 05:21 UTC | I34 | `program-libs/interface/src/state/tree.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`; the active interface worker owns the fix
- Explanation: This public state module defines the tree constants, nullifier-tree parameters, account size `1_186_136`, and root offset `16`.
- Evidence: TypeScript exposes none of these values. Exact browser-safe vectors are absent. No tests ran for this recorder update.
- Verdict: `MISSING`
- Gap and smallest fix: Add one exact browser-safe tree authority and current-Rust vectors, coordinated with I06 and I18.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `K05 sdk-libs/keypair/src/pubkey.rs`
- Full SDK parity claim: unsupported; a public interface state authority is missing

### 2026-07-25 05:21 UTC | I35 | `program-libs/interface/src/state/zone_config.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`; the active interface worker owns the fix
- Explanation: This public state type has a 67-byte layout. TypeScript decodes valid values into the same fields.
- Evidence: The policy for enabled bytes outside `0` and `1` differs from or leaves ambiguous the current Rust boundary, and exact canonical and noncanonical vectors are absent. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Preserve the proven current Rust byte policy and add exact canonical and noncanonical enabled-byte vectors.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `K05 sdk-libs/keypair/src/pubkey.rs`
- Full SDK parity claim: unsupported; zone-config decoding lacks exact boundary parity

### 2026-07-25 05:21 UTC | I36 | `program-libs/interface/src/state/mod.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`; the active interface worker owns the fix
- Explanation: This module is the public state export root.
- Evidence: TypeScript omits the discriminator table, `FIRST_ASSET_ID`, and the full tree export set, and it inherits child behavior and evidence gaps. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Export and reuse the canonical state authorities, then pin the exact root allowlist and inherited behavior.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `K05 sdk-libs/keypair/src/pubkey.rs`
- Full SDK parity claim: unsupported; the interface state export set is incomplete

### 2026-07-25 05:21 UTC | I37 | `program-libs/interface/src/lib.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`; the active interface worker owns the non-conflicting fixes
- Explanation: This crate root exposes program addresses, modules, features, constants, and public capabilities. TypeScript exposes the program addresses and package subpaths.
- Evidence: The root inherits 35 adverse child reports and omits constants, event capability dispositions, a complete inventory, and an exact export ledger. Generated verifying keys are a justified JavaScript omission. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Complete the non-conflicting root exports and evidence, document event and generated-key dispositions, and retain the unresolved child conflicts.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `1/37`
- Exact next file: `K05 sdk-libs/keypair/src/pubkey.rs`
- Full SDK parity claim: unsupported; the interface root and 35 child reports remain adverse

### 2026-07-25 05:21 UTC | K01 | `sdk-libs/keypair/src/constants.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This module defines keypair constants that are public through the Rust crate.
- Evidence: Seven Rust-public constants are hidden, the inventory incorrectly calls them internal, and direct constant evidence is incomplete. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Export or record an exact JavaScript disposition for each public constant, correct the inventory, and add current-Rust evidence.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `K05 sdk-libs/keypair/src/pubkey.rs`
- Full SDK parity claim: unsupported; the keypair public constant set is incomplete

### 2026-07-25 05:21 UTC | K02 | `sdk-libs/keypair/src/signing_key.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This module owns signing-key generation, import, public-key derivation, and signatures.
- Evidence: The tagged public-key runtime value is 34 bytes but its TypeScript type is `Bytes33`, and `isEd25519` is missing. RNG, scalar, signature, and secret-inspection evidence is incomplete. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Correct the tagged-key type and `isEd25519` adaptation, then add generation, malformed-input, signing-boundary, and secret-exposure tests.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `K05 sdk-libs/keypair/src/pubkey.rs`
- Full SDK parity claim: unsupported; the keypair signing API has a public type conflict

### 2026-07-25 05:21 UTC | K03 | `sdk-libs/keypair/src/nullifier_key.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This module derives the nullifier secret, public value, and per-output nullifier. Source behavior aligns in TypeScript.
- Evidence: Malformed import, repeatability, capability separation, and secret-inspection vectors are incomplete. The inventory says leaf index where the input is a blinding, and fixture names and provenance point to the wrong responsibility. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Correct the inventory and fixture provenance, then add exact success, malformed-input, repeatability, capability, and inspection evidence.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `K05 sdk-libs/keypair/src/pubkey.rs`
- Full SDK parity claim: unsupported; keypair evidence and inventory remain incomplete

### 2026-07-25 05:21 UTC | M01 | `sdk-libs/merkle-tree/src/indexed.rs`

- Baseline: HEAD `90d8c1e10ba0db92527f835302d2c6fecec5008a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: This module provides indexed-tree insertion and low/high-neighbor non-inclusion proofs.
- Evidence: Default vectors pass. TypeScript lacks custom highest-sentinel behavior and public path, proof, and update APIs; verification trusts the supplied root and path length; numeric, error, sentinel, and mutation behavior diverges or lacks evidence. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Add the missing public operations, validate roots and path lengths, align numeric and sentinel boundaries and errors, and add custom-sentinel and mutation vectors.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/2`
- Exact next file: `K05 sdk-libs/keypair/src/pubkey.rs`
- Full SDK parity claim: unsupported; indexed-tree public behavior diverges

### 2026-07-25 11:26 UTC | K05 | `sdk-libs/keypair/src/pubkey.rs`

- Baseline: HEAD `a19c99b365e5ad5a67891d2f890c0160263298e2`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines the tagged signing public-key type and its P256 address behavior.
- Evidence: The runtime value is 34 bytes while TypeScript declares `Bytes33`. P256 decompression, canonical equality, structured errors, exports, adversarial inputs, and browser behavior differ or lack current-Rust proof. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Correct the type and API, align decompression, equality, and errors, then add exact malformed, parity, export, and browser vectors.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `K07 sdk-libs/keypair/src/hash.rs`
- Full SDK parity claim: unsupported; the public-key contract and evidence diverge

### 2026-07-25 11:26 UTC | K06 | `sdk-libs/keypair/src/shielded.rs`

- Baseline: HEAD `a19c99b365e5ad5a67891d2f890c0160263298e2`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module constructs shielded keypairs, owner hashes, and compressed addresses.
- Evidence: The spec-authoritative P256 owner hash conflicts with TypeScript. Construction, facade, compressed-address, ownership, and exact fixture behavior are missing or divergent. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Resolve the owner-hash conflict, align construction and capability boundaries, and add exact plus malformed fixtures.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `K07 sdk-libs/keypair/src/hash.rs`
- Full SDK parity claim: unsupported; P256 owner-hash behavior conflicts with the spec

### 2026-07-25 11:26 UTC | S01 | `sdk-libs/smart-account-client/src/lib.rs`

- Baseline: HEAD `a19c99b365e5ad5a67891d2f890c0160263298e2`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This crate compiles and executes smart-account transactions.
- Evidence: Rust casts compiled account positions to `u8`; TypeScript rejects indexes above 255. The 1232-byte limit, execute fixture, and export surface lack equivalent enforcement or exact evidence. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Set one canonical overflow policy, enforce the transaction-size limit, and add exact execute and export fixtures.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/1`
- Exact next file: `K07 sdk-libs/keypair/src/hash.rs`
- Full SDK parity claim: unsupported; account-index and transaction-size policies are not aligned

### 2026-07-25 11:26 UTC | T01 | `sdk-libs/transaction/src/error.rs`

- Baseline: HEAD `a19c99b365e5ad5a67891d2f890c0160263298e2`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines the transaction crate's public error categories and payloads.
- Evidence: TypeScript collapses or misclassifies variants, drops payloads, and blurs keypair and authority boundaries. Redaction and current-Rust fixture coverage are absent. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Preserve stable open codes, details, category boundaries, and unknown variants, then add redaction and exact fixture tests.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/31`
- Exact next file: `K07 sdk-libs/keypair/src/hash.rs`
- Full SDK parity claim: unsupported; transaction error categories and payloads diverge

### 2026-07-25 11:26 UTC | T27 | `sdk-libs/transaction/src/instructions/merge.rs`

- Baseline: HEAD `a19c99b365e5ad5a67891d2f890c0160263298e2`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module prepares merge instructions and revalidates their authority, zone, and expiry inputs.
- Evidence: TypeScript uses the wrong nullifier authority, classifies zone failures incorrectly, and omits `PreparedMerge` revalidation. Expiry, constants, public API, secret boundaries, and exact fixtures are incomplete. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Align authority, zone errors, revalidation, expiry, constants, and API, then add stale, malformed, capability, and secret-exposure fixtures.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/31`
- Exact next file: `K07 sdk-libs/keypair/src/hash.rs`
- Full SDK parity claim: unsupported; merge authority and revalidation behavior diverge

### 2026-07-25 11:27 UTC | K07 | `sdk-libs/keypair/src/hash.rs`

- Baseline: HEAD `405e3ea6dd94d01a49199c43fcd024be2b7897c4`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module exposes Poseidon and key-derived hash operations.
- Evidence: Covered valid vectors match current Rust. TypeScript omits public Poseidon, accepts malformed field widths and arities outside `1..=12`, exposes unsafe extra helpers, lacks boundary, browser, and property evidence, and inherits the K06 owner-hash conflict. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Add public Poseidon, enforce Rust widths and arities, limit unsafe helpers, resolve K06, and add exact rejection, boundary, browser, and property vectors.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `K08 sdk-libs/keypair/src/encryption.rs`
- Full SDK parity claim: unsupported; hash validation, exports, and owner-hash behavior diverge

### 2026-07-25 11:28 UTC | T02 | `sdk-libs/transaction/src/data.rs`

- Baseline: HEAD `42875823b9e5f1376b48f37ec4dbc2b36670bd42`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines the transaction data model and its encoded representation.
- Evidence: Valid deterministic bytes match current Rust. Malformed runtime kinds and byte values are coerced or silently encoded, the constructor changes the serialization-time length boundary, the direct codec is not packed, and adversarial, boundary, error-detail, and provenance evidence is incomplete. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Reject malformed values, restore the Rust length boundary, expose the packed codec capability, and add exact rejection, boundary, error, and provenance fixtures.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/31`
- Exact next file: `K08 sdk-libs/keypair/src/encryption.rs`
- Full SDK parity claim: unsupported; malformed values and serialization boundaries diverge

### 2026-07-25 11:28 UTC | K09 | `sdk-libs/keypair/src/merge.rs`

- Baseline: HEAD `42875823b9e5f1376b48f37ec4dbc2b36670bd42`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module provides merge encryption and the public symmetric transform.
- Evidence: Merge encryption and its frozen vector are byte-compatible. TypeScript omits public `symmetric_apply`; malformed-secret, error, info, chunk, cleanup, export, and provenance evidence is incomplete. Rust can panic on unrestricted info lengths. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Fix the Rust info-length panic risk before porting unrestricted `symmetric_apply`, then add bounded inputs, temporary cleanup, exact exports, and rejection and boundary fixtures.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `K08 sdk-libs/keypair/src/encryption.rs`
- Full SDK parity claim: unsupported; a public merge capability and boundary evidence are missing

### 2026-07-25 11:29 UTC | K08 | `sdk-libs/keypair/src/encryption.rs`

- Baseline: HEAD `a3d5a60fec597a80ff2fc454ea3c1b17c31215c8`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module performs P256 ECDH, HKDF derivation, and AES-CTR encryption.
- Evidence: TypeScript matches current Rust bytes, and its internal API disposition is valid. Shared-secret cleanup is not exception-safe; multi-block, counter, empty, boundary, malformed salt and slot, tamper, truncation, extension, defensive-copy, browser, security, and provenance evidence is incomplete. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Make shared-secret cleanup exception-safe and add exact current-Rust boundary, malformed, mutation, browser, security, and fixture-description evidence.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `K10 sdk-libs/keypair/src/error.rs`
- Full SDK parity claim: unsupported; cleanup and adversarial encryption evidence remain incomplete

### 2026-07-25 11:30 UTC | K10 | `sdk-libs/keypair/src/error.rs`

- Baseline: HEAD `acc4fad0f188e27b2c73f8c48886b9fd6eac712f`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines the keypair crate's public error distinctions.
- Evidence: TypeScript collapses or omits five distinctions, lacks code-indexed immutable diagnostics and exhaustive current-Rust evidence, and allows enumerable causes or details to expose data. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Add one-to-one closed codes and details, sanitize causes and serialization, and add exhaustive fixtures plus export and package tests.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `K11 sdk-libs/keypair/src/traits/view_key.rs`
- Full SDK parity claim: unsupported; keypair errors lose distinctions and may expose data

### 2026-07-25 11:30 UTC | T03 | `sdk-libs/transaction/src/serialization/scheme.rs`

- Baseline: HEAD `acc4fad0f188e27b2c73f8c48886b9fd6eac712f`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines the seven serialization scheme tags and their checked conversion.
- Evidence: Tags match current Rust. TypeScript omits the root export and standalone checked conversion, accepts invalid runtime schemes and scheme and encoding combinations, mishandles empty-blob details, and lacks direct rejection and export evidence. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Add checked conversion and the root export, reject invalid values and combinations with exact details, and add current-Rust rejection and export fixtures.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/31`
- Exact next file: `K11 sdk-libs/keypair/src/traits/view_key.rs`
- Full SDK parity claim: unsupported; serialization scheme rejection and exports diverge

### 2026-07-25 11:31 UTC | K11 | `sdk-libs/keypair/src/traits/view_key.rs`

- Baseline: HEAD `5ffa42da9f7c06a76230e3a9cfc26005f9dcd908`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This public trait defines the viewing-key capability surface.
- Evidence: The 14 concrete operations exist on TypeScript `ViewingKey`, but public `ViewingKeyLike` has only two unused methods. `ShieldedKeypair` cannot substitute, higher packages require concrete `ViewingKey`, and trait declaration, facade, malformed-input, secret-exposure, browser, and current-Rust evidence is missing. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Add the public trait adaptation and facade, accept the least-powerful capability in higher packages, and add the missing evidence.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `K12 sdk-libs/keypair/src/traits/shielded_keypair.rs`
- Full SDK parity claim: unsupported; viewing-key abstraction and evidence remain incomplete

### 2026-07-25 11:34 UTC | T04 | `sdk-libs/transaction/src/serialization/plaintext.rs`

- Baseline: HEAD `f3d34e98405bfe648069cf70311c19d978eb3dac`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines plaintext UTXO serialization and conversion capabilities.
- Evidence: Exact bytes match current Rust, but TypeScript permits inner/outer discriminator and scheme/encoding confusion, omits public conversion and sealing capabilities, diverges on output-limit and error boundaries, and lacks adversarial and export evidence. Rust `from_utxos` positional and owner defects are prerequisites. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Correct the Rust prerequisites, then align validation, capabilities, limits, errors, and evidence.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/31`
- Exact next file: `K12 sdk-libs/keypair/src/traits/shielded_keypair.rs`
- Full SDK parity claim: unsupported; plaintext serialization validation and capabilities diverge

### 2026-07-25 11:34 UTC | T05 | `sdk-libs/transaction/src/serialization/confidential.rs`

- Baseline: HEAD `f3d34e98405bfe648069cf70311c19d978eb3dac`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines confidential UTXO serialization and recipient and sender decryption capabilities.
- Evidence: Exact plaintext and ciphertext bytes match, but recipient decryption accepts malformed embedded P256 keys. Sender decryption, embedded-key, and scheme-locked encode capabilities are not packed; crypto error boundaries and malformed and browser evidence are incomplete. Rust's `from_utxos` cardinality defect is a prerequisite. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Correct the Rust prerequisite, then align validation, capabilities, errors, and malformed and browser evidence.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/31`
- Exact next file: `K12 sdk-libs/keypair/src/traits/shielded_keypair.rs`
- Full SDK parity claim: unsupported; confidential decryption validation and capabilities diverge

### 2026-07-25 11:34 UTC | K12 | `sdk-libs/keypair/src/traits/shielded_keypair.rs`

- Baseline: HEAD `f3d34e98405bfe648069cf70311c19d978eb3dac`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This public trait defines the generic shielded-keypair capability surface.
- Evidence: Concrete operations exist, but the generic interface omits six named capabilities, is unused, and lacks a workable async/HSM facade and evidence. Rust's malformed-P256-sign panic and secret-returning nullifier trait method must be corrected. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Correct the Rust defects, then complete and consume the generic facade with current-Rust, malformed, capability, async/HSM, browser, and secret-exposure evidence.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `K13 sdk-libs/keypair/src/traits/mod.rs`
- Full SDK parity claim: unsupported; the generic keypair facade and safety evidence remain incomplete

### 2026-07-25 11:36 UTC | K13 | `sdk-libs/keypair/src/traits/mod.rs`

- Baseline: HEAD `a0c49ffcb18418873494a7910ccf75411c51125c`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module exports the keypair crate's public trait surface.
- Evidence: Rust trait-module exports are represented only by incomplete root-level TypeScript interfaces; no documented traits subpath or counterpart and no trait-specific fixture exist. The declarations are accurate, but consumer, browser, and packed-package evidence does not exercise the interfaces. No tests ran for this recorder update.
- Verdict: `PARTIAL`
- Gap and smallest fix: Add the documented traits surface and trait-specific fixture, then exercise the interfaces through consumer, browser, and packed-package tests.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `K14 sdk-libs/keypair/src/lib.rs`
- Full SDK parity claim: unsupported; the trait export surface and evidence remain incomplete

### 2026-07-25 11:37 UTC | T06 | `sdk-libs/transaction/src/serialization/anonymous.rs`

- Baseline: HEAD `6daa55950dd853fbc58a4a10685228a3d382048b`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines anonymous UTXO serialization and authority-context flows.
- Evidence: Exact frozen bytes match current Rust, but TypeScript diverges on zone-context resolution, omits scheme-locked UTXO-to-plaintext and authority flows, has no shared-tag state progression, and lacks adversarial, export, and browser evidence. Rust conflicts with `docs/spec.md` on anonymous recipient program and zone data and has lossy `from_utxos` defects that must be fixed before copying. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Correct the Rust spec conflict and lossy conversion defects first, then align TypeScript zone resolution, scheme-locked and authority flows, shared-tag progression, and evidence.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/31`
- Exact next file: `K14 sdk-libs/keypair/src/lib.rs`
- Full SDK parity claim: unsupported; anonymous context, capability, and state behavior diverge

### 2026-07-25 11:39 UTC | K04 | `sdk-libs/keypair/src/viewing_key.rs`

- Baseline: HEAD `7e2743cac2a231991069ffb30d20574c4eb0057a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines concrete viewing-key cryptographic behavior.
- Evidence: Valid cryptographic behavior and current-Rust vectors align, but zero-scalar is collapsed to invalid-secret, HKDF failures lack Rust error parity, and boundary, browser-runtime, inspection, adversarial, and temporary-cleanup evidence is incomplete. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Preserve the aligned behavior, distinguish zero-scalar and HKDF failures, and add the missing boundary, runtime, security, and cleanup evidence.
- Row transition: `in_progress -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `K14 sdk-libs/keypair/src/lib.rs`
- Full SDK parity claim: unsupported; viewing-key errors and evidence remain divergent

### 2026-07-25 11:39 UTC | K14 | `sdk-libs/keypair/src/lib.rs`

- Baseline: HEAD `7e2743cac2a231991069ffb30d20574c4eb0057a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines the keypair package's public root surface.
- Evidence: The package export map and browser graph are coherent, but Rust-public constants, Poseidon, `symmetricApply`, `isEd25519`, `Signature`, compressed-address and traits surfaces are missing; `Bytes33` falsely declares a 34-byte key. The K06 owner-hash spec conflict, collapsed errors, stale metadata, and missing exact root, type, tarball, and consumer allowlists prevent package parity. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Complete and correct the package surface, resolve inherited owner-hash and error conflicts, refresh metadata, and add exact root, type, tarball, and consumer allowlists.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/14`
- Exact next file: `X01 sdk-libs/indexer-api/src/lib.rs`
- Full SDK parity claim: unsupported; the keypair root surface and package evidence diverge

### 2026-07-25 11:39 UTC | X01 | `sdk-libs/indexer-api/src/lib.rs`

- Baseline: HEAD `7e2743cac2a231991069ffb30d20574c4eb0057a`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This crate defines the public indexer data and conversion contract.
- Evidence: TypeScript accurately follows current Rust and Photon, but authoritative `docs/spec.md` defines materially different indexer context, UTXO, transaction, and output schemas. Public base64-to-bytes and hash error distinctions are incomplete, the promised Rust fixture is absent, and exhaustive rejection and live-Photon evidence is missing. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Resolve the Rust and Photon conflict with the spec, then align the TypeScript schema, public conversions, errors, fixtures, and exhaustive rejection and live-Photon evidence.
- Row transition: `todo -> needs_fix`
- Progress: `4/118`; package `0/1`
- Exact next file: `T07 sdk-libs/transaction/src/serialization/proofless.rs`
- Full SDK parity claim: unsupported; the indexer schema conflicts with the authoritative spec

### 2026-07-25 11:40 UTC | interface post-fix re-review

- Baseline: HEAD `00addfc50b3a6a405c53491b7e251e41578143b2`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed independent post-fix re-review; implementation commits recorded on passing rows
- PARITY: `I01`, `I02`, `I05`, `I06`, `I14`, `I16` unchanged, `I18`, `I23`, `I30`, `I31`, `I32`, `I33`, `I34`, `I35`, `I36`
- BLOCKED: `I07`, `I10`, `I19`, `I22` remain gated by conflicts with authoritative `docs/spec.md`
- DIVERGENT: `I08`, `I20`, `I21`, `I28` share the encrypted-UTXO prefix validation conflict
- PARTIAL: `I03`, `I04`, `I09`, `I11`, `I12`, `I13`, `I15`, `I17`, `I24`, `I25`, `I26`, `I27`, `I29`, `I37` retain the row-specific implementation or evidence gaps above
- Row transitions: 14 rows `needs_fix -> done`; the adverse interface rows remain `needs_fix`; `I16` remains `done`
- Progress: `18/118`; package `15/37`
- Exact next file: `T07 sdk-libs/transaction/src/serialization/proofless.rs`
- Full SDK parity claim: unsupported; interface protocol conflicts, one codec divergence, and aggregate evidence gaps remain

### 2026-07-25 11:40 UTC | T07 | `sdk-libs/transaction/src/serialization/proofless.rs`

- Baseline: HEAD `00addfc50b3a6a405c53491b7e251e41578143b2`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines proofless UTXO serialization and integrity context.
- Evidence: Valid simple bytes match, but public conversion and scheme-lock capabilities are absent, owner-hash tampering is ignored in wallet sync, TypeScript follows Rust's spec-conflicting memo field, and optional, boundary, export, browser, and tamper evidence is incomplete. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Remove memo per spec; fix Rust's exact-one UTXO, owner, context, integrity, and `Serialize`-category prerequisites; then align TypeScript capabilities and complete the evidence.
- Row transition: `todo -> needs_fix`
- Progress: `18/118`; package `0/31`
- Exact next file: `T08 sdk-libs/transaction/src/serialization/split.rs`
- Full SDK parity claim: unsupported; proofless integrity and protocol behavior diverge

### 2026-07-25 11:43 UTC | T08 | `sdk-libs/transaction/src/serialization/split.rs`

- Baseline: HEAD `f2f1a0e8a9b893b080fabcc2bd5f3ea58995c225`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines split serialization, encrypted UTXO grouping, and scheme-locked conversion.
- Evidence: Exact frozen bytes match current Rust, but TypeScript lacks zone-context parity and the public `SplitEncryptedUtxos` and scheme-locked conversion surface, accepts wrong split discriminators and cross-scheme envelopes, has runtime count and error-boundary gaps, and lacks adversarial, browser, and export evidence. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Make Rust `Split::from_utxos` validate the UTXO set, owner, and context before porting it; then align TypeScript capabilities, discriminator and scheme validation, count and error boundaries, and evidence.
- Row transition: `todo -> needs_fix`
- Progress: `18/118`; package `0/31`
- Exact next file: `T09 sdk-libs/transaction/src/serialization/merge.rs`
- Full SDK parity claim: unsupported; split context, validation, and public capabilities diverge

### 2026-07-25 11:44 UTC | T09 | `sdk-libs/transaction/src/serialization/merge.rs`

- Baseline: HEAD `c08d91a70b47f0eb43e29e984967f71a04ec3bfe`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines merge serialization, UTXO conversion, sealing, and verifiable-encryption contribution.
- Evidence: Fixed-layout and verifiable-encryption bytes match current Rust, but TypeScript lacks a merge-specific scheme-locked conversion and sealing API, accepts invalid runtime amount and blinding values, requires raw secret bytes instead of `ViewingKey`, omits public UTXO conversion, and lacks malformed, export, browser, and proof-contribution evidence. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Make Rust require exactly one compatible UTXO, validate owner, data, and zone, preserve `zone_program_id` on reconstruction, and return a structured unknown-asset error; then align the TypeScript surface, validation, key capability, and evidence.
- Row transition: `todo -> needs_fix`
- Progress: `18/118`; package `0/31`
- Exact next file: `T10 sdk-libs/transaction/src/serialization/mod.rs`
- Full SDK parity claim: unsupported; merge conversion, validation, key capability, and evidence diverge

### 2026-07-25 11:47 UTC | T10 | `sdk-libs/transaction/src/serialization/mod.rs`

- Baseline: HEAD `975783aa38b65734585f7749e347201fd67a2b71`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This public aggregate module supplies serialization contexts, the scheme-locked `UtxoSerialization` capability pipeline, encoding selection, and selected family re-exports.
- Evidence: Valid family bytes are represented, but TypeScript omits Rust context and `UtxoSerialization` capability adaptations, does not seal scheme-to-encoding combinations, misses several packed public capabilities, and lacks exact root/subpath declaration, runtime, tarball, browser, and consumer allowlists. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Preserve T03-T09 ownership and their Rust conversion/spec prerequisites; after those are resolved, add the aggregate context and capability adaptations, seal scheme-to-encoding combinations, pack the missing public capabilities, and pin root, subpath, runtime, tarball, browser, and consumer allowlists.
- Row transition: `todo -> needs_fix`
- Progress: `18/118`; package `0/31`
- Exact next file: `T11 sdk-libs/transaction/src/utxo.rs`
- Full SDK parity claim: unsupported; aggregate serialization capabilities, sealing, exports, and consumer evidence diverge

### 2026-07-25 11:54 UTC | T11 | `sdk-libs/transaction/src/utxo.rs`

- Baseline: HEAD `abaa9984ae522cdacfa4941a323fdb3cccbbfbc5`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module defines UTXO construction, hashing, nullifiers, proof-input field encoding, zone context, and public helpers.
- Evidence: Valid frozen UTXO, hash, and nullifier vectors match current Rust, but TypeScript omits the field-encoded proof-input public API, domain, and helpers. Both Rust and TypeScript accept a spec-invalid nonzero zone hash without a nonzero zone program; runtime, copy, and error boundaries differ; and malformed, property, tamper, export, and browser evidence is incomplete. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First centralize strict zone-pair validation in Rust; then align the TypeScript proof-input surface, domain and helpers, runtime, copy, and error boundaries, and complete malformed, property, tamper, export, and browser evidence.
- Row transition: `todo -> needs_fix`
- Progress: `18/118`; package `0/31`
- Exact next file: `T12 sdk-libs/transaction/src/wallet/asset.rs`
- Full SDK parity claim: unsupported; UTXO proof-input capabilities, zone validation, boundaries, and evidence diverge

### 2026-07-25 11:57 UTC | T12 | `sdk-libs/transaction/src/wallet/asset.rs`

- Baseline: HEAD `bd4ed7bd`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none`
- Worker: completed review report; implementation commit `none`
- Explanation: The public asset registry maps mint addresses and asset IDs for wallet lookup. Valid Rust and TypeScript mappings match; I33 retains ownership of registry account codec and sync behavior.
- Evidence: Both implementations accept spec-invalid asset ID `0`. TypeScript omits public `address_for_field`, does not validate runtime mint/address or lookup-ID domains, exposes undeclared insertion-ordered `entries()`, and lacks current-Rust rejection, property, error-detail, export, browser, and pack evidence.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First make Rust reject non-native asset IDs below `2` precisely; then align the TypeScript API, runtime domains, undeclared export, and evidence.
- Row transition: `todo -> needs_fix`
- Progress: `18/118`; package `0/31`
- Exact next file: `T13 sdk-libs/transaction/src/wallet/authority.rs`
- Full SDK parity claim: unsupported; asset-ID domains, public capability parity, runtime validation, and evidence diverge

### 2026-07-25 12:01 UTC | T13 | `sdk-libs/transaction/src/wallet/authority.rs`

- Baseline: HEAD `8152a4865c832ea0b56c02fdd656776986d71cac`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed review report; implementation commit `none`
- Explanation: This module defines local and remote wallet authority capabilities, signer selection, output preparation, and authority-facing public exports. K11/K12 retain generic key capability and secret-boundary ownership; W06 retains application-level wallet-authority ownership.
- Evidence: TypeScript omits anonymous-transfer capability and several Rust public exports or ownership dispositions. Authority APIs expose viewing/nullifier secrets; remote output and rejection contracts are insufficient; and current-Rust malformed, HSM, concurrency, browser, and export evidence is incomplete.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First make Rust reject the wrong signer rail, remove the implicit zero Solana address, validate remote signatures and results, and provide coherent snapshots with least-privilege secret boundaries; then align TypeScript capabilities, contracts, exports, dispositions, and evidence without taking K11/K12 or W06 ownership.
- Row transition: `todo -> needs_fix`
- Progress: `18/118`; package `0/31`
- Exact next file: `T14 sdk-libs/transaction/src/wallet/state.rs`
- Full SDK parity claim: unsupported; authority capabilities, secret boundaries, remote contracts, and evidence diverge

### 2026-07-25 12:05 UTC | T14 | `sdk-libs/transaction/src/wallet/state.rs`

- Baseline: HEAD `14ad30017ef5b512548f65284eae0212684d8197`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed review report; implementation commit `none`
- Explanation: This module owns wallet state, transaction history, balances, filters, reports, viewing-key access, snapshots, checkpoints, and registry-backed state.
- Evidence: TypeScript omits or changes core wallet state/history/balance/filter/report/viewing-key/checkpoint APIs, uses unsafe `number` indices, exposes mutable internals and an aliased registry, and produces shallow snapshots. Fixture tests ignore much of the current-Rust oracle.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First add checked Rust balance and spent-total arithmetic and stage sync mutations atomically; then align the TypeScript surface, numeric domains, encapsulation, snapshots, and current-Rust evidence.
- Row transition: `todo -> needs_fix`
- Progress: `18/118`; package `0/31`
- Exact next file: `T15 sdk-libs/transaction/src/wallet/sync.rs`
- Full SDK parity claim: unsupported; wallet state capabilities, numeric safety, encapsulation, atomicity, and current-Rust evidence diverge

### 2026-07-25 12:07 UTC | interface residual re-review | `program-libs/interface`

- Baseline: source snapshot `14ad30017ef5b512548f65284eae0212684d8197`; recorder HEAD `2429244a29fd8f3193ec664e651d0de9392215ee`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only residual re-review; implementation commits `484ac5ed` through `14ad3001`
- Explanation: The residual review covered canonical interface hashes, PDAs, merge prefixes, instruction routing, current-Rust oracles, exports, and aggregate inheritance.
- Evidence: I03, I04, I08, I09, I11, I12, I15, I17, I20, I21, I24, I25, and I27 now have canonical hash, PDA, prefix, routing, rejection, and current-Rust oracle evidence. Reported gates passed: 29 Rust interface tests; 385 TypeScript tests with 1 skipped; browser, API/export, dependency, package, and focused package checks. These checks were not rerun by the recorder.
- Verdict: the 13 named rows are `PARITY`; I07, I10, I19, I22, I26, I28, I29, and I37 are `BLOCKED`
- Gap and smallest fix: Resolve the deposit and protocol-config authority conflicts for blocked children. The legacy frozen-revision fixture gate remains package-wide bookkeeping rather than scoped evidence-blocking; preserve the stale `CURRENT_RUST_INTERFACE_FIXTURE.sourceCommit` for the fixture-gate worker.
- Row transitions: 13 rows `needs_fix -> done`; I26 `PARTIAL -> BLOCKED`; I28 `DIVERGENT -> BLOCKED`; I29 and I37 `PARTIAL -> BLOCKED`
- Progress: `31/118`; package `28/37`
- Exact next file: `T15 sdk-libs/transaction/src/wallet/sync.rs`
- Full SDK parity claim: unsupported; interface protocol children and other package rows remain adverse

### 2026-07-25 12:08 UTC | T15 | `sdk-libs/transaction/src/wallet/sync.rs`

- Baseline: HEAD `2429244a29fd8f3193ec664e651d0de9392215ee`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed review report; implementation commit `none`
- Explanation: This module owns tag-driven transaction windows, sync counters, viewing epochs, scheme history, reports, ordering, checkpoints, and public wallet sync and balance helpers. T16 retains parallel-scanning ownership; W08 retains application-level wallet-backfill ownership.
- Evidence: TypeScript lacks the Rust/spec tag-driven windows, counters, viewing epochs, and public helpers; it changes scheme history, report ordering, and checkpoint behavior. Existing evidence is narrow and proofless.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First make Rust resume counters correctly, reject a zero window, stage sync mutations atomically, supply zone and data contexts, and add merge-tag scanning; then align TypeScript without taking T16 or W08 ownership.
- Row transition: `todo -> needs_fix`
- Progress: `31/118`; package `0/31`
- Exact next file: `T16 sdk-libs/transaction/src/wallet/parallel.rs`
- Full SDK parity claim: unsupported; sync windows, counters, epochs, history, report order, checkpoints, public helpers, and evidence diverge

### 2026-07-25 12:11 UTC | T16 | `sdk-libs/transaction/src/wallet/parallel.rs`

- Baseline: HEAD `506d8b9fb1e8e46496f1e7556e09e0c50115be91`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed review report; implementation commit `none`
- Explanation: This module owns feature-gated parallel scanning and its worker adaptation. T15 retains serial wallet-sync ownership.
- Evidence: The TypeScript worker-equivalent is only a serial alias and lacks Rust's parallel capability, deterministic merge, cancellation, error, secret-transfer behavior, and worker evidence.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First make Rust's parallel path record confidential sends, sort keys and merge deterministically, run feature tests in normal gates, and assert exact serial-parallel state; then implement and prove the TypeScript worker adaptation without taking T15 ownership.
- Row transition: `todo -> needs_fix`
- Progress: `31/118`; package `0/31`
- Exact next file: `T17 sdk-libs/transaction/src/wallet/mod.rs`
- Full SDK parity claim: unsupported; parallel capability, worker adaptation, deterministic merge, cancellation, errors, secret transfer, and worker evidence diverge

### 2026-07-25 12:21 UTC | T17 | `sdk-libs/transaction/src/wallet/mod.rs`

- Baseline: HEAD `4e271aac6aac7ab5751a0a437b4fda4983ff0059`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed review report; implementation commit `none`
- Explanation: This module owns the aggregate public wallet surface and its root and wallet entry-point contract. T12-T16 retain asset, authority, state, sync, and parallel ownership and their Rust prerequisites.
- Evidence: TypeScript root and wallet entry points omit much of Rust's aggregate public API, expose an undeclared serial worker alias plus mutable internals and registry entries, and lack exact runtime, declaration, tarball, browser, named-consumer, and aggregate-fixture allowlists.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Add the missing aggregate surface, remove or document excess exports, and prove exact entry-point contracts without taking T12-T16 ownership or bypassing their Rust prerequisites.
- Row transition: `todo -> needs_fix`
- Progress: `31/118`; package `0/31`
- Exact next file: `T18 sdk-libs/transaction/src/instructions/types.rs`
- Full SDK parity claim: unsupported; aggregate wallet API coverage, excess exports, mutability boundaries, and entry-point evidence diverge

### 2026-07-25 12:24 UTC | T18 | `sdk-libs/transaction/src/instructions/types.rs`

- Baseline: HEAD `ee8adef485f654d1eacd20dd6c73efd709d240d0`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module owns `SppProofInputUtxo` construction, dummy handling, proof-input hashing and nullifiers, and `InputUtxoContext`. T11 retains canonical UTXO and proof-input field encoding ownership.
- Evidence: The TypeScript `ProofInputUtxo` wrapper exists, but custom zero-owner inputs discard supplied amount, data, and zone fields when hashing instead of matching current Rust. Construction retains mutable UTXO and nullifier-key references instead of Rust move and clone semantics; the instructions subpath omits the mapped class; and the inventory still names `SpendUtxo` and `InputCommitment`, maps a nonexistent `types.ts`, and promises stale fixture evidence. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First make Rust reject noncanonical zero-owner dummies so dummy detection cannot silently accept malformed custom inputs. Until that robustness prerequisite lands, TypeScript must preserve current-Rust hash behavior; then align defensive ownership and clone boundaries, export the mapped class from the instructions subpath, and refresh inventory and evidence.
- Row transition: `todo -> needs_fix`
- Progress: `31/118`; package `0/31`
- Exact next file: `T19 sdk-libs/transaction/src/instructions/transact/types.rs`
- Full SDK parity claim: unsupported; dummy hashing, ownership boundaries, instructions exports, inventory, and evidence diverge

### 2026-07-25 12:25 UTC | M01/M02 | `sdk-libs/merkle-tree`

- Baseline: recorder HEAD `33a6a3b9d1091502af6cecb597be1df1d584118c`; canonical Rust fix `975783aa`; TypeScript alignment `bd4ed7bd`; provenance repair `4e271aac`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`
- Worker: completed final Merkle re-review; implementation commits `975783aa`, `bd4ed7bd`, and `4e271aac`
- Explanation: M01 owns indexed insertion and non-inclusion behavior. M02 owns the aggregate Merkle tree implementation and package surface.
- Evidence: Atomic mutations, exclusive sentinels, trusted roots, exact proof lengths, next-index and history behavior, public APIs, structured errors, exports, browser execution, packed contents, and current-source fixtures align. P06 records the requested gates passing with no scoped source drift or blocker. These checks were not rerun by the recorder.
- Verdict: M01 and M02 are `PARITY`
- Gap and smallest fix: none
- Row transitions: M01 `needs_fix/DIVERGENT -> done/PARITY`; M02 `in_progress/- -> done/PARITY`
- Progress: `33/118`; package `2/2`
- Exact next file: `T19 sdk-libs/transaction/src/instructions/transact/types.rs`
- Full SDK parity claim: unsupported; unrelated adverse rows and package gates remain

### 2026-07-25 12:27 UTC | T19 | `sdk-libs/transaction/src/instructions/transact/types.rs`

- Baseline: HEAD `ac364ba03994d909f0d89888d3df83882c8787c5`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This public transact-types module owns transaction aggregates, builders, private hashes, indexed shapes, output slots, equality, and its root and instructions exports. T11 retains canonical UTXO, proof-field, and zone-pair validation ownership; T18 retains proof-input construction, dummy, hash, nullifier, and ownership responsibility.
- Evidence: TypeScript partially covers only the default private-hash and indexed-shape paths. It omits several public Rust aggregate, builder, hash, and output-slot capabilities, runtime validation, owned copies, equality, root and instructions exports, fixtures for omitted capabilities, and adversarial cases.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First make Rust require zero dummy hashes, address-hash cardinality equal to input cardinality, and a zone program when the zone hash is nonzero. Then align `transaction/src/instructions/transact.ts` and package exports with the omitted public surface, validation, ownership, equality, fixtures, and adversarial evidence without taking T11 or T18 ownership.
- Row transition: `todo -> needs_fix`
- Progress: `33/118`; package `0/31`
- Exact next file: `T20 sdk-libs/transaction/src/instructions/transact/shape.rs`
- Full SDK parity claim: unsupported; transact aggregate, validation, ownership, equality, export, fixture, and adversarial coverage diverge

### 2026-07-25 12:30 UTC | T20 | `sdk-libs/transaction/src/instructions/transact/shape.rs`

- Baseline: HEAD `c94c05a1c60de345cd321abfe0498aac5921efd3`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module selects a canonical transaction shape and validates optional declared shape capacity while reusing the immutable interface-owned shape table. I02 retains ownership of the public shape type, constants, table, ordering, and immutability.
- Evidence: The canonical immutable table and selection match current Rust. TypeScript conflates `TooManyOutputsForShape`, treats malformed falsy declarations as omission, and lacks exhaustive boundary, error, declaration, runtime, and pack evidence. Direct Rust tests for this module are also missing; no Rust implementation defect was found.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Align TypeScript declared-shape validation and error distinctions, then add exhaustive boundary, error, declaration, runtime, and packed-package evidence without duplicating or changing I02 interface shape ownership. Add direct Rust tests as evidence only; no Rust implementation change is required.
- Row transition: `todo -> needs_fix`
- Progress: `33/118`; package `0/31`
- Exact next file: `T21 sdk-libs/transaction/src/instructions/transact/external_data.rs`
- Full SDK parity claim: unsupported; declared-shape semantics and boundary, error, declaration, runtime, pack, and direct Rust evidence remain incomplete

### 2026-07-25 12:33 UTC | T21 | `sdk-libs/transaction/src/instructions/transact/external_data.rs`

- Baseline: HEAD `cd2a7eec69cdf1bbbc462838e905459b6fa95c0b`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module owns construction and hashing of transaction external data. I11 retains ownership of the canonical interface `externalDataHash`.
- Evidence: The valid hash preimage matches the spec and current canonical interface. TypeScript omits Rust constructor defaults, builders, and duplicate errors; retains optional hashes and arrays without complete defensive copies or freezing; has inconsistent malformed-input errors; and lacks root, subpath, export, dedicated boundary, property, tamper, and current-Rust fixture evidence.
- Verdict: `PARTIAL`
- Gap and smallest fix: First replace Rust's unchecked `u16` casts with checked conversions and named errors. Then align the TypeScript defaults, builders, duplicate and malformed-input errors, ownership boundaries, exports, and dedicated evidence without taking canonical `externalDataHash` ownership from I11.
- Row transition: `todo -> needs_fix`
- Progress: `33/118`; package `0/31`
- Exact next file: `T22 sdk-libs/transaction/src/instructions/transact/slots.rs`
- Full SDK parity claim: unsupported; external-data API, ownership, error, export, boundary, property, tamper, and current-Rust fixture evidence remain incomplete

### 2026-07-25 12:36 UTC | T22 | `sdk-libs/transaction/src/instructions/transact/slots.rs`

- Baseline: HEAD `7116c995542496f4265840b10a83513dc263ac29`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module owns transaction slot assembly and confidential-output encryption. T13 retains wallet-authority capability ownership, and T03-T10 retain serialization ownership.
- Evidence: TypeScript has only an internal wallet adaptation and omits the public Rust `EncryptedTransactionData`, `encrypt_transaction_data`, and `encode_confidential_slots` APIs. Runtime, copy, error, and export evidence is incomplete. Both Rust and TypeScript mirror one ciphertext per output, conflicting with the `docs/spec.md` sender-bundle and recipient-ordinal mapping.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First correct Rust's slot layout per spec, replace unchecked slot casts with checked conversion and a named error, and reject inconsistent hash-only output contexts. Then align TypeScript's public adaptation and evidence without taking authority or serialization ownership from T13 or T03-T10.
- Row transition: `todo -> needs_fix`
- Progress: `33/118`; package `0/31`
- Exact next file: `T23 sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs`
- Full SDK parity claim: unsupported; slot layout, public API, runtime, ownership, error, export, and current-Rust evidence diverge

### 2026-07-25 12:38 UTC | T23 | `sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs`

- Baseline: HEAD `176509028d7367ff9bcaaa7aaf8968ff745a0658`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module owns transaction proof-input assembly and its public transaction helpers. Client/prover retain prover transport and proof-generation ownership, and T19 retains aggregate transaction-input ownership.
- Evidence: Core current-Rust proof assembly and frozen prover vectors match. The public helper and `PublicAmounts` API disposition is incomplete; constructor, signature, error, mutation, and real-before-dummy validation differ; and boundary, property, tamper, declaration, and pack evidence is incomplete.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Resolve the `docs/spec.md` P256 input-owner field conflict with current Rust, Go, and TypeScript behavior, and add canonical BN254 validation to Rust. Then align the TypeScript API, validation, errors, ownership, and evidence without taking client/prover or T19 ownership.
- Row transition: `todo -> needs_fix`
- Progress: `33/118`; package `0/31`
- Exact next file: `T24 sdk-libs/transaction/src/instructions/transact/split.rs`
- Full SDK parity claim: unsupported; public API, validation, errors, mutation, spec, BN254, and boundary/property/tamper/declaration/pack evidence diverge

### 2026-07-25 12:43 UTC | T24 | `sdk-libs/transaction/src/instructions/transact/split.rs`

- Baseline: HEAD `97713a7e09e76ee06da8cb91229fbbaf80e98325`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module owns fixed `1x8` split preparation, signing, and instruction construction. T08 retains serialization ownership.
- Evidence: Valid split construction and bytes match current Rust. Rust lacks required input-owner, nullifier, and dummy validation; TypeScript diverges in zone and amount error categories and details, public signing, fields, and `PreparedSplit.asset` surface, malformed prepared-state and ownership semantics, and evidence, export, and browser coverage.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First add Rust ownership validation and named errors. Then align the TypeScript error contract, public surface, prepared-state and ownership semantics, and evidence without taking serialization ownership from T08.
- Row transition: `todo -> needs_fix`
- Progress: `33/118`; package `0/31`
- Exact next file: `T25 sdk-libs/transaction/src/instructions/transact/transfer.rs`
- Full SDK parity claim: unsupported; split validation, errors, public surface, prepared-state ownership, and evidence diverge

### 2026-07-25 12:47 UTC | T25 | `sdk-libs/transaction/src/instructions/transact/transfer.rs`

- Baseline: HEAD `11761d89fc639da660ef70f9494a52347082b4de`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module owns transfer preparation, finalization, signing, and chaining. T22 retains slot-layout ownership, and T23 retains proof-input ownership.
- Evidence: Valid transfer bytes and conservation match. TypeScript pads during prepare rather than finalize, derives dummy tags from the sender rail, omits Rust public fields, types, direct signing, and chaining dispositions, and differs in ownership, withdrawal, amount, payload, error semantics, and evidence. It also inherits T22's spec-conflicting ciphertext layout.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First add Rust withdrawal-rail and range checks, excess-slot rejection, and checked recipient positions. Then align TypeScript's lifecycle, dummy tags, public surface, semantics, and evidence without taking T22 or T23 ownership.
- Row transition: `todo -> needs_fix`
- Progress: `33/118`; package `0/31`
- Exact next file: `T26 sdk-libs/transaction/src/instructions/transact/mod.rs`
- Full SDK parity claim: unsupported; transfer lifecycle, dummy tags, public surface, ownership, withdrawal, amount, payload, errors, slot layout, Rust validation, and evidence diverge

### 2026-07-25 12:49 UTC | T26 | `sdk-libs/transaction/src/instructions/transact/mod.rs`

- Baseline: HEAD `19d4d5875c7aa37479e68059d81b4d1723ee4194`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This aggregate exposes the transact modules and flattened public symbols. T19-T25 retain ownership of their child behavior and defects.
- Evidence: Rust exposes seven modules and 29 flattened symbols. TypeScript offers a narrowed, orphaned surface with no transact subpath, incomplete capabilities, and no exact root, instructions, declaration, tarball, or packed-consumer aggregate evidence; it inherits T19-T25 defects. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Add a deliberate transact subpath and complete aggregate exports and capabilities, then add exact root, instructions, declaration, tarball, and packed-consumer evidence without taking T19-T25 child ownership.
- Row transition: `todo -> needs_fix`
- Progress: `33/118`; package `0/31`
- Exact next file: `T28 sdk-libs/transaction/src/instructions/merge_zone.rs`
- Full SDK parity claim: unsupported; the transact aggregate surface, capabilities, packaging evidence, and inherited child defects diverge

### 2026-07-25 12:54 UTC | T28 | `sdk-libs/transaction/src/instructions/merge_zone.rs`

- Baseline: HEAD `c602f945a8784c5e5f9ebfcf4000c54e736bb006`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module owns merge-zone preparation, proof construction, and instruction assembly. T09 retains merge serialization ownership, and T27 retains ordinary merge ownership.
- Evidence: The TypeScript builder, prepared flow, and proof flow exist, but reject Rust-accepted `ZoneData` and `Memo`, lack expiry configuration, do not revalidate prepared zone consistency, alias or defer zone-hash and address validation, and lack boundary, property, tamper, browser, pack, and live merge-zone evidence.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Accept the Rust-supported payloads, expose configurable expiry, revalidate prepared zone consistency during finalization, perform canonical zone-hash and address validation, and add the missing evidence without taking T09 or T27 ownership.
- Row transition: `todo -> needs_fix`
- Progress: `33/118`; package `0/31`
- Exact next file: `T29 sdk-libs/transaction/src/instructions/zone_authority.rs`
- Full SDK parity claim: unsupported; merge-zone payload, expiry, prepared-state validation, canonical zone validation, and evidence diverge

### 2026-07-25 12:58 UTC | T29 | `sdk-libs/transaction/src/instructions/zone_authority.rs`

- Baseline: HEAD `ab60bc541488b6c3e6972684d4d0305a9bfccb87`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module owns zone-authority transaction construction, proof finalization, and instruction assembly.
- Evidence: TypeScript omits `ExternalData`, shape and field-encoded public asset, and proof/finalization flow; changes optional-zone and public-amount semantics; uses noncanonical merge errors; aliases mutable inputs; and lacks direct fixture, malformed, tamper, browser, declaration, pack, and E2E evidence.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First make Rust enforce canonical constructor and private invariants, a required nonzero zone, shape and tail padding, derived amounts and payer hash, and spec-required rejection of zone-authority withdrawals. Then align TypeScript semantics, errors, ownership, proof/finalization flow, and evidence.
- Row transition: `todo -> needs_fix`
- Progress: `33/118`; package `0/31`
- Exact next file: `T30 sdk-libs/transaction/src/instructions/mod.rs`
- Full SDK parity claim: unsupported; zone-authority construction, invariants, proof/finalization, semantics, errors, ownership, and evidence diverge

### 2026-07-25 13:01 UTC | T30 | `sdk-libs/transaction/src/instructions/mod.rs`

- Baseline: HEAD `731b06511e06ff40311061b53925be8ce566c65e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module owns the public instructions aggregate, including approved instruction capabilities and input/output types.
- Evidence: The TypeScript entry point is a narrowed, undocumented aggregate, omits approved Rust capabilities and instruction input/output types, has inconsistent root forwarding and an orphan transact barrel, inherits T18-T29 defects, and lacks exact declaration, runtime, tarball, browser, packed-consumer, and aggregate-fixture allowlists.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Expand and document a coherent instructions and root aggregate, expose the approved capabilities and types, remove the orphan-barrel inconsistency, and add the exact allowlists while leaving T18-T29 implementation and evidence defects owned by their child rows.
- Row transition: `todo -> needs_fix`
- Progress: `33/118`; package `0/31`
- Exact next file: `T31 sdk-libs/transaction/src/lib.rs`
- Full SDK parity claim: unsupported; the instructions aggregate, root forwarding, capability and type exports, inherited child defects, and exact aggregate evidence diverge

### 2026-07-25 13:04 UTC | T31 | `sdk-libs/transaction/src/lib.rs`

- Baseline: HEAD `8a61adab06bc40d81b0b594bc8baca662c24d0bc`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module owns the transaction package root surface and package metadata; T01-T30 retain their child implementation and evidence ownership.
- Evidence: The TypeScript root omits or remaps many Rust exports, exposes undocumented extras and a name collision, inherits T01-T30 gaps, lacks exact declaration, runtime, tarball, browser, named-consumer, and root-fixture allowlists, has undeclared direct Noble dependencies, and has incomplete license, repository, and package metadata.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Align and document the root surface, declare direct dependencies, complete package metadata, and add exact root allowlists while preserving T01-T30 child ownership.
- Row transition: `todo -> needs_fix`
- Progress: `33/118`; package review `31/31` complete; package parity gates failed
- Exact next file: `C01 sdk-libs/client/src/retry.rs`
- Full SDK parity claim: unsupported; transaction root exports, inherited child gaps, evidence allowlists, dependencies, and package metadata diverge

### 2026-07-25 13:08 UTC | C01 | `sdk-libs/client/src/retry.rs`

- Baseline: HEAD `6882ca259c206780e977199e51408d1f1aa2d512`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module owns the public indexer polling configuration, capped backoff iterator, synchronous `poll_until` operation, defaults, and wait factory.
- Evidence: The normal private TypeScript backoff schedule matches, but TypeScript omits Rust's public retry operations, defaults, factories, and `pollUntil`; differs on Rust-valid configurations, zero delay, timer bounds, maximum attempts, and retry error handling; duplicates retry loops; and lacks focused fixture, error, export, and packed-package evidence.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First classify Rust's idempotent retry policy, retain structured causes, cap the first delay, and add first-delay and attempt-count tests. Then expose and reuse one aligned TypeScript retry surface and add focused fixture, error, export, and pack evidence.
- Row transition: `todo -> needs_fix`
- Progress: `32/118`; package `1/22`; `C02` reopened for re-review after transaction error changes in `6882ca25`
- Exact next file: `C02 sdk-libs/client/src/error.rs` re-review
- Full SDK parity claim: unsupported; retry policy, public surface, boundary behavior, reuse, and focused evidence diverge

### 2026-07-25 13:13 UTC | C02 | `sdk-libs/client/src/error.rs`

- Baseline: HEAD `f0006e69211c5edea9193398be0692f1ea6b7e7b`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only re-review; implementation commit `none`
- Explanation: This module owns the public client error taxonomy and its dependency-error conversions; C01 retains retry-policy ownership.
- Evidence: The exhaustive 58-code fixture proves structural mapping, but `CLIENT_POLL_TIMED_OUT` has no TypeScript runtime producer. The runtime constructor accepts arbitrary codes and malformed payloads; details/cause validation plus deep immutability and redaction evidence are incomplete; and call-site reachability is unproven.
- Verdict: `PARTIAL`
- Gap and smallest fix: Close and validate runtime construction, produce each implemented code through its intended boundary, and add deep immutability, redaction, malformed-payload, and call-site evidence.
- Row transition: `needs_re_review -> needs_fix`
- Progress: `32/118`; package `1/22`
- Exact next file: `C03 sdk-libs/client/src/rpc.rs`
- Full SDK parity claim: unsupported; runtime construction, timeout production, validation, immutability, redaction, and reachability evidence remain incomplete

### 2026-07-25 13:16 UTC | C03 | `sdk-libs/client/src/rpc.rs`

- Baseline: HEAD `ff5d05c56e2a721689a283c1fa6293c7e83a1b30`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only review; implementation commit `none`
- Explanation: This module owns the blocking RPC capability contract, account and transaction retrieval, submission and confirmation, proving, subscriptions, decoding, constants, and public exports.
- Evidence: TypeScript `Rpc` exposes only 11 of 30 blocking capabilities, reduces account, send, and confirmation semantics, handles JSON integers, envelopes, and errors lossily, and incompletely decodes versioned transactions, loaded addresses, and outer and inner instructions. Retries, subscriptions, prove results, constants, root exports, and current fixture, declaration, browser, pack, and live evidence are missing. No tests ran for this recorder update.
- Verdict: `DIVERGENT`
- Gap and smallest fix: First use `Address` in Rust, make transaction construction fallible, and restore trait capability symmetry. Then align the TypeScript surface, semantics, decoding, errors, exports, and evidence.
- Row transitions: `C03 todo -> needs_fix`; `C04 done -> needs_re_review`
- Progress: `31/118`; package `0/22`
- Exact next file: `C04 sdk-libs/client/src/indexer.rs` re-review
- Full SDK parity claim: unsupported; RPC capabilities, semantics, decoding, resilience, exports, and evidence diverge

### 2026-07-25 13:23 UTC | C04 | `sdk-libs/client/src/indexer.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`
- Worker: completed read-only re-review; implementation commit `none`
- Explanation: This module owns the feature-gated public indexer adapter; the asynchronous TypeScript adapter consolidates the blocking and asynchronous Rust types, and the blocking-only 60-second Merkle proof-count loop remains a justified omission.
- Evidence: The four requests, tag and leaf ordering, cursor conversion, defensive copies, response ordering, base58 and curve validation, unknown-field rejection, abort support, and browser-safe imports are represented. The frozen `rpc-indexer-v1.json` predates the active C01 retry integration, no live Photon contract test exists, and focused fatal-versus-transient, cause-retention, exhaustion, and full-width integer evidence is absent.
- Verdict: `DIVERGENT`
- Gap and smallest fix: Stop `wrapIndexer` from collapsing `API_JSON_RPC`, invalid content types, missing results, and malformed JSON-RPC response bodies into the generic `CLIENT_INDEXER` that `isRetryable` accepts, so a bad request or malformed response fails on the first attempt while transport failures, timeouts, and the HTTP statuses the API layer already treats as transient still repeat; keep `CLIENT_POLL_TIMED_OUT` when the schedule ends on a transient cause and return `CLIENT_INDEXER_NOT_CAUGHT_UP` only after a valid lagging response; apply the same policy to Rust `wait_for_indexer`; decide how both languages encode `u64` slots, leaf indexes, and root sequences above `2^53 - 1`; expose or document the omitted API accessor; regenerate fixtures once the concurrent retry work settles.
- Rust defects: `docs/spec.md` defines indexer `Context { slot: u64 }` while both languages expose `block_time: i64`; `wait_for_indexer` duplicates retry iteration instead of using `poll_until`; `ZolanaIndexer::prove_transact` zips `spend_proofs` by position without checking requested leaves or trees; `spend_proofs` reports incomplete responses as a formatted `Rpc` error instead of `IncompleteInputProofs`; `indexer_error` stringifies `ApiError` and can leak HTTP bodies into public error text.
- Row transition: `needs_re_review -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C05 sdk-libs/client/src/solana_rpc.rs`
- Full SDK parity claim: unsupported; retry classification, integer domain, adapter surface, and current evidence diverge

### 2026-07-25 13:30 UTC | C05 | `sdk-libs/client/src/solana_rpc.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; a concurrent worker holds uncommitted edits in `sdk-libs/client/src/{error,indexer,lib,retry}.rs`, `sdk-libs/client/src/prover/transact/witness.rs`, and `sdk-libs/ts/client/src/{client,error,index,indexer,rpc,retry}.ts` plus `prover/assembly.ts`
- Worker: client prover review worker; implementation commit `none`
- Explanation: This feature-gated module is the generic Solana JSON-RPC backend. It wraps `solana_rpc_client::RpcClient` and its nonblocking twin, and `sdk-libs/client/src/lib.rs` re-exports `SolanaRpc`, `AsyncSolanaRpc`, `ConfirmedInstructionGroups`, and `transact_output_view_tags_from_instruction_groups`. It imports Solana account, address, commitment, hash, message, signature, transaction, and transaction-status types, `zolana_event::{InstructionGroup, ParsedInstruction}`, and the interface `fetch_tag`, `TransactIxData`, tag, and program-ID constants. Both structs implement the crate `Rpc` and `AsyncRpc` traits over 14 methods and add inherent helpers for executable checks, airdrops, confirmed-transaction fetches, instruction-group assembly, and output view tags. The view-tag flow fetches the JSON-encoded confirmed transaction, rebuilds the account key list from the raw message plus writable and readonly loaded addresses, decodes base58 instruction data, groups inner instructions under their outer index, then walks each group's outer instruction followed by its inner instructions until one shielded-pool `TRANSACT` (`tag::TRANSACT == 0`) payload decodes; `fetch_tag` resolves inline, account-index, and P256 owner tags, and a `BTreeSet` deduplicates and byte-sorts the result. The module handles no signing, viewing, or nullifier secrets: it reads public transaction data and returns public 32-byte owner tags. Rust evidence is `sdk-libs/client/tests/solana_rpc.rs`; the TypeScript counterpart is `sdk-libs/ts/client/test/solana-rpc.test.ts`.
- Evidence: `docs/spec.md` defines no RPC backend contract, so current Rust governs. `program-libs/event/src/tag.rs` pins `TRANSACT = 0`, matching the TypeScript `data[0] !== 0` guard, and `fetch_tag` in `program-libs/interface/src/instruction/instruction_data/transact.rs` matches the three TypeScript owner-tag branches with `OwnerTagAccountMissing` and `MissingP256SigningKey` collapsed into `CLIENT_RPC_OWNER_TAG`. `BTreeSet` ordering and the TypeScript base64-keyed `Map` plus unsigned byte comparison agree on deduplication and order for fixed 32-byte tags. The four Rust mock-client tests cover `get_account`, `get_program_accounts`, `get_latest_blockhash`, `get_balance`, `get_block_height`, and `get_slot`; they do not touch instruction-group assembly or view-tag extraction. Eight TypeScript tests cover request shape, malformed JSON-RPC response and integer rejection, program-account decoding, known and unknown custom program errors, unsigned transaction serialization, cancellation versus timeout, direct and inner tag extraction, and the missing-transact rejection. The inventory row promises a dedicated `fixtures/client/solana_rpc.json`, which does not exist; the tests use the `confirmation` block of `client/rpc-indexer-v1.json`, whose `rustPath` and `rustSymbol` do name `solana_rpc.rs` and `transact_output_view_tags_from_instruction_groups` but record only two direct-and-inner tag lists plus two error shapes. No loaded-address, scan-order, inner-metadata, retry, or lookup-table case has coverage in either language.
- Verdict: `DIVERGENT`
- Gap and smallest fix: `sdk-libs/ts/client/src/solana-rpc.ts::SolanaRpc.sendTransaction` posts `sendTransaction` and returns, while `SolanaRpc::send_transaction` calls `send_and_confirm_transaction`, so the Rust call returns only after confirmation. `extractOutputViewTags` reads only `result.transaction.message.accountKeys`, while `transaction_message_parts` appends `meta.loadedAddresses.writable` then `.readonly`, so an address-lookup-table transaction resolves account-index owner tags to the wrong key or fails with `CLIENT_RPC_OWNER_TAG`. The same function flattens the outer instructions ahead of the inner ones, while `transact_output_view_tags_from_instruction_groups` walks each group's outer instruction and then that group's inner instructions, so the two select different `TRANSACT` calls when a wrapper program CPIs into `transact` in one group and a later group calls it directly. TypeScript treats absent `meta` or `innerInstructions` as an empty list and ignores `index`, while `instruction_groups_from_confirmed_transaction` rejects both. `transactOutputViewTags` performs one `getTransaction` call, while `fetch_confirmed_transaction` retries at 250 ms intervals for 30 seconds. `confirmTransaction` sends `searchTransactionHistory: true`, while `confirm_transaction` leaves it false. The public `assert_executable`, `airdrop`, `fetch_confirmed_transaction`, `fetch_confirmed_instruction_groups`, `ConfirmedInstructionGroups`, and `transact_output_view_tags_from_instruction_groups` items have no TypeScript counterpart or recorded disposition; `get_minimum_balance_for_rent_exemption`, `get_block_height`, `get_slot`, `get_signature_statuses`, `health`, and `send_transaction_with_config` remain C03 trait-surface gaps. Smallest fix: confirm after send, append loaded addresses to the key list, restore per-group scan order and the two rejection rules, add the bounded confirmation retry, drop `searchTransactionHistory`, record a disposition for each omitted public item, and add the promised `fixtures/client/solana_rpc.json` covering lookup-table keys, scan order, missing inner metadata, unmatched group index, and duplicate tags.
- Rust defects: `transact_output_view_tags_from_instruction_groups` and `parse_pubkey` build public error text with `format!`, so RPC payload fragments reach `ClientError::Rpc` strings instead of structured details; `SolanaRpc::wait_for_signature` and `fetch_confirmed_transaction` hard-code 250 ms and, for `AsyncSolanaRpc`, the 30-second `DEFAULT_CONFIRMATION_TIMEOUT` rather than accepting the configurable `confirmation_timeout` that `SolanaRpc` already stores.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C06 sdk-libs/client/src/prover/field.rs`
- Full SDK parity claim: unsupported; send-and-confirm semantics, lookup-table key resolution, scan order, rejection rules, retry behavior, and the promised fixture diverge

### 2026-07-25 13:38 UTC | C06 | `sdk-libs/client/src/prover/field.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This 23-line module holds three prover conversion helpers. It imports `num_bigint::BigUint` and `crate::error::ClientError`; `sdk-libs/client/src/prover/mod.rs` declares `pub mod field` and `sdk-libs/client/src/lib.rs` declares `pub mod prover`, so the helpers are reachable as `zolana_client::prover::field::*` even though the crate root does not flatten them. `right_align<N>` copies an `N`-byte array into the low bytes of a 32-byte buffer and rejects `N > 32` at compile time. `right_align_slice` does the same for a runtime slice and returns `ClientError::FieldTooLong` above 32 bytes. `be` reads a 32-byte buffer as a big-endian `BigUint` with no range reduction. The module holds no key material; `right_align_slice` is applied to a 31-byte nullifier secret at the call site in `p256_and_eddsa.rs`, so the helper itself grants no capability. No Rust test targets the file, and the TypeScript behavior lives in the unexported `sdk-libs/ts/client/src/internal.ts`.
- Evidence: `docs/spec.md` describes no conversion helper, so current Rust governs. The single caller is `sdk-libs/client/src/prover/transact/p256_and_eddsa.rs`, which imports `be` and `right_align_slice`; `merge.rs`, `merge_zone.rs`, `zone_authority.rs`, `zone_eddsa.rs`, and `zone_p256.rs` import `be` alone. `internal.ts::bytesToBigInt` reproduces `be(right_align(x))` for any length because leading zero bytes do not change the integer, and `bytesField` reproduces `right_align_slice` followed by `be`, raising `CLIENT_FIELD_TOO_LONG` with `{field, actual, maximum: 32}` above 32 bytes. `bytesField` and the `asField` wrappers in `prover/assembly.ts` and `prover/merge.ts` add a BN254 range check that `be` omits; `asset_field` and `signed_to_field` in `sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs` already reduce their outputs, so no reachable input distinguishes the two. `sdk-libs/ts/fixtures/client/errors-v1.json` lists `CLIENT_FIELD_TOO_LONG` structurally; the inventory's promised `fixtures/client/field.json` does not exist, and neither language exercises a slice longer than 32 bytes.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/ts/reports/inventory.json` records `sdk-libs/client/src/prover/field.rs` with `disposition: internal` and `target: @zolana/client · src/prover/field.ts`, but the Rust module is public and the TypeScript file is `src/internal.ts`, which no package subpath exports. Correct the inventory target, record whether the Rust module should stay public or become `pub(crate)`, and add the promised `fixtures/client/field.json` covering a 1-byte, 31-byte, and 32-byte alignment, a 33-byte rejection, and a value at the BN254 boundary so a stale alignment or width cannot pass.
- Rust defects: `sdk-libs/client/src/prover/merge.rs::right_align` is a second 31-byte implementation of `field::right_align`, which has no caller; keep one implementation and delete the duplicate.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C07 sdk-libs/client/src/prover/inputs.rs`
- Full SDK parity claim: unsupported; the public module has no recorded TypeScript disposition and no direct oracle

### 2026-07-25 13:47 UTC | C07 | `sdk-libs/client/src/prover/inputs.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This module declares the flat prover request payloads. It imports `num_bigint::BigUint`, `zolana_transaction::{ProofInputUtxo, instructions::types::SppProofInputUtxo}`, `ClientError`, `prover::field::be`, and the two tree heights from `crate::rpc`. `sdk-libs/client/src/prover/mod.rs` re-exports `BatchAddressAppendInputs`, `MergeInputs`, `TransferInput`, `TransferInputs`, `TransferOutput`, and `TransferP256Inputs`, and `sdk-libs/client/src/lib.rs` flattens each of those except `MergeInputs` to the crate root. `TransferInput` and `TransferOutput` mirror the Go circuit input and output. `TransferInputs` is the Solana-only payload, `TransferP256Inputs` adds the P256 public key, signature, split message digest, and shared signing field, `MergeInputs` carries the eight-input merge witness plus the shared owner and viewing material, and `BatchAddressAppendInputs` carries the forester's address-append witness. The one behavior is `TransferInput::new_dummy`, which builds a padding slot over the caller's random 31-byte blinding, zeroes both proof paths at `STATE_TREE_HEIGHT` and `NULLIFIER_TREE_HEIGHT`, mirrors the caller's roots and owner hash, sets `is_dummy` to 1 and `nullifier_secret` to 0, and returns the dummy nullifier alongside. The types hold no secret except `nullifier_secret`, which a dummy leaves at 0. The TypeScript counterpart is `sdk-libs/ts/client/src/prover/types.ts`, with the dummy constructor in `prover/assembly.ts::createDummyTransferInput` and coverage in `test/vectors/prover-inputs.test.ts`.
- Evidence: `docs/spec.md` does not define the prover payloads, so current Rust and the Go parameter structs govern. The Rust fields map one to one onto TypeScript members of the same meaning under the SDK vocabulary rename (`owner_pk_hash` to `ownerPublicKeyHash`, `nullifier_pk` to `nullifierPublicKey`, `user_nullifier_pk` to `userNullifierPublicKey`, `tx_viewing_sk` to `txViewingSecret`), and `prover/client.ts` restores the Go wire names, so the rename does not reach the request. TypeScript models `TransferP256Inputs` as an extension of `TransferInputs`, which yields the same member set as the separate Rust struct. `createDummyTransferInput` reproduces `new_dummy` for `is_dummy`, both zero path vectors at 32 and 40 elements, zero indices, mirrored roots and owner, and zero secret. Rust-generated `client/proof-input-v1.json` cites `inputs.rs` and `TransferInput::new_dummy`, but records one case: a single 31-byte blinding of repeated `0x08`, one owner hash, and the resulting dummy nullifier and two roots. Nothing pins the path lengths, the zero secret, or the `is_dummy` flag against a stale value beyond that case, and no fixture or test covers `BatchAddressAppendInputs`.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/client/src/lib.rs` exports `BatchAddressAppendInputs`, and `sdk-libs/client/src/prover/json.rs::to_json_batch_address_append` serializes it, but `sdk-libs/ts/client/src/prover/types.ts` declares no counterpart and no inventory row records the omission. `MergeInputs` exists in `types.ts` yet `sdk-libs/ts/client/src/prover/index.ts` does not export it, so no package subpath exposes the merge payload type that `proveMerge` accepts. `TransferInput::new_dummy` has no exported TypeScript constructor; `createDummyTransferInput` is module-internal. Smallest fix: record a disposition for the forester-only address-append payload or add the type, add `MergeInputs` to the `@zolana/client/prover` export list, and extend `proof-input-v1.json` with a second blinding, a nonzero root pair, and the full zeroed path vectors so a shortened path or a nonzero dummy secret fails the vector test.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C08 sdk-libs/client/src/prover/proof.rs`
- Full SDK parity claim: unsupported; one exported payload type has no counterpart and the dummy oracle covers a single case

### 2026-07-25 15:05 UTC | W01 | `sdk-libs/wallet/src/actions/create_associated_token_account.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; concurrent uncommitted worker edits in `sdk-libs/ts/client/`, `sdk-libs/client/`, `sdk-libs/transaction/`, and `xtask/`
- Worker: wallet review worker; implementation commit `none`
- Explanation: This is the smallest wallet action. It imports `solana_keypair::Keypair`, `solana_pubkey::Pubkey`, the interface `CreateAssociatedTokenAccount` builder, and `zolana_client::{error::ClientError, rpc::AsyncRpc}`, and exposes one async function `create_associated_token_account(rpc, payer, owner, mint) -> Result<(Signature, Pubkey), ClientError>`. It builds the idempotent SPL associated-token-account instruction, reads the derived address off the builder, and hands the single instruction to `AsyncRpc::create_and_send_transaction`, which fetches the blockhash, calls `Transaction::new(&[payer], message, blockhash)`, and sends. `actions/mod.rs` and `lib.rs` both re-export it. It touches no shielded key material: the payer keypair is a plain Solana signer and the owner and mint are public addresses. Rust evidence is the localnet path in `sdk-libs/wallet/tests/`; the TypeScript counterpart is `sdk-libs/ts/wallet/src/submit.ts::createAssociatedTokenAccount` with `test/wallet.test.ts` and the e2e suite.
- Evidence: `docs/spec.md` defines no ATA action, so current Rust governs. `xtask/src/ts_fixtures_wallet.rs::ata_vectors` calls the Rust action itself, so `sdk-libs/ts/fixtures/wallet/create_associated_token_account.json` is a genuine Rust oracle rather than a restated expectation; it pins the instruction, the canonical address, and the compiled transaction bytes. `test/wallet.test.ts` replays that fixture against a mocked RPC and matches all three. `internal.ts::compileTransaction` reproduces `CompiledKeys::compile`: the fee payer is forced first and writable, and the remaining keys sort lexicographically by decoded address bytes inside the signer-writable, signer-readonly, writable, readonly buckets, which is what the `BTreeMap<Pubkey, CompiledKeyMeta>` in current Solana produces. The tuple-versus-object return and the `TransactionSigner` interface in place of `&Keypair` are reasonable JavaScript adaptations, and the signer interface is the narrower capability. No test covers a signer that returns an under-signed transaction, and the wallet package has no canonical list of `WALLET_*` codes.
- Verdict: `PARTIAL`
- Gap and smallest fix: The queue and `sdk-libs/ts/reports/inventory.json` both name `wallet/src/actions.ts` as the TypeScript owner; the function is in `sdk-libs/ts/wallet/src/submit.ts` and `actions.ts` holds the transfer, withdrawal, and split builders instead. `Transaction::new` panics when the supplied keypairs do not cover every required signature, so Rust cannot send an under-signed transaction, while `createAssociatedTokenAccount` forwards the signer's output to `rpc.sendTransaction` without checking the signature set. `wrapWalletError("WALLET_CREATE_ASSOCIATED_TOKEN_ACCOUNT", cause)` hides the `ClientError` code one `cause` level deep, so a caller switching on the client code has to unwrap. `AsyncRpc::create_and_send_transaction` has no counterpart on the TypeScript `Rpc` interface, which is the already-recorded C03 trait-surface gap. Smallest fix: correct the inventory and queue path to `wallet/src/submit.ts`, reject an incomplete signature set before `sendTransaction`, and surface the client code on the wrapper.
- Rust defects: none observed.
- Row transition: `in_progress -> needs_fix`
- Progress: `31/118`; package `0/9`
- Exact next file: `W02 sdk-libs/wallet/src/actions/deposit.rs`
- Full SDK parity claim: unsupported; the recorded owner path is wrong and signature completeness is unchecked

### 2026-07-25 15:12 UTC | W02 | `sdk-libs/wallet/src/actions/deposit.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; concurrent uncommitted worker edits remain in place
- Worker: wallet review worker; implementation commit `none`
- Explanation: This module turns a public shielded address plus an amount into a deposit note and its instruction. It imports `zolana_interface` deposit instruction data and builders, `zolana_transaction::{ProofInputUtxo, random_blinding}`, and the client RPC traits. Public items are `Deposit`, `DepositParams`, `Deposit::{new, instruction, build_transaction, build_transaction_sync}`, `create_deposit`, `build_deposit_transaction`, `build_deposit_transaction_sync`, and `deposit`. `Deposit::new` derives `owner` from `recipient.owner_hash()`, draws a fresh blinding, sets the view tag to the recipient viewing pubkey x-coordinate, computes `utxo_hash` through `ProofInputUtxo::new(owner, asset, amount, &blinding)?.hash()?`, and resolves SOL against SPL routing in `spl_accounts`. The blinding travels in the clear on purpose, so a third-party depositor needs no shared secret; the module handles no signing, viewing, or nullifier secret. `deposit` is the only item that signs and sends, taking a payer and a depositor keypair. TypeScript evidence is `test/vectors/deposit-vector.test.ts` plus `fixtures/workflows/deposit-v1.json` and `fixtures/wallet/deposit.json`.
- Evidence: `docs/spec.md` fixes the deposit note fields, and both languages agree on the view tag, the clear blinding, and `utxo_data: None`. The fixture pins the instruction discriminator, data bytes, account metas, and the unsigned message for the SOL rail, and `deposit-vector.test.ts` matches all of them. What it does not do is exercise the derivation: the test builds `new Deposit({ owner: bytes(fixture.inputs.ownerBytes), viewTag: bytes(fixture.inputs.viewTagBytes), blinding: ..., utxoHash: ... })` from fixture values, so an incorrect `ownerHash` or `ownerUtxoHash` in `createDeposit` still passes. `random_blinding` and the view-tag derivation agree between languages. `build_deposit_transaction` matches `buildDepositTransaction` for the account order and the blockhash fetch.
- Verdict: `DIVERGENT`
- Gap and smallest fix: `sdk-libs/ts/wallet/src/deposit.ts::createDeposit` rejects `params.amount <= 0n` with `WALLET_INVALID_AMOUNT` and rejects a SOL deposit that carries `splTokenAccount` with `WALLET_UNEXPECTED_SPL_TOKEN_ACCOUNT`; `Deposit::new` accepts a zero amount and `spl_accounts` ignores a token account on the SOL rail, so the two accept different input domains. `actions/mod.rs` exports `deposit`, the build-sign-send entry point that takes both a payer and a depositor keypair, and `sdk-libs/ts/wallet/src/index.ts` has no counterpart; `lib.rs` does not re-export it either, so the Rust surface is itself inconsistent. `Deposit::build_transaction_sync` and `build_deposit_transaction_sync` have no recorded JavaScript disposition. `ClientError::MissingSplTokenAccount` becomes `WALLET_MISSING_SPL_TOKEN_ACCOUNT`, another instance of the package-level `WALLET_*` re-coding recorded under W09. Smallest fix: drop the two extra rejections or add them to Rust, add `deposit` to both roots or record why it is module-only, and change `deposit-vector.test.ts` to call `createDeposit` with the recipient shielded address and a pinned blinding so the owner hash and note hash are checked against the fixture.
- Rust defects: `actions/mod.rs` re-exports `deposit` while `lib.rs` omits it, so the crate root advertises `build_deposit_transaction` without the send path that uses it.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/9`
- Exact next file: `W03 sdk-libs/wallet/src/actions/submit.rs`
- Full SDK parity claim: unsupported; the accepted input domain differs, one public action is absent, and the note derivation has no oracle

### 2026-07-25 15:20 UTC | W03 | `sdk-libs/wallet/src/actions/submit.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; concurrent uncommitted worker edits remain in place
- Worker: wallet review worker; implementation commit `none`
- Explanation: This module submits a prepared merge. Public items are `MergeMaterial`, `SubmitMergeTransaction`, `SubmittedMerge`, and `submit_merge_transaction`; `MERGE_CU_LIMIT` is the private `1_400_000` compute-unit ceiling the Groth16 merge verification needs. The flow validates the request against the on-chain user record through `validate_merge_submission`, fetches the input commitments, asks the indexer for the Merkle proofs, runs `ensure_proofs_match_submit_tree`, drives `MergeProver`, compresses the proof, builds the merge instruction behind a `ComputeBudgetInstruction::set_compute_unit_limit`, signs with the payer, and returns the signature plus the output hash. `MergeMaterial` is the capability boundary: it carries the merge witness the prover needs and deliberately excludes the signing and viewing secrets, which stay behind the authority. TypeScript evidence is `sdk-libs/ts/wallet/test/submit.test.ts` against `sdk-libs/ts/wallet/src/submit.ts::submitMergeTransaction`.
- Evidence: `docs/spec.md` fixes the merge circuit shape and the registry merging flag; current Rust governs the submission mechanics. `sdk-libs/ts/client/src/client.ts` applies `computeUnitLimitInstruction(1_400_000)` in both merge finish paths, matching `MERGE_CU_LIMIT`. `validate_merge_submission` checks the registry `merging_enabled` flag, that the signing key matches the owner's curve (P256 or Ed25519), and the nullifier and viewing pubkeys; TypeScript keeps `WALLET_MERGE_DISABLED` separate and compares the same three key byte sequences. The explicit-hash path in `create_merge` and `createMerge` agree on `InputUtxoTreeMismatch`, the eight-input ceiling, and the two-input minimum. `submit.test.ts` covers the disabled flag and a mismatch, but neither language has a test where the indexer returns a proof rooted in a different tree.
- Verdict: `PARTIAL`
- Gap and smallest fix: `ensure_proofs_match_submit_tree` walks the proofs the indexer returned and rejects any whose `state_tree` or `nullifier_tree` differs from the submit tree; `sdk-libs/ts/wallet/src/submit.ts::submitMergeTransaction` compares only its own configured tree field against the request tree, so a wrong-tree indexer response is passed to `proveMerge` unchecked and fails later as an opaque proof error. `validate_merge_submission` returns distinct rejections for the signing curve, the viewing key, and the nullifier key; TypeScript collapses them into `WALLET_MERGE_MATERIAL_MISMATCH`, so a caller cannot tell a wrong-rail key from a wrong viewing key. `MergeMaterial` in TypeScript holds `nullifierKey`, widening a struct whose Rust counterpart holds no secret, and its `proverUrl` field is declared and never read. The unchecked wrong-tree case duplicates the already-recorded C04 finding that `ZolanaIndexer::prove_transact` zips spend proofs by position without checking the requested leaves or trees; cite C04 rather than fixing it twice. Smallest fix: port `ensure_proofs_match_submit_tree` to the TypeScript path, split the three mismatch codes, and delete `proverUrl` and `nullifierKey` from `MergeMaterial`.
- Rust defects: none observed.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/9`
- Exact next file: `W04 sdk-libs/wallet/src/actions/transaction.rs`
- Full SDK parity claim: unsupported; indexer proof trees are unvalidated and the material struct carries a secret Rust withholds

### 2026-07-25 14:02 UTC | C08 | `sdk-libs/client/src/prover/proof.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This module turns a gnark proof response into the wire-format proof the program verifies. It imports `groth16_solana::groth16::negate_g1_be`, the `alt_bn128_g1_compress_be` and `alt_bn128_g2_compress_be` helpers from `solana_bn254`, `num_traits::Num`, serde, and the interface `P256Proof` and `TransactProof`. `prover/mod.rs` re-exports `Commitments`, `CompressedCommitments`, `Proof`, and `ProofCompressed`, and `lib.rs` flattens them to the crate root; `GnarkProofJson` and `proof_from_gnark_json` stay `pub(crate)`. The flow is: parse the gnark JSON into an uncompressed proof with `proof_a` negated and the commitment present only when both commitment arrays are, compress G1 to 32 bytes and G2 to 64 through `TryFrom<Proof>`, then emit either `TransactProof::P256` or `TransactProof::Eddsa` from `to_transact_proof`, or the five-tuple `P256Proof` from `to_p256_proof` and its `to_merge_proof` alias, which reject a proof carrying no commitment. The module handles no key material; a proof and its commitment are public. Rust evidence is the three unit tests at the foot of the file; TypeScript evidence is `sdk-libs/ts/client/test/vectors/proof-compression.test.ts` against `sdk-libs/ts/client/src/prover/proof.ts`.
- Evidence: `docs/spec.md` does not define the response format, so current Rust and the two Rust-generated fixtures govern. `client/proof-validity-v1.json` cites `proof_from_gnark_json`, `ProofCompressed::try_from`, and `to_transact_proof`, and pins the uncompressed and compressed bytes of both rails, the resulting rail tag, and two malformed inputs; the TypeScript vector test matches all of them, including the `0x80` largest-`y` flag on the bsb22 `a` point and the all-zero G1 compression. `client/proof-result-compression-v1.json` cites `to_p256_proof` and pins its missing-commitment rejection as code `ProofParse`. `negate_g1_be` returns the input unchanged for an all-zero point and otherwise computes `p - y` with a borrow chain, which `parseProof` reproduces for a nonzero `y`. The Rust-generated `client/errors-v1.json` lists `CLIENT_PROOF_PARSE` among the 58 client variants and lists no code for a bad curve point or a rail mismatch.
- Verdict: `DIVERGENT`
- Gap and smallest fix: `sdk-libs/ts/client/src/prover/types.ts::CompressedProof` exposes `toTransactProof` alone, so `to_p256_proof` and `to_merge_proof` have no counterpart; the rejection the fixture pins as `ProofParse` is raised instead from `sdk-libs/ts/client/src/client.ts:316` and `:352` as `CLIENT_MERGE_PROOF_COMMITMENT`, a code with no Rust variant, and no test replays `proof-result-compression-v1.json`. `proof.ts::parseCoordinate` demands a `0x`-prefixed hex string below the base modulus while `hex_to_be_32` accepts an unprefixed string, maps an unparsable one to zero through `unwrap_or_default`, and truncates a longer value to its low 32 bytes, so Rust silently accepts a corrupt coordinate that TypeScript rejects. `parseG1` and `compressG1` check the curve equation and `rejectUnknown` refuses extra members, while Rust performs no curve check at parse time and serde ignores unknown members; the two extra TypeScript codes `CLIENT_PROOF_POINT` and `CLIENT_PROOF_RAIL_MISMATCH` have no Rust variant, and Rust has no rail check at all, so an eddsa request answered with a commitment yields a P256 instruction in Rust and an error in TypeScript. `negate_g1_be` writes `p` for a point with a nonzero `x` and a zero `y`, where `parseProof` writes zero. Smallest fix: add `toP256Proof` to `CompressedProof` raising the pinned `CLIENT_PROOF_PARSE` and have the merge paths call it, decide in one place whether the strict coordinate, curve, and unknown-member checks belong in both languages or neither, record the two added codes in `errors-v1.json`, and extend `proof-validity-v1.json` with an unprefixed coordinate, an out-of-range coordinate, and an off-curve point.
- Rust defects: `hex_to_be_32` swallows a hex parse failure with `unwrap_or_default()`, turning a malformed coordinate into zero instead of an error, and truncates an over-long value rather than rejecting it; `proof_from_gnark_json` returns a bare `Option`, discarding which member failed.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C09 sdk-libs/client/src/prover/json.rs`
- Full SDK parity claim: unsupported; the pinned missing-commitment error code differs and coordinate acceptance differs in both directions

### 2026-07-25 15:36 UTC | W04 | `sdk-libs/wallet/src/actions/transaction.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; concurrent uncommitted worker edits remain in place
- Worker: wallet review worker; implementation commit `none`
- Explanation: At 1777 lines this is the core of the package. It imports `zolana_transaction`'s wallet state, `ConfidentialTransfer`, `SppProofInputs`, `Shape`, and `MERGE_INPUTS`, the client RPC traits and `ZolanaClient`, and the interface instruction data. Public items are `UnsignedPrivateTransaction`, the four created-transaction structs with their parameter structs, `TransferRecipient`, `ResolvedAddress`, `create_transfer`, `create_transfer_sync`, `create_withdrawal`, `create_split`, `create_merge`, `build_private_transaction`, `build_private_transaction_sync`, `sign_private_transaction`, `sign_private_transaction_sync`, and the `doc(hidden)` `sign_shielded_transaction` pair. The create functions read wallet state and produce an unsigned plan; the sign functions are the only ones that reach the authority, and the split between them is the capability boundary. `resolve_spend_tree` picks the single tree holding plain notes for an asset, `select_inputs` accumulates unspent notes until the target is met, `validate_unsigned_inputs` re-checks the plan against current wallet state at signing time, and `apply_p256_signature` adds the P256 ownership signature. TypeScript splits this across `src/actions.ts` (create) and `src/private-transaction.ts` (build and sign), with `createMerge` living in `src/submit.ts`.
- Evidence: `docs/spec.md` fixes the two ownership rails and the supported circuit shapes; current Rust governs the selection and validation. The plan structures, the eight-input merge ceiling, the two-to-eight split part bound, the largest-first split candidate, the smallest-first merge candidate, and `num_inputs` counting real notes before padding all agree. `fixtures/wallet/transaction.json` and the `dependency-vector.test.ts` split and merge blocks pin the created plans. What is not covered anywhere: a wallet whose authority rail differs from the rail of the notes it spends, a note substituted between create and sign, and a split input bound to a zone program rather than carrying data. `sign_private_transaction` calls `Transaction::try_sign`, which rejects a blockhash that does not match the message and a signer set that does not cover the required signatures; `buildPrivateTransaction` hands the compiled transaction to an external signer with no equivalent check, which is the same class of gap recorded under W01.
- Verdict: `DIVERGENT`
- Gap and smallest fix: `sdk-libs/ts/wallet/src/private-transaction.ts::applyP256Signature` decides whether to sign from `proofInputs.inputUtxos.some((input) => !input.isDummy() && input.utxo.owner.signatureType() === "p256")`, while `apply_p256_signature` decides from `address.signing_pubkey.signature_type()` on the authority's own shielded address. The two agree only when the spent notes are owned by the signing authority's rail, so an ed25519 authority spending a P256-owned note signs where Rust does not, and the reverse case skips a signature Rust supplies. `private-transaction.ts::matchingInput` compares the output hash, nullifier, asset, amount, and blinding; `validate_unsigned_inputs` compares the entire `Utxo` value plus `data_hash` and `zone_data_hash`, so a note swapped for one with a different owner, zone program, or payload passes the TypeScript guard. `sdk-libs/ts/wallet/src/actions.ts::createSplit` throws `WALLET_SPLIT_INPUT_HAS_DATA` for both the zone-bound and data-carrying cases that `create_split` separates into `SplitInputZoneMismatch` and `SplitInputHasData`. `WALLET_MULTIPLE_INPUT_TREES` puts the tree addresses into `details.trees` where `AmbiguousTree` carries only `{ asset, tree_count }`, and `WALLET_INPUT_UTXO_TREE_MISMATCH` carries no details where the Rust variant names the hash and both trees. `createMerge` reports `WALLET_NOTHING_TO_MERGE` for an empty note set where `resolve_spend_tree` reports `InsufficientBalance { requested: 1, available: 0 }`. TypeScript also hardcodes the eight-input and eight-part ceilings rather than reading `MERGE_INPUTS` and `Shape::IN1_OUT8.n_outputs()`, and `UnsignedPrivateTransaction` exposes `_inputs()`, `_action()`, `_withdrawal()`, and `_summary()` on an exported class where the Rust fields are private, so the spend plan is readable by any holder of the object. Smallest fix: read the rail from the authority address, compare the full note plus both hashes in `matchingInput`, restore the two split rejections and the empty-set balance error, carry the Rust error details, import the two ceilings, and make the four accessors non-public.
- Rust defects: `create_transfer_with_recipient` resolves the spend tree before the registry lookup while the TypeScript order is reversed, which is a defensible ordering in either language but should be pinned in one place.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/9`
- Exact next file: `W05 sdk-libs/wallet/src/actions/mod.rs`
- Full SDK parity claim: unsupported; the P256 rail is selected from the wrong source and the create-to-sign re-check is weaker than Rust

### 2026-07-25 15:44 UTC | W05 | `sdk-libs/wallet/src/actions/mod.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; concurrent uncommitted worker edits remain in place
- Worker: wallet review worker; implementation commit `none`
- Explanation: This file declares the four action submodules and re-exports thirty names from them: the ATA action, six deposit items, three merge-submission items, the four build and sign entry points, and sixteen private-transaction types and constructors. It holds no logic and no key material; its whole responsibility is the action surface. The TypeScript counterpart is the `@zolana/wallet/actions` subpath backed by `sdk-libs/ts/wallet/src/actions/index.ts`, which re-exports twenty-six names from `../deposit.js`, `../actions.js`, `../private-transaction.js`, and `../submit.js`. Governing evidence is `sdk-libs/ts/fixtures/wallet/mod.json` and `test/vectors/export-vector.test.ts`.
- Evidence: `docs/spec.md` defines no module layout, so current Rust governs. The export-vector test walks `fixture.expected.exports`, maps each Rust name through a hand-written `names` record, asserts the TypeScript name is a function on the actions subpath, and asserts the root export is the same object. That identity check between `@zolana/wallet` and `@zolana/wallet/actions` is real evidence and it passes. The problem is the list it walks: `mod.json` records nine names out of thirty, all of them functions, so no type export and no omitted function is covered. Dropping `createWithdrawal` from `actions/index.ts` would leave the vector test green. `expected.routing` in the same fixture records `solAssetBytes` and `splRequiresSettlementAccounts` and no test reads either.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/ts/wallet/src/actions/index.ts` has no counterpart for `deposit` (recorded under W02), for `ResolvedAddress`, which Rust exports from this module and TypeScript exports only from `./registry`, or for `build_deposit_transaction_sync`, `build_private_transaction_sync`, `create_transfer_sync`, and `sign_private_transaction_sync`. It adds `MergeMaterial` and `TransactionSigner`, neither of which `actions/mod.rs` exports. Smallest fix: generate `expected.exports` in `xtask` from the actual `pub use` list so the fixture cannot drift from the module, extend the `names` record and the vector test to cover type exports as well as functions, assert `expected.routing` or remove it, record one JavaScript disposition covering the blocking adapters, and move `ResolvedAddress` onto the actions subpath.
- Rust defects: none observed.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/9`
- Exact next file: `W06 sdk-libs/wallet/src/wallet_authority.rs`
- Full SDK parity claim: unsupported; the export oracle covers nine of thirty names and six names have no counterpart

### 2026-07-25 15:51 UTC | W06 | `sdk-libs/wallet/src/wallet_authority.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; concurrent uncommitted worker edits remain in place
- Worker: wallet review worker; implementation commit `none`
- Explanation: The file is four lines. It re-exports `AnonymousRecipientSlot`, `ApprovalRequest`, `EncryptedEnvelope`, `EncryptedSplit`, `EncryptedTransfer`, `LocalWalletAuthority`, `P256Signature`, `SyncWalletAuthority`, `WalletAuthority`, and `WalletSyncMaterial` from `zolana_transaction`, so wallet callers reach the authority surface without depending on the transaction crate directly. The definitions live in `sdk-libs/transaction/src/wallet/authority.rs`, which is the T-package responsibility. `WalletAuthority` is the capability boundary of the whole SDK: it holds the signing, viewing, and nullifier secrets and exposes encryption, approval, and signing operations without handing out the keys, while `SyncWalletAuthority` is the read-only half used during sync. Evidence is `sdk-libs/ts/wallet/test/authority.test.ts` and `fixtures/wallet/wallet_authority.json`, whose `rustPath` correctly names both this file and the transaction-crate original.
- Evidence: `docs/spec.md` fixes the P256 signing and encryption behavior, and `wallet_authority.json` pins the deterministic P256 signature, the sync-material identity bytes, the viewing-key count, and the encryption-before-approval ordering with the rejection short circuit. `authority.test.ts` matches those. The behavior of `LocalWalletAuthority` is therefore evidenced. The structural question is where the declarations live. `sdk-libs/ts/wallet/src/wallet-authority.ts` imports helpers from `@zolana/transaction` and `@zolana/transaction/serialization` but declares `ApprovalRequest`, `WalletAuthority`, and `LocalWalletAuthority` itself, and `@zolana/transaction` separately declares its own `WalletAuthority` that `decryptTransactions` accepts. The two are structurally similar, so assignment happens to work today, but they are two declarations that can drift apart.
- Verdict: `DIVERGENT`
- Gap and smallest fix: The Rust file's only job is re-export; `sdk-libs/ts/wallet/src/wallet-authority.ts` performs a redeclaration instead. `LocalWalletAuthority` is defined in the Rust `zolana_transaction` crate and appears in TypeScript only inside `@zolana/wallet`, so a `@zolana/transaction` consumer cannot construct the reference authority the crate owns. `AnonymousRecipientSlot`, `EncryptedEnvelope`, `EncryptedSplit`, `EncryptedTransfer`, `P256Signature`, `SyncWalletAuthority`, and `WalletSyncMaterial` are reachable from the Rust wallet crate root and from no `@zolana/wallet` subpath. The `encryptAnonymousTransfer` capability that both TypeScript `WalletAuthority` declarations omit is the already-recorded T13 gap; do not re-fix it here. Smallest fix: move `LocalWalletAuthority` and `ApprovalRequest` into `@zolana/transaction` beside the interface it implements, then reduce `wallet-authority.ts` to a re-export of the same ten names so one declaration exists per concept.
- Rust defects: none observed.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/9`
- Exact next file: `W07 sdk-libs/wallet/src/user_registry.rs`
- Full SDK parity claim: unsupported; the authority interface is declared twice and seven re-exported names are unreachable

### 2026-07-25 14:18 UTC | C09 | `sdk-libs/client/src/prover/json.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This module renders the prover payloads as the JSON body the Go server accepts. It imports `num_bigint::BigUint`, serde, `zolana_transaction::ProofInputUtxo`, and the six payload structs from `prover::inputs`. Nothing here is public: the seven `*Json` structs and the eight `to_json_*` functions are `pub(crate)` and reachable only through the provers. `big_uint_to_string` renders a value as `0x` followed by unpadded lowercase hex, so zero renders as `0x0`, and `fe_to_string` reads a 32-byte array big-endian first. Every numeric member crosses the wire as such a string; only `nInputs`, `nOutputs`, `startIndex`, `stateTreeHeight`, `treeHeight`, and `batchSize` stay JSON numbers. Eight circuit types share three body shapes: `transfer-confidential`, `transfer-zone`, and `transfer-zone-authority` use the Solana-only 13-key body, `transfer-p256-confidential` and `transfer-p256-zone` use the 20-key P256 body, `merge` and `merge-zone` use the 14-key merge body separated by the top-level `zoneProgramId`, and `address-append` has its own forester body. The merge body deliberately reuses the transfer input JSON and leaves the transfer-only members in place because the Go decoder drops unknown keys. The module handles the nullifier and transaction viewing secrets as request members, which is the capability boundary: whatever reaches these functions reaches the prover server. Rust evidence is the three shape tests at the foot of the file; TypeScript evidence is `sdk-libs/ts/client/test/vectors/prover-request.test.ts`, `test/vectors/prover-inputs.test.ts`, and `test/merge.test.ts` against `sdk-libs/ts/client/src/prover/client.ts`.
- Evidence: `docs/spec.md` does not define the request body, so current Rust and the Go server govern. `client/prover-shapes-v1.json` names `json.rs` among its sources and carries a Rust-captured `proverJson` for 10 shapes on each rail: 13 top-level keys for `transfer-confidential` and 20 for `transfer-p256-confidential`, matching the two Rust structs. `prover-inputs.test.ts` compares `proverRequest` against each of those 20 bodies, and `api/prover-request-v1.json` pins a 21st, whose `0x8080808080808080808080808080808080808080808080808080808080808` blinding confirms that both languages emit unpadded lowercase hex and that `Field.toString(16)` agrees with `BigUint::to_str_radix(16)`. `merge.test.ts` asserts the 14 merge keys in Rust declaration order, the `merge` and `merge-zone` circuit types, `zoneProgramId` of `0x0` for the default merge, 8 inputs, and a 65-element `userViewingPubkey`, which is the same key set the Rust `to_json_merge_shape` test asserts. A search of `sdk-libs/ts` for `transfer-zone`, `transfer-p256-zone`, `transfer-zone-authority`, and `address-append` returns nothing.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/ts/client/src/prover/client.ts::proverRequest` derives `circuitType` from a two-way branch on `inputs.circuit`, so it can emit `transfer-confidential` and `transfer-p256-confidential` and no other transfer type; `to_json_zone`, `to_json_p256_zone`, `to_json_zone_authority`, and `to_json_batch_address_append` have no TypeScript counterpart and no recorded omission, which is the request-body half of the C13, C14, and C18 gaps. `mergeProverRequest` agrees with `to_json_merge` only through two independently written key lists; no fixture carries a Rust-captured merge body, so a renamed member would have to be caught twice by hand. Smallest fix: extend the `ProverInputs` circuit union with the zone and zone-authority variants or record their omission in `inventory.json`, and add a Rust-captured merge and merge-zone body to the fixture set so `mergeProverRequest` has the same oracle the transfer bodies already have.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C10 sdk-libs/client/src/prover/transact/witness.rs`
- Full SDK parity claim: unsupported; four of the eight request shapes have no TypeScript path

### 2026-07-25 16:02 UTC | W07 | `sdk-libs/wallet/src/user_registry.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; concurrent uncommitted worker edits remain in place
- Worker: wallet review worker; implementation commit `none`
- Explanation: This module is the wallet's view of the on-chain user registry. It depends on `zolana_user_registry_interface` for `USER_RECORD_SEED`, `user_record_pda`, `user_registry_program_id`, the `UserRecord` and `SyncDelegateEntry` layouts, and the `register` and `update_keys` builders, and on `zolana_keypair` for `P256Pubkey` and `ShieldedAddress`. Seventeen public functions cover registration (`ensure_registered`, `register_if_absent`, `build_registration_transaction` and its blocking twin), fetching and decoding (`fetch_user_record_checked`, the two optional-checked variants, `decode_user_record_account`), validation (`validate_registered_keypair`), resolution (`resolve_registered_address`, `try_resolve_registered_address`, `try_resolve_registered_address_async`, `resolved_address_from_record`), and the two convenience pairs `is_wallet_registered` and `recipient_confidential_view_tag`. The record holds only public keys, so no secret is handled; the capability that matters is which viewing key a sender encrypts to. TypeScript evidence is `sdk-libs/ts/wallet/test/registry.test.ts` against `sdk-libs/ts/wallet/src/registry.ts` plus `fixtures/wallet/user_registry.json`.
- Evidence: `docs/spec.md` defines the registry record and the sync-delegate role; `program-libs/user-registry-interface/src/state.rs::UserRecord::sender_viewing_pubkey` implements it as: when `sync_delegate` is set, return the last `entries` viewing key, otherwise the record's own. `resolved_address_from_record` calls that accessor. `registry.ts` decodes `syncDelegate` and `entries` off the wire and then never reads them. The 106-byte entry size, the view tag as the viewing pubkey x-coordinate, the `EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc` program id, and the `REGISTER = 0` and `UPDATE_KEYS = 5` discriminators match the Rust constants; the Borsh instruction payloads match byte for byte. `register` marks the owner writable and `update_keys` read-only, and `compileTransaction` forces the fee payer writable in both languages, so the compiled metas agree. `registry.test.ts` has no case with a populated `sync_delegate`.
- Verdict: `DIVERGENT`
- Gap and smallest fix: `sdk-libs/ts/wallet/src/registry.ts::resolveRegisteredAddress` builds `viewingPublicKey` from `record.viewingPublicKey` instead of the delegate-aware accessor, so for any recipient with an active sync delegate the sender encrypts the output to the wrong viewing key and the delegate cannot read it. That is the most severe finding in this package: it is silent, it produces a valid on-chain transaction, and the funds land in a note nobody watching the delegate key will see. Thirteen public Rust functions have no counterpart: `ensure_registered`, `register_if_absent`, `fetch_user_record_checked`, `fetch_user_record_optional_checked`, `fetch_user_record_optional_checked_async`, `decode_user_record_account`, `validate_registered_keypair`, `resolved_address_from_record`, `try_resolve_registered_address`, `try_resolve_registered_address_async`, `recipient_confidential_view_tag`, and the two blocking adapters, and `lib.rs` names `try_resolve_registered_address_async` in its module documentation as the way to look a recipient up before creating a transfer. `registry.ts` also carries its own ed25519 on-curve check, its own SHA-256 PDA loop with an inlined `PDA_MARKER`, an inlined `"zolana/registry/v0"` seed, and an inlined program id, duplicating protocol math that `@zolana/interface` already owns. Smallest fix: port `sender_viewing_pubkey` and call it from `resolveRegisteredAddress`, add a `registry.test.ts` case with a populated delegate, add the missing lookup and validation functions, and derive the PDA through the interface package helpers.
- Rust defects: none observed.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/9`
- Exact next file: `W08 sdk-libs/wallet/src/wallet_sync.rs`
- Full SDK parity claim: unsupported; senders encrypt to the wrong viewing key when the recipient has a sync delegate

### 2026-07-25 16:14 UTC | W08 | `sdk-libs/wallet/src/wallet_sync.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; concurrent uncommitted worker edits remain in place
- Worker: wallet review worker; implementation commit `none`
- Explanation: This module drives wallet discovery. It imports `zolana_transaction`'s `Wallet`, `SyncReport`, `SyncWalletAuthority`, `WalletSyncMaterial`, and `DEFAULT_TAG_WINDOW`, `zolana_keypair::viewing_key::ViewTag`, the interface `SplAssetRegistry` and `decode_output_data`, and the client `Rpc`, `AsyncRpc`, and `IndexerPollConfig`. Public items are `SyncWalletConfig`, `sync_wallet`, `sync_wallet_async`, the two with-config variants, `get_private_transactions`, and `get_private_token_balances`. Each round derives the query tag set from the wallet's viewing-key history, pages `get_shielded_transactions_by_tags` and `get_encrypted_utxos_by_tags` in chunks, orders the results, and hands them to `Wallet::sync_with_material` with the current Unix timestamp; the loop stops when a round adds nothing. A final pass refreshes the asset registry from chain when decoding hit unknown asset ids. `SyncWalletAuthority` is the read-only capability: sync needs viewing keys and never a signing key. TypeScript evidence is `sdk-libs/ts/wallet/test/sync.test.ts` against `sdk-libs/ts/wallet/src/sync.ts` plus `fixtures/wallet/wallet_sync.json`.
- Evidence: `docs/spec.md` defines the tag families and the counter-plus-window scan. `wallet_query_tags` emits the owner confidential tag, and per viewing key the bootstrap tag, sender tags over `0..tx_count + window`, recipient-request tags over `0..request_count + window`, recipient-shared tags per known sender, and send-shared tags per known recipient. `sync.ts` emits the confidential tag, the bootstrap tag, and sender and recipient-request tags over `0..tagWindow`. The identity and current-viewing-key checks Rust performs in `wallet_query_tags` do exist downstream in `@zolana/transaction`'s `validateMaterial`, so that check is covered, but `syncWallet` calls `authority.syncMaterial()` and then `decryptTransactions` calls it a second time, which prompts a hardware authority twice per sync. `wallet_sync.json` records a config with `waitForIndexer: true` and the three indexer lag, abort, and timeout error shapes; no TypeScript test asserts any of them, and `sync.test.ts` never populates `known_senders` or `known_recipients`.
- Verdict: `DIVERGENT`
- Gap and smallest fix: `sdk-libs/ts/wallet/src/sync.ts::syncWallet` never calls the shared-tag families, so a wallet that has transacted with a known counterparty cannot discover those notes at all; it also drops the `tx_count` and `request_count` offsets, so a wallet past `tagWindow` sends stops scanning its own range. The underlying `viewingKeyHistory` counters are the already-recorded T15 gap; the tag construction that consumes them is this row's. Rust skips a transaction from `get_shielded_transactions_by_tags` when it is `proofless` or lacks both `tx_viewing_pk` and `salt` without a merge ciphertext, and reaches proofless deposits only through `get_encrypted_utxos_by_tags` keyed by `signature:leaf_index`; TypeScript applies no filter on the first endpoint and keys the second by `signature:hash`, so one deposit visible on both endpoints enters `collected` twice. Rust sorts real transactions by `(slot, signature)` and appends deposits sorted by first output tree, leaf index, slot, and signature; TypeScript passes map-insertion order. `input.config?.waitForIndexer !== true` guards a bare `continue` at the end of the loop body, which changes nothing, and `undefined` is passed where the Rust calls pass `IndexerRpcConfig`, so neither `wait_for_indexer` nor `IndexerPollConfig` has any effect and `SyncWalletConfig` has no retry field. `positiveInteger` throws `WALLET_INVALID_SYNC_CONFIG` on values `normalized_config` clamps with `max(1)`, and adds ceilings Rust does not have. `sync_wallet` defaults `wait_for_indexer` to true through `SyncWalletConfig::new()` while the TypeScript default is false. `getPrivateTokenBalances` calls `wallet.balances()` where Rust calls `balances(true)`; the `skipUtxos` option is accepted and discarded by `void options`, and the TypeScript `AssetBalance` has no `assetId` or `utxos` member, which is the recorded T14 state gap. Registry backfill only runs when the caller passes the optional `registryRpc`, so the default TypeScript sync never performs the refresh `sync_wallet_with_config` always attempts. Smallest fix: add the two shared-tag families and the counter offsets, restore the proofless filter and the deterministic sort, pass the poll config and honor `waitForIndexer`, clamp instead of rejecting, reuse one `syncMaterial()` result, and drive the backfill from the indexer the caller already supplied.
- Rust defects: `sync_wallet` and `sync_wallet_async` differ only in the default `wait_for_indexer`, which is easy to miss; state the intended default in one place.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/9`
- Exact next file: `W09 sdk-libs/wallet/src/lib.rs`
- Full SDK parity claim: unsupported; two tag families are never queried, deposits can be collected twice, and the poll configuration is inert

### 2026-07-25 16:24 UTC | W09 | `sdk-libs/wallet/src/lib.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; concurrent uncommitted worker edits remain in place
- Worker: wallet review worker; implementation commit `none`
- Explanation: The crate root declares the four modules `actions`, `user_registry`, `wallet_authority`, and `wallet_sync`, documents the five-step private transfer flow, and re-exports fifty-two names: twenty-nine from `actions`, sixteen from `user_registry`, ten from `wallet_authority`, seven from `wallet_sync`, and the two `doc(hidden)` shielded-signing helpers. The module documentation states that the spend tree and the recipient registry lookup are inferred internally and points callers at `is_wallet_registered` and `try_resolve_registered_address_async` when they need an explicit lookup. The TypeScript counterpart is `sdk-libs/ts/wallet/src/index.ts` plus the four subpaths `@zolana/wallet/{actions,authority,registry,sync}` declared in `package.json`. Evidence is `fixtures/wallet/lib.json` and the second case in `test/vectors/export-vector.test.ts`.
- Evidence: `docs/spec.md` defines no crate layout, so current Rust governs. `lib.json` records the flow, the four module names, and a nested error where a client-level `Transaction` wraps a transaction-level `NoInputs`; the vector test maps the flow through the same `names` record used for W05, asserts the five steps resolve, and checks that a no-balance withdrawal raises `WALLET_INSUFFICIENT_BALANCE` while a direct `ConfidentialTransfer` raises the transaction-level code. That is real evidence for the flow and for the wrapping shape. It says nothing about the export list: no test compares the crate-root names against `index.ts`, and `lib.json` records no export inventory to compare against.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/ts/wallet/src/index.ts` exports twenty-two names. Missing against the Rust root: `deposit` (W02), thirteen registry functions (W07), seven authority types (W06), and the seven `_sync` adapters. Added beyond it: `WalletError`, `MergeMaterial`, and `TransactionSigner`. `WalletError` is the package-level divergence this row owns. Rust defines no wallet error type and lets `ClientError` and `TransactionError` propagate, so a caller matches on one of two known enums; `sdk-libs/ts/wallet/src/error.ts` declares an open `WALLET_${string}` code template with no closed union and no canonical list, and `wrapWalletError` re-codes every failure while pushing the original code into `cause`. The result is that a TypeScript caller cannot enumerate the codes it must handle and cannot switch on the client or transaction code without unwrapping, which is the underlying cause of the error-mapping findings recorded in W01, W02, W03, and W07. Smallest fix: replace the template literal with a closed union enumerating the `WALLET_*` codes, have `wrapWalletError` re-expose the wrapped `ClientError` or `TransactionError` code as a public member, add a root export inventory to `lib.json` generated from the Rust `pub use` list, and assert it in `export-vector.test.ts`.
- Rust defects: `lib.rs` documents `try_resolve_registered_address_async` and `is_wallet_registered` as the explicit-lookup entry points and re-exports `build_deposit_transaction` without the `deposit` send path that uses it; align the documented surface with the re-export list.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/9`
- Exact next file: none; the wallet package queue is complete and every row is `needs_fix`
- Full SDK parity claim: unsupported; the wallet package has nine adverse verdicts, and the error surface has no closed code set

### 2026-07-25 14:41 UTC | C10 | `sdk-libs/client/src/prover/transact/witness.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted edits include this file, where `WitnessInputCountMismatch` is being renamed to `ProofInputCountMismatch`
- Worker: client prover review worker; implementation commit `none`
- Explanation: This module assembles a padded transaction into a prover payload and the matching `Transact` instruction data in one pass. It imports the interface `InputUtxo`, `TransactIxData`, and `TransactProof`, `zolana_keypair::SignatureType`, and the transaction crate's `inputs_require_p256`, `SppProofInputs`, and `SppProofInputUtxo`. Public items are `SpendProof`, `CircuitType`, `BuiltCircuit`, `ProverInputs`, `AssembledTransfer` with `with_proof`, `into_prover`, `assemble`, and the `ProverClient::prove_transact` method; `attach_input_proofs` is crate-private and shared with merge, merge-zone, and zone-authority. `attach_input_proofs` walks the padded inputs and hands the next fetched proof to each slot whose owner is nonzero, leaving dummy slots proofless. `into_prover` decides the rail from `inputs_require_p256`, recovers the P256 owner, checks the shape, and returns one of the two provers. `assemble` records a signer index per real input, runs the prover build, checks that the nullifier and root-index counts equal the shape's input count, and emits one `InputUtxo` per slot with `tree_index` 0 and `eddsa_signer_index` of 255 for a P256-owned slot. The capability boundary is `p256_owner`: the signature bytes come from the transaction, and the public key comes from the first real P256-owned input, so the payload is bound to the owner rather than to whoever signed. Rust evidence is `sdk-libs/client/tests/steps/mod.rs` through the localnet flows; TypeScript evidence is `test/vectors/prover-inputs.test.ts`, `test/vectors/prover-request.test.ts`, and `test/vectors/client-vectors.test.ts` against `sdk-libs/ts/client/src/prover/assembly.ts::assemble`.
- Evidence: `docs/spec.md` fixes the public-input chain and the instruction layout, and both languages agree on the 15-element chain, `tree_index` 0, and the 255 sentinel. `client/prover-shapes-v1.json` is Rust-captured and pins `proverInputs`, `proverJson`, `publicInputHashBytes`, and `transactIxData` for 10 shapes on each rail; `prover-inputs.test.ts` replays all 20 through `assemble`. `is_dummy()` is `owner.is_zero()` in `sdk-libs/transaction/src/instructions/types.rs:57`, so the Rust proof-attachment predicate and the TypeScript `isDummy()` filter select the same slots, and `inputs_require_p256` skips dummies exactly as the TypeScript `realInputs.some(...)` does. No test in either language covers a surplus proof, a dummy slot ahead of a real one, or a signature whose public key is not the input owner's.
- Verdict: `DIVERGENT`
- Gap and smallest fix: `sdk-libs/ts/client/src/prover/assembly.ts` derives `p256SigningField` and the instruction's `p256SigningPkX` from `proofInputs.p256Signature().publicKey`, while `witness.rs::p256_owner` takes the public key from the first real P256-owned input and `TransferP256Prover::build` derives both values from it; a signature carrying a different key produces a payload bound to the signer in TypeScript and to the owner in Rust. `assembleUnchecked` requires `spendProofs.length === realInputs.length` and raises `CLIENT_INCOMPLETE_INPUT_PROOFS`, while `attach_input_proofs` ignores surplus proofs and raises `MissingInputMerkleProof { index }` when short, so the same short list yields two different codes and the same surplus list is accepted by one language only. `assemble` reads `real_signer_indices.get(i)` by absolute slot while TypeScript advances a counter over real inputs; with a dummy ahead of a real input the two assign different `eddsa_signer_index` values. `validateSpendProof` checks the state and nullifier leaves and the shared tree before building, which Rust does not do at this layer. Smallest fix: take the P256 public key from the input owner in TypeScript, make the two proof-count paths agree on one code and on whether a surplus is an error, and index `real_signer_indices` by a real-input counter in Rust.
- Rust defects: `assemble` indexes `real_signer_indices` by the absolute slot index, so a padded dummy ahead of a real input shifts every later signer index and can mark a real P256 input as eddsa-signed; index by a real-input counter as the TypeScript port does.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C11 sdk-libs/client/src/prover/transact/eddsa.rs`
- Full SDK parity claim: unsupported; the P256 signing key source, the proof-count contract, and the dummy signer indexing differ

### 2026-07-25 14:52 UTC | C11 | `sdk-libs/client/src/prover/transact/eddsa.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This 92-line module builds the Solana-only transfer payload. It imports `num_bigint::BigUint`, the transaction crate's `PrivateTxHash`, `ExternalData`, and `SppProofOutputUtxo`, `prover::field::be`, `resolve_shape`, and the four shared helpers from `p256_and_eddsa`. `prover/mod.rs` re-exports `TransferProver` and `TransferProofResult` and `lib.rs` flattens both to the crate root. `build` resolves the shape, fixes the shared signing field and the message hash at zero because the rail has no P256 gadget, assembles the inputs under `OwnerMode::ConfidentialEddsa`, assembles the outputs, hashes the external data, derives the private transaction hash from the input hashes, the private output hashes, and that external hash, folds the 15-element public-input chain with a zero zone program and a zero signing field, and returns the payload alongside the nullifiers, output hashes, private transaction hash, and per-slot root indices. The capability separation is the owner mode: `ConfidentialEddsa` rejects a P256-owned input with `EddsaInputNotSolanaOwned { index }`, so the Solana-only rail cannot silently carry a key the circuit has no gadget for. The module holds no secret beyond the nullifier secret each assembled input already carries. No Rust test targets the file directly; TypeScript evidence is `test/vectors/prover-inputs.test.ts` and `test/vectors/client-vectors.test.ts` against the `signature === undefined` branch of `sdk-libs/ts/client/src/prover/assembly.ts`.
- Evidence: `docs/spec.md` fixes the public-input chain, and the TypeScript `publicInputHash` call lists the same 15 elements in the same order as `PublicInputs::hash`, with `hashField(bigintToBytes(p256MessageHash))` standing in for `hash_field(&[0u8; 32])` and a literal `0n` for the zone program. The eddsa rail of `client/prover-shapes-v1.json` is Rust-captured and pins the payload, the request body, the public-input hash, and the instruction data for 10 shapes; the TypeScript branch reproduces all four. `zoneProgramId` is a literal zero on both sides and `publicSplAssetPublicKey` falls back to zero when the SPL amount is absent or zero. A search of `sdk-libs/ts` finds `CLIENT_EDDSA_INPUT_NOT_SOLANA_OWNED` declared in `error.ts` and asserted for shape in `test/error.test.ts`, and no code that raises it.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/client/src/prover/transact/eddsa.rs::TransferProver` and `TransferProofResult` are crate-root exports with no TypeScript counterpart; `sdk-libs/ts/client/src/prover/types.ts::AssembledTransfer` returns `instructionData`, `proverInputs`, and `withProof` alone, so a caller cannot read the `nullifiers`, `outputHashes`, `privateTxHash`, `inputRootIndexes`, or `publicInputHash` that both Rust result structs expose, and `inventory.json` records no omission. Because the TypeScript port has no standalone prover entry point, the `ConfidentialEddsa` guard is unreachable: a P256-owned input is caught earlier as `CLIENT_MISSING_P256_SIGNATURE`, leaving `CLIENT_EDDSA_INPUT_NOT_SOLANA_OWNED` a declared code with no throw site, which the error-shape test cannot detect. Smallest fix: add `publicInputHash` and the per-slot nullifier and root-index lists to `AssembledTransfer` or record the omission, and either raise the declared code where a P256-owned input reaches the Solana-only path or remove it from the canonical list.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C12 sdk-libs/client/src/prover/transact/p256_and_eddsa.rs`
- Full SDK parity claim: unsupported; two crate-root result types and one error code have no reachable TypeScript counterpart

### 2026-07-25 15:06 UTC | C12 | `sdk-libs/client/src/prover/transact/p256_and_eddsa.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This is the shared assembly layer for every transfer rail plus the P256 prover itself. It imports the `p256` curve encoding, `zolana_hasher::hash_chain::create_hash_chain_from_slice`, the keypair `hash_field`, `sha256`, and `split_be_128`, `NullifierKey`, `P256Pubkey`, and the transaction crate's `PrivateTxHash`, `ExternalData`, `ProofInputUtxo`, and `Utxo`. `prover/mod.rs` re-exports `P256Owner`, `PublicAmounts`, `TransferP256Prover`, `TransferP256ProofResult`, and `TransferSpendInput`, and `lib.rs` flattens them; `AssembledInputs`, `AssembledOutputs`, `OwnerMode`, `PublicInputs`, `P256SignatureWitness`, `assemble_inputs`, and `assemble_outputs` stay crate-private. `assemble_inputs` converts each padded slot: a slot without a fetched proof mirrors the first accumulated root pair, root indices, and owner hash and becomes a dummy, and a real slot derives its nullifier public key, proof-input UTXO, hash, and nullifier, selects the owner field by `OwnerMode`, right-aligns the 31-byte nullifier secret, and checks both path lengths. `assemble_outputs` gives a real output its signing key's owner field and nullifier public key and a dummy the hashed random view tag with a zero nullifier key, while contributing zero to the private hash chain. `PublicInputs::hash` folds the 15-element chain. `TransferP256Prover::build` adds the shared signing field, the SHA-256 message hash split into two 128-bit halves, and the signature coordinates. The capability boundary is `OwnerMode`, which decides per rail whether a P256 owner exposes the shared signing field, a zero sentinel, or its own field, and the nullifier secret is the one secret that crosses into the payload. No Rust test targets the file; TypeScript evidence is `test/vectors/prover-inputs.test.ts`, `test/vectors/prover-request.test.ts`, and `test/prover/p256.test.ts` against `sdk-libs/ts/client/src/prover/assembly.ts`.
- Evidence: `docs/spec.md` fixes the public-input chain and the owner-tag reconstruction, and both languages fold the same 15 elements. The p256 rail of `client/prover-shapes-v1.json` is Rust-captured and pins the payload, request body, public-input hash, and instruction data for 10 shapes, covering the shared signing field on every P256-owned input, the two message-hash halves, and the dummy mirroring rule. `createOutput` reproduces `assemble_outputs` for both branches, including the hashed view tag and the zero nullifier key on a dummy, and `privateOutputHashes` reproduces the zero contribution. `bytesField` on a 31-byte secret reproduces `right_align_slice`, as recorded under C06. `check_path_length` and `validateSpendProof` agree on 32 and 40. Neither language has a test for a P256 public key that is not on the curve, for a transaction carrying two distinct non-SOL assets, or for a dummy slot whose asset differs from the real ones.
- Verdict: `DIVERGENT`
- Gap and smallest fix: `sdk-libs/ts/client/src/prover/assembly.ts::p256Y` recovers the y coordinate as a modular square root and flips it by the parity byte without confirming that the recovered pair satisfies the curve equation, so a corrupt compressed key yields a silently wrong witness coordinate; `P256Owner::witness` decodes through `p256::PublicKey::to_encoded_point` and fails on an invalid key. The same package already has the validating version: `internal.ts::p256Coordinates` checks the prefix, the x range, and `y * y == y2`, and `prover/merge.ts` uses it. `findPublicSplAsset` returns the first non-system asset among non-dummy inputs and then non-dummy outputs, while `SppProofInputs::public_amounts` calls `check_public_spl_asset`, which scans every input and output including dummy slots and rejects a second distinct asset with `MultiplePublicSplAssets`; the TypeScript uniqueness check lives one layer up in `transaction.ts::prepare`, so a hand-built `SppProofInputs` reaches `assemble` unchecked. `P256Owner`, `PublicAmounts` with its `transfer()` constructor, `TransferSpendInput`, `TransferP256Prover`, and `TransferP256ProofResult` are crate-root exports with no TypeScript counterpart and no recorded omission. `CLIENT_PROOF_PATH_LENGTH` carries `index` and `kind` in TypeScript where the Rust-captured `errors-v1.json` variant carries `expected` and `got` alone. Smallest fix: replace the private `p256Y` with the validating `p256Coordinates`, call one shared asset helper that keeps the Rust scan set and uniqueness rule, and record a disposition for the five omitted crate-root types.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C13 sdk-libs/client/src/prover/transact/zone_eddsa.rs`
- Full SDK parity claim: unsupported; the P256 key recovery skips a validity check Rust performs and the public SPL asset is selected by a different rule

### 2026-07-25 15:21 UTC | C13 | `sdk-libs/client/src/prover/transact/zone_eddsa.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This module builds the Solana-only transfer payload bound to a zone program. It imports `solana_address::Address`, `create_hash_chain_from_slice`, the keypair `hash_field`, and the transaction crate's `PrivateTxHash`, `program_id_field`, `ExternalData`, and `SppProofOutputUtxo`, and reuses `assemble_inputs`, `assemble_outputs`, `OwnerMode`, `PublicAmounts`, and `TransferSpendInput`. `prover/mod.rs` re-exports `ZoneTransferProver` and `ZoneTransferProofResult` and `lib.rs` flattens both. `build` follows the confidential eddsa builder up to the private transaction hash, then converts the optional zone program into its field through `program_id_field` and folds a 13-element chain: the 12 base elements with the zone field in the zone slot, plus the input owner chain, and no confidential appendix. Outputs are anonymous, carrying an owner tag rather than an owner address, while input owners stay in the chain so the program can route the per-input signer check. Owner selection uses `OwnerMode::ConfidentialEddsa`, so a P256-owned input is rejected. No Rust test targets the file; the TypeScript side has no test because it has no implementation.
- Evidence: `docs/spec.md` and the Go `public_inputs.go` layout with `Confidential=false, ZoneAuthority=false` govern the 13-element chain, and the Rust comment cites that source. `sdk-libs/ts/reports/inventory.json` records this file with `disposition: port`, `target: @zolana/client · src/prover/transact/zone-eddsa.ts`, and a promised Rust-generated `fixtures/client/zone_eddsa.json`. `sdk-libs/ts/client/src/prover/` holds `assembly.ts`, `client.ts`, `index.ts`, `merge.ts`, `proof.ts`, and `types.ts`, with no `transact/` directory; `sdk-libs/ts/fixtures/client/` holds six files and no `zone_eddsa.json`. A search of `sdk-libs/ts` for `transfer-zone` returns nothing, so `proverRequest` cannot address the circuit, and `assembly.ts::publicInputHash` folds the 15-element confidential chain unconditionally.
- Verdict: `MISSING`
- Gap and smallest fix: `zolana_client::prover::ZoneTransferProver` and `ZoneTransferProofResult` have no TypeScript symbol. The gap is not only the missing `transfer-zone` circuit type recorded under C09: the payload commits to a different public-input preimage, so reusing the confidential path would produce a payload the zone verifying key rejects. Smallest fix: add `src/prover/transact/zone-eddsa.ts` with the 13-element chain, `program_id_field` conversion, and the `zoneProgramId` payload member, extend the `ProverInputs` circuit union with the zone variant, and generate the promised `fixtures/client/zone_eddsa.json` from Rust; if the zone rails are out of scope for the port, change the inventory disposition and say so in `public-exports.md` instead.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C14 sdk-libs/client/src/prover/transact/zone_p256.rs`
- Full SDK parity claim: unsupported; the surface is absent

### 2026-07-25 15:29 UTC | C14 | `sdk-libs/client/src/prover/transact/zone_p256.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This module builds the P256-rail transfer payload bound to a zone program. Its imports match the eddsa zone builder plus `sha256`, `split_be_128`, `PublicKey`, and `P256Owner`. `prover/mod.rs` re-exports `ZoneTransferP256Prover` and `ZoneTransferP256ProofResult` and `lib.rs` flattens both. `build` derives the shared signing key's raw x-coordinate and its field, assembles the inputs under `OwnerMode::Zone`, hashes the private transaction, takes the SHA-256 message hash and its two 128-bit halves, converts the zone program to its field, and folds the same 13-element chain the eddsa zone rail uses, with the real message hash in the message slot. The privacy separation is the point of the module: `OwnerMode::Zone` gives every P256-owned input the zero sentinel instead of its owner field, and the shared signing field stays in the payload without entering the public-input hash, so the shared owner is provable without being publicly identified. No Rust test targets the file; the TypeScript side has no test because it has no implementation.
- Evidence: the Go `public_inputs.go` layout governs, and the Rust comment cites the same `ZoneAuthority=false, Confidential=false` case as the eddsa zone rail. `inventory.json` records `disposition: port`, `target: @zolana/client · src/prover/transact/zone-p256.ts`, and a promised Rust-generated `fixtures/client/zone_p256.json`; neither the source file nor the fixture exists. `assembly.ts` implements one owner rule for a P256 input, the confidential shared field, and has no branch for the zero sentinel, so the anonymity property this module provides is unreachable from TypeScript.
- Verdict: `MISSING`
- Gap and smallest fix: `zolana_client::prover::ZoneTransferP256Prover` and `ZoneTransferP256ProofResult` have no TypeScript symbol, nothing emits `transfer-p256-zone`, and no TypeScript code implements the `OwnerMode::Zone` sentinel. Smallest fix: add `src/prover/transact/zone-p256.ts` reusing the shared input and output assembly with the zero-sentinel owner rule and the 13-element chain, extend the `ProverInputs` circuit union, and generate the promised `fixtures/client/zone_p256.json` from Rust covering a P256-owned input, a mixed-owner shape, and the sentinel; otherwise change the inventory disposition.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C15 sdk-libs/client/src/prover/transact/mod.rs`
- Full SDK parity claim: unsupported; the surface is absent

### 2026-07-25 15:37 UTC | C15 | `sdk-libs/client/src/prover/transact/mod.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This 15-line module declares the five transact submodules and re-exports their public items: `TransferProofResult` and `TransferProver` from the eddsa rail, `P256Owner`, `PublicAmounts`, `TransferP256ProofResult`, `TransferP256Prover`, and `TransferSpendInput` from the shared assembly, `assemble`, `into_prover`, `AssembledTransfer`, `BuiltCircuit`, `CircuitType`, `ProverInputs`, and `SpendProof` from the witness layer, and the two result-and-prover pairs from the zone rails. It holds no logic, no state, and no key material; it is the single place that decides what the transact layer exposes. `prover/mod.rs` re-exports the same names and `lib.rs` flattens them, so this list is the crate-root transact surface. Its evidence is whatever covers the underlying modules, reviewed as C10 through C14.
- Evidence: the module re-exports 16 names. `sdk-libs/ts/client/src/index.ts` exports `SpendProof` as a type, and `sdk-libs/ts/client/src/prover/index.ts` exports `assemble`, `intoProver`, `AssembledTransfer`, and `ProverInputs`, which covers 5. The remaining 11, `BuiltCircuit`, `CircuitType`, `P256Owner`, `PublicAmounts`, `TransferSpendInput`, `TransferProver`, `TransferProofResult`, `TransferP256Prover`, `TransferP256ProofResult`, and the two zone pairs, appear nowhere in `sdk-libs/ts`. The TypeScript `prover/index.ts` also exports `compressProof`, `ProverClient`, `canonicalShape`, `resolveShape`, and the payload types, which come from other Rust modules, so the two lists are not a like-for-like comparison of this row alone.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/ts/reports/inventory.json` records this file with `target: @zolana/client · src/prover/transact/index.ts`, a path that does not exist, while the queue row names `client/src/prover/index.ts`; the two disagree and neither carries the 11 omitted names. `CircuitType` and `BuiltCircuit` are the rail-selection surface a caller needs to build a prover directly, and their absence is the same one recorded under C11, C12, C13, and C14 rather than a separate defect. Smallest fix: settle on one inventory target for this module, and record for each of the 11 omitted names whether it is deliberately internal to the TypeScript port or still owed, so a later reviewer does not have to re-derive the list.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C16 sdk-libs/client/src/prover/merge.rs`
- Full SDK parity claim: unsupported; 11 of 16 re-exported names have no TypeScript counterpart or recorded disposition

### 2026-07-25 15:58 UTC | C16 | `sdk-libs/client/src/prover/merge.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This module builds the 8-in, 1-out merge payload. It imports the `p256` encoding and `SecretKey`, `create_hash_chain_from_slice`, the interface `MergeExternalDataHash`, `MergeTransactIxData`, `MergeZoneIxData`, and `P256Proof`, the keypair `encrypt_verifiable`, `merge_public_contribution`, `NullifierKey`, `P256Pubkey`, and `PublicKey`, and the transaction crate's `PreparedMerge`, `asset_field`, `PrivateTxHash`, and `EncryptedScheme`. `prover/mod.rs` re-exports `MergeProofResult` and `MergeProver`, and the module itself is `pub`, so `MergeWitness`, `merge_encrypted_utxo`, and the `TryFrom<MergeWitness>` conversion are reachable as `zolana_client::prover::merge::*`. `MergeProver::common` assembles the inputs under `OwnerMode::Merge`, splits the root indices into two lists, assembles the single output, encrypts the merged `(amount, asset field, blinding)` plaintext to the owner's viewing key, derives the published blob and the external-data hash over the instruction tag, expiry, output hash, and blob, folds the private transaction hash, and selects the owner rail: a P256 owner witnesses its real point with a zero owner field, while a Solana owner witnesses the P256 generator as a discarded dummy and passes its own field. `build` then appends the signing hash, the viewing hash, the two ephemeral key halves, and the ciphertext hash, giving an 11-element chain. The capability boundary is sharp: the nullifier secret and the ephemeral viewing scalar enter the payload, while the owner's signing secret never does. Rust evidence is the `merge` feature suite under `sdk-libs/client/tests/`; TypeScript evidence is `sdk-libs/ts/client/test/merge.test.ts` against `sdk-libs/ts/client/src/prover/merge.ts`.
- Evidence: `docs/spec.md` fixes the merge instruction and the published blob, and both languages emit `EncryptedScheme::Merge`, the 33-byte ephemeral key, and the ciphertext inside the verifiably-encrypted output encoding, with TypeScript adding a 110-byte length assertion. The hardcoded `P256_GENERATOR_X` and `P256_GENERATOR_Y` in `merge.ts` are the curve generator that `dummy_p256_xy` derives from the scalar 1. `merge.test.ts` pins the 14 request keys in Rust declaration order, the `merge` and `merge-zone` circuit types, eight nullifiers, a 65-element viewing key, the root-index arrays, the first six blob bytes, and the output hash from `fixtures/transaction/merge-v1.json`. That fixture's `rustPath` is `sdk-libs/transaction/src/instructions/merge.rs` and it pins the prepared merge and its output hash only; the inventory promises a Rust-generated `fixtures/client/merge.json`, which does not exist, so no oracle pins the merge public-input hash, external-data hash, or ciphertext contribution.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/ts/client/src/prover/merge.ts::MergeAssembly` exposes the payload, expiry, output hash, nullifiers, root indexes, private transaction hash, blob, owner flag, and `instructionData`, while `MergeProofResult` also exposes `public_input_hash`, `external_data_hash`, `ciphertext`, `tx_viewing_pk`, and the `zone_instruction_data` method that wraps the merge body with a `merge_view_tag`; none of those five have a TypeScript counterpart, so a caller cannot build `MergeZoneIxData` or check the committed hashes. `assembleMergeWithProofsUnchecked` derives each real input's owner field from `prepared.signingPublicKey`, while `assemble_inputs` under `OwnerMode::Merge` derives it from `spend.utxo.owner`, so the two commit different values whenever an input's own owner is not the prepared signing key. `MergeProver::common` accepts an ephemeral scalar at or above the BN254 modulus that its own comment forbids, while `asField` rejects it. Smallest fix: add the five missing result members, take the per-input owner field from the input as Rust does, and generate the promised `fixtures/client/merge.json` covering both owner rails, the ciphertext contribution, and the 11-element chain.
- Rust defects: `MergeProver::common` documents that `tx_viewing_sk` must be below the BN254 modulus and never checks it, so an out-of-range scalar reaches the prover as a silently reduced witness; `right_align` here duplicates `field::right_align_slice`, as recorded under C06.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C17 sdk-libs/client/src/prover/merge_zone.rs`
- Full SDK parity claim: unsupported; five result members are missing and no oracle pins the merge public-input hash

### 2026-07-25 13:54 UTC | C01, C02 | `sdk-libs/client/src/retry.rs`, `sdk-libs/client/src/error.rs`

- Baseline: HEAD `7bcc80bdcd0e413c5344d55d15ea6e45fccf612c` at the time the Rust and TypeScript sources were read, `142b2b985da00fc6a6a02691469aca6062ddf608` by the end of the session; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f` with `canonicalSourceRevisions.client` at `3ba527850a7986f36c47ad2082598edff3e3e5b7`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`. A concurrent worker left `sdk-libs/client/src/error.rs` and `sdk-libs/client/src/retry.rs` dirty partway through the session, adding `poll_until_async` and reshaping `ClientError::Indexer` into `{ method, retryable }`. That work is uncommitted, so it carries no weight here, and it invalidates part of this evidence once it lands.
- Worker: independent C01/C02 re-review worker, separate from the implementer; implementation commits `3ba52785`, `aa9ad01a`, `0a260feb`, `b230b314` (each signed by `6C33D04110CE55E5C76DB027BF6506C50270BE4B`)
- Explanation: `retry.rs` owns `IndexerPollConfig` (`num_retries: u32`, `delay_ms: u64`, `max_delay_ms: u64`) with a `Default` of 10 / 400 / 8000, `new`, a `backoff` iterator that caps the first delay at `max_delay_ms` and doubles under saturation, `attempts()` returning `num_retries + 1` as `u64`, and `poll_until`, which prefixes a zero delay, treats a non-matching `Ok` as another round, classifies failures through `ClientError::retry_cause`, returns a non-retryable failure at once, and ends with `PollTimedOut { attempts, last_cause }`. It also owns `IndexerRpcConfig` and `wait()`. `error.rs` owns the 58-variant `ClientError`, the three-variant `RetryErrorCause`, and `retry_cause`, which classifies `Rpc`, `Indexer`, and `IndexerTimeout` as retryable. Both are re-exported from `lib.rs`. Rust evidence is the four `retry.rs` unit tests; TypeScript evidence is `client/test/retry.test.ts`, `client/test/error.test.ts`, and the fixture-driven schedule assertion in `client/test/indexer-client.test.ts`.
- Evidence: `client/errors-v1.json` and `client/rpc-indexer-v1.json` carry `sourceRevision` `3ba52785`, and the manifest records the same revision under `canonicalSourceRevisions.client`, so both fixtures track the corrected Rust. `expected.retry` pins `IndexerPollConfig::new(4, 5, 12)` to delays `5, 10, 12, 12` and 5 attempts; `indexer-client.test.ts` drives `ZolanaIndexer.getMerkleProofs` under fake timers and asserts both. `errors-v1.json` now carries `lastCause: {category: "indexer"}` and `CLIENT_PROOF_INPUT_COUNT_MISMATCH`, matching the renamed Rust variants. Commands run from a clean checkout of the four commits: `npm run build`, `npm run typecheck`, `npm run lint`, `npm run format:check`, `npm run test:unit` (395 passed, 1 skipped), `npm run test:inventory`, `npm run test:exports`, `npm run test:dependencies`, `npm run api:check`, `npm run pack:check`, and `npm run test:browser` each exit 0, which covers the whole `npm run check` chain plus the two checks the new `./retry` subpath needs. `npm run lint:packages` exits 1 on four `keypair/src/public-key.ts` assertions, one `interface/src/codecs/index.ts` arrow body, and one unused `Bytes64` import, none of them in the client package. `npm run fixtures:check` cannot run: the default mode calls `assert_frozen_sources`, and `sdk-libs/client/src/prover` plus 14 `sdk-libs/transaction` paths already differ from the frozen baseline. The `--current-client --check` mode that `aa9ad01a` added also cannot run, because the concurrent worker's uncommitted `ClientError::Indexer` reshape stops `xtask/src/ts_fixtures_client.rs` from compiling.
- Verdict: C01 `DIVERGENT`; C02 `PARTIAL`
- Gap and smallest fix: C01 has three residual differences. `retry.ts::retryErrorCause` falls back to `error.cause ?? {category:"client", code}`, so a retried `CLIENT_TIMEOUT` from `indexer.ts::wrapIndexer` lands `{category:"external", code:"API_TIMEOUT"}` in `CLIENT_POLL_TIMED_OUT.details.lastCause`, a value `Option<RetryErrorCause>` cannot hold, where Rust would report `Indexer`. `retry.ts::isRetryable` matches `CLIENT_RPC`, which no file under `sdk-libs/ts` constructs, and rejects `CLIENT_RPC_HTTP`, `CLIENT_RPC_JSON`, and `CLIENT_RPC_ENVELOPE`, the codes `solana-rpc.ts` raises for the transport failures Rust reports as the retryable `ClientError::Rpc`. `indexer.ts::pollIndexer` gained a `pollUntil` call that swallows retryable failures; when they exhaust, `latest` is still its `-(2n**63n)` seed and the caller receives `CLIENT_INDEXER_NOT_CAUGHT_UP` with `latest: "-9223372036854775808"`, while `indexer.rs::wait_for_indexer` propagates each failure through `request()?`. The pre-`b230b314` loop had no `catch`, so this one is a regression. `IndexerPollConfig::attempts` and `ClientError::retry_cause` are public in Rust and have no exported TypeScript counterpart; three call sites open-code `numRetries + 1` instead. Smallest fix: restrict `retryErrorCause` to the three Rust causes, classify the codes the RPC adapter raises, and let `pollIndexer` rethrow the exhausted cause. C02's remaining gap is call-site reachability. The producer-disposition test in `error.test.ts` asserts only that four hand-written sets partition `CANONICAL_CLIENT_ERROR_CODES`, so it cannot fail when a code loses its producer. A scan for `new ClientError` across `sdk-libs/ts` finds no site for `CLIENT_RPC`, `CLIENT_SOLANA_TRANSACTION_SIGNING`, `CLIENT_ACCOUNT_NOT_FOUND`, or `CLIENT_DEPOSIT_SENDER_NOT_SIGNER`, yet the test files them under `structuredTransport` and `rustWorkflowBoundary`. Smallest fix: derive the produced set from the package sources, then reclassify or add a producer for those four codes.
- Closed by this re-review: the C01 findings on the omitted public surface, the disagreement over Rust-valid configurations (`validatePollConfig` now accepts `delayMs > maxDelayMs` and `backoff` caps the first delay, matching `backoff_caps_the_first_delay_and_doubles_from_the_cap`), zero delay, the browser timer bound, attempt counts, and the duplicated loops. The C02 findings on the missing `CLIENT_POLL_TIMED_OUT` producer, the open runtime constructor, malformed payloads, deep immutability, and redaction. The mid-flight defect the C04 reviewer reported is closed: `ClientErrorDetailsMap.CLIENT_POLL_TIMED_OUT` declares `{attempts, lastCause?}`, `DETAIL_SHAPES` and `REQUIRED_DETAIL_FIELDS` agree, and `retry.ts:117` constructs `lastCause`.
- Rust drift after this re-review: `6d757791` landed the concurrent worker's edits while this entry was being written. `retry.rs` gained `poll_until_async`; `indexer.rs::wait_for_indexer` now routes through `poll_until` behind a `Lag` guard that returns `IndexerNotCaughtUp` only when the response count reaches the attempt count and otherwise returns the precise failure; `ClientError::Indexer` became `{ method, retryable }` with no response text, and `retry_cause` consults the flag. The lag-report finding above is therefore settled on the Rust side and still open in TypeScript. `canonicalSourceRevisions.client` (`3ba52785`) and both refreshed client fixtures are stale against `6d757791`, and `isRetryable` treating bare `CLIENT_INDEXER` as retryable is a fourth difference to close.
- Row transition: C01 `needs_fix -> in_progress -> needs_fix`; C02 `needs_fix -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C22 sdk-libs/client/src/lib.rs`
- Full SDK parity claim: unsupported; the retry classifier and the indexer lag report still disagree with current Rust, and no client error code has producer evidence

### 2026-07-25 13:54 UTC | C22 | `sdk-libs/client/src/lib.rs`

- Baseline: HEAD `142b2b985da00fc6a6a02691469aca6062ddf608`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f` with `canonicalSourceRevisions.client` at `3ba527850a7986f36c47ad2082598edff3e3e5b7`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted `error.rs` and `retry.rs` edits remain in place and do not touch `lib.rs`
- Worker: independent C01/C02 re-review worker; implementation commit `none`
- Explanation: This 63-line file is the `zolana-client` crate root. It declares seven modules, four of them behind the `indexer-api` and `solana-rpc` features, and flattens their public items into one import surface: `SignedPrivateTransaction`, `ZolanaClient`, and `DEFAULT_TRANSACT_CU_LIMIT` from `client`; `ClientError` and `RetryErrorCause` from `error`; `AsyncZolanaIndexer` and `ZolanaIndexer` from `indexer`; a 42-name block from `prover` covering shape resolution, the prover clients, proof types, and the transact assembly; `IndexerPollConfig` and `IndexerRpcConfig` from `retry`; a 19-name block from `rpc` covering the two traits, the response and proof types, and the two tree-height constants; `AsyncSolanaRpc`, `ConfirmedInstructionGroups`, and `SolanaRpc` from `solana_rpc`; and a 17-name block re-exported from `zolana_transaction` so a client consumer needs one crate rather than two. It holds no logic and no key material. The TypeScript counterpart is `sdk-libs/ts/client/src/index.ts`, with `prover/index.ts` and the new `retry/index.ts` as separate subpaths.
- Evidence: `planning/typescript-sdk-port/public-exports.md` is the documented allowlist for `@zolana/client`, and `planning/typescript-sdk-port/inventory-client.md` records this row as a `crate-root pub use allowlist` whose evidence is a Rust-generated `fixtures/client/lib.json`. That fixture is absent from `sdk-libs/ts/fixtures/client/`, which holds six other files. `npm run test:exports` compares each `package.json` export map against `config/packages.mjs` entry points and conditions, and `npm run api:check` runs `checkScaffold`, which asserts that per-package scripts exist. Neither reads a symbol list, and the client package has no export test under `sdk-libs/ts/client/test/`. Both commands exit 0 against the current surface.
- Verdict: `DIVERGENT`
- Gap and smallest fix: `index.ts` omits `DEFAULT_TRANSACT_CU_LIMIT`, `RetryErrorCause`, the 42-name prover block, `OutputContext`, `OutputSlot`, `ProveResult`, `ShieldedTransaction`, `NULLIFIER_TREE_HEIGHT`, `STATE_TREE_HEIGHT`, `ConfirmedInstructionGroups`, and the 17 `zolana_transaction` names. Four of those exist in TypeScript as module-private constants: `DEFAULT_TRANSACT_CU_LIMIT` at `client.ts:42`, `MERGE_INPUTS` at `prover/merge.ts:31`, and both tree heights at `prover/assembly.ts:34-35`. The prover block is reachable only from `@zolana/client/prover`, so `import { ProverClient } from "@zolana/client"` fails where `use zolana_client::ProverClient` succeeds. `AsyncZolanaIndexer`, `AsyncRpc`, `AsyncSolanaRpc`, and `ShieldedTransactionStream` are the Rust async twins that a Promise-based port folds away, and `Context` maps to `RpcContext`; the ledger records those five and no more. In the other direction `index.ts` exports 19 names the ledger does not list: `CANONICAL_CLIENT_ERROR_CODES`, `CanonicalClientErrorCode`, `ClientErrorCause`, `ClientErrorCode`, `ClientErrorDetails`, `ClientErrorDetailsMap`, `HasherErrorCode`, `ProvedMergeZone`, `RpcAccount`, `PollUntilOptions`, and the nine retry names `b230b314` added. The ledger still declares `ClientError.code` as a template string and `cause` as `unknown`, while the class now has a closed `ClientErrorCode` union and a `ClientErrorCause`. Smallest fix: re-export or record a disposition for each crate-root name, reconcile `public-exports.md` with the shipped surface, and generate `fixtures/client/lib.json` with a test that asserts each entry, so the queue can detect a dropped or added root export.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C19 sdk-libs/client/src/prover/client.rs` for the client prover worker; `C21 sdk-libs/client/src/client.rs` stays deferred until the pending `indexer.ts` change lands
- Full SDK parity claim: unsupported; the client root surface has no allowlist evidence in either direction

### 2026-07-25 16:12 UTC | C17 | `sdk-libs/client/src/prover/merge_zone.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This module builds the policy-zone merge payload. It imports `p256::SecretKey`, `solana_address::Address`, `create_hash_chain_from_slice`, the keypair `NullifierKey`, `P256Pubkey`, and `PublicKey`, and the transaction crate's `PreparedMergeZone` and `program_id_field`. `prover/mod.rs` re-exports `MergeZoneProver` and `MergeZoneWitness`. `build` stamps the shared zone onto every input that carries a proof and onto the output, runs the shared merge computation under the `ZONE_MERGE_TRANSACT` tag, then folds a 10-element chain: the 6-element merge prefix, the two ephemeral key halves, the ciphertext hash, and the zone field. It differs from the default merge in exactly two ways, both deliberate: the owner signing and viewing hashes are omitted because a policy zone has no registry to bind an identity against, and the zone field is committed instead. The same zone field becomes the payload's top-level zone member. `MergeZoneWitness` carries the prepared merge, the owner nullifier key, and the fetched proofs, and its conversion attaches the proofs positionally. Rust evidence is `sdk-libs/client/tests/merge_zone/features/merge_zone.feature`; TypeScript evidence is the merge-zone cases in `sdk-libs/ts/client/test/merge.test.ts`.
- Evidence: `docs/spec.md` and the program's `zone_config` binding govern the final element. The TypeScript zone branch folds `[...commonPublicInputs, txViewingPublicKeyLow, txViewingPublicKeyHigh, ciphertextHash, zoneProgramField]`, which is the Rust order, and omits the two owner hashes exactly as Rust does. `MERGE_ZONE_INSTRUCTION_TAG` of 13 in `merge.ts` matches `tag::ZONE_MERGE_TRANSACT` as used by `program-libs/interface/src/instruction/builders/merge_zone.rs`, and `hashField(addressBytes(zone))` matches `program_id_field(&Some(zone))`. `merge.test.ts` asserts the `merge-zone` circuit type and a nonzero `zoneProgramId`. The promised `fixtures/client/merge_zone.json` does not exist, so no oracle pins the zone chain, and the `merge_zone.feature` scenarios have no TypeScript counterpart.
- Verdict: `PARTIAL`
- Gap and smallest fix: `sdk-libs/ts/reports/inventory.json` promises `src/prover/merge-zone.ts`; the behavior lives in `merge.ts` behind an optional `zoneProgramId` parameter, and `MergeZoneProver` and `MergeZoneWitness` have no counterpart. Rust stamps `zone_program_id` onto every proofed input and the output before assembly, while TypeScript validates instead of stamping, in `PreparedMergeZone.inputUtxoHashes`; `assembleMergeZone` reaches that validation through the indexer call, but `assembleMergeZoneWithProofs` does not call `inputUtxoHashes` at all, so a caller supplying its own proofs gets neither the stamp nor the check and commits a zone the input UTXOs do not carry. Smallest fix: call the zone validation from `assembleMergeZoneWithProofsUnchecked` so both entry points enforce it, correct the inventory target to `merge.ts`, and generate `fixtures/client/merge_zone.json` pinning the 10-element chain and the stamped per-UTXO zone field.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C18 sdk-libs/client/src/prover/zone_authority.rs`
- Full SDK parity claim: unsupported; one entry point skips the zone check and no oracle pins the zone chain

### 2026-07-25 16:26 UTC | C18 | `sdk-libs/client/src/prover/zone_authority.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This module builds the payload for a transition the zone authority performs on its own zone-owned notes. It imports `solana_address::Address`, `create_hash_chain_from_slice`, the keypair `hash_field`, and the transaction crate's `PreparedZoneAuthority`, `PrivateTxHash`, and `program_id_field`, and reuses the shared input and output assembly. `prover/mod.rs` re-exports `ZoneAuthorityProver`, `ZoneAuthorityProofResult`, and `ZoneAuthorityWitness`. `build` assembles under `OwnerMode::ZoneAuthority`, where each owner contributes its own field as a private value, hashes the external data and the private transaction, converts the zone program to its field, and folds the 12 base elements with no owner chain and no confidential appendix. The capability model is what makes the module distinct: the `zone_config` PDA signs on-chain, so there is no per-input signer and no P256 signature, and owner identities stay out of the public preimage. `ZoneAuthorityWitness` pairs a prepared transition with the fetched proofs. No Rust test targets the file; the TypeScript side has no test because it has no implementation.
- Evidence: the Go `NewTransferZoneAuthorityCircuit` public-input layout governs, and the Rust comment cites it. `inventory.json` records `disposition: port`, `target: @zolana/client · src/prover/zone-authority.ts`, and a promised Rust-generated `fixtures/client/zone_authority.json`; neither exists. `sdk-libs/ts/transaction/src/instructions/builders.ts:476` defines `PreparedZoneAuthority` and `sdk-libs/ts/interface` ships `zoneAuthorityTransactInstruction` with tag 3, so the surrounding pipeline is ported and only the proving step is absent. A search of `sdk-libs/ts` for `transfer-zone-authority` and for `ZoneAuthorityProver` returns nothing.
- Verdict: `MISSING`
- Gap and smallest fix: `zolana_client::prover::{ZoneAuthorityProver, ZoneAuthorityProofResult, ZoneAuthorityWitness}` have no TypeScript symbol, so a caller can build and submit a zone-authority instruction but cannot produce its proof. Because the preimage drops the owner chain, the existing confidential path cannot stand in. Smallest fix: add `src/prover/zone-authority.ts` reusing the shared assembly with the pubkey-agnostic owner rule and the 12-element chain, extend the `ProverInputs` circuit union with the zone-authority variant so `proverRequest` can emit `transfer-zone-authority`, and generate the promised fixture; otherwise change the inventory disposition and note the omission in `public-exports.md`.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C19 sdk-libs/client/src/prover/client.rs`
- Full SDK parity claim: unsupported; the surface is absent

### 2026-07-25 16:47 UTC | C19 | `sdk-libs/client/src/prover/client.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This module is the HTTP client for the prover server. It imports `std::process::Command`, `reqwest` in both blocking and async form, and `tokio::time::sleep`, and pulls the eight `to_json_*` bodies plus `proof_from_gnark_json`. `prover/mod.rs` re-exports `spawn_prover`, `AsyncPollConfig`, `AsyncProverClient`, `ProverClient`, `PROVE_PATH`, and `SERVER_ADDRESS`; `HEALTH_CHECK` and `server_address()` stay reachable through the `pub mod` path. `ProverClient` and `AsyncProverClient` each carry a server address, an HTTP client with a 10-second connect and 600-second request timeout, and an `AsyncPollConfig` defaulting to a 3-second interval and a 1200-second ceiling. Each offers eight prove entry points, one per circuit. `send` posts the body, retries a transport error twice with a 2-second backoff, fails on any non-success status, and either returns the proof or, when the body carries a job handle and no proof, polls `/prove/status`. Polling treats a 4xx as fatal, a 5xx or a transport error as retryable, `completed` as the terminal success reading the nested `result`, `failed` as terminal, and anything else as keep-waiting. `spawn_prover` health-checks the address and otherwise starts the server through the `zolana` CLI, honoring `ZOLANA_PROVER_URL`, `ZOLANA_CLI_CMD`, `ZOLANA_CLI_BIN`, and `ZOLANA_PROVER_REDIS_URL`. The module handles no key material; it forwards an already-built body containing the payload secrets. Rust evidence is the 10 unit tests at the foot of the file, including a mock server for the queued path; TypeScript evidence is `sdk-libs/ts/client/test/prover/*.test.ts` against `sdk-libs/ts/client/src/prover/client.ts`.
- Evidence: no spec governs the transport, so current Rust governs. Both languages post to `<base>/prove`, retry three times with a 2-second backoff on a transport failure, detect the job handle by an absent `proof` plus a string `job_id`, poll `/prove/status?job_id=<id>` at 3 seconds, cap the wait at 1200 seconds, read the nested `result` on `completed`, and fail on `failed`. The Rust mock-server tests cover the queued, failed, timed-out, malformed-body, 404, and transient-disconnect paths, and the TypeScript tests cover the same shapes plus a response-size cap and URL validation. The environment default and the server spawn have moved to `@zolana/test-kit`, which reads `ZOLANA_PROVER_URL` with the same port-offset rule, so `spawn_prover` is relocated rather than missing.
- Verdict: `DIVERGENT`
- Gap and smallest fix: `sdk-libs/ts/client/src/prover/client.ts::ProverClient` sets no request timeout, so a prover that accepts the connection and never answers hangs the call until the caller's own signal fires, while `build_http_client` caps a prove at 600 seconds. `retryableStatus` retries 408, 425, 429, and every 5xx, while `send` in Rust returns `ProverServer` on the first non-success status, so the two disagree on how many requests a failing server receives and on which error the caller sees. The class exposes `prove` and the two symbol-keyed merge methods, and `prover/index.ts` exports neither `proveMerge` nor `proveMergeZone`, so 6 of the 8 Rust prove entry points, `prove_zone_authority`, `prove_transfer_zone`, `prove_transfer_p256_zone`, `prove_batch_address_append`, and the two merge functions as public API, are unreachable from the package. `AsyncPollConfig`, `ProverClient::local()`, `SERVER_ADDRESS`, and `PROVE_PATH` have no counterpart, so the poll cadence and ceiling are fixed constants. Smallest fix: give the TypeScript client a default request timeout matching the Rust ceiling, make the two retry rules agree in one place, export the merge entry points, and add a poll-config parameter; the four missing circuits depend on the C13, C14, and C18 ports.
- Rust defects: `poll_async` interpolates the server-supplied `job_id` straight into the status URL with no validation, so a malicious or buggy prover controls the query string; the TypeScript port validates it against `[A-Za-z0-9_-]{1,256}` first. `send` builds the URL by string concatenation, so a base address with a trailing slash produces a double-slash path.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: `C20 sdk-libs/client/src/prover/mod.rs`
- Full SDK parity claim: unsupported; the timeout and retry rules differ and 6 of 8 entry points are unreachable

### 2026-07-25 16:58 UTC | C20 | `sdk-libs/client/src/prover/mod.rs`

- Baseline: HEAD `a7fe607cd2c9148a5712bbb0bef32fa57be9a03e`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `sdk-libs/merkle-tree/src/indexed.rs`; the concurrent worker's uncommitted client and transaction edits remain in place
- Worker: client prover review worker; implementation commit `none`
- Explanation: This module is the prover subtree's façade. It keeps `client`, `inputs`, `json`, and `proof` private and publishes `field`, `merge`, `merge_zone`, `transact`, and `zone_authority` as modules, then re-exports 39 names: 6 transport items from `client`, 6 witness types from `inputs`, the merge and merge-zone provers and their results, 4 proof types, 11 transact provers, results, and helpers, the 3 zone-authority items, and 5 names borrowed from `zolana_transaction` (`canonical_shape`, `resolve_shape`, `Shape`, `SPP_SUPPORTED_SHAPES`, `ProofInputUtxo`). It holds no logic and no key material; the borrowed shape names exist so a caller building a proof does not also have to depend on the transaction crate. The TypeScript counterpart is the `./prover` subpath of `@zolana/client`, declared in `sdk-libs/ts/client/package.json`.
- Evidence: no spec governs a re-export list, so current Rust governs. `sdk-libs/ts/client/src/prover/index.ts` exports 6 values and 11 types. Ten map onto Rust names: `ProverClient`, `canonicalShape`, `resolveShape`, `Shape`, `Proof`, `CompressedProof` for `ProofCompressed`, `TransferInput`, `TransferInputs`, `TransferOutput`, and `TransferP256Inputs`. Seven have no name in this Rust module but are reachable through the public `transact` module or as a method: `assemble`, `intoProver`, `compressProof`, `AssembledTransfer`, `ProverInputs`, `SpendProof`, and the TypeScript-only `Field`. The wallet package pins its module surface with `fixtures/wallet/mod.json` and `sdk-libs/ts/wallet/test/vectors/export-vector.test.ts`; the client package has no equivalent, so nothing freezes this subpath.
- Verdict: `PARTIAL`
- Gap and smallest fix: 29 of the 39 re-exported names have no counterpart in `sdk-libs/ts/client/src/prover/index.ts`. Twenty are the prover, result, and witness types already recorded under C13 through C18 and C16; the rest are `spawn_prover`, `AsyncPollConfig`, `AsyncProverClient`, `PROVE_PATH`, `SERVER_ADDRESS`, `MergeInputs`, `BatchAddressAppendInputs`, `Commitments`, `CompressedCommitments`, `SPP_SUPPORTED_SHAPES`, and `ProofInputUtxo`. The last two are exported by `@zolana/interface` and `@zolana/transaction`, so they are a re-export-location difference rather than a hole; `MergeInputs` is declared in `types.ts` and exported from no subpath. `canonicalShape` and `resolveShape` are re-declared pass-through wrappers returning `Readonly<{ inputs: number; outputs: number }>` instead of the exported `Shape`, so a caller cannot assign the result where a `Shape` is required. Smallest fix: add an export-vector fixture and test for the `./prover` subpath as the wallet package has, record a per-name disposition for the 29, export `MergeInputs`, and give the two wrappers a `Shape` return type.
- Rust defects: none observed.
- Row transition: `todo -> in_progress -> needs_fix`
- Progress: `31/118`; package `0/22`
- Exact next file: none in this worker's queue; `C21` remains with the client retry and error worker
- Full SDK parity claim: unsupported; the subpath publishes 10 of 39 names and no frozen evidence guards it

### 2026-07-25 13:59 UTC | evidence | client fixture check

- Baseline: HEAD `403d8309`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`
- Worker: coordinator; command evidence only, no verdict change
- The C01 and C02 re-review recorded the `xtask` `ts-fixtures` binary in `--check --current-client` mode as the one command that could not produce a result, because `xtask` failed to compile against an uncommitted `ClientError::Indexer` change.
- That change landed in `6d757791`. The command now reports `verified 2 current client fixtures` and exits `0`.
- The same commit advanced `canonicalSourceRevisions.client` to `6d757791`, so the predicted stale client pin does not apply.
- Default-mode `fixtures:check` stays blocked on baseline drift in `sdk-libs/client/src/prover/transact/witness.rs` and 14 `sdk-libs/transaction` paths. That is the register issue G8-1 and is not evidence about C01 or C02.
- Adverse verdicts stand: `C01 DIVERGENT`, `C02 PARTIAL`, `C22 DIVERGENT`.
