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
- Review HEAD: `8152a4865c832ea0b56c02fdd656776986d71cac`
- Fixture `frozenCommit`: `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`
- Canonical Rust drift since freeze: `sdk-libs/merkle-tree/src/indexed.rs`
- Primary rows: `118`
- Progress: `18 done / 118 total`; `53 needs_fix`; `0 needs_re_review`; `1 in_progress`
- Exact next eligible row: `T14 sdk-libs/transaction/src/wallet/state.rs`
- Active reviews: `M02 sdk-libs/merkle-tree/src/lib.rs`
- Active fixes: `K01 proposed`; `K02 proposed`; `K03 proposed`; `M01 proposed`
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
| I01 | `program-libs/interface/src/error.rs` | `interface/src/errors.ts`, `interface/src/index.ts` | done | PARITY | committed | The named 26-code map, structured decoder, unknown-code preservation, client translation, redaction, exports, and current-Rust evidence now align. | 2026-07-25 re-review | `e7fa785b` |
| I02 | `program-libs/interface/src/shape.rs` | `interface/src/internal.ts` | done | PARITY | committed | One deeply immutable interface shape authority now covers ordering, empty and boundary selection, unsupported pairs, malformed counts, reuse, exports, and current-Rust evidence. | 2026-07-25 re-review | `a384d9c1` |
| I03 | `program-libs/interface/src/merge_utils.rs` | `interface/src/internal.ts` | needs_fix | PARTIAL | proposed | Interface hash helpers align on covered flows, but keypair duplicates the hash implementation and no full boundary oracle covers packing, chunking, cardinality, and rejection behavior. Reuse the interface authority and add the complete current-Rust boundary oracle. | 2026-07-25 re-review | - |
| I04 | `program-libs/interface/src/pda.rs` | `interface/src/pda/index.ts` | needs_fix | PARTIAL | proposed | The canonical PDA surface is present and reused, but current-Rust vectors omit nonzero inputs, canonical bumps, malformed address positions, and rejection paths. Add exact vectors across the PDA flows and address positions. | 2026-07-25 re-review | - |
| I05 | `program-libs/interface/src/instruction/instruction_data/batch_update_nullifier_tree.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | Public data and proof types, the exact codec, builder reuse, proof ordering, boundaries, malformed rejection, exports, and current-Rust evidence now align. | 2026-07-25 re-review | `a384d9c1` |
| I06 | `program-libs/interface/src/instruction/instruction_data/create_tree.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | The public create-tree data type and exact codec are reused by the builder and cover ownership, lengths, malformed addresses, browser behavior, and current-Rust bytes. | 2026-07-25 re-review | `a384d9c1` |
| I07 | `program-libs/interface/src/instruction/instruction_data/deposit.rs` | `interface/src/codecs/index.ts`, `interface/src/instructions/index.ts` | needs_fix | BLOCKED | proposed | Current Rust and locked TypeScript behavior conflict with authoritative `docs/spec.md` on deposit layouts and signing-tag semantics, so parity cannot be determined. Resolve the protocol authority before aligning codecs, builders, and evidence. | 2026-07-25 re-review | - |
| I08 | `program-libs/interface/src/instruction/instruction_data/merge_transact.rs` | `interface/src/codecs/index.ts` | needs_fix | DIVERGENT | proposed | TypeScript rejects an encrypted-UTXO prefix other than `2`, while current Rust fails to validate that prefix. Choose and enforce the canonical boundary consistently, then pin acceptance and rejection evidence. | 2026-07-25 re-review | - |
| I09 | `program-libs/interface/src/instruction/instruction_data/merge_zone.rs` | `interface/src/codecs/index.ts` | needs_fix | PARTIAL | proposed | The interface codec and exact instruction evidence align, but the dedicated zone-merge client proving, assembly, submission, and wrong-path rejection flow is still missing. Implement and exercise that client flow. | 2026-07-25 re-review | - |
| I10 | `program-libs/interface/src/instruction/instruction_data/protocol_config.rs` | `interface/src/codecs/index.ts` | needs_fix | BLOCKED | proposed | Current Rust and TypeScript update one selected protocol-config field, while authoritative `docs/spec.md` requires rewriting the owner, authority fields, and flags. Resolve that protocol conflict before completing codec parity. | 2026-07-25 re-review | - |
| I11 | `program-libs/interface/src/instruction/instruction_data/transact.rs` | `interface/src/codecs/index.ts` | needs_fix | PARTIAL | proposed | Core layouts and helpers align, but `ExternalDataHash` remains private or duplicated across packages instead of one public interface authority. Export and reuse the canonical hash and pin its root and mutation evidence. | 2026-07-25 re-review | - |
| I12 | `program-libs/interface/src/instruction/instruction_data/zone_config.rs` | `interface/src/codecs/index.ts` | needs_fix | PARTIAL | proposed | Zone-config codecs and builders align, but test-kit returns the wrong zone account and no exact current-Rust fixture covers the contract. Return `zone_auth` and add exact success and rejection evidence. | 2026-07-25 re-review | - |
| I13 | `program-libs/interface/src/instruction/instruction_data/mod.rs` | `interface/src/codecs/index.ts` | needs_fix | PARTIAL | proposed | Most instruction-data counterparts and dispositions are present, but the aggregate inherits blocked deposit and protocol-config authority and still lacks a complete protocol-config codec. Resolve those dependencies and pin the export ledger. | 2026-07-25 re-review | - |
| I14 | `program-libs/interface/src/instruction/builders/batch_update_nullifier_tree.rs` | `interface/src/instructions/index.ts` | done | PARITY | committed | The builder reuses the canonical codec and exact current-Rust evidence covers program, bytes, account metas, boundaries, malformed input, and defensive ownership. | 2026-07-25 re-review | `a384d9c1` |
| I15 | `program-libs/interface/src/instruction/builders/create_asset_counter.rs` | `interface/src/instructions/index.ts` | needs_fix | PARTIAL | proposed | Builder behavior aligns, but the current-Rust fixture, exact account-meta assertions, and defensive-copy evidence remain missing. Add exact program, data, meta, malformed, and mutation coverage. | 2026-07-25 re-review | - |
| I16 | `program-libs/interface/src/instruction/builders/create_associated_token_account.rs` | `interface/src/instructions/index.ts` | done | PARITY | none | The TypeScript builder preserves the legacy SPL associated-token derivation, canonical program IDs, six accounts and flags, and the one-byte idempotent discriminator. A current-Rust workflow fixture plus exact transaction and live repeated-call coverage supports parity. The planning fixture name has bookkeeping drift only. | 2026-07-25 review | - |
| I17 | `program-libs/interface/src/instruction/builders/create_spl_interface.rs` | `interface/src/instructions/index.ts` | needs_fix | PARTIAL | proposed | Builder behavior aligns, but evidence still lacks a nonzero-mint current-Rust vector with exact PDAs, account metas, malformed rejection, and defensive-copy checks. Add that fixture and focused evidence. | 2026-07-25 re-review | - |
| I18 | `program-libs/interface/src/instruction/builders/create_tree.rs` | `interface/src/instructions/index.ts` | done | PARITY | committed | Default and custom nullifier-parameter paths, canonical codec reuse, exact bytes, account metas, rejection, and current-Rust fixtures now support parity. | 2026-07-25 re-review | `a384d9c1` |
| I19 | `program-libs/interface/src/instruction/builders/deposit.rs` | `interface/src/instructions/index.ts` | needs_fix | BLOCKED | proposed | Current Rust and TypeScript agree on covered SOL and SPL behavior, but authoritative `docs/spec.md` conflicts on accounts, payload, tag semantics, and the initial viewing-key tag. Resolve the protocol authority before completing evidence. | 2026-07-25 re-review | - |
| I20 | `program-libs/interface/src/instruction/builders/merge_transact.rs` | `interface/src/instructions/index.ts` | needs_fix | DIVERGENT | proposed | Exact builder bytes and metas align, but this builder inherits I08's encrypted-UTXO prefix divergence between TypeScript and Rust. Resolve and pin the canonical prefix boundary. | 2026-07-25 re-review | - |
| I21 | `program-libs/interface/src/instruction/builders/merge_zone.rs` | `interface/src/instructions/index.ts` | needs_fix | DIVERGENT | proposed | Outer and CPI builder behavior aligns on covered flows, but this builder inherits I08's encrypted-UTXO prefix divergence. Resolve the shared codec boundary and re-run both mode fixtures. | 2026-07-25 re-review | - |
| I22 | `program-libs/interface/src/instruction/builders/protocol_config/mod.rs` | `interface/src/instructions/index.ts` | needs_fix | BLOCKED | proposed | Builder behavior follows current Rust, but the aggregate inherits I10's unresolved conflict with authoritative `docs/spec.md`. Resolve the protocol-config update contract before parity. | 2026-07-25 re-review | - |
| I23 | `program-libs/interface/src/instruction/builders/transact.rs` | `interface/src/instructions/index.ts` | done | PARITY | committed | Canonical builder reuse now preserves Rust's construction boundary, exact layouts, account metas, settlement errors, client integration, and current-Rust evidence. | 2026-07-25 re-review | `a384d9c1` |
| I24 | `program-libs/interface/src/instruction/builders/zone_authority_transact.rs` | `interface/src/instructions/index.ts` | needs_fix | PARTIAL | proposed | Valid builder behavior aligns, but exact outer and CPI fixtures do not cover both SOL and SPL routes, account selection, and rejection paths. Add the complete routing fixture matrix. | 2026-07-25 re-review | - |
| I25 | `program-libs/interface/src/instruction/builders/zone_config/mod.rs` | `interface/src/instructions/index.ts` | needs_fix | PARTIAL | proposed | Create and update builders align, but exact outer and CPI fixtures, account metas, creation routing, and rejection evidence remain incomplete. Add the full routing matrix. | 2026-07-25 re-review | - |
| I26 | `program-libs/interface/src/instruction/builders/zone_deposit.rs` | `interface/src/instructions/index.ts` | needs_fix | PARTIAL | proposed | Covered SOL and SPL behavior aligns, but exact outer and CPI fixtures, account metas, routing, and rejection evidence remain incomplete and the I07 authority conflict remains. Add the fixture matrix after resolving I07. | 2026-07-25 re-review | - |
| I27 | `program-libs/interface/src/instruction/builders/zone_transact.rs` | `interface/src/instructions/index.ts` | needs_fix | PARTIAL | proposed | The prior settlement-boundary divergence is fixed, but exact outer and CPI fixtures still lack complete withdrawal, owner-index, account-meta, and rejection evidence. Add those current-Rust vectors. | 2026-07-25 re-review | - |
| I28 | `program-libs/interface/src/instruction/builders/mod.rs` | `interface/src/instructions/index.ts` | needs_fix | DIVERGENT | proposed | The aggregate builder root is coherent but inherits I08, I20, and I21's encrypted-UTXO prefix divergence. Resolve the shared boundary and pin exact runtime and declaration allowlists. | 2026-07-25 re-review | - |
| I29 | `program-libs/interface/src/instruction/mod.rs` | `interface/src/index.ts` | needs_fix | PARTIAL | proposed | The instruction aggregate is substantially complete but inherits blocked protocol authority, child evidence gaps, and incomplete aggregate allowlists. Resolve blocked children and pin exact root and subpath exports. | 2026-07-25 re-review | - |
| I30 | `program-libs/interface/src/state/discriminator.rs` | `interface/src/internal.ts` | done | PARITY | committed | One exported discriminator authority now includes the tree value, records reserved value `2`, is reused by codecs, and has complete current-Rust drift evidence. | 2026-07-25 re-review | `a384d9c1` |
| I31 | `program-libs/interface/src/state/protocol_config.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | The exact 132-byte layout, Rust nonzero-boolean decoding, size disposition, boundaries, malformed input, and current-Rust fixture now align. | 2026-07-25 re-review | `a384d9c1` |
| I32 | `program-libs/interface/src/state/spl_asset_counter.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | The exact codec, `FIRST_ASSET_ID`, reserved bytes, `u64` boundaries, initialization, allocation, overflow, and sequencing evidence now align. | 2026-07-25 re-review | `a384d9c1` |
| I33 | `program-libs/interface/src/state/spl_asset_registry.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | Exact registry bytes and boundaries align, and wallet sync now records, fetches, and retries unknown asset registries with current-Rust evidence. | 2026-07-25 re-review | `a19c99b3` |
| I34 | `program-libs/interface/src/state/tree.rs` | `interface/src/index.ts` | done | PARITY | committed | Public tree constants, nullifier parameters, account size, root offset, browser-safe exports, and current-Rust vectors now align. | 2026-07-25 re-review | `a384d9c1` |
| I35 | `program-libs/interface/src/state/zone_config.rs` | `interface/src/codecs/index.ts` | done | PARITY | committed | The exact 67-byte layout and canonical and noncanonical enabled-byte behavior now match current Rust with strict fixture evidence. | 2026-07-25 re-review | `a384d9c1` |
| I36 | `program-libs/interface/src/state/mod.rs` | `interface/src/index.ts` | done | PARITY | committed | The state root now reuses and exports canonical discriminators, asset constants, tree authorities, child codecs, and exact allowlist evidence. | 2026-07-25 re-review | `a384d9c1` |
| I37 | `program-libs/interface/src/lib.rs` | `interface/src/index.ts` | needs_fix | PARTIAL | proposed | The package root and evidence improved substantially, but the aggregate inherits blocked and divergent child rows plus remaining export and fixture gaps. Resolve those children and pin the final package allowlists. | 2026-07-25 re-review | - |

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
| K11 | `sdk-libs/keypair/src/traits/view_key.rs` | `keypair/src/viewing-key.ts` | needs_fix | PARTIAL | proposed | All 14 concrete operations exist on TypeScript `ViewingKey`, but public `ViewingKeyLike` exposes only two unused methods. `ShieldedKeypair` cannot substitute, higher packages require concrete `ViewingKey`, and trait declaration, facade, malformed-input, secret-exposure, browser, and current-Rust evidence is missing. Add the public trait adaptation and facade, accept the least-powerful capability in higher packages, and add the missing evidence. | 2026-07-25 review | - |
| K12 | `sdk-libs/keypair/src/traits/shielded_keypair.rs` | `keypair/src/shielded.ts` | needs_fix | PARTIAL | proposed | Concrete operations exist, but the generic interface omits six named capabilities, is unused, and lacks a workable async/HSM facade and evidence. Correct Rust's malformed-P256-sign panic and secret-returning nullifier trait method, then complete and consume the generic facade with current-Rust, malformed, capability, async/HSM, browser, and secret-exposure evidence. | 2026-07-25 review | - |
| K13 | `sdk-libs/keypair/src/traits/mod.rs` | `keypair/src/index.ts` | needs_fix | PARTIAL | proposed | Rust trait-module exports are represented only by incomplete root-level TypeScript interfaces; no documented traits subpath or counterpart and no trait-specific fixture exist. The declarations are accurate, but consumer, browser, and packed-package evidence does not exercise the interfaces. Add the documented traits surface and trait-specific fixture, then exercise the interfaces through consumer, browser, and packed-package tests. | 2026-07-25 review | - |
| K14 | `sdk-libs/keypair/src/lib.rs` | `keypair/src/index.ts` | needs_fix | DIVERGENT | proposed | The package export map and browser graph are coherent, but Rust-public constants, Poseidon, `symmetricApply`, `isEd25519`, `Signature`, compressed-address and traits surfaces are missing; `Bytes33` falsely declares a 34-byte key. The K06 owner-hash spec conflict, collapsed errors, stale metadata, and missing exact root, type, tarball, and consumer allowlists also prevent package parity. Complete and correct the package surface, resolve the inherited conflicts, refresh metadata, and add exact allowlist evidence. | 2026-07-25 review | - |

### Merkle tree, 2 rows

| ID | Canonical Rust source | TS owner | Status | Verdict | Fix | Gap / fix | Review | Fix commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M01 | `sdk-libs/merkle-tree/src/indexed.rs` | `merkle-tree/src/indexed.ts` | needs_fix | DIVERGENT | proposed | Default vectors pass, but TypeScript lacks custom highest-sentinel behavior and public path, proof, and update APIs. Verification trusts the supplied root and path length, and numeric, error, sentinel, and mutation behavior diverges or lacks evidence. Add the missing public operations, validate roots and path lengths, align boundaries and errors, and add custom-sentinel and mutation vectors. | 2026-07-25 review | - |
| M02 | `sdk-libs/merkle-tree/src/lib.rs` | `merkle-tree/src/merkle-tree.ts`, `index.ts` | in_progress | - | none | Active read-only review; recorder awaits the completed report. | - | - |

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
| T01 | `sdk-libs/transaction/src/error.rs` | `transaction/src/error.ts` | needs_fix | DIVERGENT | proposed | The Rust error enum is an open public code set, but TypeScript collapses or misclassifies variants, drops structured payloads, and blurs keypair and authority boundaries. Redaction and current-Rust fixture coverage are absent. Add stable codes and details for each represented category, preserve unknown variants and payloads, keep authority errors distinct, and add boundary, redaction, and fixture tests. | 2026-07-25 review | - |
| T02 | `sdk-libs/transaction/src/data.rs` | `transaction/src/data.ts` | needs_fix | DIVERGENT | proposed | Normal deterministic models and current-Rust bytes match, but malformed runtime kinds and byte values are coerced or silently encoded. The constructor moves Rust's serialization-time length boundary, the direct codec capability is not packed, and adversarial, boundary, error-detail, and fixture-provenance evidence is incomplete. Reject malformed runtime values, restore the canonical length boundary, expose the packed codec capability, and add exact current-Rust rejection and provenance fixtures. | 2026-07-25 review | - |
| T03 | `sdk-libs/transaction/src/serialization/scheme.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | DIVERGENT | proposed | The seven tags match current Rust, but TypeScript omits the Rust root export and standalone checked conversion. Encoding accepts invalid runtime scheme values and scheme and encoding combinations, mishandles empty-blob details, and lacks direct rejection and export evidence. Add the checked conversion and root export, reject invalid values and combinations with exact details, and add current-Rust rejection and package-export fixtures. | 2026-07-25 review | - |
| T04 | `sdk-libs/transaction/src/serialization/plaintext.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | DIVERGENT | proposed | Exact bytes match current Rust, but TypeScript permits inner/outer discriminator and scheme/encoding confusion, omits public conversion and sealing capabilities, diverges on output-limit and error boundaries, and lacks adversarial and export evidence. Correct Rust `from_utxos` positional and owner defects first, then align validation, capabilities, limits, errors, and evidence. | 2026-07-25 review | - |
| T05 | `sdk-libs/transaction/src/serialization/confidential.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | DIVERGENT | proposed | Exact plaintext and ciphertext bytes match, but recipient decryption accepts malformed embedded P256 keys. Sender decryption, embedded-key, and scheme-locked encode capabilities are not packed; crypto error boundaries and malformed and browser evidence are incomplete. Correct Rust's `from_utxos` cardinality defect first, then align validation, capabilities, errors, and evidence. | 2026-07-25 review | - |
| T06 | `sdk-libs/transaction/src/serialization/anonymous.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | DIVERGENT | proposed | Exact frozen bytes match current Rust, but TypeScript diverges on zone-context resolution, omits scheme-locked UTXO-to-plaintext and authority flows, has no shared-tag state progression, and lacks adversarial, export, and browser evidence. Rust conflicts with `docs/spec.md` on anonymous recipient program and zone data and has lossy `from_utxos` defects; fix those prerequisites before copying behavior, then align the TypeScript flows and evidence. | 2026-07-25 review | - |
| T07 | `sdk-libs/transaction/src/serialization/proofless.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | DIVERGENT | proposed | Valid simple bytes match, but public conversion and scheme-lock capabilities are absent, owner-hash tampering is ignored in wallet sync, TypeScript follows Rust's spec-conflicting memo field, and optional, boundary, export, browser, and tamper evidence is incomplete. First remove memo per spec and fix Rust's exact-one UTXO, owner, context, integrity, and `Serialize`-category prerequisites; then align TypeScript capabilities and evidence. | 2026-07-25 review | - |
| T08 | `sdk-libs/transaction/src/serialization/split.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | DIVERGENT | proposed | Exact frozen bytes match current Rust, but TypeScript lacks zone-context parity and the public `SplitEncryptedUtxos` and scheme-locked conversion surface, accepts wrong split discriminators and cross-scheme envelopes, has runtime count and error-boundary gaps, and lacks adversarial, browser, and export evidence. Rust's lossy `Split::from_utxos` must first validate the UTXO set, owner, and context; then align the TypeScript surface, validation, and evidence. | 2026-07-25 review | - |
| T09 | `sdk-libs/transaction/src/serialization/merge.rs` | `transaction/src/serialization/codecs.ts` | needs_fix | DIVERGENT | proposed | Fixed-layout and verifiable-encryption bytes match current Rust, but TypeScript lacks a merge-specific scheme-locked conversion and sealing API, accepts invalid runtime amount and blinding values, requires raw secret bytes instead of `ViewingKey`, omits public UTXO conversion, and lacks malformed, export, browser, and proof-contribution evidence. First make Rust require exactly one compatible UTXO, validate owner, data, and zone, preserve `zone_program_id` on reconstruction, and return a structured unknown-asset error; then port and prove the surface. | 2026-07-25 review | - |
| T10 | `sdk-libs/transaction/src/serialization/mod.rs` | `transaction/src/serialization/index.ts` | needs_fix | DIVERGENT | proposed | Valid family bytes are represented, but TypeScript omits adaptations for Rust's `DecodeCx`, `OwnerCx`, and `UtxoSerialization` capabilities, does not seal scheme-to-encoding combinations, misses several packed public capabilities, and lacks exact root/subpath declaration, runtime, tarball, browser, and consumer allowlists. Preserve T03-T09 ownership and their Rust conversion/spec prerequisites; then add the aggregate capability adaptations, sealing, exports, and allowlist evidence. | 2026-07-25 review | - |
| T11 | `sdk-libs/transaction/src/utxo.rs` | `transaction/src/utxo.ts` | needs_fix | DIVERGENT | proposed | Valid frozen UTXO, hash, and nullifier vectors match current Rust, but TypeScript omits the field-encoded proof-input public API, domain, and helpers. Both implementations accept a spec-invalid nonzero zone hash without a nonzero zone program; runtime, copy, and error boundaries differ; and malformed, property, tamper, export, and browser evidence is incomplete. First centralize strict zone-pair validation in Rust, then align the TypeScript surface, boundaries, and evidence. | 2026-07-25 review | - |
| T12 | `sdk-libs/transaction/src/wallet/asset.rs` | `transaction/src/wallet/asset.ts` | needs_fix | DIVERGENT | proposed | Valid registry mappings match, but Rust and TypeScript accept spec-invalid asset ID `0`. TypeScript also omits public `address_for_field`, runtime mint/address and lookup-ID validation, and current-Rust rejection, property, error-detail, export, browser, and pack evidence, while exposing undeclared insertion-ordered `entries()`. First make Rust reject non-native asset IDs below `2`; then align the TypeScript API, domains, and evidence. Preserve I33 registry-codec ownership. | 2026-07-25 review | - |
| T13 | `sdk-libs/transaction/src/wallet/authority.rs` | `transaction/src/wallet/authority.ts` | needs_fix | DIVERGENT | proposed | TypeScript omits anonymous-transfer capability and several Rust public exports or ownership dispositions. Authority APIs expose viewing/nullifier secrets; remote output and rejection contracts are insufficient; and current-Rust malformed, HSM, concurrency, browser, and export evidence is incomplete. First make Rust reject the wrong signer rail, remove the implicit zero Solana address, validate remote signatures and results, and provide coherent snapshots with least-privilege secret boundaries; then align TypeScript while preserving K11/K12 capability ownership and W06 application-authority ownership. | 2026-07-25 review | - |
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
| T27 | `sdk-libs/transaction/src/instructions/merge.rs` | `transaction/src/instructions/builders.ts` | needs_fix | DIVERGENT | proposed | TypeScript uses the wrong nullifier authority, reports zone failures under the wrong error category, and does not reproduce `PreparedMerge` revalidation. Expiry handling, constants, public API, secret boundaries, and exact current-Rust evidence are also incomplete. Require the Rust-equivalent nullifier capability, align zone errors and revalidation, expose the canonical expiry and constants, and add exact, stale, malformed, capability, and secret-exposure fixtures. | 2026-07-25 review | - |
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
- Evidence: All 14 concrete operations exist on TypeScript `ViewingKey`, but public `ViewingKeyLike` has only two unused methods. `ShieldedKeypair` cannot substitute, higher packages require concrete `ViewingKey`, and trait declaration, facade, malformed-input, secret-exposure, browser, and current-Rust evidence is missing. No tests ran for this recorder update.
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
