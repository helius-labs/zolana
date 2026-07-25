# Queue coverage audit: is the 118-row denominator complete?

Read-only audit of `planning/typescript-sdk-port/review-checklist.md` against the
Rust and TypeScript sources on `ts-sdk-port`. No production code, test, fixture,
or checklist row was changed. The checklist is owned by a reconciliation worker
and was not edited.

## Bottom line

The queue is not complete. It has 118 rows and needs **145**. Twenty-seven Rust
source files that the port depends on carry no row:

| Uncovered crate | Files | Rows needed | Of which `NOT_APPLICABLE` |
| --- | ---: | ---: | ---: |
| `program-libs/event` | 6 | 6 | 2 |
| `program-libs/hasher` | 14 | 14 | 7 |
| `program-libs/indexed-array` | 4 | 4 | 0 |
| `program-libs/user-registry-interface` | 3 | 3 | 0 |
| Total | 27 | 27 | 9 |

Eighteen of the twenty-seven need a real parity verdict. The other nine are
justified omissions that still need a row, because the checklist requires a
recorded `NOT_APPLICABLE` disposition rather than an absence.

The uncovered files are not peripheral. They hold the Poseidon parameters, the
instruction tag table, the output-data encoding tags, the proofless output
layout, and the `UserRecord` account layout. The TypeScript port reimplements
every one of them, in several cases more than once, and no row has ever checked
those reimplementations against their Rust definitions.

The nine packages that the queue does cover are covered exactly. Every one of
the 118 rows names a Rust path that still exists, and each package's row count
equals its Rust source-file count with no file missed and none counted twice.
The gap is entirely at the `program-libs` boundary, where the scope rule was
applied to `interface` and to nothing else.

## The scope rule, as actually applied

The queue's stated unit is one row per production Rust source file. Measured
against the tree, that rule holds inside every crate it reaches:

| Package | Rust `src/*.rs` files | Rows | Match |
| --- | ---: | ---: | --- |
| `program-libs/interface` | 84, of which 47 are `verifying_keys/` | 37 | yes, 84 - 47 = 37 |
| `sdk-libs/keypair` | 14 | 14 | yes |
| `sdk-libs/merkle-tree` | 2 | 2 | yes |
| `sdk-libs/indexer-api` | 1 | 1 | yes |
| `sdk-libs/smart-account-client` | 1 | 1 | yes |
| `sdk-libs/zolana-api` | 1 | 1 | yes |
| `sdk-libs/transaction` | 31 | 31 | yes |
| `sdk-libs/client` | 22 | 22 | yes |
| `sdk-libs/wallet` | 9 | 9 | yes |

The 47 `verifying_keys/` files are excluded by a recorded decision in the Scope
reconciliation section, which names them as annex evidence. That exclusion is
sound and is written down.

The rule that was never stated is which `program-libs` crates come into scope.
`interface` is in scope because the SDK depends on it. Four other `program-libs`
crates are also direct dependencies of SDK crates, and the same reasoning admits
them:

| Crate | Depended on by | In queue |
| --- | --- | --- |
| `interface` | client, transaction, wallet | yes, 37 rows |
| `event` | client, transaction, wallet | no |
| `hasher` | client, keypair, merkle-tree, transaction | no |
| `indexed-array` | merkle-tree | no |
| `user-registry-interface` | wallet | no |

Verified by reading each crate's `Cargo.toml` and grepping the `use` sites in
`sdk-libs/*/src`. The remaining five `program-libs` crates (`account-checks`,
`batched-merkle-tree`, `bloom-filter`, `merkle-tree-metadata`, `tree`) appear in
no SDK `Cargo.toml` and in no SDK source file. They are program-only and
legitimately out of scope.

So the scope rule is defensible; it was simply applied to one crate out of five.
The two protocol defects found this session support that reading. The
unconstrained padding nullifier column
([double-spend-analysis.md](double-spend-analysis.md)) and the unbound
`user_record` in `merge_transact`
([registry-merge-verification.md](registry-merge-verification.md)) both surfaced
in code no row points at. Neither is a parity gap, and neither is the port's
problem to fix, but both are evidence for the same conclusion: the areas outside
the queue's reach are the areas nobody has read closely.

## Uncovered Rust files, with a scope verdict for each

### `program-libs/event`, 6 files, 6 rows needed

The crate splits cleanly in two, and the answer to the question that prompted
this audit is different for each half. See the dedicated section below for the
reasoning; the verdicts are:

| File | Verdict | TypeScript counterpart |
| --- | --- | --- |
| `src/tag.rs` | needs a row | `interface/src/index.ts`, `InstructionTag` |
| `src/output_data.rs` | needs a row | `interface/src/index.ts`, `MessageData` |
| `src/output_utxo.rs` | needs a row | `interface/src/index.ts`, `OutputUtxo` |
| `src/proofless.rs` | needs a row | `transaction/src/serialization/codecs.ts` |
| `src/lib.rs` | `NOT_APPLICABLE`, record it | none, no TypeScript decodes `GeneralEvent` |
| `src/program_test.rs` | `NOT_APPLICABLE`, record it | shapes only, in `@zolana/test-kit` |

### `program-libs/hasher`, 14 files, 14 rows needed

This is the largest hole and the one with the most protocol risk. The Rust
Poseidon parameters live in `src/poseidon.rs`, and the TypeScript port
reimplements them in **four** independent places:

- `sdk-libs/ts/keypair/src/poseidon.ts`, a 16-entry `PARTIAL_ROUNDS` table
- `sdk-libs/ts/interface/src/merge-utils.ts`, a 12-entry `PARTIAL_ROUNDS` table
- `sdk-libs/ts/transaction/src/internal.ts`, a 16-entry `PARTIAL_ROUNDS` table
- `sdk-libs/ts/merkle-tree/src/hashers.ts`, arity-1 and arity-2 constants inline

Three of those four files carry no row at all (`keypair/src/poseidon.ts`,
`transaction/src/internal.ts`, `merkle-tree/src/hashers.ts`). The fourth,
`interface/src/merge-utils.ts`, is reached only through row `I03`, whose Rust
source is `program-libs/interface/src/merge_utils.rs` and not the hasher. No row
in the queue compares any of these tables against `hasher/src/poseidon.rs`.
Poseidon output feeds every UTXO hash, nullifier, and proof input, so a
divergence here is silent and total.

| File | Verdict | Reason |
| --- | --- | --- |
| `src/poseidon.rs` | needs a row | reimplemented four times in TypeScript |
| `src/sha256.rs` | needs a row | `merkle-tree/src/hashers.ts`, `interface/src/internal.ts` |
| `src/keccak.rs` | needs a row | `merkle-tree/src/hashers.ts` |
| `src/bigint.rs` | needs a row | `merkle-tree/src/bytes.ts`, `keypair/src/bytes.ts` |
| `src/hash_chain.rs` | needs a row | `client/src/internal.ts`, `transaction/src/internal.ts` |
| `src/errors.rs` | needs a row | `merkle-tree/src/errors.ts`, `client/src/error.rs` maps `HasherError` |
| `src/lib.rs` | needs a row | the `Hasher` trait, mirrored as `Hasher32` |
| `src/hash_to_field_size.rs` | `NOT_APPLICABLE` | no SDK caller |
| `src/syscalls/mod.rs` | `NOT_APPLICABLE` | Solana BPF syscalls, no browser or Node analogue |
| `src/syscalls/definitions.rs` | `NOT_APPLICABLE` | same |
| `src/zero_bytes/mod.rs` | `NOT_APPLICABLE` | TypeScript computes zeros at runtime |
| `src/zero_bytes/poseidon.rs` | `NOT_APPLICABLE` | same |
| `src/zero_bytes/sha256.rs` | `NOT_APPLICABLE` | same |
| `src/zero_bytes/keccak.rs` | `NOT_APPLICABLE` | same |

The `zero_bytes` verdict rests on `sdk-libs/ts/merkle-tree/src/merkle-tree.ts`
building its zero column by hashing upward from a 32-byte zero leaf rather than
reading a table. That is a behavior-preserving adaptation and it deserves a row
that says so, because the tables are the Rust side's canonical values.

### `program-libs/indexed-array`, 4 files, 4 rows needed

`sdk-libs/merkle-tree/src/indexed.rs` is row `M01`, and it imports
`zolana_indexed_array` for the array type, its changelog, and its errors. The
TypeScript `merkle-tree/src/indexed.ts` reimplements that behavior. `M01` covers
the Rust wrapper; nothing covers the definitions underneath it.

| File | Verdict |
| --- | --- |
| `src/array.rs` | needs a row |
| `src/changelog.rs` | needs a row |
| `src/errors.rs` | needs a row |
| `src/lib.rs` | needs a row |

### `program-libs/user-registry-interface`, 3 files, 3 rows needed

`sdk-libs/wallet/src/user_registry.rs` (row `W07`) and
`sdk-libs/wallet/src/actions/submit.rs` (row `W03`) both import this crate for
`UserRecord`, `SyncDelegateEntry`, `user_record_pda`, and the instruction
discriminators. `sdk-libs/ts/wallet/src/registry.ts` reimplements all of it: the
program id `EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc`, the seed
`zolana/registry/v0`, the borsh field order, and the `mergingEnabled` flag. The
Rust definitions have no row.

This matters more than it did yesterday.
[registry-merge-verification.md](registry-merge-verification.md) found that
`merge_transact` does not bind its `user_record` to the owner being merged. That
finding sits in exactly this crate's account layout, and the queue has no row
that would have looked at it.

| File | Verdict |
| --- | --- |
| `src/lib.rs` | needs a row, holds the program id, the seed, and the PDA derivation |
| `src/state.rs` | needs a row, holds the `UserRecord` and `SyncDelegateEntry` layouts |
| `src/instruction.rs` | needs a row, holds the instruction discriminators |

### `sdk-libs/program-test`, 11 files, 0 rows, decision needs recording

Out of scope, but for a reason the checklist states only half of. The header
declares `@zolana/test-kit` annex material rather than a primary review
iteration, and `sdk-libs/ts/test-kit/src/*` is the TypeScript counterpart of
`sdk-libs/program-test/src/*`. The TypeScript side of that decision is written
down; the Rust side is not, which is why `program-test` reads as an absence in
the same way `event` did.

Recommendation: extend the annex sentence to name `sdk-libs/program-test`
alongside `@zolana/test-kit`, so the pairing is explicit. No rows needed. If the
project later decides test-kit needs parity review, that is 11 more rows and the
denominator becomes 156.

## The `program-libs/event` question, resolved

The hypothesis in the brief was that the crate is out of scope because Photon
parses on-chain events and TypeScript consumes its JSON. That is right about
half the crate and wrong about the other half.

**Verified by reading, the event-emission layer is not ported.** `GeneralEvent`,
`Input`, `DepositWithdraw`, `EventKind`, `encode_event_instruction`,
`encode_event_instruction_with`, and `encode_event_payload` live in
`program-libs/event/src/lib.rs`. A search across all of `sdk-libs/ts` for
`GeneralEvent`, `EventKind`, `EMIT_EVENT`, `emitEvent`, and
`first_output_leaf_index` returns two files: `interface/src/index.ts`, where the
only hit is the `emitEvent: 14` entry in the `InstructionTag` table, and
`interface/test/interface.test.ts`, which asserts that tag value. No TypeScript
file borsh-decodes an event payload. `test-kit/src/events.ts` defines
`ParsedInstruction`, `InstructionGroup`, and `IndexedTransaction` as plain
shapes with no decoder, and `test-kit/src/indexer.ts` only stores and copies
them. The wallet reads parsed slots through `indexer-api`. So the hypothesis
holds for `lib.rs` and for the feature-gated `program_test.rs`.

**But four of the crate's six files are not about events at all, and all four
are already ported.** `program-libs/interface/src/lib.rs` opens with
`pub use zolana_event as event;`, and
`program-libs/interface/src/instruction/mod.rs` re-exports
`zolana_event::{tag, tag::InstructionTag}` and, through `instruction_data`,
`MessageData` and `OutputUtxo`. The event crate is part of the interface crate's
public API. Concretely:

- `tag.rs` defines every first-byte instruction tag. `interface/src/index.ts`
  mirrors the whole table as `InstructionTag`. The queue's own rows `I29` and
  `I37` point at that TypeScript file, so a reviewer walking them would meet the
  tags without ever being told where their definition lives.
- `output_data.rs` defines `MessageData` with a `FixIntLen<u16>` length prefix on
  `data`. TypeScript has `MessageData` in `interface/src/index.ts` and encodes it
  in `interface/src/codecs/index.ts`. Rust callers span
  `transaction/src/{wallet/authority,serialization/mod,instructions/transact/*}.rs`
  and `client/src/indexer.rs`.
- `output_utxo.rs` defines `OutputUtxo`, likewise mirrored in
  `interface/src/index.ts`.
- `proofless.rs` defines `ProoflessOutput`, `OutputDataEncoding`, and its three
  tag constants, plus `encode_output_data` and `encode_verifiably_encrypted`.
  TypeScript has `ProoflessOutput`, `OutputDataEncoding`,
  `encodeProofless`/`decodeProofless`, `encodeOutputData`/`decodeOutputData`, and
  `outputDataEncoding` in `transaction/src/serialization/codecs.ts`, all exported
  from `transaction/src/serialization/index.ts`. Rust callers include
  `wallet/src/wallet_sync.rs`, `transaction/src/serialization/proofless.rs`, and
  `client/src/prover/merge.rs`.

Recommendation: add four parity rows for `tag.rs`, `output_data.rs`,
`output_utxo.rs`, and `proofless.rs`, and two `NOT_APPLICABLE` rows for `lib.rs`
and `program_test.rs` recording that Photon owns event parsing and TypeScript
consumes parsed JSON. The four parity rows belong to the interface and
transaction packages by TypeScript owner, so they should sit with `I*` and `T*`
in the queue order rather than in a new block, or take an `E*` prefix if the
package-pair table is easier to keep honest that way.

### The three spec divergences now have an owner

The brief left three `docs/spec.md` divergences for whichever row owns the event
crate. Two of the three belong to `lib.rs`, which this audit recommends closing
as `NOT_APPLICABLE`, and one belongs to `proofless.rs`, which needs a parity
verdict:

- `tx_viewing_pk` and `salt` typed as `Option` in the spec against `[u8; 33]` and
  `[u8; 16]` zeroed arrays in `GeneralEvent`. Owner: the new `lib.rs` row. A
  `NOT_APPLICABLE` disposition does not excuse the divergence, so the row should
  carry it forward to the spec rather than absorb it.
- The output slot tag field named `owner` in the spec and `view_tag` in
  `output_utxo.rs` and `output_data.rs`. Owner: the new `output_utxo.rs` and
  `output_data.rs` rows. TypeScript uses `viewTag`, matching the code and not the
  spec, so this is a spec-side correction rather than a port defect.
- The `memo` field on `ProoflessOutput` that the spec does not list. Owner: the
  new `proofless.rs` row, and it is a live parity question because the
  TypeScript `ProoflessOutput` in `transaction/src/serialization/codecs.ts` has
  to agree with the Rust field order byte for byte.

Until those rows exist, the three divergences have no owner. They should not be
parked on `I29` or `I37` just because those rows happen to name
`interface/src/index.ts`.

## TypeScript files that no row covers

Run the other direction, over `sdk-libs/ts/*/src/**/*.ts`, excluding
`node_modules`, `dist`, and `.d.ts`. Eleven production TypeScript files are
named by no row.

| File | Assessment |
| --- | --- |
| `interface/src/external-data-hash.ts` | Ports `sdk-libs/transaction/src/instructions/transact/external_data.rs`, which is row `T21`. `T21` names `transaction/src/instructions/transact.ts`, and that file imports `externalDataHash` from `@zolana/interface`. The row points at the consumer, not the implementation. Stale path, see below. |
| `keypair/src/poseidon.ts` | Ports `program-libs/hasher/src/poseidon.rs`. Genuine hole. |
| `keypair/src/bytes.ts` | Fixed-width byte types and `bigIntToBytes`; part `hasher/src/bigint.rs`, part TypeScript-specific branding. Needs a row through the hasher block. |
| `merkle-tree/src/hashers.ts` | Ports `hasher/src/{poseidon,sha256,keccak}.rs`. Genuine hole. |
| `merkle-tree/src/bytes.ts` | Ports `hasher/src/bigint.rs` plus local validation. Needs a row through the hasher block. |
| `merkle-tree/src/errors.ts` | Ports `hasher/src/errors.rs` and `indexed-array/src/errors.rs`. Needs a row through those blocks. |
| `transaction/src/internal.ts` | A fourth Poseidon plus `hashChain`, from `hasher/src/{poseidon,hash_chain}.rs`. Genuine hole. |
| `wallet/src/internal.ts` | Base58 and byte helpers with no single Rust counterpart. Language-specific, defensible, but undocumented. |
| `wallet/src/error.ts` | `WalletError` and its codes. `sdk-libs/wallet` has no `error.rs`; the Rust crate returns errors inline. A legitimate language-specific addition that no row records. |
| `wallet/src/registry/index.ts`, `wallet/src/authority/index.ts`, `wallet/src/sync/index.ts` | Re-export barrels over `registry.ts`, `wallet-authority.ts`, and `sync.ts`, all of which do have rows. Covered in substance. |

Nine of the eleven trace back to the same four uncovered Rust crates. That is
the cross-check: the Rust-side gap and the TypeScript-side gap are the same gap
seen from two directions, which is the strongest available evidence that the
list above is the whole of it.

The `@zolana/test-kit` (18 files) and `e2e` (5 files) trees are excluded by the
recorded annex decision and are not counted as uncovered.

## Rows whose paths have gone stale

All 118 Rust paths resolve against the working tree, checked by script. All 118
TypeScript owners resolve too, once the comma-separated second entries are read
as package-relative (`hash/index.ts` for `keypair/src/hash/index.ts`, and so
on). No row points at a deleted file.

Five rows point at a file that exists but does not hold the behavior:

| Row | Rust source | Row says | Behavior actually lives in |
| --- | --- | --- | --- |
| `I02` | `interface/src/shape.rs` | `interface/src/internal.ts` | `interface/src/shape.ts` |
| `I03` | `interface/src/merge_utils.rs` | `interface/src/internal.ts` | `interface/src/merge-utils.ts` |
| `I30` | `interface/src/state/discriminator.rs` | `interface/src/internal.ts` | `interface/src/state.ts`, as `StateDiscriminator` |
| `I34` | `interface/src/state/tree.rs` | `interface/src/index.ts` | `interface/src/state.ts`, re-exported through `index.ts` |
| `T21` | `transaction/src/instructions/transact/external_data.rs` | `transaction/src/instructions/transact.ts` | `interface/src/external-data-hash.ts`, a different package |

`interface/src/internal.ts` was read in full. It holds `fail`, `copyBytes`, the
integer and address validators, base58, `findProgramAddress`, `sha256`, and the
`Writer`/`Reader` pair. It holds no shape logic, no Poseidon, and no state
discriminators. The three `I*` rows that name it are pointing at the wrong file
in the same way the wallet row named `actions.ts` for code in `submit.ts`.

`I34` is the mildest of the five: the constants are re-exported through
`index.ts`, so a reviewer following the row would find them. `T21` is the most
consequential, because it sends a reviewer to the wrong package entirely and
leaves `interface/src/external-data-hash.ts` looking like TypeScript with no
Rust counterpart when it has one.

## The honest denominator

**145 rows**, against the 118 the queue has. Twenty-seven missing, of which
eighteen need a parity verdict and nine need a recorded `NOT_APPLICABLE`.

| Package pair | Rows now | Rows needed |
| --- | ---: | ---: |
| `program-libs/interface` to `@zolana/interface` | 37 | 37 |
| `program-libs/event` to `@zolana/interface`, `@zolana/transaction` | 0 | 6 |
| `program-libs/hasher` to `@zolana/keypair`, `@zolana/merkle-tree`, `@zolana/transaction`, `@zolana/client` | 0 | 14 |
| `program-libs/indexed-array` to `@zolana/merkle-tree` | 0 | 4 |
| `program-libs/user-registry-interface` to `@zolana/wallet` | 0 | 3 |
| `sdk-libs/keypair` to `@zolana/keypair` | 14 | 14 |
| `sdk-libs/merkle-tree` to `@zolana/merkle-tree` | 2 | 2 |
| `sdk-libs/indexer-api` to `@zolana/indexer-api` | 1 | 1 |
| `sdk-libs/smart-account-client` to `@zolana/smart-account-client` | 1 | 1 |
| `sdk-libs/zolana-api` to `@zolana/api` | 1 | 1 |
| `sdk-libs/transaction` to `@zolana/transaction` | 31 | 31 |
| `sdk-libs/client` to `@zolana/client` | 22 | 22 |
| `sdk-libs/wallet` to `@zolana/wallet` | 9 | 9 |
| Total | 118 | 145 |

The numerator moves with it. The Mutable baseline reads `6 done / 118 total`.
Against a 145-row denominator the same six rows read `6 done / 145`, and the
parity-evidence audit's finding that only one of thirty-six `done` claims was
supported applies unchanged. Adding twenty-seven rows does not reopen any
existing verdict; it widens the surface those verdicts are measured against.

## What was verified by reading, and what was inferred

Verified by reading the files:

- The 118 row identifiers and their Rust and TypeScript paths, extracted from
  the checklist tables and each path tested for existence by script.
- Every `.rs` file under `sdk-libs/` (excluding `ts/`) and `program-libs/`,
  enumerated and counted per crate.
- Every `.ts` file under `sdk-libs/ts/` excluding `node_modules`, `dist`, and
  `.d.ts`, enumerated and matched against the row TypeScript owners.
- Each SDK crate's `Cargo.toml` dependency block, and the `use zolana_event`,
  `use zolana_hasher`, `use zolana_indexed_array`, and
  `use zolana_user_registry_interface` sites in `sdk-libs/*/src`.
- `program-libs/event/src/{lib,proofless,output_data,output_utxo,tag}.rs` in
  full, and `program-libs/user-registry-interface/src/{lib,state}.rs`.
- `program-libs/interface/src/lib.rs` line 2 and
  `program-libs/interface/src/instruction/mod.rs`, which are where the event
  re-export lives.
- `sdk-libs/ts/interface/src/{internal,index,shape,state,external-data-hash}.ts`
  and the head of `merge-utils.ts`.
- `sdk-libs/ts/transaction/src/serialization/index.ts` and the symbol list in
  `codecs.ts`.
- `sdk-libs/ts/test-kit/src/{events,indexer}.ts`, to establish that no
  TypeScript decodes event bytes.
- The four TypeScript Poseidon parameter tables, and the zero-column
  construction in `merkle-tree/src/merkle-tree.ts`.

Inferred, and worth a second pair of eyes:

- The per-file row counts for the four uncovered crates assume the queue keeps
  its one-row-per-file unit. A reviewer who prefers one row per crate would
  reach a different denominator for the same gap.
- The `NOT_APPLICABLE` verdicts for `hasher/src/zero_bytes/*` and
  `hash_to_field_size.rs` rest on absence of a TypeScript caller and a runtime
  zero-column construction. Absence of a caller is weaker evidence than presence
  of one, and the owning row should confirm it.
- The claim that the five remaining `program-libs` crates are program-only rests
  on grepping SDK `Cargo.toml` files and source, not on a `cargo tree` run. A
  transitive dependency through `interface` would not show up that way, though
  it would not create a TypeScript porting obligation either.
- Whether `wallet/src/error.ts` and `wallet/src/internal.ts` should carry rows is
  a judgment about how the queue wants to treat language-specific additions, not
  a fact about the tree.

## Recommended actions, for the checklist owner

1. Add 27 rows: 6 for `program-libs/event`, 14 for `program-libs/hasher`, 4 for
   `program-libs/indexed-array`, 3 for `program-libs/user-registry-interface`.
2. Fix the five stale TypeScript owners on `I02`, `I03`, `I30`, `I34`, and `T21`.
3. Write the `program-libs` scope rule into the Scope reconciliation section:
   a `program-libs` crate is in scope when an SDK crate depends on it.
4. Name `sdk-libs/program-test` beside `@zolana/test-kit` in the annex sentence,
   so its absence reads as a decision.
5. Route the three spec divergences to the new `event` rows rather than leaving
   them unowned.
6. Update the Mutable baseline denominator from 118 to 145 once the rows land.
