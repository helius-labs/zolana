# The two unowned serialization rows, `port/serialization`

T06 (`serialization/anonymous.rs` -> `serialization/codecs.ts`) and T10
(`serialization/mod.rs` -> `serialization/index.ts`), neither of which had an
owner. Both close.

| Commit | What it closed |
| --- | --- |
| `c750b5ef` | T06: four inputs the two languages sorted into different refusal categories |
| `ee6f89db` | T10: the built runtime and declaration surfaces of all five entry points |
| `4c4d509c` | T06: cipher failures escaping as `KeypairError` rather than `TransactionError` |

## Verdicts

| Row | Verdict | Basis |
| --- | --- | --- |
| T06 | `PARITY` | Every residual the row named is either closed here or was closed in the tree before this branch, and the three divergences this pass found are each pinned by a test observed to fail against the previous code. One API-shape widening remains, recorded below; it changes no behaviour on an input Rust can express. |
| T10 | `PARITY` | Four of the five residuals were stale at HEAD and are now pinned so they cannot silently return. The fifth, the declaration and runtime allowlists, was real and is closed with three control edits against the built artifact. |

## T06

### Divergences found and fixed

Each was confirmed by running the Rust rail, not by reading it. The order
question was settled with a throwaway crate against the workspace `Cargo.lock`,
because the workspace pins `wincode = "0.5"` while `solana-address` pulls
`0.6`, and a probe without the lockfile does not compile.

1. **The asset and the zone refusal were reported in the wrong order.** A
   payload can fail the asset lookup and the zone resolution at once. Rust
   builds a struct literal whose fields evaluate in written order, `asset`
   before `zone_program_id` (`anonymous.rs:47,50` for the recipient and
   `:99,102` for the sender's SPL leg), so both report `UnknownAsset`.
   TypeScript spread the zone into the object literal first and reported
   `MissingZoneProgramId`. Reordered at `codecs.ts:456-471` and `:522-565`.
   Note the split rail genuinely resolves the zone first (`split.rs:61-62`) and
   the test pins that difference in the same place, so the fix cannot be
   "resolve the asset first everywhere".

2. **An unrecognised data record tag reported the wrong family.** Rust reads
   the record enum through wincode, which refuses an unknown tag as a read
   failure and lands on `TransactionError::Deserialize`. TypeScript raised
   `TRANSACTION_BAD_DISCRIMINATOR`, a code the oracle's category map does not
   widen. Changed at `codecs.ts:331-346`.

3. **A 256-entry recipient viewing key list reported the output-count
   refusal.** The list is not outputs; Rust lets the
   `containers::Vec<_, FixIntLen<u8>>` prefix refuse it as a write failure
   (`anonymous.rs:64-65`, `:71-75`), which is `TransactionError::Serialize`.
   TypeScript raised `TRANSACTION_TOO_MANY_OUTPUTS`. Changed at
   `codecs.ts:473-482`.

4. **A cipher failure escaped the transaction error type entirely.** Rust
   reaches the cipher through `?` on both anonymous rails
   (`anonymous.rs:135-143`, `:175-179`, `:198-206`, `:268-272`), so a caller
   sees `TransactionError::Keypair`. `encryptAnonymous` and `decryptAnonymous`
   called straight through, so a `KeypairError` reached a caller that catches
   `TransactionError`. Both now go through the `inTransactionCategory` helper
   the confidential and merge rails already used (`codecs.ts:970-993`). This
   also covers `encryptSplit` and `decryptSplit`, which are the same two
   functions under their split names.

   The same defect was present one function away in `encryptConfidential`,
   whose Rust counterpart also uses `?` (`confidential.rs:139-147`). It is
   fixed in the same commit; that half belongs to T05, which is already
   `PARITY`, so the reconciler may want to note it there rather than under T06.

### Control edits

| Fix | Reverted | Test that went red |
| --- | --- | --- |
| Asset before zone, both rails | the two reorderings in `codecs.ts` | `reports the asset refusal before the zone refusal on the anonymous rails` |
| Record tag category | `TRANSACTION_DESERIALIZE` back to `TRANSACTION_BAD_DISCRIMINATOR` | `sorts a malformed anonymous body into the category Rust does` |
| Viewing key overflow category | `TRANSACTION_SERIALIZE` back to `TRANSACTION_TOO_MANY_OUTPUTS` | same test |
| Cipher failure category | the `inTransactionCategory` wrap on `decryptAnonymous` | `reports a cipher failure in Rust's category on every rail`, which reported the raw `KeypairError` |

### The residuals the row carried, checked rather than assumed

- **No TypeScript counterpart for either `from_utxos`.** Stale.
  `anonymousRecipientFromUtxos` (`codecs.ts:1305-1321`) and
  `anonymousSenderFromUtxos` (`:1323-1370`) exist, are exported from
  `./serialization` and the root, and the oracle replays eleven cases through
  them (`fromUtxos.anonymousRecipient`: `single`, `withMemo`, `zoneBound`,
  `empty`, `twoUtxos`, `foreignOwner`; `fromUtxos.anonymousSender`:
  `splAndSol`, `solOnly`, `empty`, `solAtTheSplPosition`, `twoSplLegs`).

- **No shared-tag state progression.** Closed in the tree, not by this branch.
  `23781efc` added `oracle.anonymousProgression`, replayed at
  `rust-oracle.test.ts:1607-1640`: four transfers whose shared view tag is
  derived independently by both sides at each index, compared against the
  Rust-recorded tag, with the body that tag addresses decrypted and decoded at
  the same step, plus an assertion that no two steps share a tag.

- **`serialization-v1` predates the Rust data change.** True, and still true:
  the fixture contains no zone record at all. It is a coverage gap rather than
  a wrong expectation, the suite is green against it, and the Rust oracle
  regenerated from current Rust covers both halves of the change (the
  `zoneBound` case binds a zone program id and carries a `zoneData` record).
  Regenerating it needs `xtask/`, which is another worker's scope. Same
  disposition the T02, T04 and T05 updates already took.

### Left open on T06: the `solMint` parameter

`anonymousSenderUtxos` takes `solMint: Address` as a required third parameter
(`codecs.ts:525`) where Rust uses the `SOL_MINT` constant
(`anonymous.rs:109`). `plaintextTransferUtxos` has the same shape
(`codecs.ts:645`). Both let a caller mint the SOL leg against a foreign mint,
which Rust cannot express. It is not a behavioural divergence under the
standard, since for the only value Rust can supply the two agree, and
`codecs.ts` already imports `SOL_MINT` at line 21 so the parameter buys
nothing.

Removing it means editing the two call sites at `wallet/sync.ts:624` and
`:683`, which belongs to the worker holding T16. Handoff below.

## T10

### The residuals, one by one

- **`DecodeCx` and `OwnerCx` have no TypeScript adaptation and no root
  export.** Stale. They ship as `DecodeContext` (`codecs.ts:1149`) and
  `OwnerContext` (`:1190`), are exported from `./serialization`
  (`serialization/index.ts:53,56`) and from the root (`index.ts:104,106`), and
  the rename pair is recorded in `module-surface.test.ts:40-41` so the oracle
  check resolves the Rust name onto the shipped one.

- **`UtxoSerialization` has no adaptation.** Deliberate, and the brief's
  warning applies: the name is dispositioned as not carried with a written
  reason (`module-surface.test.ts:72-73` and `:84-85`), and adding it turns the
  surface test red. What replaces it is stronger than an export would be. The
  `UtxoSerialization capability contract` suite (`:402-439`) reads the Rust
  trait's implementor list and operation list out of the oracle and requires a
  named shipped function for every operation of every implementor: seven
  schemes times six direct operations, with the two plaintext rails' identity
  `encrypt` and `decrypt` allowed to be blank only because they are listed in
  `IDENTITY_CRYPTO`, and the three trait defaults listed as compositions. The
  assertion inverts for anything recorded absent, so an absence stays declared
  only while it is true.

- **`SplitBundlePlaintext` names two different types.** Stale. There is one
  declaration, `codecs.ts:110`; `wallet/authority.ts:27` re-exports it and the
  root reaches it through `wallet/index.ts`. The
  `one declaration per exported name` suite (`module-surface.test.ts:514-535`)
  fails if a second module ever declares it again.

- **Declaration, runtime, tarball, browser and consumer allowlists are
  absent.** Three of the five were already gates rather than gaps.
  `config/pack-check.mjs` packs each production package, refuses anything
  outside `dist/` and `package.json`, requires every target in the exports map
  to be in the tarball, installs the tarballs into a scratch consumer and
  imports all five `@zolana/transaction` entry points under Node 20 and 22 as
  both ESM and CommonJS, typechecks the same specifiers through `.mts` and
  `.cts`, and bundles the graph under the `browser` condition with a `node:`
  import and Node-global scan. `config/workspace-check.mjs:21-37` pins the
  exports map itself to the entry point list in `config/packages.mjs:40-41`.
  The declaration and runtime halves were the real gap: nothing compared what
  the build hands a consumer against what the source barrel promises.

### What was added for the two real halves

`module-surface.test.ts` gained a `built entry-point surface` suite that reads
the build rather than the sources. Per entry point it dynamically imports the
built package through its published specifier and requires the runtime export
set to equal exactly the value names its barrel declares, and it reads
`dist/es/<stem>.d.ts` and requires the shipped declarations to name exactly the
barrel's names with the same value-or-type kind. A third case walks all five
namespaces and fails if two entry points publish one name bound to different
values, which is the runtime half of the `SplitBundlePlaintext` defect: two
barrels may share a name only by re-exporting the module that declares it.

The name-and-kind reader is now one function, `declaredExports`, which the
Rust-oracle checks above also use; they were carrying a near-duplicate that
discarded the kind.

### Control edits

Each was made against the build, not the source, which is what proves the tests
read the artifact. `npm run build` restored the tree afterwards.

| Edit to `dist/es/` | Test that went red |
| --- | --- |
| dropped `decodeData` from `serialization/index.d.ts` | `./serialization ships declarations for exactly its barrel's names` |
| dropped `decodeData` from `serialization/index.js` | `./serialization exports exactly its barrel's value names at run time` |
| re-declared `outputDataEncoding` in `index.js` instead of re-exporting it | `binds a name two entry points share to one value` |

## Handoffs

- **T16 owner, `wallet/sync.ts`.** Dropping the `solMint` parameter from
  `anonymousSenderUtxos` and `plaintextTransferUtxos` needs the two call sites
  at `sync.ts:624` and `:683` to lose their third argument in the same commit.
  Both already pass `SOL_MINT`, so the change is mechanical and behaviour-free;
  it removes a public API a Rust caller has no equivalent for.

- **`xtask/` owner.** `sdk-libs/ts/fixtures/transaction/serialization-v1.json`
  predates the zone and program-data change to the anonymous recipient rail and
  contains no zone record. Regenerating it would give the fixture suite the
  coverage the oracle currently carries alone.

## Found and not recorded anywhere

- **`readOutputData` is exported from `codecs.ts` but not from any barrel.**
  Deliberate as far as its own comment goes, and it is used by `wallet/sync.ts`
  as the lenient dispatch reader, but the surface tests only see barrels, so
  nothing would notice if it were promoted or dropped. Worth a line in whatever
  row owns the package-internal surface.

- **The confidential encrypt half of divergence 4 is a T05 finding.** T05 is
  recorded `PARITY` on the strength of a decrypt-side sweep;
  `encryptConfidential` had the same unwrapped call and no case reached it.

- **`decrypt_transactions` remains recorded as a plain rename.** Already
  written up in `transaction-independent-read.md`, and repeated here only
  because the coordinator flagged it as touching T10's surface claims: it does
  not. `RENAMES` is shared across all five aggregates, but
  `decrypt_transactions` is published by `src/lib.rs` and `src/wallet/mod.rs`,
  not by `src/serialization/mod.rs`, so the concealment sits on the root and
  wallet aggregate rows rather than on T10.

## Verification

From `sdk-libs/ts`, after `npm run build`: `test:unit` 2020 passed, 1 skipped;
`test:vectors` all five projects green; `lint`, `lint:packages`, `typecheck`
and `format:check` clean. The oracle was not regenerated: nothing this pass
changed a value Rust records, only the TypeScript-side category of four
refusals, and the oracle's category map already covers the comparison.
