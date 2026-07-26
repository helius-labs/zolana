# 2026-07-26 10:12 UTC | the `@zolana/transaction` adverse cluster, re-verified at HEAD | T12-T31, S01

- Baseline: work committed through HEAD `cd9f5715` on `port/tx-close`
- Worker: transaction cluster worker
- Scope: `sdk-libs/ts/` and `planning/` only. `wallet/sync.ts` and
  `serialization/codecs.ts` belong to another worker and were read, not edited
- Evidence: [row-updates/transaction-cluster.md](../row-updates/transaction-cluster.md),
  with the Rust source and its TypeScript mirror cited per row
- Gates: `npm run build`, `npm run test:unit` (2007 passing, 1 skipped),
  `npm run lint`, `npm run typecheck`, all green at `cd9f5715`. The committed
  Rust oracle is unchanged and every comparison against it passes, so no
  regeneration was warranted

Each verdict below was re-derived at this HEAD rather than credited to a
previous report. Several recorded residuals described a tree state that had
already moved; those are called stale in the row-update file rather than
repeated.

- Verdict: `T12` reaches PARITY
- Verdict: `T13` reaches PARITY
- Verdict: `T14` reaches PARITY
- Verdict: `T16` reaches PARITY
- Verdict: `T23` reaches PARITY
- Verdict: `T28` reaches PARITY
- Verdict: `T29` reaches PARITY
- Verdict: `T31` reaches PARITY
- Verdict: `T17` stays PARTIAL
- Verdict: `T26` stays PARTIAL
- Verdict: `T30` stays PARTIAL
- Verdict: `T21` stays PARTIAL

## What closed on code rather than on verification

Four rows needed a change. `T28` was one clause from parity: the refusal of an
out-of-field zone data hash existed but reported `TRANSACTION_KEYPAIR`, where
Rust reports `Poseidon` for the commitment path alone. `T23` moved the public
leg into `SppProofInputs.publicAmounts()`, which now returns the three field
elements Rust returns and enforces the SPL asset rule that had been living in
`@zolana/client`. `T29` follows from it: `prepareZoneAuthority` takes the
external data Rust takes and derives the shape and amounts instead of accepting
a caller-supplied pair it never checked. `T31` had a second constant
duplication, `VIEW_TAG_LEN` redeclared at the root where Rust re-exports it.

`T12` and `T16` closed on narrowing and on a test rather than on behaviour:
`AssetRegistry` lost two members Rust has no counterpart for, and the atomicity
of a failed sync is now pinned, having been true in both languages and asserted
in neither.

## Why three rows stay PARTIAL on one clause each

`T17`, `T26`, and `T30` each list Rust names their aggregate omits, and every
listed name is exported at this HEAD, guarded going forward by the
`module-surface.test.ts` oracle comparison. What remains in all three is the
packaging allowlist clause, which is a `sdk-libs/ts/config` question about the
published tarball rather than a barrel-versus-Rust question. It is the same work
in three places and a reconciler may want it as its own row.

`T21` is owed by `sdk-libs/transaction` and `program-libs/interface` under the
`2026-07-26` ruling. TypeScript already carries the guard the ruling wants;
removing it to close the row from this side would restore the quiet truncation
the ruling exists to end.

## S01

Not recorded here. It was verified by a subagent against
`sdk-libs/smart-account-client/src/lib.rs` and its TypeScript counterpart, and
whoever folds that result in owns the row.
