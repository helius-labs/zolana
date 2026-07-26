# 2026-07-26 10:12 UTC | the `@zolana/transaction` adverse cluster, re-verified at HEAD | T12-T31, S01

- Baseline: work committed through HEAD `cd9f5715` on `port/tx-close`
- Worker: transaction cluster worker
- Scope: `sdk-libs/ts/` and `planning/` only. `wallet/sync.ts` and
  `serialization/codecs.ts` belong to another worker and were read, not edited
- Evidence: [row-updates/transaction-cluster.md](../row-updates/transaction-cluster.md),
  with the Rust source and its TypeScript mirror cited per row
- Gates: `npm run build`, `npm run test:unit` (2014 passing, 1 skipped),
  `npm run lint`, `npm run typecheck`, all green. The committed Rust oracle is
  unchanged and every comparison against it passes, so no regeneration was
  warranted

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
- Verdict: `T21` reaches PARITY at the SDK layer, one layering note open
- Verdict: `T17` stays PARTIAL
- Verdict: `T26` stays PARTIAL
- Verdict: `T30` stays PARTIAL
- Verdict: `S01` stays DIVERGENT

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

## Correcting `T21` in this entry's own first draft

This entry first recorded `T21` as owed by Rust on both halves. That was wrong
and is corrected in the row-update file. The Rust guard has landed in
`external_data.rs:159-184`, TypeScript matches it at the same layer in
`transact.ts:252-280`, and the boundary vector the row asked for exists in the
oracle and is replayed, accepted at `0xffff` and refused at `0x10000` for both
the output and the message count.

What was actually missing was one layer down, and is closed here: a caller
reaching `@zolana/interface`'s `externalDataHash` directly bypasses the SDK
guard, and nothing failed if that function were "simplified" back to the Rust
`program-libs/interface` cast, which would put a hash over a truncated preimage
back into TypeScript with every suite still green. The four prefixes are now
pinned there. The note left open is which error taxonomy that layer should use;
both layers refuse the same inputs, so no input distinguishes them.

## S01 stays DIVERGENT

Verified independently by two workers reaching the same verdict. Valid inputs
agree byte for byte, with the PDAs, the create instructions, and the execute
fixture pinned against Rust. The row stays adverse because TypeScript refuses
inputs Rust accepts: the 1232-byte limits, the create signer and threshold rules,
and an inner instruction at `0x10000` bytes that Rust truncates through an
`as u16` cast.

Not closable from `sdk-libs/ts/` in a direction worth taking. Deleting the
guards would accept oversized payloads and silently truncate, the trade the
`T21` ruling rejected; the alternative is fallible Rust builders with stable
codes, which is out of scope. The row needs an owner ruling of the same kind
`T21` got. Three of its recorded claims are stale and named in the row-update
file.
