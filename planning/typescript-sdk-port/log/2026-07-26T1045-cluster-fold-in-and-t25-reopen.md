# 2026-07-26 10:45 UTC | reconciler pass six: three clusters folded, three claims refused, T25 reopened | queue-wide

- Baseline: HEAD `08393b33`, the `ts-sdk-port` tip, checked out as `port/reconcile5`
- Worker: reconciler, sole writer of `review-checklist.md`
- Scope: `planning/` only. No source file was read-only-verified and then edited; nothing under `sdk-libs/`, `programs/`, `program-libs/`, `prover/`, `services/` or `xtask/` was touched
- Folded: [row-updates/rereview-cluster.md](../row-updates/rereview-cluster.md),
  [row-updates/client-cluster.md](../row-updates/client-cluster.md),
  [row-updates/transaction-cluster.md](../row-updates/transaction-cluster.md), and the two
  outstanding from earlier, [row-updates/c03-rpc-surface.md](../row-updates/c03-rpc-surface.md)
  and [row-updates/transaction-independent-read.md](../row-updates/transaction-independent-read.md).
  The reconciliation debt [README.md](../README.md) records is now clear
- Gates: `npm run fixtures:check` re-executed in this worktree, `verified 58 fixtures and 182 inventory rows`, exit 0, which is `I37`'s last residue. `node sdk-libs/ts/config/review-checklist-check.mjs` and `node sdk-libs/ts/config/pkp-entry-gate.mjs` both run clean after this entry landed

- Verdict: `K11`, `K12`, `K13`, `K14` reach PARITY
- Verdict: `W04` reaches PARITY
- Verdict: `I37` reaches PARITY
- Verdict: `X01` reaches PARITY
- Verdict: `C03` reaches PARITY
- Verdict: `C05` reaches PARITY
- Verdict: `C18` reaches PARITY
- Verdict: `T12`, `T13`, `T28`, `T29`, `T31` reach PARITY
- Verdict: `T14` stays PARITY, already closed at `569544e0` and re-confirmed here
- Verdict: `T16` stays DIVERGENT
- Verdict: `T23` stays DIVERGENT
- Verdict: `T25` reopens to DIVERGENT
- Verdict: `C04` stays PARTIAL
- Verdict: `C06` becomes DIVERGENT
- Verdict: `C21` becomes DIVERGENT
- Verdict: `T17`, `T26`, `T30` improve to PARTIAL
- Verdict: `T21` stays PARTIAL

Counted from the tables with `awk` over the Status and Verdict columns rather
than adjusted from the previous figure: **122 `done`/`PARITY`, 13 adverse**, 7
`done`/`NOT_APPLICABLE` and 3 `needs_re_review`/`NOT_APPLICABLE`, summing to 145.
The adverse denominator falls from 27 to 13.

Sixteen rows were claimed to close and fifteen did. Every claim credited was
re-derived at this HEAD with a file and a line; none was credited to the report
that made it. Two of them turned on a single factual question that could not be
answered inside this repository's `sdk-libs`, and both were checked where the
answer actually lives.

## The three refusals

**`T16`.** The transaction cluster reports PARITY on atomicity. Atomicity is
genuinely pinned and that half is accepted. It is not what the row is about. The
row is about UTXO ordering, and the owner ruled on it *after* the report was
written, so the report answers a question nobody had asked yet. The ruling: check
how Light Protocol handles it, and failing that match Rust's sorted parallel
ordering, since that is the one ordering Rust actually specifies; and no oracle
may pin an order Rust leaves undefined.

Checked, in that order. Rust's serial path collects `known_senders.keys()` with
no sort (`sdk-libs/transaction/src/wallet/sync.rs:868`, and `known_recipients`
identically at `:893`) over a `HashMap` (`:383`), while the parallel path sorts by
key bytes before probing (`parallel.rs:242-243`, `:268-269`). TypeScript matches
neither: `CounterpartyCounters.advance` walks Map discovery order
(`ts/transaction/src/wallet/sync.ts:226-232`). Light Protocol does not address it,
which is the substantive finding rather than a formality: `js/stateless.js/src/`
contains no viewing-key scanning and no decryption at all, so Light has no
counterparty walk to order. Its sorts are account selection by lamports, amount
or leaf index, a different problem. The fallback therefore applies and the row
stays open with the fix named: sort by key bytes in `advance`.

The no-pinning clause is already satisfied and the row records that it must stay
so. The Rust-fixture assertions compare counts and balances, not order
(`wallet-sync.test.ts:313`, `:372`, `:454`); the one order-sensitive assertion at
`:329` compares the two TypeScript paths against each other.

**`T23`.** The owner ruled, again after the reports, that TypeScript must match
Rust exactly here, including deleting checks Rust does not have and reshaping both
`publicAmounts()` and `inputUtxoHashes()`. One clause of four is done. The worker
did `publicAmounts()`, which now returns three `Bytes32` and raises Rust's two
error codes (`transact.ts:527-534`, `:550`, `:555`). Not done: `inputUtxoHashes()`
still returns `readonly Bytes32[]` (`transact.ts:560-562`) where Rust returns
`Vec<InputUtxoContext>` (`spp_proof_inputs.rs:162-178`), with the contexts split
into a separate `inputContexts()`; the `check_canonical_dummy()` sweep Rust runs
over every input at `spp_proof_inputs.rs:163-165` has no counterpart; and two
checks Rust does not have survive, the constructor's `this.checkShape()` at
`transact.ts:520` against a Rust `new` that validates nothing
(`spp_proof_inputs.rs:91-104`), and `TRANSACTION_SIGNATURE_OWNER_MISMATCH` at
`transact.ts:601` where Rust's `sign_p256` checks the keypair's curve instead
(`:106-116`).

**`C04`.** The report verified the decoder field by field, correctly, and then
offered the reconciler both answers. Scored end to end, and the reasoning is on the
row. The ruled precision-loss refusal is unreachable through the shipped stack:
`quoteUnsafeIntegers` rewrites unsafe integer literals into quoted strings before
`JSON.parse` (`api/src/index.ts:358`, defined `:373`), so on the five unbounded
fields a value the ruling says to refuse arrives as one the decoder accepts. The
report measured it through `ZolanaIndexer`, which is C04's own surface. Nothing is
truncated, so this is a wrong error path rather than data loss, but recording
`PARITY` for a row whose ruled refusal cannot fire is the failure
[run-authorizations.md](../run-authorizations.md#a-suite-you-cannot-certify-honestly)
names. `A01` is the dependency.

## T25 reopened

The rereview worker found this while working `W04` and it holds. Rust's
`ConfidentialTransfer::new` validates nothing
(`sdk-libs/transaction/src/instructions/transact/transfer.rs:89-98`); TypeScript's
constructor refuses three inputs at `ts/transaction/src/instructions/transact.ts:661-673`,
namely an empty input list (`:662`), a dummy input (`:665`), and an input owned by
anyone but the transfer owner (`:671`). Rust reaches `NoInputs` only later, from
`first_nullifier` in `prepare` (`spp_proof_inputs.rs:59-64`), and has no
counterpart for the other two.

One thing the report understated, and it makes the row worse rather than better.
The empty-input case is not an early refusal arriving at the same error. Rust's
own test builds `ConfidentialTransfer::new(owner, Vec::new(), Address::default())`
at `transfer.rs:597` and asserts `withdraw` returns `WithdrawalAssetMismatch` at
`:602`. The identical sequence in TypeScript never reaches `withdraw`. The two
languages name different errors for one input.

## What the two out-of-repository checks changed

**`X01` is not a three-way disagreement, and this is the correction that matters
most in this pass**, because it changes what the owner is being asked for. The row
was held open as specification against Rust against Photon, which needs an owner to
arbitrate between two implementations. Photon is not a second implementation. It
defines none of these schemas and imports them:
`services/photon/src/api/method/rings/get_nullifier_queue_elements.rs:8-11` takes
the request and response types from `zolana_indexer_api` and the handler returns
the crate's own response at `:62`; `rings/common.rs:15-18` takes six more the same
way; `rings/get_encrypted_utxos_by_tags.rs:15,63` imports and constructs the
crate's `EncryptedUtxoMatch`; and `services/photon/Cargo.toml:86` takes the
workspace crate. So Photon's wire format is the Rust crate's by construction, the
agreement is two-way with the port, and the owner's standing X01 ruling decides the
row with no further input. The residue is documentation, and it is a drafting task
now rather than a decision. One genuine decision remains and points the other way:
the specification permits a decimal string on seven fields that Rust declares as
plain `i64`/`u64` with default serde, so Rust refuses a body the specification
permits. The port never writes one, so the row does not turn on it.

**Light Protocol has no precedent for `T16`**, recorded above.

## Source fixes named, none made

Per the brief, only `planning/` was changed. Five source changes are owed and each
is named on its row: give Rust's `be` a checked sibling for the merke witness
values (`C06`); return `ClientError::MissingOutput` and add a confirmation-timeout
variant (`C21`); the `sdk-libs/transaction` half of the `ExternalDataHash` guard
(`T21`); sort counterparties by key bytes in `CounterpartyCounters.advance`
(`T16`); and delete the three constructor refusals in `ConfidentialTransfer`
(`T25`). Three further `T23` clauses are named on that row.

## Owed to other document owners

- The `T23` ruling that arrived with this task is not written into
  [authority-rulings.md](../authority-rulings.md), whose `T23` section covers the
  confidential owner tag only.
- `A01` is `done` / `PARITY` and this pass did not move it, because its own scope
  was not re-reviewed here. Flagged for whoever takes it next: its quoting is what
  makes the `C04` ruling unreachable.
- `G8-1` in [production-readiness-issues.md](../production-readiness-issues.md) and
  the `fixtures:check` line in
  [testing-and-conformance.md](../testing-and-conformance.md) both still describe a
  failure that no longer occurs.
- `public-exports.md` declares neither `prepareZoneAuthority` nor `VIEW_TAG_LEN`,
  both of which the transaction root exports, and nothing in `sdk-libs/ts/config`
  reads the manifest, so it cannot fail.
