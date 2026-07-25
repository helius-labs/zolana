# Row updates: C01, C02, C22

Independent re-review of `68631870` against Rust at HEAD (`c6587b20`). Read-only:
no production code, test, or fixture was changed. A later pass reconciles these
verdicts into `review-checklist.md`.

Reviewer note: the fixer's account of its own work was not used as evidence. Each
claim below was re-derived from the Rust source and from the TypeScript at HEAD.

## C01 `sdk-libs/client/src/retry.rs` -> `client/src/retry.ts`, `retry/index.ts`

**Verdict: DIVERGENT.** One reachable difference remains, and it is the failure
mode rule 6 of the review protocol names: TypeScript is stricter than Rust.

### What the fix closed, with positive evidence

The three-cause union is exactly Rust's. `error.rs:8-12` declares
`RetryErrorCause { Rpc, Indexer, IndexerTimeout }`; `error.ts:335` declares
`Readonly<{ category: "rpc" | "indexer" | "indexerTimeout" }>` and nothing else.
`CLIENT_POLL_TIMED_OUT.lastCause` validates against it through the new
`retryCause` field kind (`error.ts:458`, `error.ts:644`), so the
`{category:"external"}` and `{category:"client"}` values the previous reviewer
found can no longer be stored in a field whose Rust counterpart is
`Option<RetryErrorCause>`.

Each canonical code maps to the cause Rust maps it to. `error.rs:228-235` gives
`Rpc(_) -> Rpc`, `Indexer { retryable: true } -> Indexer`,
`IndexerTimeout -> IndexerTimeout`, everything else `None`. `retry.ts:139-159`
gives `CLIENT_RPC -> rpc`, `CLIENT_INDEXER` gated on `details.retryable ->
indexer`, `CLIENT_INDEXER_TIMEOUT -> indexerTimeout`, `default -> undefined`.
The `default` arm covers `CLIENT_INDEXER_NOT_CAUGHT_UP`,
`CLIENT_UNSUPPORTED_RPC_METHOD`, and `CLIENT_POLL_TIMED_OUT`, which Rust also
classifies as `None`.

Collapsing `isRetryable` into `retryCause` did not make anything silently
non-retryable. The old classifier accepted `CLIENT_RPC`,
`CLIENT_INDEXER_TIMEOUT`, and `CLIENT_INDEXER`, `CLIENT_TIMEOUT`,
`CLIENT_REQUEST` when `details.retryable === true`. The new one accepts all five
under the same conditions and adds `CLIENT_RPC_HTTP`, `CLIENT_RPC_JSON`, and
`CLIENT_RPC_ENVELOPE`. The new set is a strict superset of the old, so the
margins moved in the widening direction only.

The `transportCause` split at `retry.ts:178-182` is sound rather than arbitrary.
`SolanaRpc` raises `CLIENT_TIMEOUT` and `CLIENT_REQUEST` through
`internal.ts:327-338`, which attaches no cause, so those classify as `rpc`, and
Rust's Solana adapter reports the same failures as `ClientError::Rpc`
(`solana_rpc.rs:404`, `solana_rpc.rs:436`). `ZolanaIndexer` raises them through
`indexer.ts:380-391`, which attaches an `@zolana/api` cause whose code starts
with `API_`, so those classify as `indexer`, and Rust folds the same failures
into `ClientError::Indexer` at `indexer.rs:477-487`. The status predicate agrees
on both sides: `indexer.rs:489-491` and `api/src/client.ts:511` both retry
408, 425, 429, and every status at or above 500.

`attempts` is exact at the boundary. `retry.ts:87-89` returns `numRetries + 1`,
and `validatePollConfig` caps `numRetries` at `0xffff_ffff`, so the maximum is
4294967296, a safe integer, matching `retry.rs:40-42` and its
`attempt_count_is_exact_at_the_u32_boundary` test.

### The "already closed by `455cb1b9`" claim holds at HEAD

Verified against the file rather than the commit message. `pollIndexer` reports
`CLIENT_INDEXER_NOT_CAUGHT_UP` only when a `latest` was observed and every
attempt responded: `indexer.ts:364` rethrows when `latest === undefined ||
responses !== attempts`, and `responses` increments only inside the `accept`
callback at `indexer.ts:355`. That is `Lag::resolve` at `indexer.rs:72-84`, whose
guard is `(Err(_), Some(latest)) if self.responses == self.attempts`. Bare
`CLIENT_INDEXER` is genuinely conditional on `details.retryable`
(`retry.ts:151-152`), against `ClientError::Indexer { retryable }` at
`error.rs:231`. `indexer.ts` carries no change in `68631870`, as claimed.

`indexer.ts:365` adds a guard Rust does not have, requiring the caught error to
be `CLIENT_POLL_TIMED_OUT`. It is unreachable rather than divergent: the schedule
runs exactly `attempts` iterations and `accept` runs only on success, so
`responses === attempts` implies no attempt failed, which implies the only
error the loop can raise is `CLIENT_POLL_TIMED_OUT` with no `lastCause`. Rust
reaches the same state by the same argument.

### The residual divergence

A malformed indexer field is retryable in Rust and fatal in TypeScript, inside
the polled closure.

Rust converts response fields inside the closure it hands to `wait_for_indexer`
(`indexer.rs:192-216`; the `convert_encrypted_utxo_match` call at
`indexer.rs:211` is inside the `||` block that starts at `indexer.rs:195`). A
wrong-length field there fails through `fixed_bytes` at `indexer.rs:628-639` or
`decode_error` at `indexer.rs:641-643`, both of which produce
`ClientError::Rpc`. `retry_cause` classifies that as `Some(Rpc)`, so the poll
continues, consumes the whole backoff, and ends at
`PollTimedOut { attempts, last_cause: Some(Rpc) }`.

TypeScript converts in the same position (`indexer.ts:64`, inside the
`pollIndexer` closure that starts at `indexer.ts:53`) and raises
`CLIENT_INVALID_RPC_RESPONSE`, either directly from `invalidResponse` or through
`wrapIndexer` at `indexer.ts:392-397`. `retryCause` returns `undefined` for it
(`retry.ts:156`), so `pollUntil` rethrows on the first attempt
(`retry.ts:121`). The caller sees a different error, after one attempt instead
of eleven.

Smallest fix: add `case "CLIENT_INVALID_RPC_RESPONSE": return RPC_CAUSE;` to
`retryCause`. That matches Rust in both adapters, because `solana_rpc.rs` also
reports its malformed-response cases as `ClientError::Rpc`
(`solana_rpc.rs:367`, `solana_rpc.rs:378`). If the preferred end state is that a
malformed body is fatal, which is what `indexer.rs:474-476` argues for the API
layer, then the Rust change lands first and TypeScript follows, per rule 6.

Secondary, same root cause and lower severity: `CLIENT_RPC_PROGRAM_ERROR`,
`CLIENT_RPC_TRANSACT_DECODE`, `CLIENT_RPC_TRANSACT_NOT_FOUND`,
`CLIENT_RPC_TRANSACTION_NOT_FOUND`, `CLIENT_RPC_OWNER_TAG`, and
`CLIENT_TOO_MANY_ACCOUNTS` are narrowings of `ClientError::Rpc` that
`retryCause` treats as fatal. Rust retries all of them. No Rust poll loop wraps
the Solana adapter, so the difference is observable only through the public
`retryCause` and `isRetryable` predicates rather than through a retry schedule.
`CLIENT_CONFIRMATION_TIMEOUT` belongs to the same family and already has a
recorded disposition as a Rust defect.

## C02 `sdk-libs/client/src/error.rs` -> `client/src/error.ts`

**Verdict: DIVERGENT**, on one name. The taxonomy itself is at parity; one of
the three "unproduced" dispositions does not meet the bar.

### What the fix closed

The reachability gap the previous reviewer found is genuinely closed.
`error.test.ts:73-87` derives the produced set by reading every `src` tree named
in the root `package.json` workspaces and matching `new ClientError` sites, and
`error.test.ts:359-387` fails when a produced code is undeclared or a canonical
code is neither produced nor dispositioned. A code that loses its producer now
fails the test rather than passing a partition check over hand-written sets.

`CLIENT_RPC` is recorded as narrowed into the three transport codes
(`error.test.ts:57-61`) and is asserted to keep at least one reachable narrowing
(`error.test.ts:384-386`). Note that `CLIENT_RPC` is itself still produced, at
`solana-rpc.ts:233`, so the narrowing is a partial one. The test does not claim
otherwise and stays consistent.

### The three "unproduced" claims

Two hold exactly. `ClientError::AccountNotFound` and
`ClientError::DepositSenderNotSigner` are constructed in Rust only at
`program-tests/spp-test-validator/tests/deposit_action.rs:77`, `:84`, and `:91`,
plus the fixture generator at `xtask/src/ts_fixtures_client.rs:188-189`. No
production SDK path produces either, so an unproduced TypeScript disposition is
sound in both directions.

The third does not hold. `ClientError::SolanaTransactionSigning` is produced by
production SDK code, at `sdk-libs/wallet/src/actions/transaction.rs:584` and
`:613`, where `sign_private_transaction` and `sign_private_transaction_sync` map
a `try_sign` failure onto it. TypeScript delegates instead: `TransactionSigner`
at `wallet/src/submit.ts:28-31` hands signing to the caller, and a rejection is
re-thrown as a `WalletError` by `wrapWalletError` (`wallet/src/submit.ts:73`).
The `try_sign` sub-case that Rust reports as `NotEnoughSigners` does have a
TypeScript counterpart, `WALLET_INCOMPLETE_SIGNATURES` at
`wallet/src/submit.ts:62`, but under a different error type and code.

So a Rust caller whose fee payer fails to sign receives
`ClientError::SolanaTransactionSigning`, and the TypeScript caller in the same
position receives a `WalletError`. That is observable, and the disposition text
at `error.test.ts:65-66` describes the architecture accurately while filing the
name alongside two genuinely test-only variants, which reads as a stronger claim
than the evidence supports.

Smallest fix, which lives outside `error.ts`: have `@zolana/wallet` wrap a
`signNativeTransaction` rejection in `CLIENT_SOLANA_TRANSACTION_SIGNING` with
`{ reason }` at the point where it substitutes for Rust's `try_sign`, and move
the name out of `NO_TYPESCRIPT_PRODUCER`. Failing that, split
`NO_TYPESCRIPT_PRODUCER` so a variant with a live Rust production producer is
recorded separately from the two that only tests construct. `error.ts` needs no
change either way: `CLIENT_SOLANA_TRANSACTION_SIGNING` is declared with
`{ reason: string }` (`error.ts:99`), matching `SolanaTransactionSigning(String)`.

## C22 `sdk-libs/client/src/lib.rs` -> `client/src/index.ts`

**Verdict: DIVERGENT**, on one name. Not provisional on the prover export block.

### The generator captures the crate root faithfully today

`rustup run 1.97.0 cargo run -p xtask --bin ts-fixtures -- --check
--current-client` reports `verified 3 current client fixtures`, so
`client/lib.json` regenerates byte-identically from `lib.rs` at HEAD and the
fixture is a live derivation rather than a snapshot.

Checked by hand against `lib.rs`: 7 modules and 90 names, matching the fixture.
The parser handles nested trees correctly, which is where this kind of generator
usually goes wrong. `push_use_tree_leaves` recurses through the group at
`ts-fixtures.rs`, and `split_use_tree_branches` tracks brace depth, so
`prover::{merge::MergeWitness, transact::{assemble, ..}, ..}` yields the leaf
names rather than the paths. All 43 names of the prover block, including the
two nested groups, appear in the fixture. `self` is filtered.

Two forms the parser gets wrong, neither present in `lib.rs` today. A rename
`pub use a::B as C;` yields the literal string `"B as C"` rather than `C`,
because the leaf is taken by `rsplit("::")` with no `as` handling. A glob
`pub use prover::*;` yields the literal `"*"` rather than the expanded set.
Block comments are not stripped either; only `//` is. The fixture is faithful at
HEAD, and the `--check` gate catches drift, but any of those three forms would
produce a wrong fixture silently. Worth a follow-up row rather than a C22
blocker.

The vector test is real rather than self-referential.
`crate-root-exports.test.ts:189` asserts the regex-parsed value exports equal
`Object.keys` of the imported module namespace, so the disposition tables are
checked against the module that actually ships, and lines 200-204 assert that a
dispositioned name is absent from the shipped surface. The prover block is
carried, so `import { ProverClient } from "@zolana/client"` now resolves as
`use zolana_client::ProverClient` does.

### Ruling on the transaction re-exports

There are 17 of them, not 15: `AssetBalance`, `ConfidentialTransfer`,
`InputUtxoContext`, `MERGE_INPUTS`, `Merge`, `MergeZone`, `PreparedMerge`,
`PreparedMergeZone`, `PreparedZoneAuthority`, `PrivateTransaction`,
`PrivateTransactionDirection`, `PrivateTransactionId`,
`PrivateTransactionKind`, `PrivateTransactionStatus`, `SppProofInputUtxo`,
`SppProofInputs`, `WithdrawalTarget` (`lib.rs:53-63`).

The package-ownership line justifies the divergence for 16 of them. A consumer
who follows the Rust surface finds each one, either under the same name or under
the settled TypeScript name, by importing `@zolana/transaction` instead of
`@zolana/client`. `SppProofInputUtxo` ships as `ProofInputUtxo`, which the
disposition records. The four `PrivateTransaction*` names are absent as named
exports because TypeScript inlines them into the `PrivateTransaction` interface
as string-literal unions and an inline object type
(`transaction/src/wallet/state.ts:15-21`), reachable as
`PrivateTransaction["kind"]` and so on. That is idiomatic and the enclosing type
is exported, so it does not cost the consumer the surface. Duplicating 16 names
at the client root to mirror a Rust convenience re-export would buy nothing:
`@zolana/client` depends on `@zolana/transaction`, so the names are one import
away and there is no version-skew risk.

`MERGE_INPUTS` is the exception, and it makes the row divergent. Rust declares
it `pub const MERGE_INPUTS: usize = 8` at
`sdk-libs/transaction/src/instructions/merge.rs:18` and re-exports it from the
client crate root, so `use zolana_client::MERGE_INPUTS` compiles. In TypeScript
it is a module-private literal duplicated in two files,
`transaction/src/instructions/builders.ts:21` and
`client/src/prover/merge.ts:31`, and it is exported by neither
`@zolana/transaction`, nor `@zolana/transaction/instructions`, nor
`@zolana/client`. It does not appear in `public-exports.md` either. The
disposition at `crate-root-exports.test.ts:81`, "@zolana/transaction owns the
merge instruction constants", is false at HEAD: no package owns it, and a
consumer following the Rust surface cannot find it. The duplication is a second
cost, since the two copies can drift.

Smallest fix: export `MERGE_INPUTS` from `@zolana/transaction`, have
`client/src/prover/merge.ts` import it instead of redeclaring it, and record it
in `public-exports.md`. The `NOT_CARRIED` reason then becomes true as written.

### Prover-export caveat

This verdict does not depend on the prover export block, so it is not
provisional. The block is carried at the root and asserted by
`crate-root-exports.test.ts`; if the concurrent prover work moves a name, that
test fails rather than passing silently, and the `CARRIED` or `NOT_CARRIED`
entry for the moved name would need updating. `MERGE_INPUTS` sits outside the
prover block and is unaffected by that work.

## The two flagged items

### `globalThis.process` at `prover/client.ts:374`

Genuinely pre-existing and unrelated to `68631870`. `git blame` attributes
`prover/client.ts:374-377` to `d9bd0eb2`, which is an ancestor of `68631870`,
and `68631870` does not touch the file.

The source scanner's blind spot is real and worth its own row. Both scans in
`sdk-libs/ts/config/browser-check.mjs` use the alternation
`\b(?:globalThis|window|self)\.process\b` together with
`\bprocess\s*(?:\.|\[)`. The read at `prover/client.ts:375-376` defeats both: a
type assertion and a line break separate `globalThis` from `.process`, so the
first alternative does not match, and the property access is `process?.env`, so
the optional-chaining `?` defeats `\s*(?:\.|\[)`. Only the bundle scan at line
83 catches it, after type erasure collapses the expression. The gate still
holds, so this is a diagnosis cost rather than an escape: the failure names a
bundle instead of a source line. It becomes an escape if a package is ever
covered by the source scan alone. A `\?\.` alternative and tolerance for
intervening whitespace in the `globalThis` alternative would close it.

### `sourceRevision` bump in the two client fixtures

Verified: the diff is the revision line only, in both files. `errors-v1.json`
and `rpc-indexer-v1.json` each change exactly one line, from
`6d757791552874e1068cb527bc27875740c70362` to
`30b58b9b6e51de4a5a783461f98c91c8666c71d5`. No vector, no payload, no ordering
changed.

The new pin is correct. `git log -1 -- sdk-libs/client/src` returns `30b58b9b`
(2026-07-25 16:36), which is later than `6d757791` (15:55), so the pin was
stale and the bump moves it forward. `manifest.json` carries the matching
`sha256` for both files plus the new `client/lib.json` entry, the recorded
digests match the files on disk, and `ts-fixtures --check --current-client`
verifies all three against the pinned revision.

## Where TypeScript is now stricter than Rust

One place, and it is the C01 divergence: `CLIENT_INVALID_RPC_RESPONSE` aborts a
poll that Rust retries. Nothing else found in this pass rejects an input Rust
accepts. The C02 and C22 divergences are missing surface rather than added
strictness.

## Summary

| Row | Verdict | Cite |
|-----|---------|------|
| C01 | DIVERGENT | `retry.ts:156` against `indexer.rs:628-643` |
| C02 | DIVERGENT | `error.test.ts:65-66` against `wallet/src/actions/transaction.rs:584` |
| C22 | DIVERGENT | `crate-root-exports.test.ts:81` against `transaction/src/instructions/merge.rs:18` |

Commands run: `npx vitest run` over `client/test/retry.test.ts`,
`client/test/error.test.ts`, and `client/test/vectors/crate-root-exports.test.ts`
(3 files, 22 tests, all passing); `rustup run 1.97.0 cargo run -p xtask --bin
ts-fixtures -- --check --current-client` (`verified 3 current client fixtures`).
The known-failing `lint:packages`, browser bundle scan, and
`input_commitments_include_data_and_zone_hashes` were not run.
