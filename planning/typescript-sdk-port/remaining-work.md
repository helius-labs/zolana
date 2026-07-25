# Remaining work

Read this first. It states what is left on the TypeScript SDK port, in order,
with the check that closes each step. The other documents in this directory hold
the evidence behind the steps; this one holds the sequence.

## The goal

Get `node sdk-libs/ts/config/pkp-entry-gate.mjs` to exit 0, then run the
cryptographic certification phase, PKP-00 through PKP-08, then pass the release
gates. The gate is the only arbiter of whether the first part is done. It reads
the review checklist and the pull request rather than a person's impression, and
it exists because for most of this port's life "CI is green" meant "the four
checks I run locally are green" while the jobs on pull request 159 were skipping
because it was a draft.

Two of the gate's four criteria hold today. The two that do not are 45 rows
carrying an adverse verdict and a red pull request.

## Two rules that outrank the sequence below

### Resolve an open question the way Light Protocol resolved it

Standing instruction from the protocol owner, 2026-07-26, binding on anyone
working this port.

1. **Check the problem is real.** Reproduce it, read the current source on both
   sides, and confirm it is not an artifact of a stale fixture, a cached build,
   or a row description written before the code moved. Several of this port's
   blockers dissolved at this step. `create_two_inputs_hash_chain` was recorded
   as a proof-path gap and has no production Rust callers, and `T29` described a
   guard that exists in neither language.
2. **If it is real, look at how Light Protocol solved it, and do that.** Light
   is at `/Users/tilohelius/Workspace/light-protocol`, its TypeScript SDK is
   `js/stateless.js`, and it is the mature lineage for this design. Copy its
   answer rather than reasoning one out. Read
   [`light-protocol-comparison.md`](light-protocol-comparison.md) before you do,
   so you are comparing against what Light does rather than what it seems likely
   to do.
3. **If Light has no answer, take the recommended path and record it.** Write
   the question and your choice into your `row-updates/<batch>.md` file, marked
   for the end-of-session report. Do not stop and wait.

The rule outranks a reviewer's preference. Where a document or a row recommends
one thing and Light does another, Light wins and the row is what changes. It
does not outrank the scope rule below or the authority order, since neither is a
matter of taste.

### The port changes SDK code only

Do not change `programs/`, `program-libs/`, `prover/`, or the circuits. An agent
who believes a fix belongs in one of those stops and reports rather than making
it. Violating this has cost hours twice.

Editing Rust inside `sdk-libs` is in scope and is sometimes the right answer:
`M01` and the merge oracle generators were fixed on the Rust side, and steps 5
and 6 below each require a Rust SDK change. Confusing "Rust" with "out of scope"
is what made three rows look terminal when none of them is. See
[`scope-and-denominator.md`](scope-and-denominator.md).

Two exceptions exist, both granted case by case. The owner has approved specific
`docs/spec.md` amendments where the specification described behaviour the
deployed program does not have, and a confirmed program defect may move to its
own branch and pull request off `main` rather than land here.
[`row-updates/program-lib-scope-audit.md`](row-updates/program-lib-scope-audit.md)
records the audit of this rule and two lessons that generalize: a shared library
is not automatically program code, and added validation is dangerous even when
it looks defensive.

## Where the work stands

Run these two commands before citing a number. Other agents commit while you
read.

```bash
node sdk-libs/ts/config/pkp-entry-gate.mjs        # the four entry criteria
node sdk-libs/ts/config/review-checklist-check.mjs # rows, verdicts, attribution
```

As of 2026-07-26 01:40, branch `ts-sdk-port` at 420 commits ahead of `main`:

| Criterion | State |
| --- | --- |
| 1. Each of the 145 rows reviewed | pass |
| 2. No adverse row remains | fail: 45 adverse, 27 `PARTIAL`, 17 `DIVERGENT`, 1 `STALE` |
| 3. No specification-authority blocker | pass: no row is `BLOCKED` |
| 4. Continuous integration green | fail: 3 jobs failing, 14 pending |

90 of the 145 rows are `done` on demonstrated parity and 6 more are closed on a
confirmed `NOT_APPLICABLE` disposition, which the gate counts separately. Both
figures are right; 96 rows are closed and 90 is the number the gate reports.

**The 45 is behind the code, and knowing by how much saves you rework.** Batches
write their row transitions into `row-updates/<batch>.md` and a reconciler moves
them into the table, so a row can carry a committed fix with oracle evidence and
still read adverse. Six of the 45 are in that state today: `C07`, `C08`, `C15`,
`C19`, `C20`, and the `T23` residual landed with client batch B at `d3514b24`,
`410f6757`, `1da410f3`, `d867fccc`, and `2e981b7f`, and are recorded in
[`row-updates/client-b.md`](row-updates/client-b.md) rather than in the table.
Read the batch file for a package before you start on one of its rows. Criterion
2 does not move until the reconciler folds those in, which makes the fold-in
part of the remaining work rather than bookkeeping after it.

## The sequence

| Step | Closes | Start after |
| --- | --- | --- |
| A | Whether the SDK needs versioned transactions | runs alongside, blocks nothing |
| 1 | Criterion 4, the red pull request | now |
| 2 | `I08` `I09` `I20` `I21`, on one sentence from the owner | now |
| 3 | Wallet, `W02` and `W04` | now |
| 4 | Interface, `I07` `I19` `I26` `I37` | steps 1 and 3 |
| 5 | Transaction, 15 rows, one of them already fixed | now |
| 6 | Client, 13 rows, five of them already fixed | now |
| 7 | Keypair and merkle-tree, `K11` to `K14` and `M02` | now |
| 8 | Indexer API and smart-account client, `X01` and `S01` | now |
| 9 | The package and full SDK gate sets | steps 1 to 8 |
| 10 | The cryptographic phase | step 9 |

Steps 5, 6, 7, and 8 touch disjoint packages and can run at the same time. Hold
concurrency at three: five workers exhausted the account's capacity on
2026-07-25 and died together. Step 4 waits on step 3 for a reason given in the
step. Step 2 needs a decision rather than work and can be asked for today.

Read the branch column of the worktree table in [`README.md`](README.md#worktree-topology)
before taking a step. Four directory names no longer describe what their tree
holds, and three collisions have come from trusting the name.

## Step A. Decide about address lookup tables and versioned transactions

**Now.** The SDK depends on no Solana package and compiles transactions by hand,
so `compileLegacyTransaction` (`sdk-libs/ts/client/src/client.ts:615-698`)
produces a legacy message. There is no `VersionedTransaction` and no way to pass
an address lookup table. Light Protocol moved to v0 messages because a
transaction touching several state trees and queues runs out of account slots,
and it creates lookup tables holding those addresses
(`js/stateless.js/src/utils/state-tree-lookup-table.ts:1-40`). A Zolana private
transfer touches a pool tree, a nullifier queue, a registry, an optional
withdrawal, and SPL accounts, which is the same growth pattern.

**Done when** the owner has an answer to one question: is there a wall, how far
away is it, and does this port do anything about it now. The answer may be that
there is years of headroom and nothing to do, which closes the step as
legitimately as a decision to build a v0 compiler would.

**Check.** `planning/typescript-sdk-port/versioned-transactions.md` exists,
leads with whether the wall is real and how far away, and carries a
recommendation the owner has accepted or rejected.

An agent on branch `port/versioned-tx`, in the `zolana-ts-interface-a` tree, is
writing that document now. If it has not appeared in your tree, it is in flight
rather than missing; do not answer the question yourself and do not wait for it
before starting a numbered step.

This is out of scope for the parity work and it is not part of the cryptographic
phase, which is why it carries a letter rather than a number. It is here because
it is the largest architectural question outstanding and it gets more expensive
the longer it waits, so it competes for the same attention as the numbered
steps.

**Read.**
[`light-protocol-comparison.md`](light-protocol-comparison.md), finding F1, which
records the same finding with the paths behind each claim, and
[`versioned-transactions.md`](versioned-transactions.md) once it lands.

## Step 1. Get the pull request's checks green

**Now.** `gh pr checks 159` reports 3 failing jobs and 14 pending: `tests /
sdk-libs`, `tests / client integration`, and `typescript / fixtures`. The set
moves between runs, so read it rather than trusting this list. `typescript /
static` failed on three unformatted config scripts and is closed at `5a83d7f4`.
An agent on `port/ci-green`, in the `zolana-ts-ci` tree, owns this step.

The Rust jobs are one cause rather than several. `main` deleted a dead field,
`CreateTree.owner`, that this branch still carries, so `cargo check (workspace)`
does not compile and the Rust test jobs inherit that failure rather than failing
on their own account. Fix the field and re-read the set before triaging further.

`typescript / fixtures` is the one that needs a decision rather than a fix, and
it is the one to be careful with. It runs `npm run check:fixtures`, which is
default-mode `fixtures:check`, which fails on baseline drift from `43fde8e4`
across 13 `sdk-libs/transaction` paths joined by
`sdk-libs/keypair/src/signing_key.rs`. That is
[G8-1](production-readiness-issues.md#g8-1-the-manifest-pins-multiple-source-revisions-high),
deferred until the Rust source settles. Two things follow. A deferred failure
still holds criterion 4 red, so the deferral as it stands cannot coexist with the
gate: either the manifest gets the per-revision compatibility rule G8-1 asks for,
or the job stops running the check the decision defers. And regenerating the
fixtures to quiet the job would destroy the evidence the parity claims rest on,
since the gate is correctly reporting a divergence. A stale provenance baseline
has already explained this failure twice.

**Done when** `gh pr checks 159` shows no failing and no pending job.

**Check.** Criterion 4 of the entry gate passes.

**Read.**
[`production-readiness-issues.md`](production-readiness-issues.md), items G8-1
and G9-1 through G9-4, and
[`testing-and-conformance.md`](testing-and-conformance.md#continuous-integration-tiers).

## Step 2. Close the four pinned rows with one sentence

**Now.** `I08`, `I09`, `I20`, and `I21` are the same finding on four surfaces.
TypeScript refuses a merge payload whose `encrypted_utxo` first byte is not `2`,
which the Rust decoder reads, because the prefix is not among the bytes
`MergeTransactIxData::deserialize` parses and the shielded-pool program is what
rejects the payload, with
`InvalidMergeOutputScheme` (7014). Byte-level parity holds for canonical
payloads and a committed test fails if either side moves, so these four are
`pinned_divergence` rather than `needs_fix`: the difference is understood,
reproduced, and left in place because choosing between two defensible behaviours
belongs to the owner.

No valid transaction is lost either way. What TypeScript cannot do is decode
such an instruction while indexing or debugging a failed transaction.

An agent on `port/merge-prefix`, in the `zolana-ts-programlibs` tree, holds the
strictness question. Coordinate with it rather than editing the codec.

**Done when** the owner names a side. Both fixes are in scope: drop the guard
from `sdk-libs/ts/interface`, or add the matching guard to
`program-libs/interface`, which this branch would not do. The standing
instruction, that a port stricter than its original silently breaks callers,
points at dropping the guard, and Light Protocol's rule points the same way:
decode any instruction that can appear in a transaction, build only those whose
inputs the SDK can itself produce.

**Check.** The four rows leave `pinned_divergence` and take the ordinary route
through `needs_fix` and then `done`.

**Read.**
[`scope-and-denominator.md`](scope-and-denominator.md#the-four-pinned-rows-since-one-sentence-clears-them)
and [`authority-rulings.md`](authority-rulings.md).

## Step 3. Wallet, two rows

**Now.** `W02` is `STALE` and unowned rather than blocked. Nothing blocks it:
the finding behind it was re-reviewed to parity, and the fixture regeneration it
waited on landed as `d2dcced3`. It went stale because the deposit discovery-tag
ruling moved its canonical Rust after the review. `W04` is `PARTIAL` because
half of it is proven and half is not. `wallet/test/vectors/wallet-actions.test.ts`
replays 28 cases generated from the crate by `xtask/src/bin/wallet-actions.rs`
and settles the action half, including the zero-amount withdrawal Rust builds.
The signing half was judged closed by reading `private-transaction.ts` against
`transaction.rs`, and no executed comparison covers it.

**Done when** `W02` drives `deposit-vector.test.ts` through `createDeposit` from
the recipient address rather than from `fixture.inputs.ownerBytes` and the
expected hash, so the `owner_hash` and `ProofInputUtxo::new(..).hash()`
derivations get an oracle instead of an assumption, and records a disposition
for the public `deposit` entry point. `W04` closes when
`xtask/src/bin/wallet-actions.rs` records, from Rust, which rail
`apply_p256_signature` selects for a wallet whose notes sit on the other rail
and which substitutions `validate_unsigned_inputs` refuses, and both replay
through `signPrivateTransaction`.

**Check.** Both rows reach `done` with `PARITY`, each with a log entry naming
the reviewer and the commit.

This branch has already produced one false parity claim from a reading that
looked right. Reading is not the standard here.

**Read.**
[`row-updates/open-threads-2026-07-25.md`](row-updates/open-threads-2026-07-25.md)
and
[`row-updates/parity-evidence-audit.md`](row-updates/parity-evidence-audit.md),
which is the audit that reopened 30 rows and is worth reading once before you
record any verdict.

## Step 4. Interface, four rows

**Now.** `I07`, `I19`, and `I26` carry one shared residue and nothing else.
The interface batch closed their layout, codec, and builder halves against a
JSON oracle generated from the `zolana-interface` crate, and the specification
conflicts that once blocked them are settled by the amendment at `b97b2a88` and
the discovery-tag ruling applied at `1ff51a4c` and `114a5140`. What is left is
that nobody has confirmed the regenerated wallet deposit fixtures write the
ruled-on tag. The interface passes that 32-byte field through without reading
it, so the confirmation is a `sdk-libs/wallet` artifact, which is why this step
waits on step 3.

`I37` is the interface crate root and inherits those three. Its own residue is
the G8-1 fixture-gate failure from step 1.

**Done when** a wallet-side artifact shows the deposit fixtures carrying the
signing-pubkey tag, and the G8-1 decision from step 1 has landed.

**Check.** The four rows reach `done`, and the interface package gate block has
no adverse row.

**Read.**
[`row-updates/interface-parity.md`](row-updates/interface-parity.md) and
[`row-updates/interface-spec-conflicts.md`](row-updates/interface-spec-conflicts.md).

## Step 5. Transaction, fifteen rows

`T06`, `T10`, `T12` through `T17`, `T21`, `T23`, `T26`, `T28` through `T31`.

**The trap in this package is making TypeScript stricter than Rust.** Four rows
have already recorded that failure and it is the defect class the fix workflow's
step 6 exists to prevent. A port that refuses input the program accepts breaks
callers silently, and the failure is invisible to a test suite that checks
accept-and-reject on cases both languages agree about. Three rows here run
against the intuition, each in a different direction:

- `T21` inverts the obvious reading. Silent truncation in the SDK would *agree*
  with the program, which keeps truncating the `ExternalDataHash` length prefix
  through a `u16` cast; raising an error disagrees with it. The owner ruled for
  the loud disagreement, because the trigger is more than 65,535 outputs or
  messages in one transaction and a Solana transaction has no room to carry
  that. The work is to give the Rust SDK the `TRANSACTION_TOO_MANY_OUTPUTS`
  guard TypeScript already has, and to add the boundary vector neither language
  holds, `0xffff` outputs accepted and hashed against `0x10000` refused.
  Removing the TypeScript guard alone would restore quiet truncation in one
  language, which is the state the ruling exists to end.
- `T23` was fixed on the Rust side and is waiting to be recorded. Rust's
  `hex_to_be_32` read several spellings of one number and one spelling of a
  different one: a repeated `0x` prefix, a discarded minus sign, an unparsable
  string turned into zero, an oversized value truncated to its low 32 bytes, and
  no comparison against the BN254 base modulus. TypeScript's `parseCoordinate`
  refused each of those already. `d3514b24` narrows Rust and pins both languages
  against `ts_proof_oracle.rs` over 27 adversarial cases, with three control
  edits observed to fail 14, 3, and 3 of them.
- `T28` cannot be fixed from TypeScript. It asks for canonical zone-hash
  and zone-address validation at construction, which neither language performs,
  so closing it means adding the rule to Rust first and porting it second.

`T29` runs the other way and is worth reading in full before touching it. Its
old text described a guard that exists in neither language, `cda42f01` added it,
a rejection audit found it over-strict against the circuit, and a later pass
removed it from both languages. Restoring it would refuse transactions the
program and the circuit accept. What is actually divergent is the opposite:
TypeScript is looser. Rust `PreparedZoneAuthority::new` takes `payer: Address`
and derives `payer_pubkey_hash = sha256_be(payer.as_array())`, while TypeScript
takes `payerPublicKeyHash` from the caller, so a caller can prepare a
transaction whose payer hash names someone other than the payer who signs. Each
oracle case passes the correct hash, so no replay catches it. Take the payer
address and derive the hash, as `instructions/transact.ts:558` already does on
the confidential rail.

The remaining rows are ordinary. `T12` needs one API decision recorded, whether
`entries()` stays as a deliberate TypeScript-only accessor. `T13` through `T17`
each name a list of absent types and four Rust prerequisites on
`wallet/authority.rs`. `T10`, `T26`, `T30`, and `T31` are aggregate rows that
hold the export-allowlist, browser-runtime, and packed-artifact classes for the
package; they need a build-and-pack harness rather than an oracle. `T31` also
carries a live defect from the quality audit: the codecs use a local
`SPLIT_TYPE_PREFIX` and a bare literal `4` while the exported wire constants
have no consumer, so a wire-format change has to be made in three places and two
of them are silent.

**Done when** each of the fifteen reaches `done` with `PARITY`. Fourteen need
work; `T23` needs its evidence recorded in the table.

**Check.** The transaction package gate block has no adverse row, and each
verdict rests on a Rust-generated oracle replayed by a TypeScript test rather
than a side-by-side reading.

**Read.**
[`row-updates/transaction-parity.md`](row-updates/transaction-parity.md),
[`row-updates/transaction-b.md`](row-updates/transaction-b.md), and
[`row-updates/rejection-validation.md`](row-updates/rejection-validation.md),
which is where the over-strict guards were caught against the circuit.

## Step 6. Client, thirteen rows

`C01` through `C08`, `C15`, and `C19` through `C22`. Five of the thirteen have
landed and are waiting on the reconciler; eight need work.

**Landed at `d3514b24`, `410f6757`, `1da410f3`, `d867fccc`, and recorded in
[`row-updates/client-b.md`](row-updates/client-b.md).** Read that file before
touching a `C` row, because the table does not yet show any of this.

- `C08` inverted the usual direction and is worth understanding once. Rust
  inferred the proof rail from which fields the response carried, so an Ed25519
  request answered with a commitment-bearing proof was packed as
  `TransactProof::P256`, which verifies against neither key. The owner ruled that
  TypeScript is correct and Rust moves. The rail now travels with the request
  through `send`, `poll_async`, and `proof_from_value`.
- `C07` closed by removal rather than addition.
  `batchUpdateNullifierTreeInstruction` left the public surface of
  `@zolana/interface`, because its `compressedProof` comes from the
  `address-append` circuit no TypeScript path can prove.
  `batchUpdateNullifierTreeDataCodec` stays, so a tool that finds such an
  instruction can still read it. That is Light's rule and a breaking change the
  pre-1.0 ruling permits.
- `C19` reopened and then closed on generated evidence. Its nine polling
  behaviours had been matched to Rust's `poll_async` by eye, and driving the real
  Rust through a mock server instead turned up two divergences that reading had
  missed, both about a `completed` status carrying nothing useful.
- `C15` and `C20` were held by one factual error in a generated report:
  `sdk-libs/ts/reports/inventory.json` named `src/prover/field.ts`,
  `src/prover/merge-zone.ts`, and `src/prover/transact/index.ts`, none of which
  the package ships. `ts-fixtures --reports-only` regenerates the reports without
  weakening the fixture gate.

**Still open.** `C06` shares the inventory-target complaint that `C15` and `C20`
just closed, so check whether the regenerated report already settles it.

`C02` cannot be fixed inside `error.ts`. `CLIENT_SOLANA_TRANSACTION_SIGNING` has
no producer, and giving it one means wrapping the `signNativeTransaction`
rejection in `sdk-libs/ts/wallet/`, which the client batch does not own.
Splitting the `NO_TYPESCRIPT_PRODUCER` set, so a code with a live Rust producer
is recorded apart from the two only tests construct, closes the row instead and
stays inside the package.

`C03` and `C04` interact with open pull request 158, which renames a type this
port already uses and rewrites `indexer_error` in the opposite direction from
`6d757791`. Read
[`row-updates/pr-158-impact.md`](row-updates/pr-158-impact.md) before
restructuring either file. `C01`, `C05`, `C21`, and `C22` are each one step
short: a recorded ledger line, an absent Rust oracle, or a behaviour pinned by a
TypeScript expectation rather than by an executed comparison.

**Done when** each of the thirteen reaches `done` with `PARITY`.

**Check.** The client package gate block has no adverse row.

**Read.** [`row-updates/client-b.md`](row-updates/client-b.md) and
[`row-updates/client-c01-c02-c22.md`](row-updates/client-c01-c02-c22.md).

## Step 7. Keypair and merkle-tree, five rows

**Now.** `K11` through `K14` and `M02`. The behavioural halves are settled.
`ViewingKeyLike` declares the 14 Rust trait operations rather than two,
`ShieldedKeypairLike` declares the six previously absent capabilities, the
`./traits` subpath exists and is type-only, and
`merkle-tree/test/vectors/merkle-semantics.test.ts` replays three traces
generated from the Rust crate and answers the three questions `M02` asked. One
answer corrects the row itself: `historyRootIndex` counts root updates modulo
the history length and wraps, in both languages, so the row's premise that it
holds zero describes neither.

Two things hold these rows open and one of them has gone stale.

`K12` has a real open question for the owner. Rust's `nullifier_key()` clones
out the nullifier key while TypeScript's interface offers `nullifierPublicKey()`
alone. TypeScript is the safer surface and the difference is deliberate, but a
trait whose Rust form hands out secret material and whose TypeScript form does
not is not parity, and which side moves is the owner's call.

`K13`, `K14`, and `M02` each record that the packed-package gate fails with
`packed browser bundle contains globalThis.process`. **That no longer
reproduces.** `node sdk-libs/ts/config/pack-check.mjs keypair` and the same
command for `merkle-tree` both exit 0 on this tree, and `typescript / packaging`
passes on the pull request. Re-run the gate, record the result against a commit,
and drop the residue from the three rows.

**Done when** the owner answers the `nullifier_key()` question, the surface
gates for `M02` are rerun against a named commit, and the stale pack-check
residue is removed with evidence.

**Check.** The keypair and merkle-tree package gate blocks have no adverse row.

**Read.** [`row-updates/hashers-b.md`](row-updates/hashers-b.md) and
[`row-updates/poseidon-parity.md`](row-updates/poseidon-parity.md).

## Step 8. Indexer API and smart-account client, two rows

**Now.** `X01` and `S01` are one row each, they are the only rows in their
packages, and no batch owns either. Both are `DIVERGENT` and both have been
adverse since the first review, so neither has the layers of amendment the other
packages carry.

`X01`: TypeScript follows current Rust and Photon accurately, while `docs/spec.md`
defines different indexer context, UTXO, transaction, and output schemas. The
base64-to-bytes and hash error distinctions are incomplete, the promised Rust
fixture is absent, and there is no exhaustive rejection or live-Photon evidence.
The specification is the side that lags here, so this needs an amendment rather
than a code change, then the schema, conversions, errors, and fixtures aligned
behind it.

`S01`: Rust casts compiled account positions to `u8` while TypeScript refuses an
index above 255, so the overflow policy conflicts. TypeScript also has no
equivalent enforcement or evidence for the 1232-byte transaction limit, no exact
execute fixture, and no pinned export surface. Choose one index policy at the
canonical boundary, add the size limit, and pin the execute bytes and exports
with current-Rust fixtures.

**Done when** both rows reach `done`.

**Check.** The `indexer-api` and `smart-account-client` package gate blocks have
no adverse row.

## Step 9. Pass the package and full SDK gate sets

**Now.** No package gate set has passed. That is the largest thing standing
between this queue and a claim about the SDK as a whole, and it is separate from
the row count: a package can hold 22 closed rows and still fail its gate block,
because the gates cover the export ledger, fixture provenance, browser
execution, aliasing, and pack-and-consume, which no behavioural row owns.

Two gate lines are satisfiable now and are recorded as open. G9-1 asks for a
repository workflow running the TypeScript merge tier on pull requests, and
G9-2 asks that the tier cover the cross-language, prover, browser, fixture,
packed-package, and package-lint suites. `.github/workflows/typescript.yml`
does both: it runs one job per sub-script of `npm run check` behind a `merge
gate` job, and a `gate scope` job fails if `check` and the workflow drift apart.
Verify and tick them rather than scheduling them.

**Done when** the nine package gate blocks and the full SDK gate block in the
checklist are ticked with evidence beside each line or in a `log/` entry.

**Check.** The entry gate exits 0.

**Read.** The two gate blocks in
[`review-checklist.md`](review-checklist.md#package-completion-gates) and
[`testing-and-conformance.md`](testing-and-conformance.md).

## Step 10. Run the cryptographic certification phase

**Now.** PKP-00 through PKP-08 have not started. The phase begins automatically
when the entry gate passes: `sdk-libs/ts/config/pkp-entry-watch.sh` polls the
gate and wakes the coordinator, so nobody has to notice.

**Done when** PKP-00 through PKP-08 have run in order. A complete proof or
key-handling parity claim requires native Rust verification of
TypeScript-produced artifacts and real TypeScript prove-to-chain evidence
through the same-revision local stack.

Two hazards found while building the zone rails belong to PKP-05 and are worth
carrying into it, because each needs one change applied to both languages and
fixing one language alone is how this project has introduced defects before. The
Rust zone provers take `Option<Address>` for the zone binding and accept `None`,
which becomes a literal zero and ties the proof to no zone, and the TypeScript
signature cannot express that. And `ZoneAuthorityProver` builds requests across
the ten supported shapes while four zone-authority verifying keys exist, so Rust
can construct a 2x3 request no server can answer.

**Check.** The exit criteria stated per packet in
[`proof-and-key-parity.md`](proof-and-key-parity.md#implementation-work-packets).

**Read.** [`proof-and-key-parity.md`](proof-and-key-parity.md) in order, and
[`production-readiness-issues.md`](production-readiness-issues.md#scheduling)
for the findings each packet already owns.

## Two protocol defects that no step closes

`PD-1` and `PD-2` were found while reviewing for parity, no TypeScript change
closes either, and neither is counted in the 145.

`PD-1`: a padding dummy input's public nullifier column is unconstrained in the
circuit and the program inserts it anyway. This is not a double spend, and
double spending is prevented on each of the five instructions that consume
UTXOs. It is a liveness risk: a chosen padding nullifier can wedge the nullifier
queue and freeze shielded balances pool-wide. Reproduced by execution in
`program-tests/shielded-pool/tests/transact/double_spend.rs`. Recommended route
is its own pull request against `main`.

`PD-2`: `merge_transact` does not tie its `user_record` to the owner whose UTXOs
are merged. Denial of access rather than theft, and the reachable party is a
current or former sync delegate. Its route is taken: branch
`fix/merge-user-record-binding`, commit `a811b20e`, pull request 160, which is
open and unmerged, with `a811b20e` not an ancestor of `main`. One ordering
residual survives the fix: an impostor who claims a P256 key before its real
owner registers keeps it, and closing that needs a P256 signature over a
registration challenge.

Both are recorded in [`review-checklist.md`](review-checklist.md#protocol-defects)
with their confirming tests and reach.

## Where the evidence lives

This document states the sequence. It does not restate the findings, and a
summary is not a substitute for the record when you are about to change code.

| Document | What it holds |
| --- | --- |
| [`review-checklist.md`](review-checklist.md) | The 145 rows, their verdicts, and the shared-worktree rules. A reconciler owns it. Read it; write to `row-updates/<batch>.md` instead |
| [`authority-rulings.md`](authority-rulings.md) | One section per disputed behaviour, with the owner's ruling and the artifacts a change would touch |
| [`scope-and-denominator.md`](scope-and-denominator.md) | Why no row is terminal, and the route for the findings that are genuinely outside |
| [`light-protocol-comparison.md`](light-protocol-comparison.md) | Eleven findings against Light's SDK, read from source with a path and line per claim |
| [`row-updates/quality-and-completeness-audit.md`](row-updates/quality-and-completeness-audit.md) | What the TypeScript SDK cannot do, established by comparing the `circuitType` values each language sends |
| [`row-updates/program-lib-scope-audit.md`](row-updates/program-lib-scope-audit.md) | The audit of the scope rule and the two lessons that generalize |
| [`row-updates/parity-evidence-audit.md`](row-updates/parity-evidence-audit.md) | The audit that reopened 30 rows upgraded on a reading |
| [`production-readiness-issues.md`](production-readiness-issues.md) | 26 cross-cutting findings that no single row owns, each scheduled into a phase |
| [`log/`](log/) | One file per review, per fix, per reconciliation. A reconciler owns it |
| [`archive/`](archive/) | Documents superseded by the work they planned, kept for the record |

## Working rules that cost something to learn

Read
[working in a shared worktree](review-checklist.md#working-in-a-shared-worktree)
before your first commit. The rules below are the ones outside it.

**Commit with an explicit pathspec.** Write `git commit -m "..." --` followed by
the exact paths. Two mixed commits were produced by a bare `git commit` picking
up another worker's staged index. A pathspec still commits the current content
of the paths it names, so read `git diff <path>` immediately before committing
and say in the message what you carried that is not yours.

**One tree, one branch, one agent.** A second agent's `git checkout` silently
moves the first agent's `HEAD`, and the damage surfaces at commit time. This has
happened three times in one evening. Do not reassign a worktree while its
previous agent can still be resumed, and prefer creating a tree over reusing
one: a tree costs a copy of `node_modules` and a collision costs an hour.

**When 91 test files fail to collect at once, check the branch before the
cache.** That is what a checkout under your feet looks like from inside, and it
impersonates the stale `node_modules/.vite` problem below. Run `git branch
--show-current` first. If it is not your branch, clearing caches will not help
and rebuilding will write your work onto someone else's branch. Guard each
commit with a branch check; that guard is what made the third collision an
interruption rather than a loss.

**After a merge, run `npm run build` and `rm -rf node_modules/.vite` before
believing a failure.** Packages resolve each other through their `exports` map,
so a cross-package test imports `dist` rather than `src`, and Vitest serves a
cached transform. Both layers were stale at once after the keypair merge and the
failure read exactly like a cross-batch regression.

**Verify a merge with `npm run lint:packages`, not `npm run lint`.** The root
script reads the config files and the package script reads package source. Two
lint errors rode into the branch because the merge was checked with the wrong
one.

**A passing test is not evidence until you have seen it fail.** A redaction test
passed for an incidental reason for weeks: its fixture placed each secret under
a key outside the allowlist, so it proved that unknown keys are dropped and
would have kept passing had redaction broken for a value under a known key.
Apply a control edit and watch the assertion fail before you record a verdict.

**A fix applied to one copy of shared arithmetic does not reach its siblings.**
`client/src/internal.ts` kept a sixteen-entry Poseidon partial-round table after
the other four copies were capped at twelve, and the keypair `bigIntToBytes`
still truncated at 2^256 after `merkle-tree` was fixed. Neither had a parity
test, which is why review missed both. When fixing duplicated arithmetic, search
out the other copies and give each one the test.

**End-to-end tests do not run while the batches do.** `startLocalStack` offsets
the validator's RPC port and leaves the faucet on its default, so the validator
opens port 9900 and exits when a sibling tree holds it. Unit, vector,
cross-language, typecheck, build, and export gates are unaffected and are the
verification standard during a parallel push. The fix belongs to
`test-kit/src/node/index.ts`.
