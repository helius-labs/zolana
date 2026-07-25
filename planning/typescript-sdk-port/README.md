# TypeScript SDK port plan

This directory defines the implementation contract for a TypeScript port of the
Rust SDK.

## Scope, which is narrower than it looks

The port changes SDK crates. It does not change `programs/`, `program-libs/`,
`prover/`, or the circuits, and an agent who believes a fix belongs in one of
those should stop and report rather than make it. Two exceptions exist, both
granted case by case rather than standing: the protocol owner has approved
specific `docs/spec.md` amendments where the specification described behaviour
the deployed program does not have, and a confirmed program defect may move to
its own branch and pull request off `main` rather than land here.

The rule was audited on 2026-07-25 and mostly held. Of 171 lines the branch had
added under `program-libs/`, five were compiled into the deployed program, three
went to a protocol library outside the program's dependency tree, and 163 sit
behind `#[cfg(test)]`, an attribute `cargo build-sbf` leaves unset. Both
compiled hunks are reverted. The test-only lines stay: their binary cost is zero and three are the
golden vectors the port's parity claims rest on.

Read
[`row-updates/program-lib-scope-audit.md`](row-updates/program-lib-scope-audit.md)
before adding to them. Two lessons in it generalize. A shared library is not
automatically program code, since `indexed-array` reaches only
`sdk-libs/merkle-tree` and the forester, so establish what loads a crate before
assuming a change is in scope. And added validation is dangerous even when it
looks
defensive: the reverted hunk re-checked a merge ciphertext prefix the program
already rejected with a dedicated error, which made the program's own guard
unreachable and downgraded an error code that TypeScript consumers can observe.

## Status

Refreshed as each worker commits. Last update: 2026-07-25 20:37.

| | |
| --- | --- |
| Rows the table calls supported | 5 of 145, the figure the CI gate reports |
| Rows evidenced on the branch but not yet in the table | About 65, across three merged batches |
| Rows with an adverse verdict | 107 before the fold-in |
| Rows still unexamined | None. The 27 the coverage audit found are reviewed and merged |
| Branch | 281 commits vs `main`. 1018 unit tests pass, typecheck, lint, and the checklist gate clean |
| Phase | 2 of 4: remediation. Phase 1 reopened, phases 3 and 4 not started |

Two figures appear above because they measure different things, and the honest
one is 5. A verdict earned in a batch worktree does not reach the table by
itself: batches record outcomes in `row-updates/<batch>.md` precisely because
they must not edit `review-checklist.md`, so roughly 65 rows of real evidence
sit beside a table that still shows them open. Read that gap as bookkeeping
rather than as work outstanding, but do not quote the larger number as
progress until a reconciler has folded it in and the gate agrees.

In flight:

| Work | State |
| --- | --- |
| Quality and no-shortcuts audit of `sdk-libs/ts` | Running |
| Fold three merged batches into the table | Running |
| Wallet, merkle and stragglers, 10 rows | Running, `port/wallet-misc`, 5 commits ahead and merging clean. Landed the indexed-range sentinel bound, the faucet-port offset, and the keypair bigint bound |
| Keypair error redaction, is the guarantee real | Running |
| Client package, rows C01 to C22 | RPC half closed, prover half outstanding |
| Transaction, 31 rows | 5 commits ahead, second pass queued behind the capacity limit |
| `user_record` binding fix, own branch off `main` | Done, PR #160, 23 checks green |

Merged into the integration branch:

| Batch | Result |
| --- | --- |
| The 27 uncovered rows, `port/program-libs` | 17 parity, 1 fixed, 9 not applicable |
| Interface, 36 rows, `port/interface-a` | 33 parity, 1 divergence pinned, 3 partial. No `src/**` file changed |
| Keypair, 14 rows, `port/keypair` | Vectors and API-surface tests landed. Cut off before recording verdicts, so the reconciler judges the rows from the evidence |
| Checklist reconciliation and log split | Gate green at 145 rows |

Two operational lessons from 2026-07-25, both worth keeping.

Five concurrent workers exhausted the account's capacity and died together at
20:30. Their work survived, because each worker is told to commit after a
coherent step, and the two trees holding uncommitted changes were in a good
enough state to checkpoint. Hold concurrency at three.

A test can fail for a reason that is not in the code. Immediately after the
keypair merge the client error suite failed, which read exactly like a
cross-batch regression in secret redaction; it was vitest serving a cached
transform of the pre-merge module. Clear `node_modules/.vite` before believing
a failure that appears in the first run after a merge.

The interface batch is the pattern worth copying: it generated a JSON oracle
from the real `zolana-interface` crate and compared TypeScript against that,
rather than reading the two languages side by side. It closed 33 rows without
changing a source file, which says those rows were open for want of evidence
rather than want of correctness, and it caught a real asymmetry in the merge
codecs that side-by-side reading had twice recorded as parity.

Closed today: the deposit discovery tag moved to the signing pubkey in both
languages; double spending confirmed prevented by execution on the five
instructions that consume UTXOs, `Transact`, `ZoneTransact`,
`ZoneAuthorityTransact`, `MergeTransact`, and `ZoneMergeTransact`; the
zone-authority public leg permitted in both languages; the
end-to-end harness given a real indexer; the wallet viewing-key history made
live; five over-strict guards relaxed to match what the program accepts; and
registry resolution corrected to return the owner tag, which had survived the
deposit-tag fix and would have handed the old value to any sender who looked a
recipient up rather than being told their shielded address.

That last one also stopped the resolved tag moving when a sync delegate rotates
a viewing key, so a scanning wallet's tag now survives delegation and
revocation. The test asserting the opposite was inverted rather than deleted.

Poseidon closed as the largest open risk. Four TypeScript reimplementations
match `zolana-hasher` byte for byte across the arities Rust accepts, which was
not a foregone conclusion: Rust reads its round constants from committed tables
while TypeScript regenerates them from the Grain LFSR, two provenances for the
same 6,798 constants and 819 matrix entries that nothing had ever compared. Two
implementations accepted arities 13 to 16 that Rust rejects and the
`sol_poseidon` syscall caps at 12, so any digest they produced was unverifiable
on chain; both now stop where Rust stops. A generator at
`xtask/src/bin/poseidon-parity.rs` pins the parameters and the digests with 312
tests, and a control edit to one round count fails eight of them.

Three rows nobody has opened, found while covering the `program-libs` gap:
`create_two_inputs_hash_chain` is ported nowhere despite seven Rust callers on
the proof path, and it is not a fold of the single-input chain, so anyone
reaching for `hashChain` twice would compute different values; `keypair`'s
`bigIntToBytes` carries the same silent truncation above 2^256 that was just
fixed in `merkle-tree`; and TypeScript's `OutputUtxo` is unreachable, with no
codec, importer, or export entry.

Queued, not dispatched: a fifth Poseidon copy in `client/src/internal.ts` that
the coverage audit missed and that still carries the over-wide arity table, a
one-line change held only because a worker owns that file; branding
`PreparedZoneAuthority` in both languages, whose public fields let a literal
skip the constructor and its guards; folding three identical Poseidon copies
into one; the 27 uncovered `program-libs` rows; the five rows pointing at the
wrong file; the residual Rust prerequisites; the Merkle semantics questions; the
PR #158 rebase; the WebAssembly differential oracle; and then PKP-00 through
PKP-08.

## Worktree topology

Batches run in isolated worktrees so a drop or a bad commit cannot destroy
another batch's work, and so agents stop contending for one index. The six
branches below converge into `ts-sdk-port`, which is the single pull request.
Nothing is published from a batch branch.

| Worktree | Branch | Batch | Rows |
| --- | --- | --- | ---: |
| `zolana-ts-sdk-port` | `ts-sdk-port` | Integration, plan, client package, reconciliation, scope audit | 22 |
| `zolana-ts-interface-a` | `port/interface-a` | `@zolana/interface` | 36 |
| `zolana-ts-transaction` | `port/transaction` | `@zolana/transaction` | 31 |
| `zolana-ts-keypair` | `port/keypair` | `@zolana/keypair` | 14 |
| `zolana-ts-wallet-misc` | `port/wallet-misc` | wallet, merkle-tree, stragglers | 10 |
| `zolana-ts-programlibs` | `port/program-libs` | the 27 rows the queue omitted. **Complete, verified to merge clean** | 27 |
| `zolana-merge-record` | `fix/merge-user-record-binding` | program defect, **separate** pull request off `main` | 0 |
| (no tree) | `fix/indexed-array-exclusive-highest-value` | protocol-library fix relocated out of the port, **separate** pull request off `main` | 0 |

Both `fix/*` branches are local and unpushed. Push them before removing any
worktree, or the work is lost with it.

Each batch tree carries a copy-on-write clone of the root `node_modules`, which
works because the npm workspace symlinks are relative and therefore resolve
inside whichever tree holds them. The batch trees share
`CARGO_TARGET_DIR=/Users/tilohelius/Workspace/zolana-ts-sdk-port/target`, so a
concurrent cargo run blocks rather than triggering a cold rebuild per tree.

**End-to-end tests do not run while the batches do.** `startLocalStack` offsets
the validator's RPC port but leaves the faucet on its default, so the validator
still opens port 9900 and exits when a second clone or a sibling batch tree
already holds it. Unit, vector,
cross-language, typecheck, build, and export gates are unaffected and remain the
verification standard during a parallel push. The fix belongs to
`test-kit/src/node/index.ts`, which the wallet batch owns.

**Merge rule for the checklist.** The integration branch wins
`review-checklist.md` against any batch branch. Resolve it that way and lift
that batch's row transitions from its own `row-updates/<batch>.md`, which is
where batches are asked to record them. `port/transaction` already conflicts
this way; the other four are clean. The same applies to
`planning/typescript-sdk-port/log/`: entries are per-file precisely so two
branches cannot contend for one, and a batch that edits the table instead of
adding a log file has bypassed that.

Batches keep to their own package to make the merge trivial. Where a batch finds
a defect in another batch's package it records the required change instead of
making it: the fifth Poseidon copy in `client/src/internal.ts` and the
`PreparedZoneAuthority` branding are both being handled that way.

## Current baseline

Current Rust claims and inventory rows use the selected `origin/main`
revision
`43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f` (`43fde8e4`). This revision is
frozen for the plan; later changes to `origin/main` do not change the baseline.
Its `sdk-libs` tree contains 182 tracked paths.

The repository worktree may be older than the frozen revision. Read current
evidence with revision-qualified commands:

```text
git show 43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f:<path>
git ls-tree -r --name-only 43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f sdk-libs
```

Do not derive current claims from the checked-out file at the same path.

## History and evidence

The plan passed through three Rust baselines:

1. The first inventory used local commit
   `2e1d7c815691054f79ac2cbfb372190e61747696` (`2e1d7c8`). It counted 170
   tracked `sdk-libs` paths and assigned wallet actions to `zolana-client`.
2. Public workflows were then inspected at
   [`helius-labs/zolana-examples@4d8c2d1`](https://github.com/helius-labs/zolana-examples/tree/4d8c2d16487a653d163d80b8c7f6e3702ebfdadc/rust-client/examples).
   That examples revision pins Zolana
   `2eba04498ab852e2c3135bf25e20f11e9d28bb2c` (`2eba044`). It provided
   concrete deposit, transfer, withdrawal, private-transaction signing, and
   confirmation workflows.
3. The selected parity baseline is current `origin/main`
   `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f` (`43fde8e4`), with 182 tracked
   `sdk-libs` paths. It separates wallet state and actions into
   `zolana-wallet` and includes `zolana-indexer-api` and
   `zolana-smart-account-client`.

The first plan became stale because it combined an older 170-path inventory
with names learned from examples pinned to a different Rust revision. It listed
exports and broad responsibilities but did not define complete callable
signatures or the create, prove, build, sign, submit, confirm, and sync stages.
It also retained the old `signTransaction` name and client-owned wallet
boundary after current Rust had changed both.

PR
[`helius-labs/zolana#111`](https://github.com/helius-labs/zolana/pull/111)
remains TypeScript implementation reference material. It does not define the
current package graph or override higher-precedence sources.

## Before and after

| Concern | First plan | Refreshed plan |
| --- | --- | --- |
| Rust baseline | Local `2e1d7c8` | Frozen `origin/main` `43fde8e4` |
| Tracked SDK paths | 170 | 182 |
| Wallet ownership | Included in `@zolana/client` | Separate `@zolana/wallet` |
| Indexer schema | Included in generated `@zolana/api` | `@zolana/indexer-api` schema and `@zolana/api` transport |
| Action contract | Export names and broad responsibilities | Exact functions, methods, types, stages, errors, and examples |
| Signing name | `signTransaction` | `signPrivateTransaction` |
| Instruction flow | Deferred to final examples | Defined before implementation and tested independently |

## Start here

Several agents work this plan at once in one worktree. Read [working in a shared
worktree](review-checklist.md#working-in-a-shared-worktree) before your first
edit or commit. It carries the path-ownership, pathspec-commit, and narrow-edit
rules, with the failure that produced each one.

Read the package in this order:

1. [Architecture and API contract](architecture-and-api.md) for package
   boundaries and dependency direction.
2. [Public export manifest](public-exports.md) for the exact callable surface.
3. [Action and instruction API](action-and-instruction-api.md) for complete
   action-level and instruction-level workflows.
4. Read the six inventories for frozen-path coverage and implementation
   disposition: [client](inventory-client.md),
   [wallet](inventory-wallet.md),
   [transaction](inventory-transaction.md),
   [keypair](inventory-keypair.md),
   [supporting crates](inventory-support.md), and
   [indexer and smart account](inventory-indexer-and-smart-account.md).
5. [Examples and PR #111 assessment](examples-and-pr111.md) maps the eight
   public workflows and prior TypeScript work to the current contracts.
6. [Testing and conformance](testing-and-conformance.md) defines parity
   fixtures and independent action-level and instruction-level tests, then
   [security, dependencies, and release](security-and-release.md) defines the
   security and release gates.
7. [Implementation work packets](work-packets.md) assigns ordered,
   non-overlapping implementation work.
8. After the SDK parity gates pass, [proof and key-handling parity
   certification](proof-and-key-parity.md) defines the PKP-00 through PKP-08
   evidence phase.
9. [Production-readiness issues](production-readiness-issues.md) holds the 26
   cross-cutting findings that no single checklist row owns, each scheduled into
   one delivery phase with an owning document or packet and a closing gate.

## Planning documents

- [README](README.md): freezes the baseline, records evidence history, and
  defines navigation and source precedence.
- [Architecture and API contract](architecture-and-api.md): decides package
  ownership, dependencies, runtime boundaries, and deliberate TypeScript
  differences.
- [Public export manifest](public-exports.md): defines the checked root and
  subpath export allowlists with exact TypeScript declarations.
- [Action and instruction API](action-and-instruction-api.md): defines exact
  deposit, transfer, withdrawal, proving, signing, submission, confirmation,
  and sync call sequences.
- [Client inventory](inventory-client.md): maps current transport, RPC, prover,
  and confirmation paths and records moved wallet paths as history.
- [Wallet inventory](inventory-wallet.md): maps wallet state, actions,
  registry, authority, sync, and wallet tests.
- [Transaction inventory](inventory-transaction.md): maps transaction data,
  serialization, spend inputs, transfer construction, slots, and proof inputs.
- [Keypair inventory](inventory-keypair.md): maps shielded key material,
  encryption, hashing, signing, viewing, and keypair errors.
- [Supporting-crate inventory](inventory-support.md): maps merkle-tree,
  program-test, and Zolana API transport paths.
- [Indexer and smart-account inventory](inventory-indexer-and-smart-account.md):
  maps indexer schemas and smart-account instruction helpers.
- [Examples and PR #111 assessment](examples-and-pr111.md): decides how the
  eight pinned workflows and each PR component inform the current port.
- [Testing and conformance](testing-and-conformance.md): defines fixtures,
  byte-level parity, negative and property tests, integration and E2E tests,
  runtime coverage, and CI gates.
- [Security, dependencies, and release](security-and-release.md): defines
  authority boundaries, secret handling, dependency criteria, browser
  constraints, and release controls.
- [Implementation work packets](work-packets.md): defines prerequisites,
  disjoint file ownership, required evidence, and completion criteria.
- [Proof and key-handling parity certification](proof-and-key-parity.md):
  certifies cryptographic behavior after the row review and SDK gates
  pass. It supplements the checklist instead of duplicating its inventory.
- [Production-readiness issues](production-readiness-issues.md): records the
  cross-cutting findings in nine groups, with the evidence behind each one, and
  schedules them into the delivery phases below.
- [Rust SDK changes](rust-sdk-changes.md): records what the port changed in the
  Rust SDK and why, which of those changes break a Rust consumer, and the
  Rust-side defects review found and left open.

## Inventory rules

The inventories must account for the 182 paths returned by:

```text
git ls-tree -r --name-only 43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f sdk-libs
```

Each current path must have exactly one active row or explicit exclusion. Each
active row records:

- Rust path and symbol;
- target TypeScript package/module;
- public symbol or test responsibility;
- observable behavior and invariants;
- primary dependencies;
- typed error mapping;
- fixtures and required unit, property, integration, or E2E tests;
- owning implementation packet;
- disposition: `port`, `reuse`, `internal`, `test-only`, or `not applicable`.

## Source precedence

Use sources in this order. A lower source cannot override a higher source:

1. [`docs/spec.md`](../../docs/spec.md) defines protocol behavior and Zolana
   terminology. For this frozen plan, inspect its `43fde8e4` revision.
2. Rust at frozen revision `43fde8e4` defines current SDK behavior, package
   ownership, and program/interface layouts where the spec does not decide a
   language-level detail.
3. Rust fixtures at `43fde8e4` define observable conformance vectors.
4. The workflows in `zolana-examples@4d8c2d1`, pinned to Zolana `2eba044`,
   define usability evidence. Record differences from current Rust instead of
   copying stale names or ownership.
5. PR #111 is implementation reference material only.

## Delivery sequence

Use these phases in order:

1. Review the rows in [review-checklist.md](review-checklist.md). This phase
   was declared closed on 2026-07-25 and reopened the same day: a coverage
   audit found the queue needs 145 rows rather than 118, with 27 files in
   `program-libs` crates that the SDK depends on carrying no row, and five
   further rows pointing at files that do not hold the behaviour they claim to
   review.
2. Implement actionable adverse findings and independently re-review each
   fix. Resolve specification-authority blockers before treating disputed
   behavior as canonical. This is the active phase.
3. Pass the fixture, CI, browser, package-consumer, action E2E, and instruction
   E2E gates in [testing-and-conformance.md](testing-and-conformance.md).
4. Run PKP-00 through PKP-08 in
   [proof-and-key-parity.md](proof-and-key-parity.md).

The final phase is a cryptographic certification overlay. The checklist remains
the authority for row status and verdicts; its [mutable
baseline](review-checklist.md#mutable-baseline) holds the live counts and the
next eligible row.

Do not trust a row that says `PARITY` without reading its evidence. An audit on
2026-07-25 examined the 36 rows then claiming it and found one supported by an
independent entry naming a reviewer, a commit, and a committed oracle. The rest
recorded a verdict after someone read two files and found them similar. Those
rows were reopened, a CI check now refuses a `done` row whose most recent
verdict-bearing log entry is adverse, and the defensible figure is 1 row of 145.
A row reaches parity when a test, a fixture, or an executed comparison
demonstrates it, and recording that you could not close a row is worth more than
a verdict nobody can check.

Two protocol defects surfaced during review and are tracked outside the queue,
as rows PD-1 and PD-2, because no TypeScript change closes either. Neither
blocks the port.

PD-1, the `user_record` binding in `merge_transact`, is fixed in
[PR #160](https://github.com/helius-labs/zolana/pull/160) off `main`, with 23
checks green, and its tests are removed from this branch by `e16cb841`. Read
the residual before assuming it is closed. The eddsa rail is shut: the record
must sit at its own canonical PDA, which the registry only writes under the
owner's signature. The P256 rail is narrowed rather than shut. A canonical PDA
proves a record belongs to `record.owner`; it does not prove `owner_p256` is
that owner's key, because registration still takes that key as a bare claim.
The PR adds an exclusive first-claim-wins binding per P256 identity, which
defeats the three attacks under test, and leaves one ordering residual: an
impostor who claims a key before its real owner registers keeps it. Closing
that needs a P256 signature over a registration challenge, verified in the
registry, which is a larger change than this defect warranted and needs client
support to produce the signature. Records already carrying an `owner_p256`
have no claim account and need one `update_keys` call each before exclusivity
covers them.

The 26 findings in
[production-readiness-issues.md](production-readiness-issues.md#scheduling) are
sequenced into these phases. Fifteen land in remediation, four are authority
rulings, and seven map onto PKP packets that already own the work. The two
findings about continuous integration, G9-1 and G9-2, come first in remediation:
until a workflow runs the TypeScript scripts and the aggregate `check` script
covers the cross-language and prover suites, the later phases report gate
results that a reviewer cannot reproduce.

## Definition of complete

Base SDK parity is complete only when:

- the `port` and `reuse` inventory rows have an implementation and mapped test;
- the public export snapshot matches the crosswalk;
- Rust-generated fixture bytes and TypeScript bytes match exactly;
- the example workflows pass against localnet, Photon, and the prover;
- Node and browser gates pass for packages marked browser-compatible;
- no core package imports `node:*`, reads `process.env`, or depends on `Buffer`;
- API Extractor (or an equivalent declaration snapshot), TypeScript strict
  checking, lint, unit, property, conformance, integration, and package-consumer
  tests pass;
- security and protocol reviewers approve the invariant checklist.

A complete proof or key-handling parity claim also requires PKP-00 through
PKP-08. The evidence must include native Rust verification of
TypeScript-produced artifacts and real TypeScript prove-to-chain flows through
the same-revision local stack.

## Open questions

Only two repository-external choices remain:

1. NPM scope and publication owner. Default to `@zolana/*` until the owner
   confirms registry access.
2. Minimum supported browser versions. Default to browsers with Web Crypto,
   `BigInt`, ES2022 modules, and `fetch`; publish the exact Browserslist before
   the first release.

Everything else in this plan has a repository-derived default.
