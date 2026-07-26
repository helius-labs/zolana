# TypeScript SDK port plan

This directory holds the implementation contract for a TypeScript port of the
Rust SDK, and the record of the review that is certifying it.

**Start with [`remaining-work.md`](remaining-work.md).** It states what is left,
in order, with the check that closes each step. It also carries the two rules
that outrank the work: resolve an open question the way Light Protocol resolved
it, and change SDK code only. Read those before your first edit.

Read [working in a shared worktree](review-checklist.md#working-in-a-shared-worktree)
before your first commit. Several agents work this plan at once, and that
section carries the path-ownership, pathspec-commit, and narrow-edit rules with
the failure that produced each one.

## Status

Do not cite a figure from this table without running the two checks below; it is
refreshed by hand as workers commit and it goes stale within the hour. The gate
reports the row counts and whether the cryptographic phase may start. The health
check reports whether the table itself can be trusted: whether the checklist has
fallen behind the row updates feeding it, whether a worker branch has been left
unmerged, and which agents have stopped writing.

```bash
node sdk-libs/ts/config/pkp-entry-gate.mjs
node sdk-libs/ts/config/port-health.mjs
```

Last update: 2026-07-26 01:40 UTC. Times in this file are true UTC; some earlier
entries wrote the local `+02:00` clock and labelled it UTC.

| | |
| --- | --- |
| Rows the table calls supported | 105 of 145, the figure the gate reports. Seven more are closed on a confirmed `NOT_APPLICABLE` disposition, which the gate counts separately |
| Rows carrying an attributable verdict | 145 of 145. None is unexamined, and each one's verdict is now traceable to a log entry |
| Rows carrying an adverse verdict | 30: 20 `PARTIAL`, 10 `DIVERGENT`. No row is `BLOCKED`, `MISSING`, or `STALE` |
| Rows evidenced, but the table still shows them open | None. The reconciliation backlog is drained as of this update |
| Rows this branch cannot close | None. See [scope-and-denominator.md](scope-and-denominator.md) |
| Branch | 1941 unit tests pass, with vectors, property, cross-language and prover suites alongside them; formatting, typecheck and lint are clean |
| Phase | 2 of 4: remediation, and further into it than the last update read. Phases 3 and 4 not started |
| Entry gate to the cryptographic phase | Criteria 1 and 3 pass. Criterion 2 fails on the 30 adverse rows. Criterion 4 is pending rather than failing: 23 checks pass, none fails, 10 are still running |
| Reconciliation debt | None outstanding. The six row updates named in the last update are folded in, and two of them moved no row |
| Continuous integration | No job is red. One failure mode is designed in and worth knowing before it fires: `typescript / static`, `suites` and `packaging` carry no Rust toolchain, so a change to `program-libs/hasher` without a regenerated `@zolana/hasher` artifact turns all three red on the build's refusal |

**Do not trust a row that says `PARITY` without reading its evidence.** An audit
on 2026-07-25 examined the 36 rows then claiming it and found one supported by
an independent entry naming a reviewer, a commit, and a committed oracle. The
rest recorded a verdict after someone read two files and found them similar.
Those rows were reopened, a CI check now refuses a `done` row whose most recent
verdict-bearing log entry is adverse, and the defensible figure at that moment
was 1 row of 145. A row reaches parity when a test, a fixture, or an executed
comparison demonstrates it. Recording that you could not close a row is worth
more than a verdict nobody can check.

The count then moved from 19 to 105 in one evening, and the rise is not
bookkeeping. It comes from batches that stopped comparing implementations by
reading them and started generating oracles from Rust and replaying them in
TypeScript, most with control edits applied and observed to fail. The reports
worth reading first are the ones that say where a control was *not* caught,
because those name a rule nobody can currently observe. What the number still
does not cover is the SDK as a whole, and the two figures to watch are the 30
adverse rows and the pull request, not this one.

## Worktree topology

Batches run in isolated worktrees so a drop or a bad commit cannot destroy
another batch's work, and so agents stop contending for one index. The branches
below converge into `ts-sdk-port`, which is the single pull request. Nothing is
published from a batch branch.

Live state as of 2026-07-26 01:40 UTC, read from `git worktree list` rather than
from memory. This table has now been short twice: nine trees were missing when
it was audited, and thirteen more were missing when it was checked again an hour
later, so a coordinator reading it saw work as unowned that had an owner. Re-read
the command before trusting a row, and add your own tree when you create it.

**Four directory names no longer describe their contents.** `zolana-ts-keypair`,
`zolana-ts-interface-a`, `zolana-ts-programlibs` and `zolana-ts-wallet-misc`
were each created for one batch and have since been reused for another, so their
names say what the tree was for in the past and nothing about what it holds now.
Read the branch column. Reassigning a tree by its directory name is what caused
the collisions recorded below.

| Worktree | Branch | Work |
| --- | --- | --- |
| `zolana-ts-sdk-port` | `ts-sdk-port` | Integration, plan, reconciliation. The reconciler edits the checklist here, so treat the tree as occupied even when it looks idle. |
| `zolana-ts-transaction` | `port/transaction-b` | remaining `T` rows |
| `zolana-ts-client-b` | `port/client-b` | `C` rows and the zone prover rails. Merged; tree retained until its agent is unresumable |
| `zolana-ts-keypair` | `port/wasm-verify` | verification of the WebAssembly hasher |
| `zolana-ts-interface-a` | `port/versioned-tx` | address lookup tables and v0 messages, study only |
| `zolana-ts-programlibs` | `port/merge-prefix` | discriminator and prefix strictness, the Light way |
| `zolana-ts-wallet-misc` | `port/plan-rewrite` | restructuring these planning documents |
| `zolana-ts-ci` | `port/ci-green` | the failing CI jobs |
| `zolana-ts-interface-b` | `port/interface-b` | `X01`, `S01`, `K12`, `M02`. Unmerged, and steps 7 and 8 wait on it |
| `zolana-ts-hasher-pkg` | `port/hasher-pkg` | the `@zolana/hasher` packaging change that replaced the withdrawn artifact CI gate |
| `zolana-ts-spec` | `port/spec-amend` | `docs/spec.md` amendments the owner has authorised |
| `zolana-ts-reconcile` | `port/reconcile` | folding row updates into the checklist. Merged |
| `zolana-ts-reconcile2` | `port/reconcile2` | the same, second holder. Merged |
| `zolana-ts-reconcile3` | `port/reconcile3` | the same, fourth holder, and the plan status block. **Occupied.** The reconciler is the single writer of `review-checklist.md`; do not edit that file from another tree |
| `zolana-ts-rulings` | `port/rulings` | recorded the G7-1, X01, K11, T23 and C04 rulings. Merged; tree retained until its agent is unresumable |
| `zolana-ts-rulings2` | `port/rulings2` | the ledger's spec-authorisation wording. Merged |
| `zolana-ts-rulings-impl` | `port/rulings-impl` | implementing the ruled behaviour, six rulings reported and two halves handed off. Unmerged |
| `zolana-ts-rulings-audit` | `port/rulings-audit` | auditing whether each ruling is recorded, reflected, queued, and landed |
| `zolana-ts-stragglers` | `port/stragglers` | the eight rows no batch owned: `C01`, `C02`, `C03`, `C05`, `T14`, `T15`, `W02`, `W04` |
| `zolana-ts-t28-close` | `port/t28-close` | `T28`'s three clauses, normalising the explicit zero and pinning the split in both suites. Unmerged |
| `zolana-ts-txsurface` | `port/tx-surface` | `T10` and the transaction export surface. Unmerged |
| `zolana-ts-zone-read` | `port/zone-read` | zone read paths, currently carrying merges of `port/tx-surface` and `port/reconcile2`. Unmerged |
| `zolana-ts-keycert` | `port/key-cert` | `K1`-`K5` key certification. Unmerged |
| `zolana-ts-cryptob` | `port/crypto-b` | `K6`-`K10` certification vectors generated from production Rust. Unmerged |
| `zolana-ts-rfc6979` | `port/rfc6979` | the P256 prehash reduction before RFC 6979 nonce generation, and the signer the transaction crate uses. Unmerged |
| `zolana-ts-green` | `port/green` | suite repairs. Merged |
| `zolana-ts-green2` | `port/green2` | the same, second holder, plus the browser gate's reading of the word "process". Unmerged |
| `zolana-ts-overlap` | `port/overlap-detect` | `port-health.mjs` and what a tree collision costs. Merged |
| `zolana-ts-handoff` | `port/handoff` | integration merges. **Note:** it also committed to `review-checklist.md`, which the reconciler owns |
| `zolana-merge-record` | `fix/merge-user-record-binding` | program defect, **separate** pull request off `main` |
| (no tree) | `fix/indexed-array-exclusive-highest-value` | protocol-library fix relocated out of the port, **separate** pull request off `main` |

Both `fix/*` branches are local and unpushed. Push them before removing any
worktree, or the work is lost with it.

`port/open-questions` was listed here as an unmerged tree and is neither: the
branch is gone from this clone and from `origin`, and its work, the
open-questions register, the C04 integer domain, and the transaction size
measurement, is in `ts-sdk-port`. A row that says "unmerged" is a claim on
someone's attention, so check the branch still exists before acting on one.

### One tree, one branch, one agent

This rule has been learned three times in one evening, each time at the cost of
nearly losing work. A worktree may hold one branch, and a branch may have one
agent. The failure is not dramatic when it happens: the second agent's `git
checkout` silently moves the first agent's `HEAD`, the first agent keeps editing
files it believes are on its own branch, and the damage surfaces only at commit
time.

Two specific mistakes produced it, both in reassigning trees rather than in
anything the agents did. A finished batch's tree was handed to a new batch while
the finished batch's agent could still be resumed, and it was resumed. And the
tree kept its old batch's name, so an agent reading its own working directory
reasonably concluded the tree belonged to someone else.

So: do not reassign a worktree while its previous agent can still be resumed,
and check `git worktree list` for the branch rather than trusting a directory
name. Prefer creating a new tree over reusing one; a worktree costs a copy of
`node_modules` and a collision costs an hour.

**How it looks from inside.** When another agent checks out a branch in the tree
you are working in, you do not get a git message. You get 91 TypeScript test
files failing to collect at once, because the checkout replaced the workspace
package links. That reads exactly like the stale `node_modules/.vite` cache this
project has hit before, and the reflex is to clear the cache and rebuild. Before
doing that, run `git branch --show-current`. If it is not your branch, clearing
caches will not help and rebuilding will write your work onto someone else's
branch.

### Detecting staleness and dead agents

Two things go wrong here without announcing themselves, and both were found by
accident before they were found on purpose.

An agent dropped by the platform writes no error and no closing record. Its
transcript stops on whatever it was saying. Three agents died that way in one
evening and were noticed only because their branches happened to sit at the same
commit. Separately, a document that was accurate when written goes stale without
changing, so it keeps reading as true: the review checklist sat frozen for over
an hour while seven row updates piled up behind it, and because the entry gate
reads the checklist, the gate was answering from a count that no longer held.

`node sdk-libs/ts/config/port-health.mjs` checks both. It exits non-zero when
something needs attention and names it: agents that stopped writing, row updates
that landed after the checklist last moved, worker branches left unmerged, and a
status block whose numbers predate the branch they describe.

Two cautions, both learned by getting it wrong. A finished agent and a dead one
look similar in the text; what separates them is that a finished agent writes a
closing record. Reading the prose instead marked two agents dead that had in fact
reported back. And transcript writes lag behind the work, badly enough that one
agent appeared silent for seventeen minutes while committing at two-minute
intervals. Quiet is a reason to check the branch, not a death certificate.

**The branch guard has a blind spot, and it was found the hard way.** It compares
the current branch against the expected one, which catches a worktree taken over
by an agent that checks out something else. It does not catch two agents working
the same branch in the same tree, because the branch name stays right the whole
time; what changes underneath is the working tree. That happened twice tonight,
once when a coordinator relaunched agents it had wrongly judged dead. The signal
in that case is a file you have open being rewritten by someone else, or commits
appearing on your branch that you did not make. Check `git log` for authorship
you do not recognise, not just `git branch --show-current`.

**What made the recoveries cheap.** Each of the three cost work only in the time
spent recovering, because commits were guarded by a branch check before landing.
In the third case that guard is what saved it: two code commits landed correctly
and the documentation commit refused to land on the wrong branch. Keep the guard
in the worker prompts. It is the difference between an interruption and a loss.

Each batch tree carries a copy-on-write clone of the root `node_modules`, which
works because the npm workspace symlinks are relative and therefore resolve
inside whichever tree holds them. The batch trees share
`CARGO_TARGET_DIR=/Users/tilohelius/Workspace/zolana-ts-sdk-port/target`, so a
concurrent cargo run blocks rather than triggering a cold rebuild per tree.

**Merge rule for the checklist.** The integration branch wins
`review-checklist.md` against any batch branch. Resolve it that way and lift
that batch's row transitions from its own `row-updates/<batch>.md`, which is
where batches are asked to record them. The same applies to
[`log/`](log/): entries are per-file precisely so two branches cannot contend
for one, and a batch that edits the table instead of adding a log file has
bypassed that.

Batches keep to their own package to make the merge trivial. Where a batch finds
a defect in another batch's package it records the required change instead of
making it.

## Current baseline

Current Rust claims and inventory rows use the frozen `origin/main` revision
`43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f` (`43fde8e4`). Later changes to
`origin/main` do not move it. Its `sdk-libs` tree holds 182 tracked paths.

The checked-out worktree may be older or newer, so read current evidence with
revision-qualified commands rather than from the file at the same path:

```text
git show 43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f:<path>
git ls-tree -r --name-only 43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f sdk-libs
```

The inventories account for those 182 paths. Each current path has exactly one
active row or an explicit exclusion, and each active row records the Rust path
and symbol, the target TypeScript module, the public symbol or test
responsibility, the observable behaviour and invariants, the primary
dependencies, the typed error mapping, the fixtures and tests, the owning
packet, and a disposition of `port`, `reuse`, `internal`, `test-only`, or
`not applicable`.

[`archive/plan-history.md`](archive/plan-history.md) records the two earlier
baselines and why the first plan went stale.

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

This order settles which revision of a source to read for the frozen plan, and
it stops at the SDK. It leaves out the deployed program, the circuit, and the Go
prover, which are the authorities that decide the hardest conflicts, so it is
the shorter of the two orders this plan carries and the narrower one. Where the
two appear to disagree, the full order in
[`proof-and-key-parity.md`](proof-and-key-parity.md#authority-and-conflict-policy)
governs, and the list above extends it at the bottom rather than competing with
it. That reconciliation is the first half of finding G7-2.

Neither order settles a conflict between two implementations that both claim to
follow it. That is what [`authority-rulings.md`](authority-rulings.md) is for,
and it is the second half of G7-2.

## Planning documents

| Document | What it decides or records |
| --- | --- |
| [remaining-work.md](remaining-work.md) | What is left, in order, with the check that closes each step |
| [review-checklist.md](review-checklist.md) | The 145 rows, their verdicts, and the shared-worktree rules. A reconciler owns it |
| [authority-rulings.md](authority-rulings.md) | One section per disputed behaviour, with the owner's ruling and the artifacts a change would touch |
| [scope-and-denominator.md](scope-and-denominator.md) | Why no row is terminal, and the route for the findings that are genuinely outside |
| [architecture-and-api.md](architecture-and-api.md) | Package ownership, dependencies, runtime boundaries, and deliberate TypeScript differences |
| [public-exports.md](public-exports.md) | The checked root and subpath export allowlists, with exact declarations |
| [action-and-instruction-api.md](action-and-instruction-api.md) | Exact deposit, transfer, withdrawal, proving, signing, submission, confirmation, and sync call sequences |
| [testing-and-conformance.md](testing-and-conformance.md) | Fixtures, byte-level parity, negative and property tests, runtime coverage, and the CI tiers |
| [security-and-release.md](security-and-release.md) | Authority boundaries, secret handling, dependency criteria, browser constraints, and release controls |
| [proof-and-key-parity.md](proof-and-key-parity.md) | PKP-00 through PKP-08, the cryptographic certification phase |
| [production-readiness-issues.md](production-readiness-issues.md) | 26 cross-cutting findings that no single row owns, each scheduled into a phase |
| [light-protocol-comparison.md](light-protocol-comparison.md) | Eleven findings against Light's SDK, read from source with a path and line per claim |
| [rust-sdk-changes.md](rust-sdk-changes.md) | What the port changed in the Rust SDK, which changes break a Rust consumer, and the Rust-side defects left open |
| [review-2026-07-24.md](review-2026-07-24.md) | A frozen audit. Do not update it |
| The six inventories | Frozen-path coverage and disposition: [client](inventory-client.md), [wallet](inventory-wallet.md), [transaction](inventory-transaction.md), [keypair](inventory-keypair.md), [supporting crates](inventory-support.md), [indexer and smart account](inventory-indexer-and-smart-account.md) |
| [row-updates/](row-updates/) | One file per batch, holding its row transitions and the findings behind them |
| [log/](log/) | One file per review, per fix, per reconciliation. A reconciler owns it |
| [archive/](archive/) | Documents superseded by the work they planned, kept for the record |

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
PKP-08, including native Rust verification of TypeScript-produced artifacts and
real TypeScript prove-to-chain flows through the same-revision local stack.

## Open questions

Two repository-external choices remain, and both have a working default:

1. NPM scope and publication owner. Default to `@zolana/*` until the owner
   confirms registry access.
2. Minimum supported browser versions. Default to browsers with Web Crypto,
   `BigInt`, ES2022 modules, and `fetch`; publish the exact Browserslist before
   the first release.

The address lookup table question is larger than either and is tracked as step A
of [`remaining-work.md`](remaining-work.md#step-a-decide-about-address-lookup-tables-and-versioned-transactions).
