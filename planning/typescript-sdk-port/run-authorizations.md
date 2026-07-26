# Standing authorizations for the unattended run

Ruled by the protocol owner, 2026-07-26, to let this port run to completion
without stopping at decisions no worker is allowed to take. Every entry below is
a decision already made. Act on it; do not reopen it.

These sit alongside [`authority-rulings.md`](authority-rulings.md), which records
per-conflict rulings. This file records the blanket permissions that apply to
whatever conflict you happen to hit.

## What you may change

The port's standing rule was SDK code only, and it blocked real fixes: the Rust
size check needs a `ClientError` variant that `xtask` must match, and C18's shape
narrowing reaches a constant outside `sdk-libs`.

**Rust SDK crates and `xtask` are now in scope.** Change them when a fix
genuinely requires it, and say in your report that you did.

**Programs and circuits are still out of scope.** If a fix needs one, stop and
record it as a finding with the change it would take. Two program defects,
`PD-1` and `PD-2`, already sit outside this port and each gets its own pull
request; `PD-2` is PR #160.

## Amending the specification

You may amend `docs/spec.md` without asking, under one condition that is narrower
than the pattern the earlier rulings followed.

**The test is Rust, specifically.** Amend the specification when Rust already
implements the behaviour the amendment describes. That the implementations agree
with each other is not sufficient on its own: Rust has to be one of them, and it
has to already do the thing you are about to write down.

Where Rust does not yet implement it, the specification stays as it is and the
divergence gets recorded instead. Record every amendment in
[`authority-rulings.md`](authority-rulings.md) with the evidence that Rust
implements it.

## When Rust is the defective side

The authority order puts current Rust above TypeScript, which settles ordinary
disagreements. Certification exists to find defects, and some of them will be in
Rust. The missing transaction size check already is one.

**Fix both languages together and flag it prominently.** Matching TypeScript to
a Rust defect preserves parity while shipping the defect twice, which is the
outcome this phase exists to prevent. Keeping the two in step matters, so neither
side moves alone.

## The local stack

Certification requires native Rust verification of TypeScript-produced proof
artifacts, and real prove-to-chain evidence through a same-revision local stack.

**Run it.** Start localnet, photon and the prover, and download the proving keys
the run needs. It is slow and it is the only way the evidence means anything.
Honour `ZOLANA_PORT_OFFSET` so a run does not contend with another clone; see
`CLAUDE.md`.

## Continuous integration and the Rust toolchain

`@zolana/hasher` compiles `program-libs/hasher` during its build, and the three
TypeScript CI jobs have no Rust toolchain, so a contributor who commits Rust
without the regenerated artifact turns those jobs red on a refusal message.

**Install the Rust toolchain in those jobs.**

## A suite you cannot certify honestly

**Certify what can be certified, document each gap precisely, and finish.** A gap
entry names what is missing, why it cannot be produced here, and what would close
it. Do not block the phase on it, and do not paper over it: a suite recorded as
passing on evidence that does not support it is worse than one recorded as owed,
because the false one gets cited later.

## The evidence standard, if it conflicts with finishing

**Hold the standard.** Fixtures generated from real Rust, replayed in TypeScript,
with a control edit proving each suite can detect a divergence rather than merely
pass.

An audit on 2026-07-25 walked the paper trail behind 36 rows claiming parity and
found one that was supported. That is what this standard exists to prevent, and
finishing on time is not a reason to relax it. An honest partial certification is
worth more than a complete one nobody can trust.

## PR #158

**Rebase onto it when a fix needs the files it touches**, and record that you did.
It conflicts with `sdk-libs/client` files that pending fixes reach, and no rebase
step existed anywhere in the plan until now.

## How many workers run at once

**Four.** Six agents were dropped by the platform on the evening of 2026-07-25,
several while seven ran concurrently, and the rework and collisions cost more
than the parallelism returned. Four is the cap until something finishes.

## The pull request at the end

**Leave PR 159 open and green for review; do not merge it.** Grouping its history
by subject was considered and dropped on 2026-07-26: finishing the stages is
worth more than a navigable log, and rewriting history under agents that are
still committing would be unsafe anyway.

## Build before you run the suite

`npm run build`, then the tests. Packages resolve each other through their
`exports` maps, so `@zolana/api` reads `@zolana/indexer-api`'s built output
rather than the sources beside it. A `dist` left over from before a change
produces failures that look like logic errors and cannot be found by reading the
source, because the source is correct.

This cost roughly an agent-hour on 2026-07-26. Nineteen tests were reported
failing, a worker was dispatched to judge each one, and a clean rebuild passed
all of them. The tell was a test flipping across a merge whose diff over both
packages was empty: a merge does not rebuild `dist`.

## A failure mode that has already cost us

Do not commit another worktree's uncommitted files. Twice on 2026-07-26 an agent
was reported dead by the health check while it was in fact working, and its tree
was committed under a message naming the wrong author. Nothing was lost, but the
history is now wrong in two places. A quiet transcript is not evidence of death:
confirm against branch activity first, and prefer leaving work uncommitted to
committing it on someone else's behalf.
