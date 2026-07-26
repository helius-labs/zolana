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
request; `PD-2` is PR #160. `PD-1` is ruled `2026-07-26` to stay unwritten under
this run: do not open a branch for it. It is recorded as owed and assignable in
[`scope-and-denominator.md`](scope-and-denominator.md#pd-1-is-owed-and-assignable).

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

## The T28 normalization is split, and only one half is taken

The owner ruled on 2026-07-26 to normalize an explicitly-passed zero rather than
refuse it. Recording that ruling surfaced a distinction the question had blurred:
it names the zone address, while the counterargument it dismisses belongs to the
zone data hash, and the two clauses do not cost the same. The owner confirmed the
split the same day: **the data hash half only.**

**The data hash half is implemented**, in both languages. Normalizing an explicit
zero there moves no commitment, so it is the tidying the ruling describes.

**The zone address half is not taken, and is not open.** No normalization, no
refusal, no warning. A UTXO built today with `Some([0u8; 32])` commits to
`pk_field(0)`, a non-zero field, so the circuit treats it as zone-bound;
normalizing the address turns that into an unbound UTXO, which changes what the
commitment says rather than how a caller spells it. Such a UTXO can never settle
on chain, per [`row-updates/t28-zone-binding.md`](row-updates/t28-zone-binding.md),
so nothing is stranded by leaving it alone and nothing is bought by moving it.
Both halves are pinned by tests that fail if the address is normalized later.
[`authority-rulings.md`](authority-rulings.md#q10-an-explicitly-passed-zero-at-a-zone-binding-t28)
carries the reasoning.

**A third clause was briefly circulated and is withdrawn.** A coordinator task
sent on 2026-07-26 told a worker that the one thing left on T28 was refusing a
zone data hash at or above the BN254 modulus. Do not implement that. Both
languages already refuse such a hash by deferring to the Poseidon range check
rather than validating up front: Rust maps `light_poseidon` failures to
`TransactionError::Poseidon` in `sdk-libs/transaction/src/utxo.rs:12-18`, and
TypeScript reaches the same category through `commitmentPoseidon` in
`ts/transaction/src/internal.ts:114-115`. Adding an early refusal to TypeScript
alone would move the rejection earlier while Rust stayed put, manufacturing the
"TypeScript stricter than Rust" divergence this port has already been caught by
once on the zone read path. The clause is Rust-first or simultaneous, and Rust is
out of scope.

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

## When a commit hangs, it is the signing key

`commit.gpgsign` is on. When the agent's cached passphrase expires, `git commit`
launches pinentry, pinentry finds no terminal it can prompt on, and the command
sits there until something times it out. Thirty minutes, in the case that
prompted this note.

The damage is not the wait. An agent that commits incrementally hits this on its
first commit and stops there, holding everything in its working tree, and it
looks exactly like a dropped agent: transcript quiet, branch not moving, tree
dirty. Three agents were diagnosed as dead and relaunched on 2026-07-26 before
anyone read the actual error, and all three stalled again for the same reason,
because relaunching does not unlock a key. Two and a half hours.

The tell that separates it from a real drop: the health check reports no branch
activity while the transcripts keep growing. A dropped agent stops doing both.

`gpgconf --kill gpg-agent` clears a wedged agent and the next commit re-prompts
cleanly. Signing may then work again. If it does not, commit unsigned and keep
going. The standing instruction is not to stop when signed checkpoints stop
working, and an unsigned commit that exists beats a signed one that does not.

## A failure mode that has already cost us

Do not commit another worktree's uncommitted files. Twice on 2026-07-26 an agent
was reported dead by the health check while it was in fact working, and its tree
was committed under a message naming the wrong author. Nothing was lost, but the
history is now wrong in two places. A quiet transcript is not evidence of death:
confirm against branch activity first, and prefer leaving work uncommitted to
committing it on someone else's behalf.

## Do not relaunch a worker on a transcript reading alone

Later the same day the coordinator made the sharper version of that mistake.
Three workers showed one assistant record each and no growth for forty minutes,
their branches carried no commits, and their trees were clean. Read together
those look conclusive. They were not: the transcripts were lagging behind
processes that were reading files and about to commit. Interrupting produced a
second instance of each worker in the same worktree, on the same branch, racing
the first.

One of the three detected it and stopped without editing, which is the behaviour
to copy. It noticed files changing underneath it mid-read, checked the branch
rather than assuming a stale buffer, found three commits it had not made at
roughly two-minute intervals, and reasoned that the agent it was told had hung
was in fact alive. Its read survives as
[row-updates/transaction-independent-read.md](row-updates/transaction-independent-read.md).

The tell that separates a lagging transcript from a dead process is not in the
transcript. Interrupt only when the branch has also been still, and when the
worktree has no staged or modified files, and prefer waiting another interval to
acting on the first quiet reading. An interrupt is not free: it costs a duplicate
that has to notice its own redundancy before it damages something.
