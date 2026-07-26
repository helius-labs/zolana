# TypeScript SDK port handover

The single authoritative statement of what this work is, where it stands, and
what is left. Everything needed to pick it up or review it is here or linked
from here. Written at `efcd3bbc` on `ts-sdk-port`, pull request
[#159](https://github.com/helius-labs/zolana/pull/159).

Other documents in this directory are working records and go stale. This one is
refreshed deliberately. Where they disagree, this one wins, and the commands in
[Verify it yourself](#verify-it-yourself) outrank both.

## Goal

Port the Rust `sdk-libs` to TypeScript with the same behaviour, the same public
surface, and the same test coverage, then prove it rather than assert it.

Three constraints shaped every decision:

- **SDK only.** Solana programs, `program-libs`, and the circuits are read-only.
  Where a defect was found in them it was recorded, not fixed.
- **Evidence over claims.** A parity claim needs a Rust-generated fixture, a
  cross-language oracle, or a live run. "It looks equivalent" closes nothing.
- **Pre-release, so breaking changes are free.** No crate or package here has a
  consumer. Where Rust and TypeScript disagreed and Rust was wrong, Rust moved
  rather than TypeScript bending around it, and no compatibility shim was added
  for a surface nobody depends on. This is why the Rust SDK carries genuine
  behaviour changes inside a TypeScript port, and why no migration note or
  version dance was written for them.

The port is 11 npm packages mirroring the Rust crates, plus `@zolana/hasher`,
which has no Rust twin and carries the Rust Poseidon compiled to WebAssembly so
five hand-written copies could be deleted.

## Status

| | |
| --- | --- |
| Review rows | 148 examined, 0 adverse. The 3 reopened interface rows closed, and the two uncounted packages gained seats |
| Full SDK gates | 14 of 16 checked. The 2 open are named under [Remaining steps](#remaining-steps) |
| Package gates | 5 of 15 bullets checked across all eleven packages |
| Cryptographic certification | All 15 suites landed: key-handling `K1` to `K10`, proof `P1` to `P5`, closing evidence `PKP-08` |
| Branch health | Unit 2301 passing / 9 skipped, static clean, no fixture drift, packaging clean including a real `api:check`, `check:scope` clean |
| External review | 44 findings, 0 invalid. Blockers and High closed. The 31-row tail is triaged and ruled row by row: 12 were already fixed, 16 land here, 1 defers, 1 is dismissed, 1 waits on a Light Protocol check |

### What is proven

Each line below has a named artifact behind it, not a judgement.

| Claim | Evidence |
| --- | --- |
| All eight flows work against real components | [`gate3-flows.md`](row-updates/gate3-flows.md): deposit, registration, sync on a live validator and Photon; split, merge, transfer, withdraw against the real prover. No flow rests on a mock |
| Instruction bytes execute on same-revision programs | [`gate-submit.md`](row-updates/gate-submit.md): four spend flows landed on chain with recorded signatures, through pure TypeScript compression, no Rust fallback |
| The indexer contract matches | [`gate6-photon.md`](row-updates/gate6-photon.md): 11 tests against a same-revision Photon, no field-shape disagreement; the suite fails when a field is deliberately renamed or retyped |
| Both rails cover every shape | [`gate-shapes.md`](row-updates/gate-shapes.md): ten shapes, zone-authority restricted to the four squares, no drift across the four places the set is duplicated |
| Browser support is real | `test:browser-runtime` runs Poseidon, SHA-256, HKDF, AES-CTR, Ed25519, and P256 vectors in headless Chromium, not a static import scan |
| Secret-adjacent accessors don't alias | `keypair/test/vectors/aliasing-census.test.ts` mutates every returned buffer and asserts internal state holds |
| CI runs the tier on pull requests | `.github/workflows/typescript.yml`: eight jobs plus an aggregating `merge-gate` |

### The one defect worth knowing about

G2 proof compression was recorded for days as an accepted cross-language
divergence: TypeScript refused points a live prover produced, Rust's
`alt_bn128_g2_compress_be` accepted them. It was neither accepted nor a
divergence. `compressG2` read each `Fq2` coordinate as `c0` then `c1` while gnark
writes `c1` first, so correct bytes parsed into a genuinely off-curve point and
the curve check refused valid proofs.

Fixed at `c1a9b35e` by reading the limbs in gnark's order; curve validity now
sits with the on-chain verifier, where Rust leaves it. All 16 live proofs
compress in pure TypeScript and match Solana. This had blocked four spend flows
from reaching the chain at all.

The lesson generalises, and it is why the remaining work is framed as evidence
collection rather than documentation: **a comfortable explanation for a failing
check is the most expensive thing in this port.**

### What is not true yet

Claims previously recorded that do not hold, all found by adversarial re-checks:

| Claim | Reality |
| --- | --- |
| The export ledger is enforced | `api:check` is a scaffold. It never parsed `public-exports.md`, so nothing has been guarding the export surface |
| Fixture provenance is fresh | The manifest's `frozenCommit` is ~456 commits behind current Rust. True for no package |
| All 145 rows are closed | Three interface rows, `E03`, `E05`, and `E06`, sit at `needs_re_review` |
| Nine workspace packages | Eleven. `@zolana/hasher` and `@zolana/test-kit` were never counted, so they have had the least scrutiny of anything here |
| `check:scope` describes CI | It omitted the Photon suite that `package.json` already ran. Fixed |

## Remaining steps

### In flight, and not to be duplicated

Each worker owns a git worktree and a branch. **One tree, one branch, one
agent.** Do not touch a path another worker owns; report a gap in it instead.

| Branch | Scope |
| --- | --- |
| `port/example-surface` | Reconcile the client surface onto the example branch, per the ruling below |
| `port/reject-fixtures` | Rust-generated rejection and tamper fixtures for `indexer-api` and `smart-account-client`, closing the last fixture gate line |
| `port/ci-infra` | Strip this port's coordination tooling from the repository and scope the CI graph by path with shared build output |
| `port/f130-light` | Research only: how Light Protocol keeps secret material out of error payloads, before we unify our two contradictory rules |

### Queued, in order

1. **The twelve small behavioural fixes**, ruled row by row and recorded in
   [`authority-rulings.md`](authority-rulings.md#register-tail-the-six-behavioural-rows-are-fixed-in-this-pull-request).
   They are held rather than dispatched because most touch files
   `port/example-surface` is rewriting, and fixing a function while another
   branch moves it means resolving the same conflict twice. Six change
   behaviour: a zero-amount deposit the program always rejects, empty
   instruction data that throws where Rust returns empty bytes, RPC faults
   TypeScript treats as fatal where Rust retries, a byte comparison that calls
   a prefix equal, an airdrop that rounds large amounts, and drift oracles that
   overwrite the baseline they exist to check. Six are smaller: hardcoded page
   limits, a wrong offset in an unread fixture field, an unverifiable fixture,
   a registry copy whose `insert` silently does nothing, an unchecked payer
   hash, and a base58 length brute-force.

2. **Unify error-detail redaction** once the Light Protocol finding lands.
   `keypair` admits an allow-list, `client` keeps arbitrary scalars, so an error
   on the client path can carry data the keypair path would strip. This SDK
   handles secret keys, viewing keys, and decrypted amounts.

3. **Centralize the fixture baseline commit**, which is copied into many files
   instead of defined once. Held until `port/reject-fixtures` releases the
   fixture config.

4. **Re-run the package-gate evidence walk** for the bullets that rest on an
   export census, after the surface reconciliation lands. This is the ordering
   constraint the reconciliation ruling exists to enforce.

5. **Strip `planning/` to a side branch.** Owner ruling: the record survives, the
   pull request diff shows only code, tests, fixtures, and spec amendments. That
   removes ~40,000 lines. Promote this file to the pull request description
   before deleting the directory.

### Needs the owner

| Item | Why it is blocked |
| --- | --- |
| Make `typescript / merge-gate` a required status check on the default branch | Needs repository admin. All eight jobs run on every pull request but none is required, so a red suite does not block a merge today. Requiring the one aggregating job covers the whole tier and survives job renames |

Nothing else is waiting on a decision. Every register row is ruled, every gate
line is owned, and the two open gate lines have workers on them.

### Deferred by ruling

- **The Merkle append copies the whole tree per leaf.** Correct but quadratic for
  bulk appends, and changing it alters how a failure rolls back mid-append.
  Filed rather than taken beside the release.

### Known and accepted

- **Forester `address-append`.** No TypeScript forester ships, so the builder is
  withdrawn while the codec and tag are retained. Owner-ruled unsupported
  capability, not a gap.
- **Program defect `PD-1`.** `merge_transact` under-validates `user_record`
  binding. Confirmed, owner-ruled out of scope for this port, recorded as
  assignable work.
- **Legacy transaction messages.** Four shapes already exceed the 1232-byte
  limit. Address lookup tables make shielded transfers worse rather than better,
  so the recommendation is a size check now and no move to v0 until a second
  pool tree ships. The transaction-level `checkedTransactionSize` is in place.

## Reviewing this

The diff is large because most of it is generated or is test material. Read it in
this order and it is tractable.

| Bucket | Lines | What it is |
| --- | --- | --- |
| TypeScript source | 25,408 | **The port. Start here.** |
| TypeScript tests | 39,775 | Vector, property, oracle, and e2e suites |
| Fixtures and vectors | 40,678 | Rust-generated. Do not read; regenerate and diff |
| Markdown | 40,374 | Working records. Being stripped before merge |
| Rust SDK | 13,996 | Genuine Rust changes. Read these closely; see below |
| `xtask` generators | 19,147 | Rust programs that emit the fixtures |
| Other JSON, config, lockfiles | ~27,000 | Manifests and inventories |

Two things deserve a reviewer's attention disproportionate to their size.

**The Rust changes.** This is a TypeScript port that nonetheless modifies the
Rust SDK, and those edits are the highest-risk lines in the diff because they
alter shipping behaviour rather than adding a second implementation of it. They
exist because parity is symmetric: where TypeScript was right and Rust was wrong,
Rust moved. The two that matter are the P256 RFC 6979 nonce derivation, where
Rust passed an unreduced digest to `generate_k`, and a zero-length dummy
ciphertext that made padded outputs distinguishable on the wire.

A reviewer asked for these to be release-noted and versioned separately. The
owner dismissed that: the crates are pre-release with no consumers, so there is
no migration to describe and nobody to describe it to. Read them as ordinary
fixes, not as a compatibility event.

**The spec amendments.** `docs/spec.md` is the protocol source of truth and it
was amended in a few places where both implementations already disagreed with it
and agreed with each other. Standing rule: amend the spec only where Rust
already implements the amended behaviour. Each amendment is recorded in
[`authority-rulings.md`](authority-rulings.md).

## Verify it yourself

Do not trust the status table. Run these; they are the actual gates.

```bash
npm install && npm run build      # build first; stale dist/ causes phantom failures
npm run test:unit                 # 2290 pass / 9 skip
npm run check:static              # lint and typecheck
npm run fixtures:check            # regenerates from Rust and diffs
npm run check:packaging           # exports, dependencies, publish metadata, pack
npm run check:scope               # prints what each check group actually covers
```

Live suites need a validator, a same-revision Photon, and the prover. Set
`ZOLANA_PORT_OFFSET` to keep clones from contending:

```bash
just build-programs
ZOLANA_PORT_OFFSET=300 npm run test:e2e:gate3    # spend flows to chain
ZOLANA_PORT_OFFSET=800 npm run test:e2e:photon   # indexer contract
```

## Working rules

Learned the expensive way; each carries the failure that produced it.

- **Build before testing.** Stale `dist/` directories caused a day of phantom
  failures across three sessions.
- **One tree, one branch, one agent.** Seven agents once shared a worktree and
  raced each other's commits.
- **Commit with an explicit pathspec.** `git commit -m "..." -- path1 path2`.
  A bare `git add` swept another agent's work into an unrelated commit.
- **Resolve an open question the way Light Protocol resolved it,** unless we have
  a specific reason not to. Recorded when it applies.
- **Verify a finding before acting on it.** External reviews and prior sessions
  both produced claims that did not survive a check.
