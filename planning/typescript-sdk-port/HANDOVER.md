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
| Package gates | 15 of 15 bullets closed on named evidence for every one of the eleven packages, walked in [`gate-packages.md`](row-updates/gate-packages.md) |
| Cryptographic certification | All 15 suites landed: key-handling `K1` to `K10`, proof `P1` to `P5`, closing evidence `PKP-08` |
| Branch health | Unit 2372 passing / 9 skipped, static clean, no fixture drift, packaging clean including a real `api:check`, `check:scope` clean, `rustfmt` clean |
| External review | 44 findings, 0 invalid. Every row is now landed except the two filed as issues: 12 were already fixed, 16 landed here, 1 deferred to [#168](https://github.com/helius-labs/zolana/issues/168), 1 dismissed as pre-release |

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
| The export ledger is enforced | Was a scaffold that never parsed `public-exports.md`. Now real: `api:check` caught twelve undeclared differences on the surface reconciliation and reports a match for all eleven packages |
| Fixture provenance is fresh | The manifest's `frozenCommit` is a deliberate historical pin, hundreds of commits behind current Rust. It is now defined in one file, `sdk-libs/ts/config/historical-baseline-commit`, so moving it moves all eighteen consumers together instead of leaving copies to rot |
| All 145 rows are closed | Three interface rows, `E03`, `E05`, and `E06`, went back to `needs_re_review` and have since closed. 148 rows now, because the two uncounted packages gained seats |
| Nine workspace packages | Eleven. `@zolana/hasher` and `@zolana/test-kit` were never counted, so they have had the least scrutiny of anything here |
| `check:scope` describes CI | It omitted the Photon suite that `package.json` already ran. Fixed |

## Remaining steps

### In flight, and not to be duplicated

Each worker owns a git worktree and a branch. **One tree, one branch, one
agent.** Do not touch a path another worker owns; report a gap in it instead.

| Branch | Scope |
| --- | --- |
| `port/redaction-close` | Convert the last fail-open error-detail sanitizer, in `transaction`, to the same allow-list `keypair` and `client` now use, and audit the other eight packages for a third door |

Everything else has landed and merged: the client surface reconciled onto the
example shape, Rust-generated rejection and tamper fixtures, the coordination
tooling deleted with CI path-filtered onto one shared build, the twelve ruled
behavioural and smaller fixes, the fixture baseline commit defined in one file
that eighteen machine-readable consumers now read, and the per-package gate walk
closing all fifteen bullets on named evidence.

The merged branch is green: 2372 unit tests passing, 9 skipped, static, packaging
with all eleven API reports matching, `check:scope`, `rustfmt`, and fixture
provenance all clean.

### Queued

1. **Strip `planning/` to a side branch.** The last step, once the four live
   branches merge. Owner ruling: the record survives, the pull request diff shows
   only code, tests, fixtures, and spec amendments. That removes ~40,000 lines.
   Promote this file to the pull request description before deleting the
   directory.

2. **Write these buckets into the pull request description**, exactly as below.
   A conceptual map of what lives where, so a reviewer can find things. Not prose,
   not a commit sequence, no explanation per bucket. Counts are approximate and
   only worth refreshing if a bucket has drifted noticeably.

   ```text
   1  chore(spec): protocol authority updates              9 files   ~0.9k
        docs/spec.md, program-libs/interface/**, program-tests/**

   2  chore(ts): workspace, lint, and CI gates            ~30 files  ~6.0k
        package.json, package-lock.json, tsconfig*, eslint, vitest,
        prettier.config.js, .github/**, sdk-libs/ts/config/** (minus process scripts)
        sdk-libs/ts/.gitignore

   3  feat(ts): hasher and keypair                        ~69 files ~11.1k
        sdk-libs/hasher-wasm/**, sdk-libs/ts/hasher/**
        sdk-libs/ts/keypair/**, sdk-libs/keypair/**

   4  feat(ts): interface, merkle-tree, transaction      ~111 files ~36.9k
        sdk-libs/ts/{interface,merkle-tree,transaction}/**
        sdk-libs/{transaction,merkle-tree}/**

   5  feat(ts): indexer-api and api                       ~24 files  ~4.4k
        sdk-libs/indexer-api/**, sdk-libs/ts/{indexer-api,api}/**

   6  feat(ts): client, wallet, smart-account, test-kit  ~162 files ~34.4k
        sdk-libs/ts/{client,wallet,smart-account-client,test-kit}/**
        sdk-libs/{client,wallet,smart-account-client,program-test}/**

   7  test(ts): fixture generators and parity oracles    ~117 files ~63.3k
        xtask/**, tools/wasm-oracle/**, tools/control-edit.mjs
        sdk-libs/ts/{fixtures,vectors}/**, sdk-libs/ts/reports/inventory.json

   8  test(ts): end-to-end suites                         10 files  ~3.2k
        sdk-libs/ts/e2e/**

   9  example(sdk): paired deposit, transfer, withdraw example  8 files ~0.5k
        sdk-tests/rust-client/**, sdk-tests/typescript-client/**
   ```

### Needs the owner

| Item | Why it is blocked |
| --- | --- |
| Make `typescript / merge-gate` a required status check on the default branch | Needs repository admin. All eight jobs run on every pull request but none is required, so a red suite does not block a merge today. Requiring the one aggregating job covers the whole tier and survives job renames |

Nothing else is waiting on a decision. Every register row is ruled, every gate
line is owned, and the two open gate lines have workers on them.

### Filed as follow-up work

Both owner-ruled out of this pull request and now assignable:
[#168](https://github.com/helius-labs/zolana/issues/168) the Merkle append copy,
[#169](https://github.com/helius-labs/zolana/issues/169) the `merge_transact`
`user_record` binding.

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
