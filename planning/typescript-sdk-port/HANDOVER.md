# TypeScript SDK port handover

The single authoritative statement of what this work is, where it stands, and
what is left. Everything needed to pick it up or review it is here or linked
from here. Written against `ts-sdk-port` at `02e76a03`, pull request
[#159](https://github.com/helius-labs/zolana/pull/159).

`planning/` is stripped from the pull request branch so the diff shows only
code, tests, fixtures, and spec amendments. This record lives on the side
branch `ts-sdk-port-planning-record` (refresh branch `port/handover-refresh`).

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

**Ready for production** means a green, reviewable pull request with correct
publish metadata. Publishing happens separately after merge.

## Status

Pinned to `ts-sdk-port` `02e76a03`. TypeScript CI run
[30212983164](https://github.com/helius-labs/zolana/actions/runs/30212983164)
is green end to end, including `typescript / e2e` and `typescript / merge gate`.

| | |
| --- | --- |
| Review rows | 148 examined, 0 adverse. All seats filled; `E03`/`E05`/`E06` closed |
| Full SDK gates | 16 of 16 checked in [`review-checklist.md`](review-checklist.md) with named evidence. Several live-prove lines were recorded outside CI; see [What is not true yet](#what-is-not-true-yet) |
| Package gates | 15 of 15 bullets closed on named evidence for every one of the eleven packages, walked in [`gate-packages.md`](row-updates/gate-packages.md) |
| Cryptographic certification | All 15 suites landed: key-handling `K1` to `K10`, proof `P1` to `P5`, closing evidence `PKP-08` |
| Branch health | Unit 2392 passing / 9 skipped (`test:unit` in that CI run). Static, fixtures, packaging (including `api:check`), `check:scope`, `rustfmt`, and browser-runtime all green. Suites and e2e no longer red |
| External review | 44 findings were raised against the PR. High and blocker rows were handled on this branch. Owner ruling for the remaining Medium and Low findings (~two dozen): file as follow-up issues after merge, do not fix in this PR. Program defects already filed: [#168](https://github.com/helius-labs/zolana/issues/168), [#169](https://github.com/helius-labs/zolana/issues/169) |

### What is proven

Each line below has a named artifact behind it, not a judgement.

| Claim | Evidence |
| --- | --- |
| All eight flows work against real components | [`gate3-flows.md`](row-updates/gate3-flows.md): deposit, registration, sync on a live validator and Photon; split, merge, transfer, withdraw against the real prover. No flow rests on a mock. Suite still skips in CI until the opt-in wiring lands |
| Instruction bytes execute on same-revision programs | [`gate-submit.md`](row-updates/gate-submit.md): four spend flows submitted and confirmed with recorded signatures, through pure TypeScript compression, no Rust fallback |
| The indexer contract matches | [`gate6-photon.md`](row-updates/gate6-photon.md): 11 tests against a same-revision Photon, no field-shape disagreement; the suite fails when a field is deliberately renamed or retyped. A later local-only failure was a stale SBF binary, not a branch defect (harness now honours `CARGO_TARGET_DIR` and names the `just` recipe when a stack binary is missing) |
| Both rails cover every shape | [`gate-shapes.md`](row-updates/gate-shapes.md): ten shapes, zone-authority restricted to the four squares, no drift across the four places the set is duplicated |
| Browser support is real | `test:browser-runtime` runs Poseidon, SHA-256, HKDF, AES-CTR, Ed25519, and P256 vectors in headless Chromium, not a static import scan |
| Secret-adjacent accessors don't alias | `keypair/test/vectors/aliasing-census.test.ts` mutates every returned buffer and asserts internal state holds |
| CI runs the merge tier on pull requests, and it is green | `.github/workflows/typescript.yml`: nine jobs plus aggregating `merge-gate`. Latest run on `ts-sdk-port` succeeded for every job including e2e |
| Paired SDK examples run in CI | TypeScript example via `test:e2e:example`; Rust `deposit_transfer_withdraw` via `cargo run -p client-example` in the e2e job (both green in run 30212983164) |

CI posture versus Light Protocol is recorded in
[`ci-comparison.md`](ci-comparison.md).

### Landed since the last accurate handover

Do not re-do these; they are on `ts-sdk-port` at the pin above.

| Change | Why it mattered |
| --- | --- |
| Suites CI timeout fixed | Cold `cargo` compile of `groth16-verify` inside a test timed out the suites job. Vitest `globalSetup` (and a CI pre-build step) now build the oracle once |
| E2e negative-signer test fixed | `createTestNativeSigner` had a catch-all that signed signature slot zero for a key that was not a required signer. It now refuses via the production signer path |
| Base58, base64, compact-u16 on `@zolana/interface` | Wallet base64 accepted unpadded and non-canonical input; both compact-u16 decoders accepted Solana Alias encodings and u16 overflow that `solana_short_vec` rejects. Hex left duplicated on purpose |
| Paired-example surface alignment | Actors are `sender`/`recipient` in both languages; TypeScript uses `SppProofInputUtxo`, `wait()`, and `assets`; `decryptTransactions` returns `Balances` with `getBalance(mint)`; Rust `WithdrawalTarget::Sol` field is `recipient`. Earlier: `assembleZoneAuthorityProofInputs`, `VIEW_TAG_LEN` |
| Photon e2e harness hardening | Honours `CARGO_TARGET_DIR`; refuses loudly with the matching `just` recipe when a stack binary is missing; `ClientError.message` carries structured details for runners that only print the message |
| `planning/` stripped from the PR branch | Record kept on `ts-sdk-port-planning-record` |
| Fail-closed error-detail allow-list | Shared allow-list across keypair, client, wallet, and transaction (`port/redaction-close`) |

### The one defect worth knowing about

G2 proof compression was recorded for days as an accepted cross-language
divergence: TypeScript refused points a live prover produced, Rust's
`alt_bn128_g2_compress_be` accepted them. It was neither accepted nor a
divergence. `compressG2` read each `Fq2` coordinate as `c0` then `c1` while gnark
writes `c1` first, so correct bytes parsed into a genuinely off-curve point and
the curve check refused valid proofs.

Fixed at `c1a9b35e` by reading the limbs in gnark's order; curve validity now
sits with the Solana program verifier (`groth16-solana`), where Rust leaves it.
All 16 live proofs compress in pure TypeScript and match Solana. This had
blocked four spend flows from submitting at all.

The lesson generalises, and it is why the remaining work is framed as evidence
collection rather than documentation: **a comfortable explanation for a failing
check is the most expensive thing in this port.** It is also why P4 must run the
**full** shape set on every pull request once wired: P4 is the only suite that
proves a TypeScript-produced and TypeScript-compressed proof verifies through
the same `groth16-solana` path the program uses, and this class of bug slipped
through while that suite stayed opt-in. Why this cost stays versus Light:
[`ci-comparison.md`](ci-comparison.md) §3 (“Why full P4 stays”).

### What is not true yet

| Claim | Reality |
| --- | --- |
| The four opt-in live suites run on every PR | Still env-gated and skipped in CI. Latest green e2e run skipped `prove-to-chain.live.test.ts` and `gate3-flows.live.test.ts`. Wiring is in flight on `port/surface-close` |
| P4's full shape set is a PR gate | Local evidence exists (`test:p4:full` in [`gate-prover.md`](row-updates/gate-prover.md)). CI does not set `ZOLANA_TEST_P4` / `_FULL` yet. Owner ruling: when wired, PRs run the **full** set, not the fast subset |
| `typescript / merge-gate` is a required status check | Jobs run on every matching PR but none is required. Needs repository admin. [`ci-comparison.md`](ci-comparison.md) §6: Light Protocol also has no API-visible required checks on `main`, so this is not a gap relative to them |
| The pull request description is the review map | The nine-bucket reading-order skeleton is already in the PR body. A fuller description organized into those buckets (this handover promoted into the PR) is still to be written |
| Packages are published / production-shipped | Publish metadata and pack checks exist. Publishing is a separate step after a green, reviewable PR |
| The export ledger is enforced | Was a scaffold. Now real: `api:check` matches for all eleven packages |
| Fixture provenance is "current Rust" | The manifest's `frozenCommit` is a deliberate historical pin. Defined once in `sdk-libs/ts/config/historical-baseline-commit` for all consumers |
| Early gate adjudications still describe HEAD | [`gates.md`](row-updates/gates.md) marked gates OPEN/PARTIAL on an older revision. Prefer the checked boxes and evidence links in `review-checklist.md`, then re-run the commands below before citing a gate |

## Remaining steps

### In flight, and not to be duplicated

Each worker owns a git worktree and a branch. **One tree, one branch, one
agent.** Do not touch a path another worker owns; report a gap in it instead.

| Branch | Scope |
| --- | --- |
| `port/surface-close` | (1) Wire P4 (full shapes), P5, P5-hybrid, Gate 3, and live user-registry into CI on every PR. (2) Keep `initializePoseidon` on `@zolana/hasher` only. (3) Move `attempts` / `backoff` / `pollUntil` to `@zolana/client/retry`; rename over-generic `Data` to `OutputData`; document which `createAndSendTransaction` to prefer. Rust paired example already runs green in CI on `ts-sdk-port`; treat that confirmation as done unless the worker finds a regression |

### Queued after this PR merges (owner rulings)

1. **File the remaining Medium and Low findings as follow-up issues.** Roughly
   two dozen. Do not fix them in [#159](https://github.com/helius-labs/zolana/pull/159).
2. **Follow-up PRs for CI hygiene:** actionlint, Dependabot, and CodeQL. Wanted;
   not part of this PR. Context and prioritization in
   [`ci-comparison.md`](ci-comparison.md) §8.
3. **Write the fuller pull request description** as a reading order over the
   diff, organized into the nine buckets below. Not a commit sequence. The
   skeleton is already in the PR body; promote substance from this file.

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
| Make `typescript / merge-gate` a required status check on the default branch | Needs repository admin. All tier jobs run on matching pull requests but none is required, so a red suite does not block a merge today. Requiring the one aggregating job covers the whole tier and survives job renames. Not a relative gap versus Light Protocol (see [`ci-comparison.md`](ci-comparison.md) §6) |

Nothing else is waiting on a decision. Every register row is ruled. Opt-in-suite
CI policy (full P4 on PRs, plus P5 / hybrid / Gate 3 / user-registry) is ruled
and owned by `port/surface-close`.

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
| TypeScript tests | 39,875 | Vector, property, oracle, and e2e suites |
| Fixtures and vectors | 40,678 | Rust-generated. Do not read; regenerate and diff |
| Markdown | stripped from PR | Working records on `ts-sdk-port-planning-record` |
| Rust SDK | 13,996 | Genuine Rust changes. Read these closely; see below |
| `xtask` generators | 19,147 | Rust programs that write the fixtures |
| Other JSON, config, lockfiles | ~27,000 | Manifests and inventories |

Two things deserve a reviewer's attention disproportionate to their size.

**The Rust changes.** This is a TypeScript port that nonetheless modifies the
Rust SDK, and those edits are the highest-risk lines in the diff because they
alter shipping behaviour rather than adding a second implementation of it. They
exist because parity is symmetric: where TypeScript was right and Rust was wrong,
Rust moved. The two that matter are the P256 RFC 6979 nonce derivation, where
Rust passed an unreduced digest to `generate_k`, and a zero-length dummy
ciphertext that made padded outputs distinguishable in the serialized bytes.

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
npm run test:unit                 # 2392 pass / 9 skip at the CI pin above
npm run check:static              # lint and typecheck
npm run fixtures:check            # regenerates from Rust and diffs
npm run check:packaging           # exports, dependencies, publish metadata, pack
npm run check:scope               # prints what each check group actually covers
```

Live suites need a validator, a same-revision Photon, and the prover. Set
`ZOLANA_PORT_OFFSET` to keep clones from contending:

```bash
just build-programs
ZOLANA_PORT_OFFSET=300 npm run test:e2e:gate3    # spend flows to chain (needs ZOLANA_TEST_GATE3=1 via the script)
ZOLANA_PORT_OFFSET=800 npm run test:e2e:photon   # indexer contract
```

Opt-in prove suites (not yet in CI on `ts-sdk-port` HEAD):

```bash
npm run test:e2e:p5            # prove-to-chain
npm run test:e2e:p5:hybrid     # same with Rust compress path
# P4 full shape set: see @zolana/client scripts test:p4:full / ZOLANA_TEST_P4=1 ZOLANA_TEST_P4_FULL=1
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
  a specific reason not to. Recorded when it applies. CI comparison:
  [`ci-comparison.md`](ci-comparison.md).
- **Verify a finding before acting on it.** External reviews and prior sessions
  both produced claims that did not survive a check.
- **Opt-in suites that catch compression or prove bugs must run on PRs.** The G2
  limb-order defect is the proof. Coverage beats wall-clock for P4's full shape
  set.
