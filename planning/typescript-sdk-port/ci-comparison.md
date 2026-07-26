# CI comparison: Zolana vs Light Protocol

Research note (read-only). Sources:

- Zolana worktree: `/Users/tilohelius/Workspace/zolana-ts-sdk-port` (branch `ts-sdk-port`), workflows under `.github/workflows/`, npm scripts in root `package.json` and `sdk-libs/ts/config/`.
- Light Protocol: local checkout `/Users/tilohelius/Workspace/light-protocol` cross-checked against GitHub `Lightprotocol/light-protocol` tip `ad5964f175d0` (2026-07-21). Workflow blob hashes for the active files match that tip; several workflow IDs still appear in the Actions API for deleted paths (`nix-test.yml`, `js-cli-*.yml`, etc.) and were ignored.
- Branch protection / rulesets inspected via `gh` (read-only). Required-check lists where unavailable are marked **unknown** or **none configured**.

This file lives under `planning/` on the planning-record side branch
(`ts-sdk-port-planning-record` / `port/handover-refresh`). It is excluded from
pull request [#159](https://github.com/helius-labs/zolana/pull/159).

---

## Headline

Light runs many independent PR workflows that each boot a live validator + Photon + prover for JS/CLI/program/forester paths, and accepts flakiness with retries. Zolana concentrates TypeScript into one workflow with an explicit merge-gate job, stronger packaging/fixture/browser gates, and same-revision stack builds, but leaves the heaviest TypeScript prove-to-chain suites behind env flags that CI never sets. On the Rust side Zolana already runs a large localnet+Photon+prover matrix on every non-draft PR; Light’s equivalent is also PR-default but spread across more workflows and longer wall clocks.

Neither repository currently enforces required status checks on `main` via the APIs available here (see §6).

---

## 1. Job graph and triggers

### Zolana

| Workflow | Triggers | Path filter | Notes |
| --- | --- | --- | --- |
| `typescript.yml` | push `main`, non-draft PR | Job-level `dorny/paths-filter` (not workflow `paths:`) so the merge gate still reports when unrelated | Concurrency cancel-in-progress; sole conclusive `typescript / merge gate` |
| `rust.yml` | push `main`, non-draft PR | `paths-ignore`: `prover/server/**`, md, license | Many parallel jobs; no umbrella gate |
| `prover-server.yml` | push/PR | `prover/**`, `xtask/**`, workflow/action | Go tests + vk smoke |
| `formal-verification.yml` | push/PR | `prover/server/**` | Lean + circuit drift |
| `photon.yml` | push/PR | Photon + related crates | Postgres service |
| `photon-image.yml` | push/PR (paths), tags, `workflow_dispatch` | Photon container paths | Production publish gated |
| `async-prover.yml` | push/PR | none | Redis + proving-key cache |
| `forester.yml` | push/PR | `forester/**` etc. | Compile-only skeleton |
| `enforce-pr-only.yml` | push `main` | — | Fails direct pushes that are not merge commits |

No `schedule:` triggers in the worktree workflows. Drafts skip expensive jobs via `if: … draft == false`.

**TypeScript graph:** `changes` → parallel `build` / `gate-scope` / `fixtures`; then `static`, `suites`, `packaging`, `browser-runtime`, `e2e` consume the build artifact; `merge-gate` always runs and either accepts a deliberate path skip or requires every tier job `success`.

### Light

| Workflow | Triggers | Path filter | Notes |
| --- | --- | --- | --- |
| `js.yml` / `js-v2.yml` / `js-token-interface-v2.yml` | push `main`, non-draft PR | none (always) | Live JS e2e + retries |
| `cli-v1.yml` / `cli-v2.yml` | same | none | Live CLI against test-validator |
| `lint.yml` | same | none | Full lint via `scripts/lint.sh` |
| `programs.yml` | push/PR | programs / program-tests / program-libs / prover client | Matrix of `just ci-*` |
| `sdk-tests.yml` (`examples-tests`) | push/PR | sdk + programs + program-libs | Matrix of sbf/sdk tests |
| `rust.yml` | push/PR | program-libs + Cargo + prover client | Matrix program-libs tests |
| `forester-tests.yml` | push/PR (+ `workflow_dispatch`) | forester paths | e2e + compressible |
| `prover-test.yml` | push/PR | `prover/server/**` | Tiered: lightweight on `main` PRs; `TestFull` only on `release/**` base |
| `pr.yml` | PR opened/edited/synchronize | — | Semantic PR title |
| `ci-lint.yml` | push + PR | — | `actionlint` |
| `release-pr-ts.yml` | `workflow_dispatch` | — | Opens version-bump PR |
| `release-pr-validation.yml` / `release-rust.yml` | release-labeled PR / merge | — | crates.io publish path |
| `prover-release.yml` | tag `light-prover*` | — | binaries + Docker |
| `deploy-docs.yml` | tags/branches/paths + dispatch | JS src | TypeDoc pages |
| `metrics-contract.yml` | push/PR paths + dispatch | forester metrics | |

Also active on GitHub (not workflow YAML in-repo): **CodeQL**, **Dependabot**. No single conclusive gate job; each workflow succeeds or fails independently. Concurrency groups are per-workflow with `cancel-in-progress: true` almost everywhere.

**Triggers Zolana lacks:** semantic PR titles, actionlint, Dependabot config, CodeQL, scheduled Dependabot. **Triggers Light lacks:** draft-aware path-filter + always-green merge gate pattern; enforce-direct-push-to-main job.

---

## 2. What is actually verified

### TypeScript / JS SDK surface

| Guarantee | Zolana (`typescript.yml` + npm scripts) | Light (js / cli / token-interface workflows) |
| --- | --- | --- |
| Build | `npm run build`; artifact reused across jobs | `pnpm build:v1` / `build:v2` per package inside job |
| Typecheck / lint / format | Dedicated `static` job; `check:scope` pins `npm run check` composition | Combined into `lint.yml` (`./scripts/lint.sh`) + per-package builds |
| Unit / vectors / property / cross / offline prover vectors | `check:suites` | Package unit tests inside JS jobs; less explicit vector/fixture regeneration |
| Packaging / exports / API report / packed tarball | `packaging` job (`inventory`, exports, deps, `api:check`, `pack-check`) | Not a first-class CI gate |
| Browser bundle scan | `browser-check.mjs` in packaging | Not observed |
| Headless Chromium crypto vectors | `browser-runtime` (Playwright) | Not observed |
| Rust↔TS fixture regeneration | `fixtures` job: xtask generators `--check`, full git history | Not observed as a dedicated gate |
| Live validator e2e | `check:e2e` (actions/instructions/photon/example) + Rust paired example | `just js test-*` / CLI tests via `light test-validator` |
| Live prove-to-chain / multi-shape prove | Opt-in only (see §3) | Default path for compress/transfer e2e |
| Flake handling | Fail closed (no retry loop in workflow) | Explicit `until …; max_attempts=2` in JS workflows |

### Rust / programs / indexer / prover

**Zolana `rust.yml` (every non-draft PR, aside from prover/server ignore):** fmt, machete, clippy, `just check-all`, cli / sdk-libs / programs / shielded-pool / user-registry litesvm / client integration, Photon binary artifact, then an eight-way localnet+Photon matrix (e2e, spp lifecycle/decode/merge/randomized, zone, swap/escrow, dynamic-swap, rfq). Proving keys cached by lockfile hash; Anza CLI + pinned SBF tools installed per live job.

**Light:** path-filtered `programs.yml` (eight program-test groups), `sdk-tests.yml` (native/anchor/pinocchio/token/sdk-libs matrices), `rust.yml` (program-libs fast/slow/simulate), `forester-tests.yml` (full e2e). Shared composite `.github/actions/setup-and-build` installs Solana/Anchor/Photon (pinned submodule commit), builds programs (cached `.so`), pnpm install. Redis as a GitHub Actions service wherever the prover queue is expected.

**Prover:**

- Zolana: `prover-server.yml` runs `just prover-server-test` (long timeout); formal verification extracts circuits and fails on Lean source drift; async prover transfer-queue job with Redis.
- Light: broad Go unit/redis matrices; lightweight integration on main PRs; **full** `TestFull` only when the PR targets `release/**`; Lean verification builds extracted circuit (does not `git diff --exit-code` the committed Lean file the way Zolana does).

**Security / hygiene:** Light has CodeQL + Dependabot + actionlint + semantic PR titles. Zolana pins many Actions by commit SHA, has `enforce-pr-only`, cargo-machete, OpenAPI schema drift for Photon. Neither shows `cargo-deny` / license CI in workflows.

---

## 3. Live-stack testing (the decision axis)

### How Light boots the stack

1. CI runs `.github/actions/setup-and-build`: system deps, Rust/Node/pnpm, cached Solana CLI + Anchor + **Photon binary from `external/photon` pin**, `pnpm install --frozen-lockfile`, build programs / program-tests into `target/deploy` (cached).
2. JS/CLI tests call `./cli/test_bin/run test-validator` → `initTestEnv` starts `solana-test-validator` (default ports **8899 / 8784 / 3001**), Photon from PATH, and the prover.
3. Prover path (`processProverServer.ts`): downloads a **released** `light-prover` binary from GitHub Releases (version-pinned), then starts it with `--auto-download true` so proving keys land under `~/.config/light/proving-keys` on demand. CI does **not** pre-cache keys in `setup-and-build` today (the `skip-components: proving-keys` string in `lint.yml` is a no-op against the current action).
4. One stack per job/runner → fixed ports are fine; concurrent matrix jobs do not share a host. No `PORT_OFFSET` scheme.
5. Proof-generating JS e2e (compress, transfer, rpc-interop, lighttoken flows, CLI) runs on **every non-draft PR** that triggers those workflows (and JS workflows have **no path filter**, so they run even for unrelated PRs). Flaky suites get **one retry**.

Light’s prover *server* CI deliberately keeps the heaviest gnark integration (`TestFull`, 120m) off mainline PRs — only release-branch PRs pay that cost. That is a different axis from JS SDK e2e, which already proves against a live prover on main PRs.

### How Zolana boots the stack

1. TypeScript `e2e` job: Anza CLI, SBF tools, cache proving keys by `proving-keys.lock`, fetch Squads `.so`, `just build-programs` / `build-prover-server` / `build-photon` / `build-cli`, restore TS dist, then `npm run check:e2e` and the Rust paired example.
2. Suites use `@zolana/test-kit` `startLocalStack` with **per-suite `ZOLANA_PORT_OFFSET`** (300 / 400 / 500 / 800; Rust example 600) so sequential suites on one runner cannot collide. Job leaves service URL env vars unset so the harness owns the processes.
3. Stack binaries are **same-revision** workspace builds (Photon at `target/debug/photon`), not a release download. Keys: lockfile-pinned CloudFront download, GHA cache keyed by lockfile hash; prover is lazy-load on first proof.

### What Zolana TypeScript CI already runs live

Always on in `check:e2e` (when the typescript path filter matches):

- `e2e/actions/live.test.ts` — registration / merge opt-in / ATA on a real stack (no confidential prove-to-chain).
- `e2e/instructions/live.test.ts` — signature rejection against an isolated stack.
- `e2e/photon/photon-contract.live.test.ts` — Photon contract surface.
- Paired TS example + Rust `deposit_transfer_withdraw` example.

Fixture/mock suites (`actions.test.ts`, instruction acceptance) also run but are not live proof.

### What Zolana TypeScript CI skips (env-flag opt-in)

| Flag | Suite | What it buys |
| --- | --- | --- |
| `ZOLANA_TEST_P4=1` (+ optional `_FULL`) | `cryptographic-verification` live arm | TS builds witnesses, local prover proves, TS compresses, `groth16-verify` oracle accepts; multi-shape |
| `ZOLANA_TEST_P5=1` | `prove-to-chain.live.test.ts` | Deposit → Photon sync → confidential transfer/withdraw with real proofs on same-revision stack |
| `ZOLANA_TEST_GATE3=1` | `gate3-flows.live.test.ts` | Broader gated wallet flows against live stack |
| `ZOLANA_TEST_LIVE=1` | `test-kit` user-registry lifecycle | Register / unauthorized owner / merge enable cleanup |

None of these flags appear in `typescript.yml`. Enabling them on every PR is the change under consideration.

### Posture comparison (honest)

| Question | Light | Zolana today |
| --- | --- | --- |
| Does JS/TS CI generate real proofs on every PR? | **Yes** (compress/transfer e2e via CLI test-validator + auto-download keys) | **Partially**: stack boots and non-proof lifecycles run; P4/P5/GATE3 prove paths are opt-in and skipped |
| Same-revision prover/indexer as the PR? | **No** for prover (release binary); Photon from submodule pin; programs from this commit | **Yes** for programs, prover server, and Photon |
| Key distribution | Prover `--auto-download` at runtime; no lockfile cache in GHA for JS jobs | Committed lockfile + CloudFront + GHA cache |
| Port isolation | One stack / runner; fixed ports | Explicit offsets for multi-suite sequential jobs |
| Cost control for heaviest prover tests | `TestFull` only on `release/**` PRs | Heavy TS prove suites opt-in; Rust localnet matrix already always-on |
| Flake policy | Retry once in JS workflows | Fail closed |

**Implication for the in-progress “run P4/P5/GATE3 on every PR” change:** Light’s equivalent *JS* posture is already “prove on every PR.” Zolana would be catching up on the TypeScript rail, not inventing a stricter bar than Light’s JS CI. Zolana would still be stricter about same-revision binaries. The expensive part is wall-clock and key warm-up on `ubuntu-latest`, not philosophical novelty. Rust-side Zolana already pays a large live-proof bill that Light also pays (programs/forester), so adding TS prove suites is incremental on top of an already live-heavy CI, not the first introduction of proving keys into the repo’s CI.

---

## 4. Runners, caching, and cost

Both use **GitHub-hosted `ubuntu-latest`** (Zolana Photon jobs pin `ubuntu-24.04`). No self-hosted runners observed in workflow YAML.

| Dimension | Zolana | Light |
| --- | --- | --- |
| Rust cache | Swatinem `rust-cache`, `save-if: main` only | `actions-rust-lang/setup-rust-toolchain` cache + custom program `.so` caches |
| Node | `actions/setup-node` npm cache | pnpm store cache in composite action |
| Proving keys | Explicit GHA cache on lockfile hash (rust/ts/async-prover jobs) | Runtime auto-download into `~/.config/light`; not GHA-cached in setup |
| Solana toolchain | curl Anza install per live job | Cached under `.local/bin` in composite action |
| Typical TS/JS PR wall clock (sample) | typescript workflow ~11 min warm (e2e ~10 min critical path) on PR 159 | js-v1 ~27 min, js-v2 ~33 min; slowest program-libs job ~54 min on PR #2382 |
| Typical full PR wall clock | Dominated by rust localnet matrix (~18 min slowest sample) in parallel with typescript | Dominated by ~50–55 min program-libs / forester / system-cpi jobs; many workflows always fire |

Light pays more parallel minutes because JS/CLI/lint/programs often all run without path filters. Zolana’s typescript path filter + merge-gate skip saves minutes on non-SDK PRs; rust still runs broadly (`paths-ignore` only strips prover/server and docs).

---

## 5. Release and publishing

### Light

- **npm:** manual/operator script `scripts/release/bump-versions-and-publish-npm.sh` (pnpm publish, OTP). `release-pr-ts.yml` only opens a version-bump PR via `workflow_dispatch`; it does not publish.
- **crates.io:** merging a PR labeled `release` runs `release-rust.yml` (validate then publish + GitHub releases). `release-pr-validation.yml` dry-runs on labeled PRs.
- **Prover:** tag `light-prover*` → multi-arch binaries + GHCR/Docker Hub image (keys downloaded into image build).
- **Docs:** TypeDoc to GitHub Pages on tags/paths.

Release validation is **not** automatically the union of all PR checks; it assumes the PR already went through normal CI, then runs package-specific validate/publish scripts.

### Zolana

- **npm packages:** no publish workflow in this worktree (TypeScript SDK still pre-publish; packaging gates are “would pack correctly,” not “published”).
- **Photon image:** `photon-image.yml` validates on PR; publishes immutable `photon-zolana-<sha>` / `sha-<commit>` to ECR on tag or dispatch, with overwrite refusal and main-ancestor check.
- **Rust crates / TS SDK:** no crates.io / npm publish automation observed in `.github/workflows/`.
- Prover keys: distribution is CloudFront + lockfile (operational), not a CI publish job.

---

## 6. Required checks and branch protection

| Item | Light (`Lightprotocol/light-protocol`) | Zolana (`helius-labs/zolana`) |
| --- | --- | --- |
| Classic branch protection on `main` | Present: 1 approving review, `enforce_admins: true`, no force push | Classic endpoint 404 (rulesets used instead) |
| Required status checks | **None configured** (`requiresStatusChecks: false`, empty contexts) | Org ruleset **Standard Ruleset** on default branch: PR required (1 review), required signatures, no deletion / non-FF. **No required status checks** visible on that ruleset |
| Rulesets API | Empty list | Org-sourced ruleset id `16101728` as above |
| Practical gate | Social / review + whatever humans look at; CI is advisory unless enforced elsewhere **unknown** to this research | Comments in `typescript.yml` state intent to make `typescript / merge gate` the sole required check — **not yet reflected** in the ruleset payload we can read |
| Extra | CodeQL checks appear on PRs; Dependabot weekly | `enforce-pr-only` fails non-merge pushes to main after the fact |

**Unknown:** whether org-level or private rules outside API scopes add required checks; whether Light uses rulesets the token cannot list. Do not treat either repo as “merge blocked on green CI” based on public API alone.

---

## 7. Structural differences that matter

1. **Merge signal:** Zolana TypeScript invents a single conclusive job that stays green on path skip. Light has no equivalent; skipped path-filtered workflows simply disappear from the PR.
2. **Same-revision vs release prover (JS path):** Light JS e2e trusts a published prover binary + auto-downloaded keys. Zolana builds prover/Photon from the PR — slower CI, tighter coupling, catches prover/server drift the release binary would hide.
3. **TS prove coverage gap:** Light’s default JS CI already exercises real proofs. Zolana’s default TS CI exercises the stack and non-proof lifecycles; the prove-to-chain acceptance suites are the gap being closed.
4. **Packaging / browser / fixture discipline:** Zolana is ahead for a multi-package TS SDK (API extractor, pack-check, Playwright vectors, fixture `--check`). Light’s JS CI is integration-heavy and packaging-light.
5. **Always-on breadth:** Light’s unfiltered JS/CLI/lint workflows tax every PR. Zolana filters the expensive TS tier but still runs a wide Rust live matrix.
6. **Security automation:** Light has CodeQL + Dependabot; Zolana does not (in-repo). Zolana pins Actions SHAs more aggressively.
7. **Publish maturity:** Light has crates.io + npm operator paths; Zolana has Photon image publish and packaging *checks* only for TS.

---

## 8. Prioritized adoption list

### Worth adopting from Light (for Zolana)

1. **Run the opt-in prove suites on PR CI (P4 fast + P5 + GATE3, maybe `ZOLANA_TEST_LIVE`)** — **expensive** (keys + prove time on the e2e job or a sibling job), but this is exactly Light’s JS posture and the gap the in-progress change targets. Prefer a dedicated job (or matrix) with proving-key cache already used by `e2e`, rather than lengthening the critical path blindly; keep `P4_FULL` on schedule or release if shape fan-out is large.
2. **Retry once around known-flaky live suites** — **cheap** workflow glue; Light already does this for JS. Use sparingly so it does not mask real races.
3. **actionlint + Dependabot (Actions + npm + cargo)** — **cheap**; catches workflow syntax and stale Actions.
4. **CodeQL (or equivalent)** — **cheap-to-moderate** GitHub product enablement; Light already surfaces Analyze jobs on PRs.
5. **Semantic PR title check** — **cheap** if the team wants changelog discipline; optional culture fit.
6. **Do not copy Light’s “download release prover for JS e2e”** for Zolana’s merge gate — that would weaken same-revision guarantees Zolana already paid for. Keep workspace prover/Photon.

### Things Zolana already does that Light does not (keep)

1. **Single conclusive TypeScript merge-gate + job-level path filter** — **cheap** once required-checks are wired; avoids skipped-check deadlocks. Light has no analogue.
2. **Packaging / API / export / pack-check gates** — **cheap-moderate**; high leverage before first npm publish. Light publishes npm via operator script without these CI gates.
3. **Playwright browser-runtime crypto vectors** — **moderate** (browser download cache); Light lacks this.
4. **Fixture regeneration `--check` against Rust oracles** — **moderate-expensive** (fixtures job ~5 min sample) but prevents silent TS/Rust drift. Light has no equivalent gate.
5. **Same-revision Photon + prover in TS e2e** — **expensive** but catches cross-crate breaks Light’s release-prover path can miss.
6. **Port-offset isolation + in-harness log attach** — **cheap** design; better for multi-suite jobs than Light’s fixed ports.
7. **Formal-verification circuit drift (`git diff --exit-code`)** — **moderate**; stricter than Light’s extract-and-build-only Lean job.
8. **Photon OpenAPI / migration / container immutability checks** — domain-specific; Light’s Photon is an external submodule, not an in-repo publish surface.
9. **`check:scope` composition lock** — **cheap**; prevents CI from silently dropping a tier of `npm run check`.

### Explicit non-gaps (do not manufacture work)

- Light is **not** weaker on “do we prove in CI at all?” for the JS SDK — it is stronger on that narrow claim today.
- Light’s full gnark `TestFull` is intentionally off main PRs; copying “always run TestFull” would be more extreme than Light, not parity.
- Neither side currently shows API-visible required status checks; adopting Light’s check names without enabling enforcement changes little.
- Light’s retry loops and always-on unfiltered JS workflows buy coverage at higher flake and minute cost; copying both blindly would regress Zolana’s path-filter discipline.

---

## Appendix: source pointers

- Zolana TS gate: `.github/workflows/typescript.yml`, `package.json` scripts `check:*`, `sdk-libs/ts/config/check-scope.mjs`, `sdk-libs/ts/e2e/README.md`.
- Zolana opt-in suites: `sdk-libs/ts/client/test/vectors/cryptographic-verification.test.ts`, `sdk-libs/ts/e2e/actions/prove-to-chain.live.test.ts`, `gate3-flows.live.test.ts`, `sdk-libs/ts/test-kit/test/user-registry.live.test.ts`.
- Light live stack: `.github/actions/setup-and-build/action.yml`, `cli/src/utils/initTestEnv.ts`, `cli/src/utils/processProverServer.ts`, `js/*/package.json` `test-validator` / `test:e2e:*`, `.github/workflows/js.yml` / `js-v2.yml` / `cli-*.yml`.
- Light prover CI tiers: `.github/workflows/prover-test.yml` (`integration-test-full` ↔ `release/**` base).
