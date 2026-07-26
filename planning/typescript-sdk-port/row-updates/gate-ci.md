# Gate CI / fixture provenance cluster

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-wt-gate-ci` |
| Branch | `port/gate-ci` |
| Measured revision | `6bcd79ae7b10` |
| Measured at | 2026-07-26T13:35Z |
| Scope | G9-1, G9-2, G8-1, G8-2, and the full-command gate line under Full SDK completion gates |

## Verdict summary

| Item | Status | Notes |
| --- | --- | --- |
| G9-1 | **Closed** | Workflow already ran the merge tier on PRs; documented job names |
| G9-2 | **Closed** | Suites covered; `check:scope` states composition and service split |
| G8-1 | **Closed** | Manifest rules + provenance check; incompatible pin rejected |
| G8-2 | **Closed** | Proof fixtures carry VK module + sha256; mismatch rejected |
| Full command gate line | **Open** | Constituent commands green except `check:static` / `lint:packages` on seven pre-existing `g2-compression-live.test.ts` errors owned by `port/g2` |

## Commits on this branch for this cluster

1. `d38b5973` — `ci(ts): document merge-tier check scope and assert it in CI`
2. `6bcd79ae` — `fix(ts): gate fixture revision pins and verifying-key identity`

## G9-1 — workflow runs the TypeScript merge tier on PRs

`.github/workflows/typescript.yml` already existed. On `pull_request`
(`opened` / `synchronize` / `reopened` / `ready_for_review`), non-draft PRs run:

| Job id | Display name | Script |
| --- | --- | --- |
| `gate-scope` | typescript / gate scope | `npm run check:scope` |
| `planning` | typescript / planning | review-checklist check |
| `static` | typescript / static | `npm run check:static` |
| `suites` | typescript / suites | `npm run check:suites` |
| `packaging` | typescript / packaging | `npm run check:packaging` |
| `browser-runtime` | typescript / browser runtime | `npm run check:browser-runtime` |
| `fixtures` | typescript / fixtures | `npm run check:fixtures` |
| `e2e` | typescript / e2e | `npm run check:e2e` |
| `merge-gate` | typescript / merge gate | fails unless every `needs` job succeeded |

This worker only tightened `gate-scope` to call `npm run check:scope` instead of an
inline duplicate of the job list. The Standard Ruleset has no
`required_status_checks` entries for these jobs; the gate text requires a
workflow run on PRs, not branch-protection enforcement, so G9-1 closes on the
workflow evidence.

## G9-2 — merge tier coverage and honest `check` scope

`package.json` `check` remains the full merge-tier composition (owner ruling).
`sdk-libs/ts/config/check-scope.mjs` prints each sub-script’s contents and
service needs and fails if `scripts.check` drifts. `check:static` runs it first;
CI `gate-scope` runs it alone.

Coverage of the named suites:

| Suite | Where |
| --- | --- |
| cross-language | `check:suites` → `test:cross` |
| prover | `check:suites` → `test:prover` (offline vectors; no live prover) |
| browser | `check:packaging` → `test:browser`; runtime in `check:browser-runtime` |
| fixture | `check:fixtures` → `fixtures:check` (own CI job: Rust + git history) |
| packed-package | `check:packaging` → `pack:check` |
| package-lint | `check:static` → `lint:packages` |

Localnet/prover-backed E2E stays a separate CI job (`e2e`) and a named
`check:e2e` sub-script; the scope script states that split so `check` is not
read as Node-only.

## G8-1 — revision compatibility

`manifest.json` now has `revisionCompatibility` for all nine identity keys
(`baseline`, `client`, `interface`, `merkleTree`, `frozenCommit`,
`historicalBaselineCommit`, `photonSchemaRevision`, `specSha256`,
`provingKeyRelease`), each with `compatibility` and `regenerationTrigger`.
`frozenCommit` / `historicalBaselineCommit` / `photonSchemaRevision` must agree.

`sdk-libs/ts/config/fixtures-provenance.mjs` (from `fixtures:check`) rejects a
fixture whose `sourceRevision` disagrees with its bound pin. Control edit on
`client/errors-v1.json` failed as required.

Body-gated client stamps were not regressed: after full `ts-fixtures`
regeneration, `canonicalSourceRevisions.client` and the three current-client
fixture stamps remained `2ca98d82543f5aa8610fc3b37cb1bcae4c5f8e47`.

## G8-2 — verifying-key provenance on proof fixtures

| Fixture | Recorded modules |
| --- | --- |
| `client/proof-validity-v1.json` | `transfer_confidential_1_1` (eddsa), `transfer_p256_confidential_1_1` (p256) |
| `client/proof-result-compression-v1.json` | `transfer_p256_confidential_1_1` (p256) |
| `client/proof-input-v1.json` | `transfer_confidential_1_1` (eddsa) |

SHA-256 is over the committed
`program-libs/interface/src/verifying_keys/<module>.rs` source that
`xtask/src/bin/groth16-verify.rs` `select_vk` imports. Control: zeroing
`proof-input-v1` sha256 fails the gate. Generator:
`attach_proof_verifying_keys` in `xtask/src/bin/ts-fixtures.rs`. Programs and
circuits were not modified.

## Full command gate line

Commands enumerated and run after `npm install` + `npm run build` at
`6bcd79ae`:

| Command | Result |
| --- | --- |
| `npm run build && npm run test:unit` | **pass** — 2228 passed, 9 skipped |
| `npm run check:scope` | **pass** |
| `npm run check:static` | **fail** — seven errors in `g2-compression-live.test.ts` (owned by `port/g2`; left untouched). Scope/build/typecheck/lint/format otherwise clean; `format:check` exit 0 when run alone |
| `npm run fixtures:check` | **pass** — all generators `--check`, then `fixture provenance ok` |
| `npm run check:packaging` | **pass** — inventory, exports, dependencies, api, browser, pack |
| `npm run check:browser-runtime` | **pass** |
| `npm run test:cross` | **pass** |
| `npm run test:prover` | **pass** |
| `npm run test:e2e:actions` | **pass** — 9 passed, 1 skipped (required `just fetch-smart-account` plus built programs/prover/photon) |
| `npm run test:e2e:instructions` | **pass** — 7 passed |

Full CI as a GitHub Actions run was not re-dispatched from this worktree; the
workflow definition and the local sub-script runs above are the evidence.
The completion-gate checkbox stays open solely because of the g2 lint residue.

## Out of scope / not changed

- Solana programs, circuits, verifying-key *contents* (read-only hashing only)
- `sdk-libs/ts/client/test/vectors/g2-compression-live.test.ts`
- Branch-protection / ruleset required-check configuration
