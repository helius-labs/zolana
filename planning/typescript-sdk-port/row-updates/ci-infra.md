# CI infra cleanups (F076, F079)

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-wt-ci-infra` |
| Branch | `port/ci-infra` |
| Commits | `2474d39b` F076, `64f221c5` F079, `e226abc9` prettier on `check-scope.mjs` |

## F076: strip port coordination tooling

### Deleted

| Path | Why |
| --- | --- |
| `sdk-libs/ts/config/pkp-entry-gate.mjs` | Hardcoded `PULL_REQUEST = "159"`; cryptographic-phase entry gate for this port only |
| `sdk-libs/ts/config/pkp-entry-watch.sh` | Watcher around that gate |
| `sdk-libs/ts/config/review-checklist-check.mjs` | Policed `review-checklist.md` / log attribution for the port |
| `sdk-libs/ts/config/port-health.mjs` | Coordinator liveness / assignment overlap detector (hardcoded conversation id) |
| `sdk-libs/ts/config/port-health-watch.sh` | Watcher around port-health |
| `.github/workflows/typescript.yml` job `planning` (`typescript / planning`) | Ran `review-checklist-check.mjs`; removed from `merge-gate` `needs` |

No `package.json` scripts pointed at these files; the planning job invoked the checker by path.

### Deliberately kept

| Path | Reason |
| --- | --- |
| `api-check.mjs` / `workspace-check.mjs` | Packaging / API / export / dependency gates |
| `fixtures-check.mjs` / `fixtures-provenance.mjs` | Fixture regeneration and provenance gates (`check:fixtures`) |
| `browser-check.mjs` / `browser-runtime-check.mjs` / `browser-runtime-harness.mjs` | Browser bundle and Chromium runtime gates |
| `check-scope.mjs` | Asserts that `npm run check` matches the CI job split |
| `inventory-check.mjs` / `pack-check.mjs` / `packages.mjs` / `build.mjs` / `typecheck.mjs` | Packaging and build infrastructure |
| `poseidon.setup.mjs` / `property.setup.mjs` / vitest configs | Test harness, not port coordination |
| `planning/typescript-sdk-port/**` | Historical planning prose; not executable CI. Left so the port record stays readable |

Nothing outside planning docs imported the deleted scripts after the workflow edit.

## F079: path filter and shared build

### New job graph

```text
changes ──► build ──► static
                 ├──► suites
                 ├──► packaging
                 ├──► browser-runtime
                 └──► e2e
         ├──► gate-scope
         └──► fixtures

changes + gated jobs ──► merge-gate
```

- `changes` uses `dorny/paths-filter` (job-level, not workflow `paths:`).
- Expensive jobs run only when `typescript == true`.
- `build` runs `npm run build` once with Rust + wasm, uploads `ts-dist-${{ github.sha }}`.
- Downstream jobs restore that tarball instead of rebuilding.
- `static`, `suites`, and `packaging` still install Rust and run `node sdk-libs/ts/hasher/scripts/build-hooks.mjs` so a `program-libs/hasher` change without a regenerated `@zolana/hasher` artifact still turns those jobs red. Artifact reuse does not skip that refusal.
- `check-scope.mjs` `needs` lines now state the Rust/hasher requirement for those three parts.

### How `merge-gate` reports on pull requests that do not touch the tier

Workflow-level `paths:` is intentionally absent. A skipped workflow would leave the required `typescript / merge gate` check unreported and block unrelated PRs.

`merge-gate` is not conditioned on the path filter, so it still runs on a non-draft event when the expensive jobs are skipped. When `changes` fails, merge-gate fails. When `typescript != true`, merge-gate succeeds without waiting on the expensive jobs. When `typescript == true`, merge-gate requires `success` from `build`, `gate-scope`, `static`, `suites`, `packaging`, `browser-runtime`, `fixtures`, and `e2e`.

That yields a conclusive status on a non-draft PR: green if the tier is out of scope, green if each in-scope job passed, red if any of them failed or was unexpectedly skipped.

### Path set that activates the tier

`sdk-libs/**`, `program-libs/**`, `programs/**`, `prover/**`, `services/photon/**`, `xtask/**`, root npm/ts configs, `typescript.yml`, `setup-rust`, `justfile`, workspace Cargo/toolchain/`.cargo`. Planning-only and docs-only changes skip the expensive jobs.

### Cost (measured / estimated)

Before (run `30205795604` on PR 159; suites failed, other jobs completed, so durations are usable):

| Job | Duration |
| --- | --- |
| gate-scope | 7s |
| planning | 9s |
| static | 66s |
| packaging | 87s |
| browser-runtime | 62s |
| suites | 211s |
| fixtures | 293s |
| e2e | 374s |
| **Sum runner-seconds** | **~18.5 min** |
| **Wall clock** | **~6.2 min** (e2e) |

Each of static / suites / packaging / browser-runtime / e2e rebuilt from scratch.

After, for a TypeScript-tier change:

- One shared `build` (about 1 to 2 min with cold Rust/npm cache; tens of seconds warm) replaces five independent `npm run build` invocations.
- `planning` gone (~9s).
- Wall clock still dominated by e2e / fixtures; runner-minutes drop by roughly the four avoided rebuilds plus setup overlap (about 2 to 4 minutes of runner time when caches are warm).

After, for a change outside the path set (docs, planning, forester, and similar):

- Only `changes` + `merge-gate` run (about 10 to 20s total). The previous graph would have spent the full ~18.5 runner-minutes.

Exact post-change GitHub timings were not available from this worktree (no workflow dispatch from here); the before numbers are from the live workflow on that SHA family.

## Command results

| Command | Result |
| --- | --- |
| `npm install` | ok (196 packages) |
| `npm run build && npm run test:unit` | **pass**: 2301 passed, 9 skipped (first unit run hit a 30s timeout flake in `g2-eip197-limbs.test.ts` under load; re-run alone and full suite both green) |
| `npm run check:scope` | **pass** |
| `npm run check:static` | **pass** |
| `npm run check:packaging` | **pass** |
| `npm run fixtures:check` | **pass**: generators `--check`, then `fixture provenance ok` |

Programs, `program-libs/`, circuits, `sdk-libs/ts/*/src/`, `xtask/`, and `fixtures/manifest.json` / `fixtures-check.mjs` were not modified.
