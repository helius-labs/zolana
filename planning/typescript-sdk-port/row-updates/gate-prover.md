# Gate prover — live same-revision prove matrix and full CI commands

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-wt-gate-prover` |
| Branch | `port/gate-prover` |
| Measured revision | `a547447e9310` |
| Measured at | 2026-07-26T14:11Z |
| Scope | Full SDK completion gates: "Proof inputs work with the same-revision prover for each supported shape and rail" and "Full CI, fixture regeneration, browser, packed-package consumer, action E2E, and instruction E2E commands pass from a clean checkout." |

## Verdict summary

| Item | Status | Notes |
| --- | --- | --- |
| Same-revision prove matrix | **Closed** | Every supported shape×rail cell produced a live proof on `target/prover-server` and verified via `xtask groth16-verify` (same `groth16-solana` path as the program) |
| Full CI command gate line | **Closed** | All enumerated commands exit 0 after `npm install` + `npm run build`, including previously red `check:static` |
| Packaging dep drift | Fixed | Cherry-picked `df80c7e9` — unused `@noble/curves` on `@zolana/client` after the G2 compressor stop importing it |

## Setup

- `npm install` (196 packages), then `npm run build` before every suite (stale `dist/` causes phantom failures).
- `just build-prover-server` → `target/prover-server`.
- `just build-programs`, `just ensure-photon`, `just ensure-smart-account`.
- Port offset **400** for live prove (`ZOLANA_PORT_OFFSET=400`, prover `http://127.0.0.1:3401`).
- Action E2E pins offset **300**; instruction E2E pins **400**. Clear `ZOLANA_PROVER_URL` / indexer / localnet URL overrides before E2E so the test-kit spawns its own stack.
- Proving keys: cache-first CloudFront download via `--auto-download=true`. All **46** lockfile keys present under `prover/server/proving-keys/` after the matrix run. No missing lockfile entries for the supported shape set.

## Shape-by-rail live proof matrix

Command (evidence log `/tmp/gate-prover-p4-verbose.log`):

```bash
ZOLANA_PORT_OFFSET=400 ZOLANA_PROVER_URL=http://127.0.0.1:3401 \
  npm run test:p4:full --workspace @zolana/client -- --reporter=verbose
```

Result: **53 passed / 53** in 310s (second run with keys warm; first cold run 53/53 in 587s).

Each live cell is TypeScript witness assembly → same-revision prover → TypeScript compress → `groth16-verify` accept. Legend: **prove** = live proof + verify; **rejected** = SDK refuses (not a prove gap); **—** = rail does not apply.

| Shape | confidential eddsa | confidential p256 | transfer-zone | transfer-p256-zone | zone-authority | merge / merge-zone |
| --- | --- | --- | --- | --- | --- | --- |
| 1×1 | prove | prove | prove | prove | prove | — |
| 1×2 | prove | prove | prove | prove | rejected | — |
| 2×2 | prove | prove | prove | prove | prove | — |
| 2×3 | prove | prove | prove | prove | rejected | — |
| 3×3 | prove | prove | prove | prove | prove | — |
| 4×3 | prove | prove | prove | prove | rejected | — |
| 4×4 | prove | prove | prove | prove | prove | — |
| 5×3 | prove | prove | prove | prove | rejected | — |
| 5×4 | prove | prove | prove | prove | rejected | — |
| 1×8 | prove | prove | prove | prove | rejected | — |
| 8×1 (merge) | — | — | — | — | — | prove both |

Verbose test names that passed (live suite only):

- confidential eddsa: `1x1`, `1x2`, `2x2`, `2x3`, `3x3`, `4x3`, `4x4`, `5x3`, `5x4`, `1x8`
- confidential p256: same ten
- zone eddsa / zone p256: same ten each
- zone-authority: `1x1`, `2x2`, `3x3`, `4x4`
- merge `8x1`, merge_zone `8x1`

Lockfile coverage: every key used above is in `prover/server/prover/provingkeys/proving-keys.lock`. No lockfile gap.

Out of scope for this gate: address-append (owner-ruled unsupported in TypeScript).

## Full CI command results

| Command | Result |
| --- | --- |
| `npm install` | exit 0 — 196 packages |
| `npm run build` | exit 0 |
| `npm run build && npm run test:unit` | exit 0 — **2284 passed**, 9 skipped |
| `npm run check:scope` | exit 0 |
| `npm run check:static` | exit 0 — scope, build, typecheck, lint, lint:packages, format:check all green (g2 lint residue gone) |
| `npm run fixtures:check` | exit 0 — all generators `--check`, `fixture provenance ok` |
| `npm run check:packaging` | exit 0 — after curves dep drop |
| `npm run check:browser-runtime` | exit 0 |
| `npm run test:cross` | exit 0 — 80 tests across api/client/wallet |
| `npm run test:prover` | exit 0 — 15 passed |
| `npm run test:e2e:actions` | exit 0 — **9 passed**, 2 skipped (`ZOLANA_PORT_OFFSET=300`, clean URL env) |
| `npm run test:e2e:instructions` | exit 0 — **7 passed** (`ZOLANA_PORT_OFFSET=400`) |
| `npm run test:p4:full` (live prove) | exit 0 — **53 passed** |

Full GitHub Actions re-dispatch was not required; local sub-scripts matching `.github/workflows/typescript.yml` job scripts are the evidence, consistent with `gate-ci.md`.

## Commits on this branch for this cluster

1. `a547447e` — `fix(client): drop the @noble/curves dependency the G2 fix made unused` (cherry-pick of `df80c7e9`; packaging gate was red without it)
2. docs commit for this report + checklist update (follows)

## Gate verdicts

| Gate | Verdict |
| --- | --- |
| Proof inputs work with the same-revision prover for each supported shape and rail | **HOLDS**. Checklist box checked. |
| Full CI, fixture regeneration, browser, packed-package consumer, action E2E, and instruction E2E commands pass from a clean checkout | **HOLDS**. Checklist box checked. |

## What remains open (not these two lines)

Nothing on the two assigned gate lines. Other Full SDK completion gate bullets (package walk, flows, instruction-bytes, indexer live Photon, fixture provenance top-level, export ledger, adverse verdicts) stay as they were and are owned by other workers.
