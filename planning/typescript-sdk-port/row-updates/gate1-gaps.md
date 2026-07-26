# Gate 1 — named gaps closure

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-wt-gate1-gaps` |
| Branch | `port/gate1-gaps` |
| Measured revision | `9d21b71d` |
| Measured at | 2026-07-26 |
| Scope | Five gaps from [gate1-walk.md](gate1-walk.md) that blocked the eleven-package line |

Method: close each named gap with evidence, or record precisely what remains open.
Did not touch `.github/workflows/` or `sdk-libs/ts/client/src/prover/`.

---

## Command results (this revision)

| Command | Result |
| --- | --- |
| `npm install` | green (196 packages) |
| `npm run build` | green (run before every suite) |
| `npm run test:unit` | **green** — 138 files passed, 2 skipped; **2301** tests passed, 9 skipped |
| `npm run check:static` | **green** |
| `npm run fixtures:check` | **green** — all generators + `fixture provenance ok` |
| `npm run check:packaging` | **green** — inventory (182 frozen + 4 live), exports, dependencies, **real** `api:check`, browser, pack |

---

## Gap 1 — `api:check` was scaffold

**Done.** `sdk-libs/ts/config/api-check.mjs` extracts each package entry point's public
surface from built `.d.ts` (following relative `export *`) and compares it to
committed reports under `sdk-libs/ts/api-reports/`. Undeclared additions or
removals fail. Root `npm run api:check` still runs the scaffold script check,
then the report check. `npm run api:update` regenerates reports after an
intentional surface change. Wired into `check:packaging`.

Evidence: reports for all eleven packages; control edit removing
`resetPoseidonForTests` from the hasher report fails with
`undeclared addition(s) resetPoseidonForTests`.

---

## Gap 2 — `E03`, `E05`, `E06` `needs_re_review`

**Done — all three `done` / `NOT_APPLICABLE`.**

| Row | Disposition |
| --- | --- |
| `E03` | Deleted the unreachable TypeScript `OutputUtxo` type. Rust event `OutputUtxo` stays a `GeneralEvent` field; transact uses `TransactOutput`; do not confuse with `ProofOutputUtxo`. |
| `E05` | Confirmed no TypeScript `GeneralEvent` / `EventKind` / `encode_event_*` surface; Photon + `indexer-api` own decoding. |
| `E06` | Confirmed `program-test = []` off default in `program-libs/event/Cargo.toml`; no shipped decoder for those helpers. |

Artifact: `interface/test/vectors/event-disposition.test.ts`.
Log: [log/2026-07-26T1545-gate1-gaps-e03-e05-e06.md](../log/2026-07-26T1545-gate1-gaps-e03-e05-e06.md).
Spec `Option` vs zeroed-array note on `tx_viewing_pk`/`salt` remains a
spec-side correction and does not reopen the TypeScript disposition.

---

## Gap 3 — hasher / test-kit seats and inventory

**Done.**

| Item | Action |
| --- | --- |
| `H15` | Primary seat for `@zolana/hasher` ← `sdk-libs/hasher-wasm` — `done`/`PARITY` |
| `TK01` | Primary seat for test-kit root contract — `done`/`PARITY` |
| `TK02` | Node annex disposition — `done`/`NOT_APPLICABLE` |
| Live inventory | `sdk-libs/ts/reports/inventory-live.json` (4 rows) checked by `inventory-check.mjs` alongside the frozen 182 |
| `/node` ledger | [test-kit-node-dispositions.md](../test-kit-node-dispositions.md) |

Primary rows: **148**. Progress: **137 done / 148 total**. Checklist parsers
accept two-letter row IDs (`TK01`). Frozen inventory stays 182 paths at
`frozenCommit` (hasher-wasm did not exist there).

---

## Gap 4 — fixture freshness / `FIX-DRIFT`

**Done without re-stamping `frozenCommit`.**

| Check | Result |
| --- | --- |
| `ts-fixtures --check` | verified 58 fixtures, 182 inventory rows — **no body drift** |
| `ts-fixtures --current-client --check` | verified 3 current-client fixtures — **no body drift** |
| Commits since freeze touching fixture sources | **84** |

`frozenCommit` remains `43fde8e4…` (historical inventory / spec / proving-key
pin). Family stamps advance only when a body changes; client tip `c1a9b35e`
(G2) is ahead of the client stamp and correctly did not move the stamp because
bodies were unchanged.

Added `manifest.driftReview` + `revisionCompatibility.driftReview`, enforced by
`fixtures-provenance.mjs`. `ts-fixtures` preserves `driftReview` when rewriting
the manifest so `--check` does not erase the review.

**Behavioural drift found:** none. No fixture body changed under regeneration.

---

## Gap 5 — client / wallet property suites (`PROP`)

**Done.**

| Package | Suite | Invariants |
| --- | --- | --- |
| `@zolana/client` | `client/test/property/client-property.test.ts` | backoff monotonic/capped/length; poll config domain; retryCause category-only; `pollUntil` attempt count |
| `@zolana/wallet` | `wallet/test/property/wallet-property.test.ts` | deposit blinding varies with stable viewTag/amount/owner; amount domain; split conservation; missing SPL error code |

Scaffold `propertyPackages` now requires both. `test:property` scripts added.

---

## Collateral fix

`@zolana/client` listed `@noble/curves` after the G2 path stopped importing it,
which failed the import-aware dependency check. Removed from `package.json` and
`packages.mjs`. No prover sources touched.

---

## Checklist updates supported by this evidence

Package completion: check **P1**, **P2**, **P3**, **P4**, **P5**, **P7**,
**P12**, and keep **P15** checked. Full SDK: check **public-export ledger**
(real `api:check`). Leave the top-level eleven-package line unchecked while
client **P11** (`RAIL` / G2 shape matrix) remains owned by parallel workers.

---

## What remains open (precisely)

| Gap | Why |
| --- | --- |
| Client **P11** / Full SDK eleven-package line | Shape/rail matrix and G2 compression certification owned by parallel workers; out of scope here (`client/src/prover/` and CI workflows untouched). |
| Spec `tx_viewing_pk` / `salt` Option vs zeroed arrays | Spec-side; recorded on `E05`, not a TypeScript port blocker. |
| G8-1 historical prose in older docs | Compatibility rules + `driftReview` now exist; other workers may still need to tick related Full SDK fixture prose against their own evidence. |
