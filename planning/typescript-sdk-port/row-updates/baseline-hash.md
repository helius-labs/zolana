# F083 — Centralize the historical fixture baseline

| Field | Value |
| --- | --- |
| Finding | F083 |
| Branch | `port/baseline-hash` |
| Worktree | `/Users/tilohelius/Workspace/zolana-wt-baseline` |
| Ruling | Owner FIX in this pull request |

## Single source of truth

`sdk-libs/ts/config/historical-baseline-commit`

One line: the 40-character lowercase hex commit SHA
(`43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`).

The pin lives under `config/` rather than `fixtures/` so
`fixture_entries` / `fixture_ids` never treat it as a fixture body.

## Consumers that read it

| Consumer | How |
| --- | --- |
| `xtask/src/bin/ts-fixtures.rs` | `historical_baseline_commit(root)` loads the pin; inventory `ls-tree`, manifest stamps, transport `sourceRevision`, inventory report, and P00 report all take the loaded value |
| Packet reports P01–P13 | `stamp_packet_frozen_commits` rewrites only the `frozenCommit` string on regenerate (bodies otherwise untouched) |
| `sdk-libs/ts/config/fixtures-provenance.mjs` | Reads the pin; requires `manifest.frozenCommit`, `historicalBaselineCommit`, `photonSchemaRevision`, `inventory.frozenCommit`, and every `reports/packets/P*.json` `frozenCommit` to match |
| `sdk-libs/ts/config/inventory-check.mjs` | Reads the pin; requires manifest and inventory `frozenCommit` to match it |
| Generated stamps | `fixtures/manifest.json`, `fixtures/api/transport-v1.json` `sourceRevision`, `reports/inventory.json` — written by the generator from the pin, not independently defined |

TypeScript tests that already load `manifest.json` (`error.test.ts`,
`api/test/fixture.ts`) continue to consume the generated manifest; provenance
keeps that manifest bound to the pin.

## Proof that consumers move together

1. Created a temporary same-tree commit with `git commit-tree` parented on the
   real baseline (`98130db45d639ea9b83f246bff6a1c29c9c80a48`), so inventory path
   count and blob lookups still hold.
2. Wrote that SHA into `historical-baseline-commit` only.
3. Ran `cargo run -p xtask --bin ts-fixtures`.
4. Exactly these 18 machine-readable paths contained the proof SHA (and
   `git status` showed only those 18 modifications — no fixture-body churn):

   - `sdk-libs/ts/config/historical-baseline-commit`
   - `sdk-libs/ts/fixtures/manifest.json`
   - `sdk-libs/ts/fixtures/api/transport-v1.json`
   - `sdk-libs/ts/reports/inventory.json`
   - `sdk-libs/ts/reports/packets/P00.json` … `P13.json`

5. Restored the real SHA in the pin file, regenerated again, confirmed the
   proof SHA was gone from every non-planning path, and kept the intentional
   P00 `ownedChangedPaths` addition that names the new pin file.

## Copies deliberately left

- **Planning prose and logs** under `planning/typescript-sdk-port/` (roughly
  160 files that quote the historical SHA in narrative). Not machine-read;
  rewriting them is out of scope and would fight the planned `planning/` strip.
- **Family stamps** `BASELINE_SHA`, `INTERFACE_SHA`, and `MERKLE_SHA` in
  `ts-fixtures.rs`. Those are live regeneration stamps for fixture families,
  not the historical `frozenCommit` pin F083 names.
- **Generated stamp fields** themselves. After regeneration they still *contain*
  the SHA; that is output of the single definition, not a second definition.

## Gate notes

Run from this worktree after the plumbing landed:

```bash
npm run build && npm run test:unit && npm run check:static && npm run check:packaging && npm run fixtures:check
```
