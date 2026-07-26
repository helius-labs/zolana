# PKP-01: Harden fixture provenance

Worktree: `/Users/tilohelius/Workspace/zolana-ts-provenance`  
Branch: `port/provenance`  
Date: 2026-07-26

## Problem

`sdk-libs/ts/fixtures/client/errors-v1.json` (and the other two live client
fixtures) carry `sourceRevision` from:

```text
git log -1 --format=%H -- sdk-libs/client/src
```

That tip moves when any file under the directory changes. `--check` regenerates
fixtures and compares bytes, so the stamp was part of the gate. Unrelated edits
(client error cleanup, field validation, even a test-mock under `src`) failed CI
and forced a mechanical regen of fixtures whose bodies had not changed.

The comments already claimed stamps were informational and that `--check` body
regeneration was the drift detector. The implementation contradicted that:
stamps were rewritten on every directory tip move and then byte-compared.

## Diagnosis

| Path | Role |
| --- | --- |
| `xtask/src/bin/ts-fixtures.rs` `current_client_revision` | produces the live stamp |
| `stamp_current_client` | writes `sourceRevision` on the three current-client fixtures |
| `write_manifest` / `canonicalSourceRevisions.client` | mirrors the same stamp |
| `compare_trees` / `--check` | byte-compares generated vs committed, including stamps |
| `sdk-libs/ts/client/test/error.test.ts` | asserts stamp shape and manifest alignment |
| `sdk-libs/ts/api/test/fixture.ts` | checks frozen `sourceRevision` on the API transport fixture only |

Frozen fixtures (`HISTORICAL_BASELINE_SHA`, `MERKLE_SHA`, …) were fine. Only the
live client family conflated “which revision last regenerated this” with “is
the body stale”.

Light Protocol has no equivalent fixture `sourceRevision` / frozen-commit gate
in the local checkout, so there was no pattern to copy. The recommended split
(informational stamp vs body check) matches the comments that were already in
`ts-fixtures.rs`.

## Fix

1. **Body-gated stamps.** `stamp_current_client` compares each current-client
   fixture body with `sourceRevision` stripped. If every body matches the
   committed file, the committed stamp is kept. If any body changed, all three
   fixtures and `canonicalSourceRevisions.client` advance to the current
   `sdk-libs/client/src` git tip. Reviewers still see a real git revision; the
   gate no longer moves on comment-only or unrelated directory edits.
2. **P00 / vector boundary.** `prover-request-parity-v1.json` lived under
   `sdk-libs/ts/fixtures/client` without a P00 envelope, so `ts-fixtures`
   `--check` failed with a file-set / provenance error before client stamps
   could be tested. Moved to `sdk-libs/ts/vectors/` and pointed
   `prover-request` plus the P2 test at the new path. Certification vectors stay
   under `vectors/`; P00 fixtures stay under `fixtures/`.
3. **Pre-existing body drift.** `client/lib.json` was missing the
   `attach_input_proofs` re-export. Regenerated the three current-client
   fixtures so `--check` is green on a clean tree.
4. **F083 (baseline duplication).** See verdict below. Removed the two
   hand-maintained hardcoded baseline copies in `inventory-check.mjs` and
   `error.test.ts` so they read the machine-readable manifest instead. No
   178-file rebaseline.

## Verification

| Probe | Result |
| --- | --- |
| Comment-only edit under `sdk-libs/client/src` then `ts-fixtures --check` | exit 0 |
| Same comment then `--current-client` write | fixtures unchanged vs pre-comment bytes |
| Real behaviour change (`IndexerPollConfig::backoff` multiplier 2→3) then `--check` | exit 1, `client/rpc-indexer-v1.json` differs |
| Both probes reverted | clean relative to this work |

Also: `npm run build`, `node sdk-libs/ts/config/inventory-check.mjs`, and
`ts-fixtures --current-client --check` after the regen.

## F083 verdict

Finding F083 claims one baseline SHA is repeated across ~178 files and asks for
centralization.

Evidence on this worktree for `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`:

- **177 files** repo-wide (matches the finding’s order of magnitude).
- **159** are under `planning/` (prose, logs, inventories).
- **18** are machine-readable outside planning: one `HISTORICAL_BASELINE_SHA` in
  `ts-fixtures.rs`, generated reports (`inventory.json`, packet reports
  `P00` through `P13`), and generated fixture/manifest stamps.

So the finding is **overstated as an actionable rebaseline cost**. Generators
already had a single constant; reports and most fixture stamps are outputs of
that constant. A 178-file mechanical edit would mostly rewrite planning prose
and generated JSON and would be harmful this late in the PR.

What was real: two hand-maintained consumers duplicated the pin
(`inventory-check.mjs`, `error.test.ts`). Those now consume
`fixtures/manifest.json` / the loaded manifest. No further centralization
refactor.

## Open questions

None that block this packet. Light Protocol does not define a counterpart
mechanism; the body-vs-stamp split is the local fix.
