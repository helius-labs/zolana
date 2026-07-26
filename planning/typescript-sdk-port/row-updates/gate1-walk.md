# Gate 1 — per-package evidence walk

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-wt-gate1-walk` |
| Branch | `port/gate1-walk` |
| Measured revision | `ddee6465` (walk commits on top of `72b0a7bc`) |
| Measured at | 2026-07-26 |
| Scope | Package completion gates in `review-checklist.md` × eleven workspaces |

Method: adversarial walk. Each cell is **evidence** (named test, script, or log)
or a **named gap**. Claims whose cited files do not exist at HEAD, or do not
test what the bullet asks, are called out. Small closable gaps were fixed in
commit `ddee6465`; larger ones stay open.

Package abbreviations: `H` hasher, `I` interface, `K` keypair, `T` transaction,
`IA` indexer-api, `A` api, `C` client, `W` wallet, `M` merkle-tree, `SA`
smart-account-client, `TK` test-kit.

Bullet labels match the package-completion list (G9-4 and G6-2 already closed
before this walk).

---

## Command results (this revision)

| Command | Result |
| --- | --- |
| `npm install` | green (196 packages) |
| `npm run build` | green (run before every suite) |
| `npm run test:unit` | **green** — 132 files passed, 2 skipped; 2234 tests passed, 9 skipped |
| `npm run check:static` | **red** — only the seven known errors in `client/test/vectors/g2-compression-live.test.ts` (owned by another worker; left untouched). `format:check` alone is green |
| `npm run check:packaging` | **green** — inventory, exports, dependencies, api scaffold, browser static scan, pack:check |
| `npm run fixtures:check` | **green** — all listed generators including `poseidon-parity` and `ts-fixtures` (`verified 58 fixtures and 182 inventory rows`) |

---

## Closable gaps closed this walk (`ddee6465`)

1. `@zolana/hasher` was absent from `public-exports.md` — section + Rust-root
   reconciliation note added.
2. Missing export pin tests: `hasher/test/exports.test.ts`,
   `indexer-api/test/exports.test.ts`, `test-kit/test/exports.test.ts`.
3. Scaffold `vectorPackages` omitted `hasher` despite a non-vacuous
   `test:vectors` — added in `workspace-check.mjs`.
4. `interface-current-dispositions.md` still claimed TypeScript merge codecs
   reject non-canonical prefixes and that deposit/protocol-config were blocked —
   both false after `78039fe9` / interface-spec rulings. Corrected.

---

## Adversarial findings (cited evidence that does not hold)

| Claim | Reality at HEAD |
| --- | --- |
| `public-exports.md` final paragraph: an API-report check fails for every runtime export absent from that file | **False.** `npm run api:check` runs `workspace-check.mjs api`, which only asserts package scripts / scaffold (`test:browser`, non-vacuous vectors, etc.). There is no api-extractor report against `public-exports.md`. Corrected in the reconciliation note. |
| E03 note: `OutputUtxo` has "no importer and no consumer" | **Unreachability holds** for the interface type (only defined in `interface/src/index.ts` and ledger-mapped `OutputUtxo: null` in `rust-oracle.test.ts`). Do not confuse with `ProofOutputUtxo` in `@zolana/transaction`. Disposition (delete vs keep) remains open — row stays `needs_re_review`. |
| `interface-current-dispositions.md` merge-prefix / blocked-deposit notes | **Stale** before this walk; corrected in `ddee6465`. |
| Gate12 / prior "nine packages" roll-ups covering hasher and test-kit | **Insufficient.** Hasher H01–H14 rows point at sibling Poseidon ports, not `@zolana/hasher`. Test-kit has **zero** primary-queue rows. |
| Inventory as per-package fixture gate | `inventory.json` has **no** hasher / `sdk-libs/ts/hasher` paths. Poseidon vectors live under `sdk-libs/ts/vectors/` and are gated by `poseidon-parity --check` inside `fixtures:check`, not by the manifest file list. |
| G9-4 / G6-2 as *per-package* walks | They close the named production-readiness issues. G9-4 runs hasher+keypair crypto vectors in Chromium, not every browser package's full vector suite. G6-2 censuses keypair secret-adjacent accessors (the package that owns them). |

---

## Primary-queue row status (bullet P1 / P15)

Recount of 145 primary rows at this HEAD:

| Status / verdict | Count |
| --- | --- |
| `done` / `PARITY` | 135 |
| `done` / `NOT_APPLICABLE` | 7 |
| `needs_re_review` / `NOT_APPLICABLE` | 3 (`E03`, `E05`, `E06`) |
| `PARTIAL` / `MISSING` / `DIVERGENT` / `STALE` / `BLOCKED` | **0** |

Package mapping of TypeScript owners:

| Package | Primary rows | Notes |
| --- | --- | --- |
| hasher | 0 as package | H01–H14 exist but TS paths are keypair/interface/transaction/merkle-tree/client |
| interface | 38 | includes `E03` `needs_re_review` |
| keypair | 13+ (K*) | all `done`/`PARITY` in recount |
| transaction | 30 | all `done`/`PARITY` |
| indexer-api | 1 | `done`/`PARITY` |
| api | 1 | `done`/`PARITY` |
| client | 20 | all `done`/`PARITY` |
| wallet | 11 | all `done`/`PARITY` |
| merkle-tree | 12 | mix `PARITY` / `NOT_APPLICABLE` |
| smart-account-client | 1 | `done`/`PARITY` |
| test-kit | 0 | private annex; no primary-queue seat |

`E05`/`E06`: disposition text exists; `program-test` feature is off by default in
`program-libs/event/Cargo.toml` (confirmed). No TypeScript `GeneralEvent` /
`EventKind` / `encode_event_*` symbols. Rows still `needs_re_review` because the
checklist asks for reviewed confirmation, not a one-line Cargo.toml reading.

---

## Matrix

Legend: **OK** = evidence holds for this package; **GAP** = named gap;
**N/A** = bullet not applicable with reason; **PRIOR** = closed before this walk
(G9-4 / G6-2).

### Compact matrix (packages × bullets)

| Bullet | H | I | K | T | IA | A | C | W | M | SA | TK |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P1 rows done PARITY/N/A | GAP | GAP | OK | OK | OK | OK | OK | OK | OK | OK | GAP |
| P2 Rust export disposition | OK* | OK | OK | OK | OK | OK | OK | OK | OK | OK | GAP |
| P3 TS export → Rust/adaptation | OK* | OK | OK | OK | OK | OK | OK | OK | OK | OK | GAP |
| P4 inventory independent evidence | GAP | OK | OK | OK | OK | OK | OK | OK | OK | OK | GAP |
| P5 fixture provenance + drift | OK† | GAP | GAP | GAP | GAP | GAP | GAP | GAP | GAP | GAP | GAP |
| P6 deterministic byte parity | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | N/A |
| P7 non-deterministic / property | N/A | N/A | OK | OK | OK | OK | GAP | GAP | OK | OK | N/A |
| P8 rejection / tamper coverage | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| P9 stable error codes / details | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| P10 browser vs Node entry points | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK |
| P11 feature gates / proof rails | N/A | OK | OK | OK | N/A | N/A | GAP | N/A | N/A | N/A | N/A |
| P12 package/browser/vector/pack checks | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK‡ |
| P13 G9-4 browser runtime | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | N/A |
| P14 G6-2 aliasing census | N/A | N/A | PRIOR | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| P15 no adverse verdicts | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK | OK |

\* Hasher disposition closed this walk (`public-exports.md` + `exports.test.ts`).
† Hasher Poseidon vectors verified by `fixtures:check` → `poseidon-parity --check`;
  not listed in `fixtures/manifest.json` (manifest gap, not an ungated file).
‡ test-kit: exports/deps/api scaffold/pack apply; no `test:browser` /
  `test:vectors` by design (`browser: false`, private annex).

### Bullet detail (evidence or gap)

#### P1 — Each package row is `done` with `PARITY` or justified `NOT_APPLICABLE`

| Pkg | Cell |
| --- | --- |
| H | **GAP `H-ROW`**: no primary row owns `@zolana/hasher`; H01–H14 certify sibling Poseidon ports / N/A syscall surfaces |
| I | **GAP `E03`**: `needs_re_review` / `NOT_APPLICABLE` — type exported, disposition (delete vs keep) unresolved |
| K–SA except I | **OK** — all mapped rows `done` |
| TK | **GAP `TK-ROW`**: zero primary-queue rows for `program-test` / test-kit annex |

#### P2 — Complete public Rust export set has a TypeScript disposition

| Pkg | Evidence or gap |
| --- | --- |
| H | **OK\*** `public-exports.md` `@zolana/hasher` + narrow WASM surface vs full `zolana-hasher` crate noted in reconciliation |
| I | **OK** re-export ledgers in `interface/test/vectors/rust-oracle.test.ts` (`builders` / `instruction_data` / `state` / `instruction`) |
| K | **OK** `keypair/test/api-surface.test.ts`, `trait-surface.test.ts`, certification vectors |
| T | **OK** `transaction/test/vectors/module-surface.test.ts` |
| IA | **OK** `indexer-api/test/exports.test.ts` + `public-exports.md` |
| A | **OK** `api/test/exports.test.ts` (async-only; no `BlockingZolanaApi`) |
| C | **OK** `client/test/vectors/crate-root-exports.test.ts` |
| W | **OK** `wallet/test/vectors/export-vector.test.ts` |
| M | **OK** `merkle-tree/test/exports.test.ts` vs crate modules |
| SA | **OK** `smart-account-client/test/exports.test.ts` `RUST_TO_TS` map |
| TK | **GAP `TK-DISP`**: root five names documented; `@zolana/test-kit/node` re-exports admin/events/indexer/… without a Rust-root disposition ledger against `sdk-libs/program-test/src/lib.rs` |

#### P3 — Each TypeScript export traces to Rust or documented adaptation

Same evidence as P2 for packages with pin/ledger tests. **GAP `TK-DISP`** for
test-kit `/node`. Hasher adaptations (slim, inlined wasm, short-input
right-align) are documented in `public-exports.md` / hasher packaging notes.

#### P4 — Inventory claims have evidence independent of the inventory

| Pkg | Cell |
| --- | --- |
| H | **GAP `H-INV`**: `inventory.json` has no hasher rows; independence is via `poseidon-parity` / package tests, not inventory |
| I–SA | **OK** in spirit — primary rows + vector/oracle tests; `npm run test:inventory` only checks inventory shape vs paths |
| TK | **GAP `TK-INV`**: inventory rows under `program-test` point at Rust; TS annex surface is not inventory-backed |

#### P5 — Fixture provenance fresh for reviewed Rust revision; drift reviewed

| Pkg | Cell |
| --- | --- |
| All | **GAP `FIX-DRIFT`**: `fixtures/manifest.json` `frozenCommit` =
  `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; HEAD has **456** commits touching
  `sdk-libs/` / `program-libs/` since that pin. `fixtures:check` proves
  generators reproduce committed bytes **at current Rust**, which is stronger
  than the pin, but the package gate also asks for a reviewed drift story and
  G8-1 (compatibility rule per revision key) remains open. Not closed as a
  per-package freshness claim. Do not edit manifest / fixtures-check here
  (owned elsewhere). |
| H | Poseidon vector gated by `poseidon-parity` inside `fixtures:check` (**OK†**
  for that file); still inherits `FIX-DRIFT` for the manifest story |

#### P6 — Deterministic bytes match current Rust where applicable

| Pkg | Evidence |
| --- | --- |
| H | `hasher/test/vectors/poseidon-parity.test.ts`, `poseidon-rejection-parity.test.ts` |
| I | `interface/test/vectors/rust-oracle.test.ts`, `interface-vector.test.ts` |
| K | `keypair-parity.test.ts`, key-certification suites |
| T | `transaction/test/vectors/rust-oracle.test.ts`, `transaction-vectors.test.ts` |
| IA | `indexer-api/test/scalar-parity.test.ts`, `vectors.test.ts` |
| A | `api/test/vectors.test.ts` |
| C | multiple `client/test/vectors/*oracle*.test.ts`, prover-request parity |
| W | `deposit-vector.test.ts`, wallet action/sync vectors |
| M | `program-libs-hasher.test.ts`, `merkle-semantics.test.ts` |
| SA | `smart-account-client/test/vectors.test.ts` |
| TK | **N/A** — harness/annex; not a byte-oracle package (fixture hash pin in `test-kit.test.ts` for standard-accounts only) |

#### P7 — Non-deterministic behavior has invariant or property coverage

| Pkg | Cell |
| --- | --- |
| H, I, TK | **N/A** — deterministic / harness |
| K, T, IA, A, M, SA | **OK** — package `test:property` suites present and required by scaffold |
| C, W | **GAP `PROP`**: no package `test:property`; non-deterministic paths (retry backoff, sync ordering) covered only by focused unit/vector tests, not a property suite |

#### P8 — Rust rejection, malformed-input, and tamper behavior has TypeScript coverage

Representative evidence (not exhaustive): hasher rejection parity; interface
oracle reject cases; keypair certification dispositions; transaction zone /
serialization rejects; indexer-api integer-domain; api transport errors; client
oversized-tx / prover edge cases; wallet submit rejection oracles; merkle-tree
indexed bounds; smart-account-client `boundaries.test.ts`; test-kit malformed
base58 / fixture / abort rejects.

#### P9 — Errors preserve stable codes and structured details

| Pkg | Evidence |
| --- | --- |
| H | `HasherWasmError.code` vs Rust codes in rejection-parity |
| I | `ShieldedPoolError` / messages vs `ts-interface-oracle` |
| K | `error-redaction-certification.test.ts`, `KEYPAIR_ERROR_RUST_VARIANT` |
| T | `TRANSACTION_ERROR_CODES` + redaction in `error.ts` |
| IA | `IndexerSchemaError` |
| A | `ApiError` |
| C | `CANONICAL_CLIENT_ERROR_CODES` disposition in `error.test.ts` |
| W | `WALLET_ERROR_CODES` |
| M | `MerkleTreeError` / `IndexedMerkleTreeError` |
| SA | `SmartAccountClientError` |
| TK | `TestKitError` codes in unit tests |

Residual (does not flip P9 to GAP for the package gate alone; owned under gate 2):
`KEYPAIR_HASH` empty-slice merge-hash variant mismatch recorded in
`gate12-pkg.md` / certification residuals.

#### P10 — Browser-safe entry points; Node-only stays documented

| Pkg | Evidence |
| --- | --- |
| H–SA | `browser: true`; `npm run test:browser` / `check:packaging` green; dual export conditions |
| TK | `browser: false`; Node-only `./node`; root contract documented; `exports.test.ts` keeps annex helpers off root |

#### P11 — Feature-gated behavior and each supported proof rail have a disposition

| Pkg | Cell |
| --- | --- |
| C | **GAP `RAIL`**: shape/rail matrix and G2 compression owned by parallel workers; P3 does not certify G2; do not touch `compress.ts` / CI / fixture manifest here |
| I | **OK** — `SPP_SUPPORTED_SHAPES` / shape oracle |
| K, T | **OK** — ed25519 / P256 rails in certification and transaction builders |
| Others | **N/A** or inherit via client |

#### P12 — Relevant focused / package / browser / vector / property / export / dependency / pack checks pass

Workspace `check:packaging` green this revision (all eleven). Unit suite green.
Static lint red only on owned-elsewhere g2 file — not counted against packages
in this walk. Hasher now in `vectorPackages`. test-kit omits browser/vectors by
configuration.

#### P13 — G9-4 browser runtime (PRIOR)

Evidence: `npm run test:browser-runtime` / `check:browser-runtime`; harness in
`browser-runtime-harness.mjs`. N/A for test-kit (`browser: false`).

#### P14 — G6-2 aliasing census (PRIOR)

Evidence: `keypair/test/vectors/aliasing-census.test.ts`. N/A for packages
without public secret-adjacent byte accessors (hasher `poseidon` returns a
copied digest slice; not a stored-secret accessor).

#### P15 — No `PARTIAL` / `MISSING` / `DIVERGENT` / `STALE` / `BLOCKED`

**OK across the queue** — zero rows with those verdicts. Does **not** clear
`needs_re_review` on E03/E05/E06 (different status; blocks P1).

---

## Which bullets are closed across all eleven packages?

| Bullet | Closed? |
| --- | --- |
| P13 G9-4 | **Yes** (prior; N/A test-kit) |
| P14 G6-2 | **Yes** (prior; N/A where no secret accessors) |
| P15 no adverse verdicts | **Yes** (this walk recount) |
| P1–P12 | **No** — at least one package carries a GAP (see matrix) |

Top-level Full SDK gate line *"Each of the eleven workspace packages passes its
package gates"* remains **unchecked**.

---

## Packages carrying gaps (summary)

| Package | Gaps |
| --- | --- |
| hasher | `H-ROW` (no primary seat); `H-INV` (not in inventory); inherits `FIX-DRIFT` |
| interface | `E03` disposition open; `E05`/`E06` still `needs_re_review`; `FIX-DRIFT` |
| keypair / transaction / indexer-api / api / merkle-tree / smart-account-client | `FIX-DRIFT`; otherwise strongest cells |
| client | `FIX-DRIFT`; `PROP`; `RAIL` (G2 / full shape matrix out of scope here) |
| wallet | `FIX-DRIFT`; `PROP` |
| test-kit | `TK-ROW`; `TK-DISP`; `TK-INV`; `FIX-DRIFT` |

---

## Checklist updates made

In `review-checklist.md` package-completion block: check **P15** only (plus
prior G9-4 / G6-2). Leave P1–P12 and the Full SDK eleven-package line unchecked.
Record this file as the walk evidence.
