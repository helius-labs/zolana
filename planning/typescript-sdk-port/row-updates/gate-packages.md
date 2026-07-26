# Package-gate evidence walk

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-wt-gatepkg` |
| Branch | `port/gate-packages` |
| Measured at | 2026-07-26 |
| Scope | Package-completion bullets × eleven workspaces; re-walk after real `api:check` and example-surface reconciliation |

Method: adversarial walk. Each cell is **evidence** (named test, script, or
command result) or a **named gap**. Cheap missing pins were produced in this
worktree; behavioural defects owned by `port/tail-fixes` / `port/tail-small` /
`port/baseline-hash` were not fixed here.

Package abbreviations: `H` hasher, `I` interface, `K` keypair, `T` transaction,
`IA` indexer-api, `A` api, `C` client, `W` wallet, `M` merkle-tree, `SA`
smart-account-client, `TK` test-kit.

Bullet labels match the package-completion list in `review-checklist.md`.

---

## Command results (this revision)

| Command | Result |
| --- | --- |
| `npm install` | green (196 packages) |
| `npm run build` | green (run before every suite) |
| `npm run test:unit` | **green** — 140 files passed, 2 skipped; **2362** tests passed, 9 skipped |
| `npm run check:static` | **green** (scope, typecheck, lint, format) |
| `npm run check:packaging` | **green** — inventory 182+4, exports, deps, **`api reports match for 11 packages`**, browser, pack |
| `npm run fixtures:check` | **green** — all generators including reject oracles; `fixture provenance ok` |

First full-unit run timed out once on
`client/test/vectors/g2-eip197-limbs.test.ts` waiting on a cold
`cargo run -p xtask --bin groth16-verify` under the parallel pool. Raised that
test's timeout to 120s; subsequent full unit run was green in ~11s with a warm
binary. Not a behavioural defect owned by other workers.

---

## Prior state and ordering constraint

HANDOVER recorded **5 of 15** package bullets checked. After `port/gate1-gaps`
the checklist already had P1–P5, P7, P12–P15 checked (10 of 15). The five open
bullets were **P6, P8, P9, P10, P11**. The export-census bullets (P2/P3 and the
Full SDK public-export ledger) rested on a scaffold `api:check` that never
parsed surfaces; that is now real (`api-check.mjs` vs
`sdk-libs/ts/api-reports/**`), and the client surface was reconciled onto the
example shape (`row-updates/example-surface.md`). This walk re-affirms those
census bullets against the stable surface and closes P6/P8–P11 with named
artifacts.

`@zolana/hasher` and `@zolana/test-kit` received extra scrutiny (seated late
as `H15` / `TK01`/`TK02`).

---

## Evidence produced this walk

| Artifact | Why |
| --- | --- |
| `test-kit/test/exports.test.ts` | Pins `./node` and `./fixtures` value exports to `api-reports/test-kit.json`; closed `TEST_KIT_*` code scan over `src/` |
| `smart-account-client/test/vectors/rejects.test.ts` | Each Rust reject case now asserts the matching `SmartAccountClientError.code` |
| `public-exports.md` client zone note | Removed stale "deferred to PKP-05"; records `assembleZone*` adaptation |

---

## Compact matrix (open bullets + census)

Legend: **OK** = named evidence holds; **N/A** = not applicable with reason;
**PRIOR** = already checked with evidence that still holds after re-walk.

| Bullet | H | I | K | T | IA | A | C | W | M | SA | TK |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P1 rows done | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR |
| P2 Rust disposition | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR |
| P3 TS → Rust/adapt | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR |
| P4 inventory evidence | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR |
| P5 fixture provenance | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR |
| **P6 deterministic bytes** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **N/A** |
| P7 property / invariant | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR |
| **P8 reject / tamper** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** |
| **P9 stable error codes** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** |
| **P10 browser vs Node** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** | **OK** |
| **P11 rails / features** | **N/A** | **OK** | **OK** | **OK** | **N/A** | **N/A** | **OK** | **N/A** | **N/A** | **N/A** | **N/A** |
| P12 packaging checks | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR |
| P13 G9-4 browser runtime | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | N/A |
| P14 G6-2 aliasing | N/A | N/A | PRIOR | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| P15 no adverse verdicts | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR | PRIOR |

---

## Export census re-walk (P2 / P3 / api:check)

`npm run api:check` extracts each package entry point from built `.d.ts` +
runtime `Object.keys` and compares to committed
`sdk-libs/ts/api-reports/<pkg>.json`. It does **not** parse
`public-exports.md`; that file remains the human allowlist.

| Package | api-report | Surface pin test | public-exports.md |
| --- | --- | --- | --- |
| hasher | `api-reports/hasher.json` | `hasher/test/exports.test.ts` | `@zolana/hasher` |
| interface | `api-reports/interface.json` | `interface/test/exports.test.ts` | `@zolana/interface` |
| keypair | `api-reports/keypair.json` | `keypair/test/api-surface.test.ts` | `@zolana/keypair` |
| transaction | `api-reports/transaction.json` | `transaction/test/vectors/module-surface.test.ts` | `@zolana/transaction` |
| indexer-api | `api-reports/indexer-api.json` | `indexer-api/test/exports.test.ts` | `@zolana/indexer-api` |
| api | `api-reports/api.json` | `api/test/exports.test.ts` | `@zolana/api` |
| client | `api-reports/client.json` | `client/test/vectors/crate-root-exports.test.ts` | `@zolana/client` |
| wallet | `api-reports/wallet.json` | `wallet/test/vectors/export-vector.test.ts` | `@zolana/wallet` |
| merkle-tree | `api-reports/merkle-tree.json` | `merkle-tree/test/exports.test.ts` | `@zolana/merkle-tree` |
| smart-account-client | `api-reports/smart-account-client.json` | `smart-account-client/test/exports.test.ts` | `@zolana/smart-account-client` |
| test-kit | `api-reports/test-kit.json` | `test-kit/test/exports.test.ts` (root + **node** + **fixtures**) | root + annex ledger |

P2/P3 checklist ticks remain justified. test-kit `/node` annex dispositions live
in `test-kit-node-dispositions.md`; runtime pins now match the api-report.

---

## P6 — Deterministic byte parity

| Pkg | Status | Artifact |
| --- | --- | --- |
| H | OK | `hasher/test/vectors/poseidon-parity.test.ts` ← `vectors/poseidon-parity-v1.json`; `fixtures:check` → `poseidon-parity --check` |
| I | OK | `interface/test/vectors/rust-oracle.test.ts` ← `interface/test/rust-oracle.json`; `interface-vector.test.ts` ← `fixtures/interface/deposit-instruction-v1.json` |
| K | OK | `keypair/test/vectors/keypair-parity.test.ts` ← `vectors/keypair-parity-v1.json`; key-certification suites |
| T | OK | `transaction/test/vectors/rust-oracle.test.ts` ← `transaction/test/oracles/transaction-parity-v1.json` |
| IA | OK | `indexer-api/test/scalar-parity.test.ts`; `vectors.test.ts` ← `fixtures/indexer-api/schema-v1.json` |
| A | OK | `api/test/vectors.test.ts` ← `fixtures/api/transport-v1.json` |
| C | OK | `client/test/vectors/*oracle*.test.ts`, `prover-request-parity.test.ts`, `proof-response-parity.test.ts`, `zone-oracle.test.ts`, `merge-oracle.test.ts` |
| W | OK | `wallet/test/vectors/deposit-vector.test.ts`, `wallet-actions.test.ts`, `wallet-submit.test.ts` |
| M | OK | `merkle-tree/test/vectors/merkle-semantics.test.ts` ← `vectors/merkle-semantics-v1.json` |
| SA | OK | `smart-account-client/test/vectors.test.ts` ← `fixtures/smart-account-client/standard-create-v1.json` |
| TK | N/A | Harness/annex; only address pin in `test-kit.test.ts` for `standard-accounts-v1.json` |

---

## P8 — Rejection / malformed / tamper

| Pkg | Status | Artifact |
| --- | --- | --- |
| H | OK | `poseidon-rejection-parity.test.ts` (modulus / arity / overlength) |
| I | OK | `rust-oracle.test.ts` decoder acceptance + prefix bounds; `ed25519-point.test.ts` |
| K | OK | capability / secret-lifecycle / error-redaction certification; parity reject arms |
| T | OK | oracle rejection helper; `wallet-sync.test.ts` tamper row; zone-resolution rejects |
| IA | OK | `schema-rejects.test.ts` ← `vectors/indexer-schema-rejects-v1.json` (accepts / rejects / tampers) |
| A | OK | `vectors.test.ts` transport failures; `transport.test.ts` / `responses.test.ts` |
| C | OK | `prover-edge-cases.test.ts`; `zone-named-rejections.test.ts`; `proof-compression.test.ts` |
| W | OK | `wallet-submit.test.ts` key mismatches; `wallet-actions.test.ts` rejects; `sync.test.ts` |
| M | OK | `merkle-semantics.test.ts` REJECTIONS map; `vectors.test.ts` tamperedProofVerified |
| SA | OK | `rejects.test.ts` ← `smart-account-rejects-v1.json` (+ code pin this walk) |
| TK | OK | `test-kit.test.ts` malformed base58 / fixture / abort / port / RPC / indexer rejects (H only; no Rust oracle — harness-appropriate) |

---

## P9 — Stable error codes and structured details

| Pkg | Status | Artifact |
| --- | --- | --- |
| H | OK | `poseidon-rejection-parity.test.ts` pins `7002` / wrapper `1` / `7005` (deliberate arity divergence documented) |
| I | OK | `rust-oracle.test.ts` `describe("errors")` — every Rust code + message |
| K | OK | `error-redaction-certification.test.ts` (K10); `KEYPAIR_ERROR_RUST_VARIANT` in parity |
| T | OK | oracle error code set + `TRANSACTION_ERROR_CODES`; `fixtures/transaction/values-and-errors-v1.json` |
| IA | OK | `IndexerSchemaError` + `rustError` in schema-rejects; scalar-parity size vs invalid hash |
| A | OK | `ApiError.code` + details in transport/responses/vectors |
| C | OK | `client/test/error.test.ts` ← `fixtures/client/errors-v1.json` (58 variants) |
| W | OK | `export-vector.test.ts` `keeps WALLET_ERROR_CODES closed over every code the package raises` |
| M | OK | REJECTIONS table in merkle-semantics; `MerkleTreeError` / `IndexedMerkleTreeError` |
| SA | OK | reject→`SMART_ACCOUNT_*` code map in `rejects.test.ts` (this walk); `boundaries.test.ts` |
| TK | OK | `exports.test.ts` closed `TEST_KIT_*` scan (this walk); construction in `test-kit.test.ts` |

---

## P10 — Browser-safe vs Node-only entry points

| Pkg | Status | Artifact |
| --- | --- | --- |
| H–SA | OK | `packages.mjs` `browser: true`; dual `browser`/`import`/`require` conditions; `test:browser` → `browser-check.mjs <pkg>`; included in workspace `npm run test:browser` / `pack:check` |
| H note | OK | Default entry inlines WASM; `./slim` takes caller artifact — no `node:fs` |
| TK | OK | `browser: false`; no `browser` export condition; `./node` and `./fixtures` documented; root pin refuses annex names; private, excluded from production packs |

Production `src/` under the ten browser packages has zero `node:` imports.

---

## P11 — Feature gates and proof rails

| Pkg | Status | Artifact |
| --- | --- | --- |
| H | N/A | Poseidon host only; full hasher crate features dispositioned to merkle-tree |
| I | OK | `SPP_SUPPORTED_SHAPES` (10); forester builder withdrawn (`exports.test.ts`); P256 wire fields |
| K | OK | `SignatureType` `"p256" \| "ed25519"`; certification + parity rails |
| T | OK | `canonicalShape` / `resolveShape`; `PreparedMerge` 8×1; `prepareZoneAuthority` |
| IA, A, W, M, SA, TK | N/A | No prover rail surface (wallet inherits client) |
| C | OK | `shape-rail-coverage.test.ts` builds requests for all shipped rails; `proof.ts` `compressG2` (gnark c1-first) + compression vector suites + `g2.md`; `circuit-types.test.ts` / `prover-request-parity.test.ts` pin `address-append` unsupported; `zone-named-rejections.test.ts` for cross-rail refusals |

Live prove-all-shapes on the same-revision prover remains a **Full SDK** gate
(`gate-prover.md` / `gate-shapes.md`), not a package-disposition gap.

---

## Hasher and test-kit (extra scrutiny)

### `@zolana/hasher`

| Check | Result |
| --- | --- |
| Primary seat | `H15` `done`/`PARITY` (gate1-gaps) |
| Export pin | `exports.test.ts` default + slim |
| api-report | `api-reports/hasher.json` |
| Byte + reject parity | Poseidon vectors + rejection-parity |
| Inventory | Live inventory row; Poseidon gated by `poseidon-parity --check`, not `manifest.json` file list |
| Thin but closed | Full `HasherError` enum not exposed — only Poseidon ABI; wrapper codes `1`/`7005` vs Rust `7002` for arity/overlength are pinned as intentional |

### `@zolana/test-kit`

| Check | Result |
| --- | --- |
| Primary seats | `TK01` root `PARITY`; `TK02` node annex `NOT_APPLICABLE` with disposition ledger |
| Root pin | five-name contract (runtime four values + `LocalStack` type) |
| Node / fixtures pin | **added this walk** against api-report |
| Error codes | **closed scan added this walk** |
| P6 | N/A (harness) |
| P8/P9 | Hand-written only — no Rust reject oracle; acceptable for private annex |

---

## Checklist updates supported by this evidence

Package completion: check **P6, P8, P9, P10, P11** (all fifteen bullets now
checked). Full SDK: check **each of the eleven workspace packages passes its
package gates**. Removed stray merge conflict marker (`=======`) and duplicate
public-export-ledger bullet; refreshed adverse-verdict recount to 148 rows /
zero `needs_re_review`.

---

## What remains open (precisely)

| Item | Needs | In scope for this PR? |
| --- | --- | --- |
| Nothing on the package-completion fifteen bullets | — | — |
| Full SDK live prove matrix / CI merge-gate required status | Already evidenced elsewhere or needs repo admin | Out of this walk's ownership |
| Spec `tx_viewing_pk` / `salt` Option vs zeroed arrays | Spec-side correction | No |
| Forester `address-append` prove path | Owner-ruled unsupported | No (documented carve-out) |
| Parallel worker behavioural tails | Owned by `port/tail-fixes`, `port/tail-small`, `port/baseline-hash` | Report only; do not fix |

No package-gate bullet was left open for lack of evidence after this walk.
