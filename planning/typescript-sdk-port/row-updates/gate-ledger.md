# Gate ledger — Full SDK document-and-verification lines

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-wt-gate-ledger` |
| Branch | `port/gate-ledger` |
| Measured at | 2026-07-26 |
| Scope | Four Full SDK completion-gate lines: cross-package boundaries, live Photon, fixture provenance/rejection-tamper, public-export ledger + adverse-verdict emptiness |

## Verdict summary

| Gate line | Status | Notes |
| --- | --- | --- |
| Cross-package types/errors/deps/capabilities | **Closed** | Forester carve-out (a) kept; obsolete G2 carve-out (b) removed |
| Live Photon contract | **Closed** | Suite + CI wiring present at HEAD |
| Fixture provenance + rejection/tamper | **Open** | Provenance (G8-1/G8-2) holds; indexer-api + smart-account-client lack Rust-generated reject/tamper fixtures |
| Public-export ledger | **Closed** | Disposition tests empty of unexplained exports; hasher ledger section added |
| No unresolved adverse verdict | **Closed** | 0 adverse among 145 primary rows |

## Obsolete G2 carve-out

Checklist Gate 2 previously excepted "(b) P3 G2 proof compression, owned by
`port/g2`". That was wrong framing. Root cause was TypeScript reading each gnark
`Fq2` as `c0` then `c1` while gnark writes `c1` first (`c1a9b35e`,
[g2.md](g2.md)). Committed live evidence
[g2-compression-live.json](g2-compression-live.json): `tsCompressOk` 16,
`matchesRust` 16, `rustFallbackNeeded` 0. Carve-out (b) is removed from the
checklist. Carve-out (a), the forester path, stays as an owner ruling.

Side effect of the fix: `@zolana/client` stopped importing `@noble/curves` but
left it in `package.json` / `packages.mjs`, so `npm run test:dependencies`
failed. Removed in `a9508d05`.

## Gate — cross-package boundaries

Checked against HEAD, not against [gate12-pkg.md](gate12-pkg.md)'s earlier
PARTIAL:

| Residual (from gates.md / gate12-pkg) | HEAD |
| --- | --- |
| Empty-slice merge ciphertext → `KEYPAIR_HASH` | Closed: `KEYPAIR_POSEIDON` (`security.test.ts`, `error-redaction-certification.test.ts`) |
| Capability `Promise` | `ViewingKeyLike` synchronous; `ShieldedKeypairLike` keeps `T \| Promise<T>` per Q17 |
| `address-append` / `batchUpdateNullifierTreeInstruction` | Owner carve-out (a); builder absent; codec + tag retained; `circuit-types.test.ts` enforces |
| P3 G2 compress | Fixed; not a divergence |
| Dependency / export / api scaffolding | `test:dependencies`, `test:exports`, `api:check` pass after `a9508d05` |

## Gate — live Photon contract

Evidence exists at HEAD (not only in the plan):

| Item | Path |
| --- | --- |
| Suite | `sdk-libs/ts/e2e/photon/photon-contract.live.test.ts` — **11** `it(...)` cases |
| Script | `package.json` → `test:e2e:photon` (`ZOLANA_PORT_OFFSET=800`) |
| Merge tier | `check:e2e` includes `test:e2e:photon`; `.github/workflows/typescript.yml` e2e job runs `npm run check:e2e` after `just build-photon` |
| Report | [gate6-photon.md](gate6-photon.md) records control edits (`block_time` rename / type→string) failing the suite |

This worker did not re-run the live stack (offset 800). Closure rests on the
suite, scripts, and workflow being present and wired at HEAD, matching the
report's described contract.

## Gate — fixture provenance + rejection/tamper

### Provenance (holds)

G8-1 and G8-2 at `6bcd79ae` ([gate-ci.md](gate-ci.md)):

- `manifest.json` `revisionCompatibility` for all nine identity keys
- `fixtures-provenance.mjs` binds fixture `sourceRevision` to pins
- Proof fixtures carry `verifyingKeys[{module,rail,sha256}]`

### Rejection / tamper (does not fully hold)

Audit of `sdk-libs/ts/fixtures/**/*.json` for error/reject/tamper keys:

**Have reject/tamper (or error mutations) in fixtures:** api (transport +
prover-request), client (errors, proof-validity, proof-result-compression,
rpc-indexer), keypair (error, merge), merkle-tree (paths), most transaction and
wallet fixtures, workflows (split tamper, instruction malformed/replay, merge
typed errors).

**Gated vectors with rejects (via `fixtures:check` generators):**
`poseidon-parity-v1`, `program-libs-parity-v1`, `proof-response-parity-v1`, and
related.

**Gaps (rejection applicable, fixture is success-only):**

| Package | Fixture | Rejection coverage today |
| --- | --- | --- |
| `@zolana/indexer-api` | `schema-v1.json` (bounds only) | Hand-written `schema.test.ts` rejects; not Rust-generated |
| `@zolana/smart-account-client` | `standard-create-v1.json` | Hand-written `boundaries.test.ts`; not Rust-generated |

Closing those needs xtask generator changes and a `manifest.json` sha256 update.
This worker is forbidden from editing `manifest.json` and
`fixtures-check.mjs`, so the gaps are reported rather than papered over. The
checklist line stays **unchecked**.

Success-only fixtures that are census/constants (e.g. `client/lib.json`,
`keypair/constants.json`, `test-kit/standard-accounts-v1.json`) are not gaps.

## Gate — public-export ledger

| Check | Result |
| --- | --- |
| `crate-root-exports.test.ts` unexplained root exports | `[]` (3 tests) |
| `module-surface.test.ts` unexplained barrel exports | `[]` (24 tests) |
| `export-vector.test.ts` | 11 tests pass |
| `@zolana/hasher` in `public-exports.md` | Was **absent**; section added this run |
| Claimed "API-report check" parsing `public-exports.md` | **Does not exist.** `npm run api:check` only runs scaffolding asserts in `workspace-check.mjs` |

Cited evidence that does not test what it claimed: the closing paragraph of
`public-exports.md` said an API-report check fails for every runtime export
absent from the file. That check is not implemented. The prose is corrected to
name the disposition tests as the real gate.

## Gate — no unresolved adverse verdict

Recounted with a table parser over `review-checklist.md` primary rows:

```
total 145
status: done 142, needs_re_review 3
verdict: PARITY 135, NOT_APPLICABLE 10
adverse-like (MISSING|PARTIAL|OPEN|STALE|DIVERGENT|BLOCKED): 0
```

`needs_re_review` + `NOT_APPLICABLE` on E03/E05/E06 are confirmed dispositions
awaiting artifact refresh, not adverse open findings (see
[scope-and-denominator.md](../scope-and-denominator.md)). Unchecked
package-completion bullets remain incomplete walks; they are not adverse
verdicts.

## Commands run

After `npm install` and `npm run build` in this worktree:

| Command | Result |
| --- | --- |
| `npm run test:dependencies` | pass (after `a9508d05`) |
| `npm run test:exports` | pass |
| `npm run api:check` | pass |
| Export disposition tests (client / transaction / wallet) | pass |
| `npm run build && npm run test:unit` | (recorded in final pass below) |
| `npm run check:static` | (recorded in final pass below) |
| `npm run fixtures:check` | (recorded in final pass below) |
| `npm run check:packaging` | (recorded in final pass below) |

## Commits on this branch for this cluster

1. `a9508d05` — `fix(client): drop unused @noble/curves after G2 compress fix`
2. (docs) public-exports hasher section + checklist + this report
