# Gate shapes — EdDSA/P256 shape set and zone named coverage

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-wt-gate-shapes` |
| Branch | `port/gate-shapes` |
| Measured revision | `12c748d62a17e61070fdf16c33d209bce5d953a4` |
| Measured at | 2026-07-26 |
| Scope | Full SDK completion gates: "EdDSA and P256 rails cover the complete supported shape set" and "Zone transfer, zone authority, and merge-zone behavior has named positive and rejection coverage" |

## Authoritative shape set

Ten shapes, ordered smallest-capacity first (canonical / first-fit order):

`1×1`, `1×2`, `2×2`, `2×3`, `3×3`, `4×3`, `4×4`, `5×3`, `5×4`, `1×8`.

Derived from:

| Source | Location | Match |
| --- | --- | --- |
| Rust interface | `program-libs/interface/src/shape.rs` `SPP_SUPPORTED_SHAPES` | ten shapes above |
| Go protocol | `prover/server/prover-test/spp/protocol/shape.go` `SupportedShapes` | identical |
| Go key manager | `prover/server/prover/common/lazy_key_manager.go` `transferSupportedShapes` | identical |
| On-chain verifier | `programs/shielded-pool/src/instructions/transact/verify.rs` `select_*_verifying_key` match arms + unit test shape table | identical |

Note: `CLAUDE.md` still names `sdk-libs/client/src/shape.rs`. That path does not
exist; the client re-exports `SPP_SUPPORTED_SHAPES` from the interface /
transaction crates. That is documentation drift, not list drift.

Zone-authority is an intentional subset of four squares — `1×1`, `2×2`, `3×3`,
`4×4` — pinned in Rust `zone_authority::SUPPORTED_SHAPES`, TypeScript
`ZONE_AUTHORITY_SHAPES`, the four `transfer_zone_authority_*` verifying keys, and
`docs/spec.md`. The six non-square members are refused.

## Drift between the four lists

**None.** All four lists carry the same ten shapes in the same order. Verifying
keys under `program-libs/interface/src/verifying_keys/` exist for confidential
eddsa/p256 and zone eddsa/p256 for every shape, and for zone-authority for the
four squares only.

## Shape-by-rail coverage matrix

Legend: **build** = TypeScript serializes a prover request; **test** = named unit/vector coverage of that build (not live prove).

| Shape | confidential eddsa | confidential p256 | transfer-zone | transfer-p256-zone | zone-authority | merge / merge-zone |
| --- | --- | --- | --- | --- | --- | --- |
| 1×1 | build+test | build+test | build+test | build+test | build+test | — |
| 1×2 | build+test | build+test | build+test | build+test | rejected | — |
| 2×2 | build+test | build+test | build+test | build+test | build+test | — |
| 2×3 | build+test | build+test | build+test | build+test | rejected | — |
| 3×3 | build+test | build+test | build+test | build+test | build+test | — |
| 4×3 | build+test | build+test | build+test | build+test | rejected | — |
| 4×4 | build+test | build+test | build+test | build+test | build+test | — |
| 5×3 | build+test | build+test | build+test | build+test | rejected | — |
| 5×4 | build+test | build+test | build+test | build+test | rejected | — |
| 1×8 | build+test | build+test | build+test | build+test | rejected | — |
| 8×1 (merge) | — | — | — | — | — | build+test both |

### Test names (positives)

| Rail | Tests |
| --- | --- |
| Confidential eddsa/p256 × 10 | `shape-rail-coverage.test.ts` (`confidential rails build…`); P1 `public-input-assembly.test.ts`; P2 `prover-request-parity.test.ts` / `prover-shapes-v1.json` |
| transfer-zone × 10 | `shape-rail-coverage.test.ts`; `zone-oracle.test.ts` (`assembles … as Rust does`, `sends the … request body`); P1/P2 zone folds |
| transfer-p256-zone × 10 | same as transfer-zone |
| transfer-zone-authority × 4 | `shape-rail-coverage.test.ts`; `zone-oracle.test.ts` (including prepared-witness positives) |
| merge / merge-zone 8×1 | `shape-rail-coverage.test.ts`; `merge-oracle.test.ts` |

### Test names (named rejections)

| Rule | Code | Test |
| --- | --- | --- |
| P256-owned input on eddsa zone rail | `CLIENT_EDDSA_INPUT_NOT_SOLANA_OWNED` | `zone-named-rejections.test.ts` |
| P256 signature on eddsa zone rail | `CLIENT_PROOF_RAIL_MISMATCH` | `zone-named-rejections.test.ts` |
| P256 zone without signature | `CLIENT_MISSING_P256_SIGNATURE` | `zone-named-rejections.test.ts` |
| All-dummy zone transfer | `CLIENT_NO_INPUTS` | `zone-named-rejections.test.ts` |
| Non-square zone-authority shape | `CLIENT_UNSUPPORTED_ZONE_AUTHORITY_SHAPE` | `zone-named-rejections.test.ts` + `zone-oracle.test.ts` (`refuses the six zone-authority shapes…`) |
| P256 signature on authority rail | `CLIENT_PROOF_RAIL_MISMATCH` | `zone-named-rejections.test.ts` |
| Unbound MergeZone input | `TRANSACTION_MERGE_INPUT_ZONE_MISMATCH` | `zone-named-rejections.test.ts` + `transfer.test.ts` |
| Zone prepared value on plain merge assembler (and reverse) | `CLIENT_INVALID_MERGE` | `zone-named-rejections.test.ts` + `merge.test.ts` |
| Zone-authority input/output zone mismatch, missing program id | `TRANSACTION_ZONE_AUTHORITY_*` / `TRANSACTION_MISSING_ZONE_AUTHORITY_PROGRAM_ID` | `transfer.test.ts` |

## Zone prover paths verified at HEAD

Worker claim that the three zone prover paths were built is confirmed in
`sdk-libs/ts/client/src/prover/zone.ts`:

- `assembleZone` → circuit `transferZone` → `transfer-zone`
- `assembleZoneP256` → circuit `transferP256Zone` → `transfer-p256-zone`
- `assembleZoneAuthority` / `assembleZoneAuthorityWitness` → `transferZoneAuthority` → `transfer-zone-authority`

## What was implemented

1. `sdk-libs/ts/client/test/vectors/shape-rail-coverage.test.ts` — pins the ten
   shapes against `SPP_SUPPORTED_SHAPES` and `prover-shapes-v1.json`, and builds
   a prover request for every confidential, zone, zone-authority, and merge-zone
   cell above.
2. `sdk-libs/ts/client/test/vectors/zone-named-rejections.test.ts` — named
   rejection coverage for zone transfer, zone authority, and merge-zone rules
   that previously lacked a rule-named client test.

Commits: `44252519`, `12c748d6`.

## What remains open

| Item | Why |
| --- | --- |
| Live prove of all 10×2 confidential shapes (and full zone matrix) | Separate checklist line: "Proof inputs work with the same-revision prover for each supported shape and rail." This worktree has no `target/prover-server` and an empty `prover/server/proving-keys/`. Not started; not claimed. |
| Address-append circuit | Owner-ruled unsupported in TypeScript (no forester). Out of scope for these two gates. |

Nothing in the supported confidential or zone shape set is unimplemented in the
SDK alone.

## Command results

| Command | Result |
| --- | --- |
| `npm install` (in worktree) | exit 0 — 196 packages |
| `npm run build` | exit 0 |
| `npm run build && npm run test:unit` | exit 0 — **2283 passed**, 9 skipped (131 files passed, 2 skipped) |
| `npm run check:static` | exit 1 — **only** the seven pre-existing lint errors in `g2-compression-live.test.ts` (owned by `port/g2`). New files lint and prettier clean. |
| `npm run fixtures:check` | exit 0 |
| New vector tests alone | exit 0 — 55 passed |

## Gate verdicts

| Gate | Verdict |
| --- | --- |
| EdDSA and P256 rails cover the complete supported shape set | **HOLDS** for request-build coverage of the ten-shape set on both rails. Checklist box checked with the evidence above. Live prove remains the separate prover gate. |
| Zone transfer, zone authority, and merge-zone named positive and rejection coverage | **HOLDS**. Checklist box checked with the named tests above. |
