# FND blockers — verdicts and fixes

Worktree: `zolana-ts-fnd-blockers` · branch `port/fnd-blockers` · base `e238fe97`.

## Verdicts

| ID | Verdict | Evidence |
|----|---------|----------|
| **F070** | CONFIRMED | Canonical `isEd25519Point` in `sdk-libs/ts/interface/src/internal.ts:148` requires `(root !== 0n \|\| sign === 0)`. Wallet `registry.ts:102-113` and test-kit `user-registry.ts:499-510` (pre-fix) returned only `x² == x2`, omitting the clause. |
| **F080** | CONFIRMED | `e2e/actions/live.test.ts:94` covers registration / merge opt-in / ATA only. `e2e/instructions/live.test.ts:42` is a negative wrong-signature case. No positive proved shielded transfer/merge against a live validator. **P4 certification suite owns the fix — do not build here.** |
| **F001** | PARTIAL | At `e238fe97`, all 182 inventory `path` values exist on disk (the “82 missing” claim is stale). `inventory-check.mjs` still only pinned `frozenCommit` + row count + field presence — no `fs` existence check. |
| **F109** | CONFIRMED | Rust `MergeWitness` clears both hashes at `sdk-libs/client/src/prover/merge.rs:445-446`. TS `assembleMergeWithProofs` → `createRealInput` / `inputCircuitUtxo` retained them. Production `Merge` rejects data-carrying inputs, but hand-built `PreparedMerge` could diverge. |
| **F149** | CONFIRMED | `splitBigEndian128` used `subarray(0,16)` / `subarray(16,32)` without a length check (`hash.ts` pre-fix). 31-byte and 33-byte inputs aliased a padded/truncated 32-byte field. Rust `hash_field(&[u8; 32])` cannot represent those. `match_rust` does not excuse being looser. |
| **F121** | CONFIRMED | `MAX_BODY_BYTES = 1 MiB` in `api/src/index.ts`. With hex hashes, a 1000-tx page exceeds 1 MiB once per-slot ciphertext ≈ 50 bytes (≈1.07 MiB); 85-byte slots ≈ 1.16 MiB. TypeScript-only failure vs Photon. |
| **A001** | WRONG | Finding claims Rust lets callers disambiguate by tree via `transaction.rs:485-548`. That `tree` parameter is internal to `select_merge_inputs`. Public `MergeParams` (`:411-418`) has only `wallet`, `keypair`, `asset`, `inputs` — same as TS. Both auto-sweep reject multi-tree; both disambiguate via explicit input hashes. |
| **F089** | CONFIRMED | Rust `event::decode_output_data` (`program-libs/event/src/program_test.rs:77-91`) requires plaintext + scheme 0 + `ProoflessOutput`. TS `isDecodablePayload` only called generic `decodeOutputData`. Comments claiming Rust is more permissive were inverted. |

## Fixes landed (one commit each)

| Commit | Finding |
|--------|---------|
| `23ebb28d` | F070 — export `findProgramAddress` / `isEd25519Point`; wallet + test-kit reuse them |
| `b164a87e` | F001 — inventory gate `access()`es every row path |
| `bef83c95` | F109 — plain-rail hash clear + TS oracle test + Rust `plain_merge_clears_nonzero_data_hashes` |
| `24b2b515` | F149 — exact-32 check in `splitBigEndian128` / `ownerHash` |
| `95f5de3d` | F121 — `MAX_BODY_BYTES = 10 MiB` |
| `67fbd194` | F089 — compose `decodeOutputData` + scheme-proofless + `decodeProofless` |

## Deliberately not fixed

- **F080** — gap real; P4 owns the positive end-to-end proved transaction suite. Building it here would duplicate that work.
- **A001** — claim that Rust already has a public `tree` selector is a misread. Auto-sweep multi-tree rejection is shared. Adding `tree` only to TypeScript would be a unilateral API expansion; needs an owner ruling if both SDKs should grow that parameter.

## Owner rulings needed

1. **A001 / tree selector** — Should `MergeParams` gain an optional `tree` in *both* Rust and TypeScript so auto-sweep can target one tree after a rollover, or is explicit-hash selection enough?
2. **F001 remainder** — Gate now checks source paths exist. Fixture-responsibility prose and “executable check runs” are still not machine-verified; say whether that is in scope for a follow-up or accepted as documentation.

## Checks run

- `cargo test -p zolana-client --lib plain_merge_clears` — pass
- `npm run build` then targeted vitest: interface ed25519-point, api responses, keypair-parity, merge-oracle, wallet sync — pass
- `npm run test:inventory` — pass
