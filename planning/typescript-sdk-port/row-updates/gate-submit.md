# Gate submit — instruction bytes on same-revision programs

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-wt-gate-submit` |
| Branch | `port/gate-submit` |
| Scope | Close "Instruction bytes execute against same-revision Solana programs" and the submission half of flow coverage: split, merge, private transfer, withdraw land on chain through pure TypeScript `compressProof` (no Rust compress fallback) |
| Builds on | G2 limb-order fix `c1a9b35e`; flow scaffolding in [`gate3-flows.md`](gate3-flows.md) |

## Bottom line

Every previously G2-blocked spend flow submitted and confirmed against a live
validator, live Photon, and the real prover on port offset **300**. Pure
TypeScript compression only; `ZOLANA_TEST_P5_RUST_COMPRESS` was not set.

| Flow | Landed | Evidence (tx signature) | Suite |
| --- | --- | --- | --- |
| Registration | yes | `LtwGb1augDUhp2qWpNJN7nGQzf6SMqM6ma5FoQxhKXoDs1i7zjTrp3vUEMPAmoCR3icbGP24g7JxUgAaeAKXWDC` | gate3 |
| Deposit ×2 | yes | `bTLzwRFz4Pz7PdYmhnq96JBDzcfFpm18ypVFhYzP9FcWXtJaBw1eNR5qoPgbyPrja764UYWcJjEeWXxmmywzCdC`, `4purhPNHVcEHJsAqYS2UxabwzxkCWLSLaz1Mz7bcVFQtD9GiD7dgTS2ig6TfXgPrxWKjsYDZkJ8sXFggKTyo72RW` | gate3 |
| Sync | yes | Photon syncUntil after deposits / after spends; stranger empty; idempotent re-sync | gate3 |
| Split | yes | `3mYHBPZRuvPYg4ae74gsuLeDqnV2J4h4E2unQ1FFompwb2ho2huwuXh61eh2R85YeGHGizs1FreMmSHiP1JQiXQa` | gate3 |
| Merge | yes | `2ZoFfqu8MfZz7umc1s7AvCnu2EPsxmimvAf8pT1SSEnx5UMwKjdw7rfp3uc7o2F8LVkLwiRcyKGWATRxNvMM5njC` | gate3 |
| Private transfer | yes | gate3 `BHAJL88FGVnBkhqx2v3vsaXixbTziRgVt6YBKGWZHnuPUPnHaUf9ok3Yxy5S3oy1PMY9SYLrdrzQDZWFAfe2hko`; P5 `2jTENptXaj3TVFubrsos6zwjDqDqQWrumKqJJfvYbjyaCbuVsKNGPwS7xkB6xKPL6cRpVgeKVSs3PUVLUeJCdu5` | gate3 + P5 |
| Withdraw | yes | `3B2bDhTtNhBsNmDA6ZHxC7muzfk83oyRkg6F7J3JxoFyfCi5L56nU3WK1QjDR1QFrVcT3xsvkxytPGRSe6S9pPtc` | P5 |

Signature annexes: [`gate3-flow-signatures.json`](gate3-flow-signatures.json),
[`p5-flow-signatures.json`](p5-flow-signatures.json).

## Guards removed

1. **`signOrHitG2Wall` / `g2Blocked` / `isProofPointFailure` in gate3** — spend
   paths now call `signPrivateTransaction` / `submitMergeTransaction` and always
   submit; a `CLIENT_PROOF_POINT` fails the test.
2. **Conditional submit after G2 wall** — `if (splitSigned !== undefined)` and
   the transfer early-continue are gone; transfer requires sufficient balance.
3. **Port offsets** — `test:e2e:gate3` and `test:e2e:p5` (and hybrid) pinned to
   `ZOLANA_PORT_OFFSET=300` so this worker does not collide with others.
4. **Merge confirm path** — dropped `confirmPrivateTransaction` after merge.
   That helper only decodes `TRANSACT` tags; Rust
   `submit_merge_transaction` documents that merge is not on the
   confirm-by-tags path. Gate3 now matches Rust: RPC confirm + Photon sync of
   the output hash. This is not a weakened check; the previous call was
   unreachable behind the G2 wall and would have failed for both languages.

No Rust compress fallback was installed. P5 hybrid
(`ZOLANA_TEST_P5_RUST_COMPRESS=1`) remains available but was not used for this
gate.

## Commands and results

```bash
just build-programs          # ok (cargo via ~/.cargo/env)
just ensure-photon           # ok
just build-prover-server     # ok
just ensure-smart-account    # ok
npm install                  # ok
npm run build                # ok
ZOLANA_PORT_OFFSET=300 npm run test:e2e:gate3   # 1 passed (~128s)
ZOLANA_PORT_OFFSET=300 npm run test:e2e:p5      # 1 passed (~119s)
npm run build && npm run test:unit              # 2229 passed | 9 skipped
npm run check:static                            # ok (build, typecheck, lint, lint:packages, format:check)
npm run fixtures:check                          # ok — verified 58 fixtures and 182 inventory rows
```

## On-chain findings

None that block the gate. The only submit-path defect encountered was the
pre-existing merge/`confirmPrivateTransaction` mismatch noted above (same in
Rust). Merge instruction bytes still executed and confirmed on the
same-revision shielded-pool program.

## Checklist

- [x] Instruction bytes execute against same-revision Solana programs.
- [x] Submission half of flow coverage (split, merge, private transfer,
  withdraw) without behavior-hiding stubs or G2 soft-pass.
