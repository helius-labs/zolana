# Gate 3 — flow coverage without behavior-hiding stubs

| Field | Value |
| --- | --- |
| Worktree | `/Users/tilohelius/Workspace/zolana-ts-gate3-flows` |
| Branch | `port/gate3-flows` |
| Scope | Close gate 3: deposit, private transfer, withdraw, split, merge, registration, sync, submission against a real prover (where the flow proves) and real validator (where the flow submits), without mocks as a flow's only coverage |
| Builds on | [`pkp-p5.md`](pkp-p5.md) prove-to-chain + test-kit Photon SQLite migration fix |

## Bottom line

| Flow | Real prover | Real validator / Photon | Evidence | Blocked on G2? |
| --- | --- | --- | --- | --- |
| Deposit | n/a (proofless) | yes | `gate3-flows.live.test.ts` + P5 `prove-to-chain.live.test.ts` | no |
| Private transfer | yes | submit yes once compress accepts live B | P5 + gate3 (both call production `signPrivateTransaction`) | **yes** (submit) |
| Withdraw | yes | submit yes once compress accepts live B | P5 hybrid/pure | **yes** (pure submit) |
| Split | yes | submit yes once compress accepts live B | `gate3-flows.live.test.ts` | **yes** (submit) |
| Merge | yes (`proveMerge`) | submit yes once compress accepts live B | `gate3-flows.live.test.ts` via `submitMergeTransaction` | **yes** (submit) |
| Registration | n/a | yes | gate3 (`ensureRegistered` + record decode + merge opt-in) and `live.test.ts` | no |
| Sync | n/a | yes (Photon) | gate3 `syncUntil` / stranger empty / idempotent re-sync; P5 sync assertions | no |
| Submission | yes (prove before compress) | chain accept blocked on G2 for pure TS | gate3 merge-submit + private sign; P5 transfer/withdraw | **yes** (chain land) |

No named flow's **only** coverage is a mocked prover. Fixture suites that still mock `ProverClient.fetch` are labeled as request-shape / pipeline-order tests:

- `sdk-libs/ts/e2e/actions/actions.test.ts` — "wires merge-submit request shape against a mocked prover"
- `sdk-libs/ts/wallet/test/submit.test.ts` — frozen material + pipeline order with mocked fetch

## What was added

1. `sdk-libs/ts/e2e/actions/gate3-flows.live.test.ts` — opt-in `ZOLANA_TEST_GATE3=1`, port offset **600**.
2. `sdk-libs/ts/e2e/actions/support/live-helpers.ts` — shared airdrop / confirm / syncUntil / G2 wall detection.
3. Root script `npm run test:e2e:gate3`.

### Suite shape

One stack boot:

1. Protocol config + pool tree.
2. Register owner + recipient; enable merge opt-in; assert registry decode.
3. Two SOL deposits; Photon sync (balance, stranger empty, idempotent re-sync).
4. Split one deposit (`createSplit` → `signPrivateTransaction` → real prover).
5. Merge two unspent notes (`createMerge` → `submitMergeTransaction` → real `proveMerge`). Uses `harness.client` as the spend-proof indexer (`ZolanaIndexer` has no `getInputMerkleProofs`).
6. Private transfer submit when balance remains (same production sign path as P5).

When production `compressProof` throws `CLIENT_PROOF_POINT` after a real prove, the case records the wall and continues to the next flow that does not need that on-chain state. No Rust compress fallback is installed. Once `port/g2` lands, submit + post-submit sync assertions run without code changes.

## Commands

```bash
# prerequisites (same as P5)
just build-programs
just ensure-photon
# prover binary at target/prover-server; proving-keys present or auto-download

npm run build
ZOLANA_PORT_OFFSET=600 npm run test:e2e:gate3
```

Also still valid for deposit / transfer / withdraw / sync:

```bash
npm run test:e2e:p5          # pure TS wall
npm run test:e2e:p5:hybrid   # program accept with Rust compress (not G2 certification)
```

Measured on this worktree: `npm run test:e2e:gate3` → **1 passed** (~72s) with live G2 walls on split and merge-submit.

## G2 status during this work

`port/g2` still had uncommitted limb-order work; it had **not** merged to `ts-sdk-port`. Gate3 tests are structured to pass through submit once that fix lands. Do not cite hybrid P5 as closing pure-TS submission.

## Mock disposition

| Location | Role after this change |
| --- | --- |
| `actions.test.ts` mocked merge submit | Request-shape only; not flow evidence |
| `wallet/test/submit.test.ts` mocked fetch | Pipeline-order / fixture only; not flow evidence |
| Gate3 / P5 live suites | Sole flow evidence for prove + (when G2 allows) submit |

## Residual

1. **Chain submit for spend flows** remains blocked on TypeScript G2 compress accepting live prover B points (owned by `port/g2` / fnd-d5). Real prover coverage for split, merge, transfer, and withdraw is in place.
2. Withdraw is not re-driven inside `gate3-flows.live.test.ts`; P5 owns that path. Gate3 does not contradict P5.
3. Zone / P256 / merge-zone program paths remain out of scope (same as P5).
