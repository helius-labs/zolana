# FND tail — Medium + Low/process decision sheet

Worktree: `zolana-wt-fnd-tail` · branch `port/fnd-tail` · verified after `npm install` + `npm run build`.

Scope: ACTIONABLE_FINDINGS.md **Medium** (F154–F120, incl. A003) and **Low/process** (F112–F144, incl. A002). Release blockers / High / Decisions required ignored.

## Counts

| Classification | Count |
|----------------|------:|
| DONE | 12 |
| INVALID | 0 |
| OPEN, CHEAP | 12 |
| OPEN, COSTLY | 7 |
| **Total** | **31** |

No code fixes applied in this pass (read-and-verify only; OPEN CHEAP left for owner ruling).

## Medium

| ID | Description | Classification | Evidence | Recommendation |
|----|-------------|----------------|----------|----------------|
| F154 | Reject zero-value deposits in wallet builder | OPEN, CHEAP | `createDeposit` only rejects `amount < 0n` / `> u64::MAX` (`wallet/src/deposit.ts:79`); `deposit-vector.test.ts:141` still asserts `amount: 0n` builds. Program rejects zero on-chain. | Fix in this PR: reject `0n` with `WALLET_INVALID_AMOUNT` and flip the vector test. |
| F131 | Bind settlement accounts only when public amount exists | DONE | `createExternalData` forces unset accounts when amount absent (`transact.ts:318-332`); finalize uses `withPublicSol`/`withPublicSpl` only when amount set (`:926-938`). | — |
| F140 | Derive retry classification from complete error code set | OPEN, CHEAP | `CLIENT_INVALID_BASE58`/`BASE64` exist but are absent from `retryCause` (`client/src/retry.ts:139-169`); Rust folds bad instruction base58 into `ClientError::Rpc` which is retryable (`solana_rpc.rs:376-378`). Hand-written allow-list remains. | Fix in this PR: classify those codes as rpc-retryable (or match a Rust oracle row). Full “every code vs oracle” CI is follow-up if not already covered. |
| F142-P | Decode instruction base58 once on confirmation | OPEN, CHEAP | `decodeBase58UnknownLength` still probes lengths `1..=1232` then re-decodes (`solana-rpc.ts:776-787`). | Follow-up after merge: expose length-free decode + single length check (perf, not correctness). |
| F150 | Make `CompressedShieldedAddress` deeply immutable | DONE | Private `#ownerHash`, copy on construct via `checkedBytes`, `ownerHash` getter returns `copyBytes` (`keypair/src/shielded.ts:78-110`). | — |
| F151 | Preserve exact lamport values in `SolanaRpc.airdrop` | OPEN, CHEAP | Accepts up to `u64::MAX` then calls `Number(lamports)` (`solana-rpc.ts:357-366`); values above `MAX_SAFE_INTEGER` round. | Fix in this PR: reject unsafe integers (or JSON-RPC string form) before `Number()`. |
| F101 | Drop `zoneProgramId` when no zone data exists | DONE | `resolveZoneProgramId` mirrors Rust (`utxo.ts:38-47`); codecs call it; `zone-resolution.test.ts` covers drop / retain / missing-program. Direct hashing retains a supplied program id in both languages (documented). | — |
| F130 | Enforce one fail-closed error-detail redaction policy | OPEN, COSTLY | Keypair allow-lists primitives (`keypair/src/error.ts:77-88`); client `sanitizeDetails` recursively keeps arbitrary scalar keys (`client/src/error.ts:706-735`). Opposite policies, cross-package. | Follow-up issue: shared redactor or rename permissive helper; touches public error surfaces. |
| F137 | Add regression coverage for padded finalization | DONE | `transfer.test.ts` `padded finalize ciphertext lengths` (`:967+`) asserts equal real/dummy lengths on padded shapes. | — |
| F141-E | Accept empty instruction data during confirmation parsing | OPEN, CHEAP | `decodeBase58` rejects `value.length === 0` (`client/src/internal.ts:154-156`); Rust `bs58::decode("")` yields empty bytes. | Fix in this PR: treat empty base58 as `Uint8Array(0)` like base64/Rust. |
| F094 | Avoid cloning entire Merkle tree on every single append | OPEN, COSTLY | Rust `append` still `clone_state()` per leaf (`sdk-libs/merkle-tree/src/lib.rs:171-176`). Algorithmic change + atomicity. | Follow-up issue (SDK Rust merkle); not a TS-only patch. |
| F143-D | Make Rust→TS oracle chain drift-safe | DONE | `fixtures-check.mjs` runs many xtask `--check` generators; `npm run check:fixtures` is in `npm run check` and CI. Hasher embed wired via `hasher/scripts/build-hooks.mjs` + `artifact.lock.json`. | — |
| A003 | Make oracle drift checks non-mutating by default | OPEN, CHEAP | Merge/zone/proof/poll oracles still write then assert `ZOLANA_UPDATE_TS_ORACLES` (`ts_merge_oracle.rs:325-335`). First stale run mutates the tree. | Fix in this PR: compare-and-fail before write; write only when update env set. |
| F120 | Reject malformed base58 in test-kit account decoder | DONE | `standard-accounts.ts` uses validated `decodeBase58Address` (`instructions.ts:81-104`); rejects bad alphabet / wrong length. Local permissive decoder gone. | — |

## Low / process

| ID | Description | Classification | Evidence | Recommendation |
|----|-------------|----------------|----------|----------------|
| F112 | Correct false TypeScript-only parity claims | DONE | `TYPESCRIPT_ONLY_CODES` justifications no longer claim Rust cannot represent dummy-input / owner-mismatch (`rust-oracle.test.ts:145-157`); they describe TS builder checks. | — |
| F106 | Consolidate duplicated byte/crypto primitives | OPEN, COSTLY | Cross-package `concat`/`base58`/etc. remain; `smart-account-client/src/sha256.ts` is still a hand-rolled SHA-256 despite `@noble/hashes` elsewhere. | Follow-up issue: shared internal util surface; large mechanical refactor. |
| F104 | Pin proving-shape order, not only membership | DONE | Ordered list + selection parity: `interface/test/vectors/rust-oracle.test.ts:204+`, `interface.test.ts:246+`. | — |
| F123 | Complete schema-path reporting and shared page-limit constants | OPEN, CHEAP | Cursor paths reported (`schema.test.ts` expects `$.cursor`); but `checkedPageLimit` still hardcodes `1n`/`1000n` instead of `MIN_PAGE_LIMIT`/`PAGE_LIMIT` (`indexer-api/src/codec.ts:140-150`). | Fix in this PR: reference exported constants. |
| F124 | Derive payer public-key hash inside zone-authority prep | OPEN, CHEAP | `prepareZoneAuthority` still takes caller `payerPublicKeyHash` (`builders.ts:574-608`); no payer-key derive/verify. | Follow-up (API shape): accept payer address and derive, or verify hash. |
| F127 | Publish test-only secret for keypair hash fixture | OPEN, CHEAP | `fixtures/keypair/hash.json` has `"testOnlySecret": true` but no secret/material to recompute Poseidon fields. | Follow-up: add deterministic test secret (test-only fixture). |
| F129 | Make `compareBytes` correct for unequal lengths | OPEN, CHEAP | `client.ts:748-754` returns `0` when lengths differ but common prefix matches; `solana-rpc.ts:789-794` compares lengths. | Fix in this PR: align with length-aware sibling (or rename fixed-width helper). |
| F145 | Remove/derive misleading prepared-transaction metadata | DONE | `publicAmounts` now from `proofInputs.publicAmounts()` (`builders.ts:616`). Merge prepared types still lack a separate `ownerTag` field — Rust `PreparedMerge` likewise has none. | — |
| F146 | Make `Wallet.registry` mutation semantics explicit | OPEN, CHEAP | Getter returns `#registry.clone()` (`transaction/src/wallet/state.ts:172-174`); `insert` on the snapshot is a silent no-op vs live Rust registry. | Follow-up: readonly snapshot type or mutate-live API. |
| F148 | Honor `--skip-ci` in readiness script | DONE | Skipped criteria excluded: `criteria.every((c) => c.skipped \|\| c.pass)` (`pkp-entry-gate.mjs:135`). | — |
| F076 | Remove PR-specific coordination artifacts | OPEN, COSTLY | `PULL_REQUEST = "159"` still hardcoded (`pkp-entry-gate.mjs:29`); `review-checklist-check.mjs` / planning gates remain. `worker-liveness` already gone. | Follow-up after merge: delete one-offs; avoid baking PR numbers into repo infra. |
| F013 | Separate/release-note bundled Rust SDK changes | OPEN, COSTLY | Process finding: Rust SDK behavior changes ride inside the TS-port PR. No code defect at HEAD. | Follow-up: enumerate breaking/security Rust deltas in PR/release notes + semver. |
| F041 | Complete package metadata + import-aware deps | DONE | Publish metadata asserted (`workspace-check.mjs:176-197`); deps compared to source imports (`:209-213`). Sample `@zolana/wallet` has license/repository/publishConfig. | — |
| F079 | Scope TypeScript CI and reuse build artifacts | OPEN, COSTLY | Workflow still rebuilds across jobs; path-filter / artifact-sharing design. (Workflows owned by parallel workers — not edited here.) | Follow-up issue for CI graph. |
| F083 | Centralize historical fixture baseline SHA | OPEN, COSTLY | Baseline SHA still repeated across fixture ecosystem; centralization is a large mechanical edit. (Manifest/packages owned by parallel workers.) | Follow-up issue after merge. |
| A002 | Reject zone proofs in plain-merge runtime guard | DONE | `isProvedMerge` requires `!("zoneProgramId" in value)` (`client/src/client.ts:805-824`). | — |
| F144 | Remove authored/unused fixture “expected” values | OPEN, CHEAP | `recipientCountPrefixOffset` uses `(33 + …)` while owner key is 34 bytes (`ts_fixtures_transaction.rs:633`; decode takes 34 in `codecs.ts:500`); field appears only in fixture JSON — no TS consumer. | Follow-up: delete unused offset (or fix to 34) in generator + fixture. |

## Notes for the owner

- Several register rows were already closed by later work without ledger updates: **F148**, **F041**, **F131**, **F150**, **F101**, **F120**, **F104**, **A002**, **F143-D**, **F137**, **F145**, **F112**.
- Highest-value cheap PR fixes if you want a small closing commit: **F154**, **F151**, **F141-E**, **A003**, **F129**, **F123**.
- Do not treat **F094** / **F106** / **F076** / **F079** / **F083** / **F013** / **F130** as merge blockers for the TS port; file follow-ups.
