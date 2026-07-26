# Tail behavioural fixes (`port/tail-fixes`)

Seven owner-ruled FIX items from the register tail. Each section records what
was wrong, what changed, and the test that fails before / passes after.

## F154 — zero-value deposit

**Wrong.** `createDeposit` accepted `amount: 0n` and a vector test asserted that
building it succeeded. The program always rejects amount 0 with
`InvalidTransactShape`.

**Change.** Reject `amount <= 0` in `createDeposit` with `WALLET_INVALID_AMOUNT`
before constructing blinding, commitment, or SPL settlement accounts.

**Test.** `wallet/test/vectors/deposit-vector.test.ts`: the previous
`amount: 0n` success assertion is now an early-error check; a second case covers
zero-value SPL.

## F141-E — empty instruction data

**Wrong.** Confirmation parsing treated empty base58 instruction data as
`CLIENT_INVALID_BASE58`. Rust's `bs58::decode("")` yields an empty vector, so a
confirmed transaction with a zero-data instruction failed only in TypeScript.

**Change.** `decodeBase58UnknownLength("")` and `decodeBase58("", 0, …)` return
`Uint8Array(0)`.

**Test.** `client/test/solana-rpc.test.ts` — "treats empty instruction data as
empty bytes, matching Rust bs58".

## F140 — retry classification

**Wrong.** Malformed base58/base64 in an RPC body becomes `ClientError::Rpc` in
Rust (retryable). TypeScript raised `CLIENT_INVALID_BASE58` /
`CLIENT_INVALID_BASE64` and treated them as fatal.

**Change.** Classify both codes as `{ category: "rpc" }` in `retryCause`.

**Test.** `client/test/retry.test.ts` — table rows for both codes, plus "retries
garbled base58 in an RPC body for the whole schedule".

## F129 — byte comparison

**Wrong.** `client.ts`'s private `compareBytes` stopped at `left.length` and
returned 0 when `left` was a prefix of `right`.

**Change.** One length-aware `compareBytes` in `internal.ts` (shared with
`solana-rpc.ts`): compare the common prefix, then lengths.

**Test.** `client/test/internal.test.ts` — "treats a proper prefix as shorter,
not equal".

## F151 — airdrop amounts

**Wrong.** `SolanaRpc.airdrop` accepted any `u64` then passed `Number(lamports)`
to JSON-RPC, silently rounding values above `Number.MAX_SAFE_INTEGER`.

**Change.** Reject amounts above `Number.MAX_SAFE_INTEGER` with
`CLIENT_INVALID_INTEGER`.

**Test.** `client/test/solana-rpc.test.ts` — boundary coverage for
`MAX_SAFE_INTEGER`, `MAX_SAFE_INTEGER + 1`, and `u64::MAX`.

## A003 — oracle drift

**Wrong.** Rust→TypeScript drift oracles wrote the new output before asserting
the update env, so the first stale run rewrote the baseline and a second run
passed.

**Change.** Shared `assert_oracle_current`: compare first; write only when
`ZOLANA_UPDATE_TS_ORACLES` is set. Same gate inlined in the integration-test oracle.

**Test.** `client/src/prover/oracle_file.rs` — `check_mode_leaves_a_stale_baseline_untouched`
panics and leaves the file unchanged; update mode still rewrites.

## F130 — error-detail redaction

**Wrong.** Keypair used a fail-closed allow-list; the client wrap-path
`sanitizeDetails` used a deny-list and kept arbitrary scalars, so a
`TransactionError` wrapped into `ClientError` could carry keys keypair would
strip.

**Change.** Replace wrap-path `sanitizeDetails` with the keypair allow-list plus
the small set of transaction diagnostic keys (`requested`, `available`,
`inputs`, `outputs`). Non-primitives and unknown keys drop. Light Protocol has
no transferable redaction policy (`fnd-f130-light.md`); this is the owner-approved
fail-closed rule.

**Test.** `client/test/error.test.ts` — "drops a non-allow-listed detail on the
client wrap path" (`ciphertext` kept by transaction deny-list, dropped by
client allow-list).

## F130 close — transaction + shared allow-list (`port/redaction-close`)

**Wrong.** After the client wrap path moved to fail-closed, `@zolana/transaction`
still used a deny-list that kept arbitrary scalars (including `ciphertext`).
Wallet and other packages either copied details raw or had no bag at all, so a
third contradictory rule defeated "one fail-closed rule everywhere."

**Change.** Export one shared allow-list and sanitizer from `@zolana/keypair`
(`SAFE_ERROR_DETAIL_KEYS` / `sanitizeSafeErrorDetails`): keypair descriptors
plus the union of diagnostic keys transaction and wallet call sites already
emit (`requested`, `available`, `inputs`, `outputs`, and siblings). Values are
`string` | `number` only. `@zolana/transaction`, `@zolana/client` (wrap path),
and `@zolana/wallet` all call that helper. Nested `payload` bags no longer
survive; `unknownTransactionError` flattens allow-listed keys to the top level.
Wallet commitment hashes in details are hex strings via `bytesKey`, not
`Uint8Array`.

**Shared definition.** One copy in `@zolana/keypair` (transaction, client, and
wallet already depend on it). No new dependency edges.

### Final redaction state

| Package | Rule before | Rule after | Test that proves it |
| --- | --- | --- | --- |
| `@zolana/keypair` | Fail-closed allow-list (own keys) | Same policy; also exports the shared union sanitizer | `keypair/test/api-surface.test.ts` — "drops a non-allow-listed detail on KeypairError and the shared sanitizer" |
| `@zolana/client` | Fail-closed wrap-path allow-list (local copy) | Same rule via `sanitizeSafeErrorDetails` from keypair | `client/test/error.test.ts` — "drops a non-allow-listed detail on the client wrap path" |
| `@zolana/transaction` | Fail-open deny-list (regex drop, keep other scalars / nests) | Fail-closed shared allow-list | `transaction/test/core.test.ts` — "drops a non-allow-listed detail on TransactionError" |
| `@zolana/wallet` | Raw pass-through of `details` | Fail-closed shared allow-list | `wallet/test/wallet.test.ts` — "drops a non-allow-listed detail on WalletError" |

### Audit of all eleven packages

| Package | Findings |
| --- | --- |
| `keypair` | Allow-list (canonical). Converted earlier; now owns the shared union. |
| `client` | Constructor uses per-code `DETAIL_SHAPES`; wrap path now shared allow-list. |
| `transaction` | Converted from deny-list to shared allow-list. |
| `wallet` | Converted from raw pass-through; secret-adjacent (hashes / amounts). |
| `smart-account-client` | Raw `details` shallow copy. No `@zolana/keypair` dependency; adding one would be a new edge. Call sites only pass bounds (`name`, `value`, `maximum`, `actual`, `index`, lengths) — not viewing keys, nullifiers, or decrypted amounts. Left as a separate copy candidate if that package later grows secret surfaces. |
| `test-kit` | Raw `details` pass-through. Test harness only; not a production secret path. |
| `api` | `ApiError.details` for RPC/schema diagnostics (`status`, `retryable`, `path`). No shielded key material; no sanitizer today. |
| `indexer-api` | `IndexerSchemaError.details` for JSON path / expected / actual shape. Schema validation only. |
| `merkle-tree` | `MerkleTreeError` / `IndexedMerkleTreeError` optional `details` pass-through for tree geometry. No shielded secrets. |
| `interface` | Error codes / `ShieldedPoolError` constants; no structured `details` bag sanitizer. |
| `hasher` | No `details` bag. |

## Invalid items

None of the seven failed verification; all were real defects.
