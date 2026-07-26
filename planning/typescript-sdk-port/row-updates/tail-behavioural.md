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

## Invalid items

None of the seven failed verification; all were real defects.
