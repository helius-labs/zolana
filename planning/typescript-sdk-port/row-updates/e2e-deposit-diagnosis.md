# E2E deposit diagnosis: `test:e2e:actions`

Read-only diagnosis of the five failing tests in the end-to-end actions suite.
No production code, test, or fixture was changed. Every scratch script used to
produce the evidence below lives in `/tmp`.

**Verdict: the deposits are lost in the test double, not in the SDK.**
`sdk-libs/ts/wallet/src/sync.ts` is faithful to `sdk-libs/wallet/src/wallet_sync.rs`
at HEAD. The suite's own in-process indexer stub hands `syncWallet` rows that no
production caller could produce, and it has done so since the suite was written.
This is **not** a regression from `570162d7`, from `1ebb73fe`, or from any
uncommitted work. It is older than all three.

## The exact failing tests

All five are in `sdk-libs/ts/e2e/actions/actions.test.ts`, under
`describe("P12 action workflows")`. Three tests in the same file pass.

| Test | Failure |
|---|---|
| routes registered and unregistered SOL and SPL transfers | `WALLET_INSUFFICIENT_BALANCE` from `spendTree` (`wallet/src/actions.ts:189`) |
| creates SOL and SPL withdrawals and preserves external signer bytes | `WALLET_INSUFFICIENT_BALANCE` from `spendTree`, via `createWithdrawal` (`wallet/src/actions.ts:250`) |
| matches the split fixture and rejects a spent input without mutation | `WALLET_INSUFFICIENT_BALANCE` from `spendTree`, via `createSplit` (`wallet/src/actions.ts:329`) |
| creates and submits a merge through the production pipeline | `WALLET_NOTHING_TO_MERGE` from `selectMergeEntries` (`wallet/src/submit.ts:158`) |
| covers P256, EdDSA, mixed ownership, balances, history, lag, abort, timeout, and retry | `expected [] to deeply equal [ { amount: 80n, ... } ]` at `actions.test.ts:749` |

The five share one antecedent. Each calls `walletFromDeposits`
(`actions.test.ts:270-329`), which records deposits into a `TestIndexer`, syncs a
wallet from them, and returns the wallet. That wallet comes back with zero
UTXOs, so every later assertion fails on an empty private balance. The three
passing tests are the three that never call `walletFromDeposits`.

## The suite needs no live stack

The brief expected a validator, a Go prover, and Photon. `actions.test.ts` uses
none of them. It runs entirely in process against `TestRpc`, `TestIndexer`, and a
hand-written indexer stub, and reproduces all five failures in 559 ms:

```
npx vitest run --config sdk-libs/ts/config/vitest.e2e-actions.config.js \
  sdk-libs/ts/e2e/actions/actions.test.ts

Tests  5 failed | 3 passed (8)
Duration  559ms
```

No service was running, and none of `ZOLANA_PORT_OFFSET`,
`ZOLANA_LOCALNET_URL`, `ZOLANA_INDEXER_URL`, or `ZOLANA_PROVER_URL` was set. The
sibling `sdk-libs/ts/e2e/actions/live.test.ts` does need the stack and was not
run here; it accounts for none of the five reported failures.

## Which layer loses the deposit

A probe reproduced `walletFromDeposits` exactly, wrapped the stub in counters,
and recorded which view tags `syncWallet` actually asked for
(`/tmp/zolana-probe/probe-deposit.mjs`):

```
depositsRecorded:                            2
getShieldedTransactionsByTags_calls:         3
getShieldedTransactionsByTags_rowsReturned:  6
getEncryptedUtxosByTags_calls:               3
getEncryptedUtxosByTags_matchesReturned:     0
depositViewTagsWereQueried:                  [true, true]
distinctTagsQueried:                         130
report:                                      { received: 0, transactions: 0 }
walletUtxos:                                 0
```

That fixes the layer. The deposits are indexed by the stub, both deposit view
tags are in the query set, and the stub returns the rows on every round. Nothing
reaches decryption. The loss is between the indexer response and
`decryptTransactions`, and there are two independent reasons for it.

### Reason one: the stub emits base58 and base64 strings where the indexer returns bytes

`ZolanaIndexer` decodes the JSON-RPC response before returning it.
`convertShieldedTransaction` and `convertOutputSlot`
(`sdk-libs/ts/client/src/indexer.ts:269-300`) yield an
`IndexedShieldedTransaction` whose `outputSlots[].outputContext.hash` is a
`Bytes32` and whose `payload` is a `Uint8Array`
(`sdk-libs/ts/transaction/src/instructions/transact.ts:616-625`).

`fixtureIndexer` (`actions.test.ts:200-226`) skips that decode and emits the encoded
form instead:

```
210|            viewTag: base58(output.viewTag),
212|                hash: base58(output.utxoHash),
216|              payload: base64(output.data),
```

A field-isolation probe (`/tmp/zolana-probe/probe-fields.mjs`) called
`decryptTransactions` directly with one field string-encoded at a time:

| Row shape | UTXOs stored |
|---|---|
| all decoded | 1 |
| `viewTag` base58 only | 1 |
| `hash` base58 only | 0 |
| `payload` base64 only | 0 |
| all three encoded, the stub's actual shape | 0 |

Two fields are independently fatal. A base64 `payload` makes
`decodeOutputData` throw `TypeError: First argument to DataView constructor must
be an ArrayBuffer`, which `decodeCandidate` swallows at
`sdk-libs/ts/transaction/src/wallet/sync.ts:156-160` and returns `undefined`. A
base58 `hash` fails the recomputed-commitment check at
`sdk-libs/ts/transaction/src/wallet/sync.ts:389`. Either alone empties the
wallet. `viewTag` does not matter, because a plaintext deposit is matched by
decoding its payload rather than by its tag.

### Reason two: the stub surfaces the deposit on the wrong endpoint

Rust reaches a deposit only through `get_encrypted_utxos_by_tags` and skips it on
the transaction endpoint (`sdk-libs/wallet/src/wallet_sync.rs:368-378`,
`445-486`). `sync.ts` mirrors that at `sdk-libs/ts/wallet/src/sync.ts:209-218`.
The stub does the opposite: it returns the deposits from
`getShieldedTransactionsByTags` flagged `proofless: true`
(`actions.test.ts:221`) and returns an empty `matches` list from
`getEncryptedUtxosByTags` (`actions.test.ts:224`).

## Root cause

`sdk-libs/ts/e2e/actions/actions.test.ts:200-226`, the `fixtureIndexer` stub. It
models neither the shape nor the endpoint contract of `ZolanaIndexer`. Because
of that, `walletFromDeposits` at `actions.test.ts:327` has always returned an
empty wallet, and the five tests that depend on it have always failed.

## Regression attribution

A matrix crossed the row shape, the endpoint, and the sync implementation. The
pre-`570162d7` `sync.ts` was recovered with `git show`, compiled with `esbuild`
into `/tmp`, and driven against the same stub
(`/tmp/zolana-probe/probe-matrix.mjs`):

| sync | row shape | endpoint | `proofless` | UTXOs |
|---|---|---|---|---|
| pre-`570162d7` | base58/base64 | `getShieldedTransactionsByTags` | true | **0** |
| pre-`570162d7` | base58/base64 | `getShieldedTransactionsByTags` | false | 0 |
| pre-`570162d7` | base58/base64 | `getEncryptedUtxosByTags` | true | 0 |
| pre-`570162d7` | decoded bytes | `getShieldedTransactionsByTags` | true | 2 |
| pre-`570162d7` | decoded bytes | `getShieldedTransactionsByTags` | false | 2 |
| pre-`570162d7` | decoded bytes | `getEncryptedUtxosByTags` | true | 2 |
| current | base58/base64 | `getShieldedTransactionsByTags` | true | **0** |
| current | base58/base64 | `getShieldedTransactionsByTags` | false | 0 |
| current | base58/base64 | `getEncryptedUtxosByTags` | true | 0 |
| current | decoded bytes | `getShieldedTransactionsByTags` | true | 0 |
| current | decoded bytes | `getShieldedTransactionsByTags` | false | 0 |
| current | decoded bytes | `getEncryptedUtxosByTags` | true | 2 |

The two bold rows are the configuration the suite actually runs. Both are zero.
Whatever `570162d7` changed, the deposits were already lost before it.

The end-to-end confirmation is stronger than the matrix. The real
`actions.test.ts` was run unmodified against the pre-`570162d7` `syncWallet`,
substituted through a Vitest alias in `/tmp` so that no repository file moved:

```
npx vitest run --config /tmp/zolana-probe/vitest.oldsync.config.js

Tests  5 failed | 3 passed (8)
```

The same five tests, failing the same way. `570162d7` is cleared.

The matrix does show `570162d7` adding a second, currently unreachable blocker:
with a correctly decoded row on the transaction endpoint, the old sync stores the
deposit and the new one does not. That difference is correct behavior. It matches
`wallet_sync.rs:373-378`, and it only becomes visible once the row-shape defect
is fixed.

## The four hypotheses in the brief

1. **Counter offsets.** Not the cause. The probe shows both deposit view tags in
   the queried set, and 130 distinct tags, which is exactly the Rust count for a
   wallet with no history: one owner confidential tag, one bootstrap tag, 64
   sender tags, and 64 recipient-request tags. `viewingKeyCounters`
   (`sync.ts:94-99`) returns `undefined` when the wallet carries no history, and
   `?? 0n` then reproduces Rust's `map_or(0, ...)`. The deposit is tagged with
   the recipient bootstrap tag, which `walletDepositData`
   (`test-kit/src/wallet-data.ts:36`) derives as `viewingPublicKey.x()`, the same
   derivation `recipientBootstrapViewTag` uses.
2. **The two added shared families.** Not the cause. They only insert into a
   `Map`, so they can add tags and never remove one. The bootstrap tag is still
   added at `sync.ts:119`.
3. **The restored proofless filter.** Faithful to Rust, and not the operative
   cause. `collectProoflessDeposits` (`sync.ts:234-238`) applies the same two
   guards as `fetch_proofless_deposits` (`wallet_sync.rs:465-477`), and
   `isProoflessPayload` is if anything more permissive than Rust's
   `decode_output_data`, which additionally parses the body. The filter does drop
   the stub's rows, but so does the row shape, under both sync implementations.
4. **The added sorting.** Not the cause. Nothing survives to be sorted. The
   pre-`570162d7` code used map-insertion order and reached the same empty
   wallet.

## The two confounders

**Uncommitted zone-authority work in `sdk-libs/transaction/src`: absent.** There
is none in this worktree. A diff restricted to `sdk-libs/transaction/src` is
empty, and `git status --porcelain` listed no file under that path at any point
during this investigation. Nothing in the deposit path can be affected by it.

**`deposit.ts` and `1ebb73fe`: not on the path.** `createDeposit` is called only
at `actions.test.ts:337` and `:343`, both inside "routes SOL and SPL deposit
construction through the production API", which passes. `walletFromDeposits`
builds its deposits from `walletDepositData` (`actions.test.ts:289`), a test-kit
helper `1ebb73fe` did not touch. That commit changed only
`sdk-libs/ts/wallet/src/deposit.ts` and its vector test.

## Smallest fix

Correct `fixtureIndexer` (`actions.test.ts:200-226`) to return what
`ZolanaIndexer` returns: decoded bytes, with the deposits on the encrypted-UTXO
endpoint.

```ts
function fixtureIndexer(indexer: TestIndexer): ZolanaIndexer {
  return {
    getShieldedTransactionsByTags: () =>
      Promise.resolve({ context: { blockTime: 1n }, transactions: [] }),
    getEncryptedUtxosByTags: () =>
      Promise.resolve({
        context: { blockTime: 1n },
        matches: indexer.outputs().map((output, index) => ({
          slot: BigInt(index + 1),
          txSignature: SIGNATURE,
          outputSlot: {
            viewTag: output.viewTag,
            outputContext: {
              hash: output.utxoHash,
              tree: output.tree,
              leafIndex: output.leafIndex,
            },
            payload: output.data,
          },
        })),
      }),
  } as unknown as ZolanaIndexer;
}
```

Verified against a patched copy of the file held in `/tmp`: this takes the suite
from five failures to one.

## A second defect the fix uncovers

The remaining failure is independent and previously masked, because the test that
carries it died earlier on the empty balance.

`actions.test.ts:815-819` declares the aborting stub as
`(_request: unknown, context?: Readonly<{ signal?: AbortSignal }>)`, reading the
request context from the second positional parameter. The real method takes
`(request, config?, context?)` (`sdk-libs/ts/client/src/indexer.ts:71-75`), so
the second parameter is the `IndexerRpcConfig`. The stub therefore never sees the
aborted signal and resolves where the test expects a rejection. The pre-`570162d7`
sync passed `undefined` in that position, so this stub was wrong before
`570162d7` as well.

Adding the missing `_config` parameter takes the suite to green:

```
npx vitest run --config /tmp/zolana-probe/vitest.fixed.config.js

Tests  8 passed (8)
```

## Scope: `test:unit`

Independent, and already resolved. `npm run test:unit` at HEAD is green:

```
Test Files  58 passed | 1 skipped (59)
Tests  445 passed | 1 skipped (446)
```

The client package alone is 143 passed of 143, so no client error test is
failing. The single skip is
`sdk-libs/ts/test-kit/test/user-registry.live.test.ts`, a live test that skips
without a stack. The worker most likely observed the failure before `68631870`
landed, and it shares no cause with the deposit loss.

## Row

**W08** (`sdk-libs/wallet/src/wallet_sync.rs` -> `wallet/src/sync.ts`), currently
`needs_re_review` with fix commit `570162d7`.

The evidence here bears on that row without changing its verdict, and the
re-review running in parallel should read it that way: **the five end-to-end
failures are not caused by `570162d7`, and they are not evidence of a defect in
`sync.ts`.** The reviewed behavior is correct, and the matrix above establishes
it positively. Once the stub is corrected, the current `sync.ts` stores the
deposit and the pre-`570162d7` one on the transaction endpoint would too, which
is the parity Rust requires.

The defect itself belongs to no existing row. The checklist has no family for the
test kit or the end-to-end suites, so this file is its record.
