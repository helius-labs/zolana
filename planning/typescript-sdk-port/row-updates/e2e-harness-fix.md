# E2E harness fix: `test:e2e:actions`

Implements the smallest fix in `e2e-deposit-diagnosis.md` (`fd5f76dd`) and closes
the hole that let the double drift from the indexer in the first place. Only
files under `sdk-libs/ts/e2e/` changed.

## The three defects

All three were in `sdk-libs/ts/e2e/actions/actions.test.ts`.

1. **Encoded strings where the client returns bytes.** The double emitted a
   base58 `viewTag`, a base58 `outputContext.hash`, and a base64 `payload`.
   `ZolanaIndexer` decodes all three before returning them, so a base64 payload
   made `decodeOutputData` throw and a base58 hash failed the recomputed
   commitment check. Either alone emptied the wallet.
2. **Deposits served on the wrong endpoint.** They were returned from
   `getShieldedTransactionsByTags` flagged `proofless`, which sync skips, while
   `getEncryptedUtxosByTags` returned an empty match list.
3. **A shifted parameter list on the aborting double.** It declared
   `(request, context)` against a real `(request, config, context)`, so it read
   the poll config where it expected the request context and never saw the
   aborted signal. This one was masked: the test carrying it died earlier on the
   empty balance.

## What stops the double drifting again

**The deposit double is no longer hand-written.** `fixtureIndexer`
(`sdk-libs/ts/e2e/support/doubles.ts`) returns a *real* `ZolanaIndexer` over a
real `ZolanaApi` whose `fetch` answers in process. Rows are built as
`@zolana/indexer-api` wire values, encoded by that package's own
`encodeResponse` (which validates by decoding), and converted to SDK types by
the client's own response conversion. Nothing in the suite chooses an encoding
any more: whether a hash travels as base58 and a payload as base64 is settled by
production code, and a malformed row raises a schema error instead of silently
returning nothing. The double also answers the tags it was actually asked for,
so the wallet's tag derivation has to be right for a deposit to surface.

Both endpoints are served the way Photon serves a deposit: the flagged copy on
the transaction endpoint and the spendable one on the encrypted-utxo endpoint.
Defect 2 is therefore no longer a choice the suite can get wrong, and the suite
now covers the skip that keeps sync from storing the deposit twice.

**Behavioral doubles pass through a checked chokepoint.** The stubs that must
control failure rather than data (empty, retrying, aborting, the merge RPC, the
submission client) go through `indexerDouble`, `rpcDouble`, and `clientDouble`,
which take `Partial<ZolanaIndexer>`, `Partial<Rpc>`, and `Partial<ZolanaClient>`
and hold the single cast each. Every method a double declares is contextually
typed by the real declaration, so both remaining defect classes are compile
errors. Verified against a scratch file holding the old shapes:

```
error TS2322: ... Types of property 'viewTag' are incompatible.
  Type 'string' is not assignable to type 'Bytes32'.
error TS2322: ... Types of parameters 'context' and 'config' are incompatible.
  Type 'IndexerRpcConfig' has no properties in common with
  type 'Readonly<{ signal?: AbortSignal }>'.
```

**The e2e tree now typechecks.** It never did: `config/typecheck.mjs` walks the
package list and `tsconfig.eslint.json` includes `sdk-libs/ts/*/{src,test}`, and
`sdk-libs/ts/e2e` matches neither, so nothing had ever run `tsc` over these
files. That is what made the type-level guards worth adding and what let the old
casts hide. `sdk-libs/ts/e2e/tsconfig.json` now covers both suites and
`npx tsc --noEmit --project sdk-libs/ts/e2e/tsconfig.json` is clean.

**Open, and outside this change's file scope:** nothing runs that project in
CI. Wiring it in is a one-line addition to `sdk-libs/ts/config/typecheck.mjs`
(or a `typecheck:e2e` script), both of which are outside `sdk-libs/ts/e2e/`.

## The other doubles

`instructions/acceptance.test.ts` and both `live.test.ts` files hold no indexer
or client double; the live suites drive a real stack and the acceptance suite
drives `TestRpc`. The same audit did turn up two smaller instances of the same
class:

- `rpc as unknown as { blockhash: ... }` reached into `TestRpc` through a
  structural cast that would have kept compiling if the field were renamed or
  retyped. `TestRpc.blockhash` is public, so the test assigns it directly; only
  the string-literal type of the default value is still asserted.
- `Object.create(ZolanaIndexer.prototype)` stood in for the indexer the merge
  client never calls. It is now `fixtureIndexer(new TestIndexer())`, a real
  indexer with nothing recorded in it.

Three pre-existing type errors surfaced once the suites were typechecked, all
behavior-preserving to fix: two `exactOptionalPropertyTypes` violations in
`instructions/acceptance.test.ts` (an optional `cpiAuthority` set to `undefined`
and a `withdrawal` narrowed across two calls) and the blockhash assignment
above.

## What the five tests prove now

No assertion was weakened; the fix is entirely on the supply side. Each test
below reaches its assertions only if two deposits recorded in `TestIndexer`
travel the indexer wire, decode, decrypt, and land as spendable balance.

| Test | What it proves |
|---|---|
| routes registered and unregistered SOL and SPL transfers | A deposited balance funds a transfer, and the recipient resolves to a registered transfer or a public withdrawal per the registry record. |
| creates SOL and SPL withdrawals and preserves external signer bytes | A deposited balance funds SOL and SPL withdrawals, and external signing leaves the message bytes byte-identical. |
| matches the split fixture and rejects a spent input without mutation | The split selects the fixture's exact input hash, conserves the amount, and leaves the wallet unmutated when handed an unavailable input. |
| creates and submits a merge through the production pipeline | The merge selects the fixture's amounts from deposited balance, proves once, and submits the fixture's signature and output hash. |
| covers P256, EdDSA, mixed ownership, balances, history, lag, abort, timeout, and retry | 20 + 60 deposited reads back as 80 spendable across two history entries, a lagging indexer adds nothing, a failed round retries, and an aborted sync rejects. |

The supply side was checked by regression, not by assumption: emptying the
encrypted-utxo match list reproduces exactly the original five failures, so
these tests still detect a lost deposit.

## Verification

| Command | Result | Time |
|---|---|---|
| `npm run test:e2e:actions` | 9 passed (8 in `actions.test.ts`, 1 live) | 6.9s |
| `actions.test.ts` alone | 8 passed | 0.96s (0.60s in tests) |
| `npm run test:e2e:instructions` | 7 passed | 6.2s |
| `npx tsc --noEmit -p sdk-libs/ts/e2e` | clean | 1.1s |
| `npm run typecheck` | clean | 3.8s |
| `npm run build` | clean | 5.7s |

`actions.test.ts` needs no validator, prover, or Photon.

## Row

The defect belongs to no checklist row; the checklist has no family for the test
kit or the end-to-end suites, so this file and `e2e-deposit-diagnosis.md` are its
record. W08 is unaffected: the diagnosis cleared `570162d7`, and the corrected
double confirms it. The current `sync.ts` stores the deposit from the
encrypted-utxo endpoint and skips the flagged copy on the transaction endpoint,
which is the behavior `wallet_sync.rs:368-378` requires.
