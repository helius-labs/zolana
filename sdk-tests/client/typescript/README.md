# TypeScript client example

[`deposit-transfer-withdraw.test.ts`](deposit-transfer-withdraw.test.ts) shows
the instruction-level `@heliuslabs/zolana` flow to deposit SOL into a private balance,
transfer between private balances, and withdraw from a private balance to a
public balance.

## Flow

1. Build and send a SOL deposit instruction.
2. Fetch transaction outputs by view tag and decrypt them locally.
3. Select an input UTXO and build a confidential transfer.
4. Request a proof, construct the transact instruction, and send it.
5. Fetch and decrypt again to read the remaining private balance.
6. Repeat the transact flow for a SOL withdrawal.

The example uses SOL by default. To use SPL, remove the `SOL_MINT` import,
comment each active SOL statement, and remove `// SPL:` from the adjacent
replacement. The test harness creates and funds the SPL mint and token account.

## Run

From the repository root:

```bash
just test-ts-example
```

The command starts a validator, Photon, and the prover, loads the canonical
protocol accounts including the state Merkle tree that stores private token
accounts (UTXOs), creates test mints, and runs the example against them. The
same bring-up serves the ring flow of `just test-ts-e2e`.

The example connects with `createZolanaClient()`: the local validator, Photon,
and prover on their default ports (8899, 8784, 3001) and the state Merkle tree
at its canonical address. To run it against an already running local stack, provide
the test fixtures and invoke the npm script directly:

```bash
ZOLANA_TEST_MINT=<mint> \
ZOLANA_TEST_TOKEN_ACCOUNT=<funded-token-account> \
ZOLANA_TEST_AUTHORITY_WALLET=<wallet.json with funding_secret_hex> \
npm run test:ts:example
```

To target a remote deployment such as devnet, pass its URL to
`createZolanaClient` as shown in the commented line of the example; one URL
serves the RPC, the indexer, and the prover.

## Optimized merge and transfer

[`optimized-merge-transfer.test.ts`](optimized-merge-transfer.test.ts) is the
TypeScript counterpart of the Rust
[`optimized_merge_transfer.rs`](../rust/optimized_merge_transfer.rs). It spends
a balance spread over eight UTXOs, the width of one TypeScript merge, without
waiting for the merged output to be indexed. The merge writes its output
commitment into a slot of a cache account, and the transfer proves that input
against the cache instead of against a Merkle path, so both proofs are
requested at once.

Two actors: the **sender** owns the UTXOs and signs the transfer, and the
**rent sponsor** funds the cache, is its write authority, and sends the merge.
The sender signs no merge: its registry record opted into merging.

### Flow

1. Register the sender and opt its record into merging.
2. Deposit eight UTXOs and decrypt them.
3. Derive the cache address from the rent sponsor and a nonce with
   `getCacheAddress`, and prepare the merge.
4. Build the transfer over the merge's predicted output. The merged output's
   blinding is derived rather than random, so its commitment is known before
   the merge lands.
5. Request `proveMerge` with a `cache` target and `proveTransact` at once, on
   proof inputs whose merged input names the cache slot with `withCacheSlot`
   and which read the cache set with `withReadCache`.
6. Send `createCacheInstruction` and the merge in one transaction as soon as the
   merge proof is ready; creating an existing cache is a no-op.
7. Wait for the cache slot to hold the merge output.
8. Send the transfer, reading the cache with `TransactCacheAccounts.read`, and
   `closeCacheInstruction` in one transaction, then check that the rent went
   back to the sponsor and that both balances moved.

The run prints its own timeline, `merge and transfer proofs requested`,
`transfer proof ready`, `merge proof ready`, `merge transaction confirmed`,
`cache slot 0 holds the merge output`, and `transfer transaction confirmed`.

### Run

From the repository root:

```bash
just test-ts-example-optimized-merge-transfer
```

The recipe brings up the same stack as `just test-ts-example` and selects the
example with `ZOLANA_TS_EXAMPLE=optimized-merge-transfer`, which the example's
Vitest config reads; against an already running stack, set it before
`npm run test:ts:example`.
