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
accounts (UTXOs), creates test mints, and runs the example against them.

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
