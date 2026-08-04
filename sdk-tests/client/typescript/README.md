# TypeScript client example

[`deposit-transfer-withdraw.test.ts`](deposit-transfer-withdraw.test.ts) shows
the instruction-level `@zolana/sdk` flow to deposit SOL into a private balance,
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

The command starts the validator, Photon, and prover, then runs the example.

To use existing services, set the localnet environment variables:

```bash
npm run test:ts:example
```
