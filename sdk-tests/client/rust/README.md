# Rust client example

[`deposit_transfer_withdraw.rs`](deposit_transfer_withdraw.rs) shows the
instruction-level Rust flow to deposit SOL into a private balance, transfer
between private balances, and withdraw from a private balance to a public
balance.

## Flow

1. Build and send a SOL deposit instruction.
2. Fetch transaction outputs by view tag and decrypt them locally.
3. Select an input UTXO and build a confidential transfer.
4. Request a proof, construct the transact instruction, and send it.
5. Fetch and decrypt the sender's updated private balance.
6. Repeat the transact flow for a SOL withdrawal.

## Run

From the repository root:

```bash
just test-client-example
```

The command starts the validator, Photon, and prover, then runs the example.
