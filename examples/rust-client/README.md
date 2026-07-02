# Rust Client SDK Examples

End-to-end client examples for the shielded pool, driven through the
`zolana-client` SDK against a local validator, Photon indexer, and prover. Each
example is a self-contained binary covering one operation, in two tiers: an
ergonomic `action_*` tier and a raw `instruction_*` tier that shows the
assemble → prove → `Transact` path the actions wrap.

## Examples

- **Deposit** (proofless shield): shield a public balance into the pool.
  - SPL: [Action](examples/action_spl_deposit.rs) · [Instruction](examples/instruction_spl_deposit.rs)
- **Transfer** (private send): move value between shielded balances.
  - SPL: [Action](examples/action_spl_transfer.rs) · [Instruction](examples/instruction_spl_transfer.rs)
- **Withdraw** (unshield): move value back to a public account.
  - SPL: [Action](examples/action_spl_withdraw.rs) · [Instruction](examples/instruction_spl_withdraw.rs)
- **Sync + balance**: scan the indexer, decrypt owned notes, read balances.
  - [Action](examples/action_sync_balance.rs) · [Instruction](examples/instruction_sync_balance.rs)

The `action_*` files call the high-level SDK (`create_deposit`,
`create_transfer_sync`, `create_withdrawal_sync`, `sync_wallet`) and submit with
the one-call `Submit` action. The `instruction_*` files build the same operation
by hand: select inputs, then let `Submit` fetch the merkle and non-inclusion
proofs, assemble the witness, prove, and send the `Transact` instruction.

The wallet owns its `AssetRegistry`, so the SDK reads asset ids off the wallet
(`sync_wallet`, `get_private_token_balances`, and `create_transfer_sync` take no
separate registry argument). Register SPL assets before creating the parties
that spend them.

## Prerequisites

Build the on-chain programs, prover, CLI, and indexer once:

```bash
just build-programs build-prover-server build-cli
just ensure-photon
just ensure-smart-account
```

`ensure-photon` builds the Photon indexer from a sibling `../photon` checkout
(`just build-photon` -> `target/bin/photon`); point `ZOLANA_PHOTON_BIN` at a
prebuilt binary to skip the build.

Transfers and withdrawals generate a proof; the prover downloads its proving
keys from a GitHub release on first use, which needs `gh` authenticated for the
hosting org (`gh auth status`). Deposits and sync are proofless and need
neither, so they run with no `gh` and no keys.

## Run

Each example boots its own validator, Photon, and prover, so run one at a time:

```bash
just run-rust-client-example action_spl_deposit
```

or directly:

```bash
cargo run -p rust-client-example --example action_spl_transfer
```

Start with `action_spl_deposit` or `action_sync_balance`: they are proofless, so
they validate the setup without the prover or `gh`. Each example prints a single
`ok ...` line with the transaction signature and the resulting balance.

The validator binds the RPC port (8899) and Photon port (8784). The
`just run-rust-client-example` recipe frees stale validators on those ports
before each run; a bare `cargo run` does not, so kill leftover processes first if
a port is busy.

## Documentation

- Protocol spec: [`docs/spec.md`](../../docs/spec.md)
- Client SDK: [`sdk-libs/client`](../../sdk-libs/client)
