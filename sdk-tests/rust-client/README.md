# Rust deposit, transfer, withdraw example

Deposit SOL into a private balance, transfer part of it to a second wallet, and
withdraw the rest to a Solana account. Runs against a local validator, Photon,
and prover. For TypeScript see `../typescript-client/`.

```bash
just test-client-example          # builds programs, prover, Photon, CLI, then runs it
cargo run -p client-example --example deposit_transfer_withdraw   # if those binaries are already built
```

Files:

- `src/lib.rs` starts the stack, creates protocol state, and returns urls, one
  tree, and two funded shielded keypairs.
- `examples/deposit_transfer_withdraw.rs` builds the client and runs deposit,
  transfer, and withdraw.

This crate is the `client-example` workspace member. It is not published.

## Which layer this uses

Build instructions by hand: `Deposit` / `Transact` from `zolana-interface`,
`ConfidentialTransfer`, and `client.prove_transact`. The higher-level wallet
action helpers are not used here, so the example stays aligned with the
TypeScript instruction-level path.

For balances, query by view tag and call `decrypt_transactions` once per step.
TypeScript's example instead keeps a long-lived `Wallet` current with
`syncWallet`. Instruction building stays aligned either way.

## API surface

| Rust | TypeScript |
| --- | --- |
| `ZolanaClient::from_urls(rpc, indexer, prover, tree)` | `ZolanaClient.fromUrls({ rpc, indexerUrl, proverUrl, tree })` |
| `SolanaRpc::new(url)` | `new SolanaRpc({ url })` |
| `spawn_prover()` | spawned by `startLocalStack`, wired by `fromUrls` |
| `ShieldedKeypair::from_solana_keypair(&kp)` | `ShieldedKeypair.fromEd25519(seed, 0)` |
| `keypair.to_solana_keypair()` | `createSolanaSigner(keypair)` |
| `keypair.shielded_address()` | `keypair.shieldedAddress()` |
| `address.confidential_view_tag()` / `.owner_hash()` | `address.confidentialViewTag()` / `.ownerHash()` |
| `random_blinding()` | `randomBlinding()` |
| `Deposit { .. }.instruction()` | `depositInstruction({ tree, depositor, data })` |
| `Transact { .. }.instruction()` | `transactInstruction({ payer, tree, withdrawal, data })` |
| `TransactWithdrawal::Sol(TransactSolWithdrawal { recipient })` | `{ kind: "sol", recipient }` |
| `SppProofInputUtxo::new(utxo, &kp)` | `ProofInputUtxo.fromKeypair(utxo, keypair)` |
| `ConfidentialTransfer::new / send / withdraw / sign` | same names, same order, `sign` also synchronous |
| `client.prove_transact(inputs, config)` | `client.proveTransact(inputs, config)` |
| `client.create_and_send_transaction(ixs, payer, signers)` | `client.createAndSendTransaction({ instructions, feePayer, signers })` |
| `get_shielded_transactions_by_tags` + `decrypt_transactions` | this example's balance path; TypeScript uses `syncWallet` |
| (keep a wallet synced) | `new Wallet({ identity, registry })` + `syncWallet({ wallet, authority, indexer })` |
| `balances.get_balance(SOL_MINT)` | `wallet.balance(SOL_MINT)` |
| `client.confirm_private_transaction_sync(sig)` | `await client.confirmPrivateTransaction(sig)` |
| `client.get_balance(pubkey)` | `client.getBalance(address)` |
| `IndexerRpcConfig::wait()` | `waitForIndexer()` / `config: { waitForIndexer: true }` on `syncWallet` |

## Where the shapes differ

Network calls are async in TypeScript. Rust has blocking and non-blocking rails;
JavaScript only has the awaited ones, including methods Rust names `*_sync`.
Local calls stay synchronous on both sides, including `ConfidentialTransfer.sign`.

Rust decrypts with a bare keypair (`decrypt_transactions(&keypair, ..)`).
TypeScript sync takes a `WalletAuthority` and typically calls `syncWallet`.

## What `setup()` does

`LocalnetValidator` starts the validator and Photon through the `zolana` CLI;
`spawn_prover` starts the prover. Everything after that is protocol state the
example needs and the harness does not create:

1. Airdrop to the payer, the settings authorities, the protocol vault, and both
   wallets, then continue, because each funded account signs the next
   transaction.
2. Create the standard Squads settings accounts for the protocol, forester,
   merge, tree, and zone roles.
3. Write the protocol config through the smart account, naming the protocol vault
   as the protocol, forester, merge, tree, and zone authority.
4. Allocate and create one state tree, then return its pubkey with the urls and
   two funded `ShieldedKeypair`s.

In the example, call `to_solana_keypair()` on each returned keypair so the Solana
address and shielded address share one key.

## Running two clones at once

The justfile shifts RPC, indexer, and prover ports by `ZOLANA_PORT_OFFSET`. Use a
distinct offset per clone (0, 100, 200, and so on, below 900). Export
`ZOLANA_LOCALNET_URL`, `ZOLANA_INDEXER_URL`, and `ZOLANA_PROVER_URL` (or run via
`just`, which loads `.env`) so the example hits the matching stack.
