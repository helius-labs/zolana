# TypeScript deposit, transfer, withdraw example

Deposit SOL into a private balance, transfer part of it to a second wallet, and
withdraw the rest to a Solana account. Runs against a local validator, Photon,
and prover. For Rust see `../rust-client/`.

```bash
just test-ts-example              # builds programs, prover, Photon, then runs it
npm run test:e2e:example          # if those binaries are already built
```

Files:

- `setup.ts` starts the stack, creates protocol state, and returns urls, one
  tree, and two funded shielded keypairs.
- `deposit-transfer-withdraw.test.ts` builds the client, signer, authority, and
  wallet, then runs deposit, transfer, and withdraw.

This directory is not an npm workspace. It resolves `@zolana/*` through the root
`node_modules`. `npm run typecheck:example` and `npm run lint:example` use this
directory's `tsconfig.json`; both run under `npm run check:static`.

## Which layer this uses

Skip `@zolana/wallet`'s action layer (`createDeposit`, `createTransfer`,
`createWithdrawal`, `signPrivateTransaction`). The Rust example builds
instructions by hand, so this one does too: `@zolana/interface` builders,
`ConfidentialTransfer`, and `client.proveTransact`.

The transfer step takes a `ShieldedAddress` for the recipient, matching Rust.
The action layer instead takes a Solana address and looks up the shielded
address in the user-registry program, which would add a registration step Rust
does not have.

For balances, call `syncWallet` on a long-lived `Wallet`. Rust's example still
does one tag query and one `decrypt_transactions` per step. Instruction
building stays aligned either way.

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
| (keep a wallet synced) | `new Wallet({ identity, registry })` + `syncWallet({ wallet, authority, indexer })` |
| `get_shielded_transactions_by_tags` + `decrypt_transactions` | Rust example one-shot path; this example uses `syncWallet` |
| `balances.get_balance(SOL_MINT)` | `wallet.balance(SOL_MINT)` |
| `client.confirm_private_transaction_sync(sig)` | `await client.confirmPrivateTransaction(sig)` |
| `client.get_balance(pubkey)` | `client.getBalance(address)` |
| `IndexerRpcConfig::wait()` | `waitForIndexer()` / `config: { waitForIndexer: true }` on `syncWallet` |

## Where the shapes differ

Network calls are async. Rust has blocking and non-blocking rails; JavaScript
only has the awaited ones, including methods Rust names `*_sync`. Local calls
stay synchronous on both sides, including `ConfidentialTransfer.sign`.

Rust decrypts with a bare keypair (`decrypt_transactions(&keypair, ..)`).
TypeScript sync takes a `WalletAuthority`. The example builds
`new LocalWalletAuthority({ solanaPublicKey, keypair })` and passes it to
`syncWallet`, which walks tag ranges and pages both indexer endpoints to update
one `Wallet`.

## What `setup()` does

`startLocalStack` starts the validator, prover, and Photon, and writes the Squads
program-config fixture. Everything after that is protocol state the example needs
and the harness does not create:

1. Airdrop to the payer, the settings authority, the protocol vault, and both
   keypairs' Solana addresses, then confirm, because each funded account signs
   the next transaction.
2. Create the standard Squads settings accounts with one authority for the
   protocol, forester, merge, tree, and zone roles.
3. Write the protocol config through the smart account, naming the protocol vault
   as the protocol, forester, merge, tree, and zone authority.
4. Allocate and create one state tree. `DEFAULT_TREE_ADDRESS` is a vanity address
   with no keypair in the repo, so setup generates a tree and returns it for
   `ZolanaClient.fromUrls({ tree })` in the example.

In the example, derive the Solana signer and wallet authority from each returned
keypair so the Solana address and shielded address share one key, as in the Rust
example.

## Running two clones at once

The stack shifts its RPC, indexer, prover, faucet, and gossip ports by
`ZOLANA_PORT_OFFSET`, so use a distinct offset
per clone (0, 100, 200, and so on, below 900). The example defaults to 500 when
the variable is unset.
