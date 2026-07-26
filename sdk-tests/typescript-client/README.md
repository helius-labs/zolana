# TypeScript deposit, transfer, withdraw example

The TypeScript counterpart of
`../rust-client/examples/deposit_transfer_withdraw.rs`, kept beside it so the two
read as a pair. It moves SOL into the shielded pool, sends part of it to a second
wallet, and withdraws the rest back to a Solana account, against a local
validator, Photon, and prover.

```bash
just test-ts-example              # builds programs, prover, Photon, then runs it
npm run test:e2e:example          # if those binaries are already built
```

Two files:

- `setup.ts` brings up the stack and the protocol state, and returns two funded
  participants.
- `deposit-transfer-withdraw.test.ts` is the example itself.

This directory is not an npm workspace. It resolves `@zolana/*` through the root
`node_modules`, and its own `tsconfig.json` is what `npm run typecheck:example`
and `npm run lint:example` point at, both of which run as part of
`npm run check:static`.

## Which layer this uses

`@zolana/wallet` has an action layer (`createDeposit`, `createTransfer`,
`createWithdrawal`, `signPrivateTransaction`) that is the idiomatic way to build
these transactions. This example deliberately does not use it, because the Rust
example it mirrors builds instructions by hand and the two read as a pair. It
drops to `@zolana/interface` instruction builders, `ConfidentialTransfer`, and
`client.proveTransact`.

One consequence: the transfer step addresses the recipient by `ShieldedAddress`,
exactly as Rust does. The action layer instead takes the recipient's Solana
address and looks up the matching shielded address in the user-registry program,
which would add a registration step the Rust example does not have.

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
| `client.get_shielded_transactions_by_tags(..)` | `client.getShieldedTransactionsByTags(..)` |
| `decrypt_transactions(&kp, &txs, &assets)` | `Wallet.decrypt({ authority, transactions, assets })` |
| `balances.get_balance(SOL_MINT)` | `wallet.balance(SOL_MINT)` |
| `client.confirm_private_transaction_sync(sig)` | `await client.confirmPrivateTransaction(sig)` |
| `client.get_balance(pubkey)` | `client.getBalance(address)` |
| `IndexerRpcConfig::wait()` | `waitForIndexer()` |

## Two places the shapes differ

**Everything that touches the network is async.** Rust exposes a blocking and a
non-blocking rail; JavaScript has no blocking rail to expose, so the TypeScript
methods that Rust names `*_sync` are the plain `await`ed ones. The purely local
calls stay synchronous on both sides, including `ConfidentialTransfer.sign`.

**Decryption goes through a `WalletAuthority`, not a bare keypair.** Rust reads
`decrypt_transactions(&keypair, ..)`. In TypeScript the viewing key may live
behind a remote signer or a hardware device, so decryption asks an authority for
its sync material. `new LocalWalletAuthority({ solanaPublicKey, keypair })` is the
in-process implementation, and `setup.ts` builds one per participant. The
stateful alternative is `syncWallet`, which walks the tag ranges and pages both
indexer endpoints to keep one long-lived `Wallet` current; this example stays at
the level Rust's does, one tag query followed by one decrypt.

## What `setup()` does

`startLocalStack` starts the validator, prover, and Photon, and writes the Squads
program-config fixture. Everything after that is protocol state the example needs
and the harness does not create:

1. Airdrop to the payer, the settings authority, the protocol vault, and both
   participants, then confirm, because each funded account signs the next
   transaction.
2. Create the standard Squads settings accounts with one authority for the
   protocol, forester, merge, tree, and zone roles.
3. Write the protocol config through the smart account, naming the protocol vault
   as the protocol, forester, merge, tree, and zone authority.
4. Allocate and create one state tree. `DEFAULT_TREE_ADDRESS` is a vanity address
   with no keypair in the repo, so the example generates a tree and passes it to
   `ZolanaClient.fromUrls({ tree })`.

Participants derive their Solana signer, shielded keypair, and wallet authority
from a single seed, so a participant's Solana address and shielded address share
one key, as they do in the Rust example.

## Running two clones at once

The stack shifts its RPC, indexer, prover, faucet, and gossip ports by
`ZOLANA_PORT_OFFSET`, so use a distinct offset
per clone (0, 100, 200, and so on, below 900). The example defaults to 500 when
the variable is unset.
