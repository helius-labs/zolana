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
`client.proveTransact`, and uses the wallet package only for `syncWallet`, which
owns the view-tag walk across the two indexer endpoints.

One consequence: the transfer step addresses the recipient by `ShieldedAddress`,
exactly as Rust does. The action layer instead takes the recipient's Solana
address and looks up the matching shielded address in the user-registry program,
which would add a registration step the Rust example does not have.

## API surface

| Rust | TypeScript |
| --- | --- |
| `ZolanaClient::from_urls(rpc, indexer, prover, tree)` | `new ZolanaClient({ rpc, indexer, prover, tree })` |
| `SolanaRpc::new(url)` | `new SolanaRpc({ url })` |
| (the Rust client reaches the indexer itself) | `new ZolanaIndexer(new ZolanaApi({ url }))` |
| `spawn_prover()` | `new ProverClient({ url })`, spawned by `startLocalStack` |
| `ShieldedKeypair::from_solana_keypair(&kp)` | `ShieldedKeypair.fromEd25519(seed, 0)` |
| `keypair.shielded_address()` | `keypair.shieldedAddress()` |
| `address.confidential_view_tag()` / `.owner_hash()` | `address.confidentialViewTag()` / `.ownerHash()` |
| `random_blinding()` | `randomBlinding()` |
| `Deposit { .. }.instruction()` | `depositInstruction({ tree, depositor, data })` |
| `Transact { .. }.instruction()` | `transactInstruction({ payer, tree, withdrawal, data })` |
| `TransactWithdrawal::Sol(TransactSolWithdrawal { recipient })` | `{ kind: "sol", recipient }` |
| `SppProofInputUtxo::new(utxo, &kp)` | `new ProofInputUtxo({ utxo, nullifierKey })` |
| `ConfidentialTransfer::new / send / withdraw` | same names, same order |
| `transfer.sign(&keypair, &assets)` | `prepare()`, then encrypt, then `finalize()` |
| `client.prove_transact(inputs, config)` | `client.proveTransact(inputs, context)` |
| `client.create_and_send_transaction(ixs, payer, signers)` | `sendAndConfirm({ rpc, feePayer, instructions, keypairs })` |
| `client.get_shielded_transactions_by_tags(..)` | `client.indexer.getShieldedTransactionsByTags(..)` |
| `decrypt_transactions(&kp, &txs, &assets)` | `syncWallet({ wallet, authority, indexer, config })` |
| `balances.get_balance(SOL_MINT)` | `wallet.balance(SOL_MINT)` |
| `balance.utxos` | `wallet.utxos()` |
| `client.confirm_private_transaction_sync(sig)` | `await client.confirmPrivateTransaction(sig)` |
| `client.get_balance(pubkey)` | `client.getBalance(address)` |
| `IndexerRpcConfig::wait()` | `{ waitForIndexer: true }` |

## Three places the shapes differ

**There is no `ConfidentialTransfer.sign()`.** Rust folds signing and payload
encryption into one call. In TypeScript the output ciphertexts come from the
wallet authority, so it is three steps: `transfer.prepare()` returns the
nullifier and outputs, `authority.encryptConfidentialTransfer(...)` encrypts
them, and `prepared.finalize({ txViewingPublicKey, salt, payload })` produces the
proof inputs. The example wraps this in a local `proofInputs` helper.

**Balances are wallet state, not a return value.** `decrypt_transactions`
returns balances that the Rust example threads from step to step. `syncWallet`
mutates a long-lived `Wallet`, so each step re-syncs. Input selection reads that
same wallet, so a missing re-sync surfaces as a spend of an already-spent note
rather than as a stale number.

**Signing goes through a keypair, not a `Signer` trait.** There is no
`to_solana_keypair()`. `@zolana/test-kit/node` exports `nativeKeypair(seed)` for
a keypair that can fill a signer slot, `nativeSigner(keypair)` to adapt it to the
`TransactionSigner` interface the wallet package submits through, and
`sendAndConfirm` to compile, sign, send, and confirm in one call.

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
   `new ZolanaClient({ tree })`.

Participants derive their Solana keypair, shielded keypair, wallet, and authority
from a single seed, so a participant's Solana address and shielded address share
one key, as they do in the Rust example.

## Running two clones at once

The stack shifts its RPC, indexer, prover, faucet, and gossip ports by
`ZOLANA_PORT_OFFSET`, so use a distinct offset
per clone (0, 100, 200, and so on, below 900). The example defaults to 500 when
the variable is unset.
