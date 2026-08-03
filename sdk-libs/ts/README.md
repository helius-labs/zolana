# @zolana/sdk

`@zolana/sdk` is the TypeScript SDK for Zolana shielded assets on Solana. Use it
to:

- shield SOL, SPL Token, and Token-2022 assets;
- read private balances and transaction history;
- send confidential transfers;
- withdraw to public Solana addresses; and
- split or merge private notes when needed.

## Install

```sh
npm install @zolana/sdk @solana/kit
```

Requirements:

- Node.js 24 or newer;
- a Solana RPC endpoint;
- a Zolana indexer endpoint; and
- a Zolana prover endpoint for private spends.

## Quick start

This example creates a wallet, syncs it, shields SOL, and reads the resulting
balance and history. For the purpose of this demo the application supplies the Solana signer and stores its
seed.

```ts
import {
  createKeyPairSignerFromPrivateKeyBytes,
  getSignatureFromTransaction,
  sendAndConfirmTransactionFactory,
  signTransactionWithSigners,
  type Address,
  type KeyPairSigner,
  type Transaction,
} from "@solana/kit";
import {
  LocalWalletAuthority,
  ShieldedKeypair,
  SOL_MINT,
  Wallet,
  buildDepositTransaction,
  createZolanaClient,
  getPrivateTransactions,
  syncWallet,
  type Bytes32,
} from "@zolana/sdk";

const client = await createZolanaClient({
  solanaRpcUrl: "https://api.devnet.solana.com",
  indexerUrl: "https://indexer.example.com",
  proverUrl: "https://prover.example.com",
});

// Load this from the app wallet or key store.
declare function loadOwnerSeed(): Promise<Bytes32>;
const ownerSeed = await loadOwnerSeed();

const feePayer = await createKeyPairSignerFromPrivateKeyBytes(ownerSeed);
const keypair = ShieldedKeypair.fromEd25519(ownerSeed, 0);
ownerSeed.fill(0);

const wallet = new Wallet({ identity: keypair.shieldedAddress() });
const authority = new LocalWalletAuthority({
  solanaPublicKey: feePayer.address,
  keypair,
});

const sendAndConfirm = sendAndConfirmTransactionFactory({
  rpc: client.solanaRpc,
  rpcSubscriptions: client.solanaRpcSubscriptions,
});

async function submit(transaction: Transaction, signer: KeyPairSigner) {
  const signed = await signTransactionWithSigners([signer], transaction);
  await sendAndConfirm(signed, { commitment: "confirmed" });
  return getSignatureFromTransaction(signed);
}

await syncWallet({
  client,
  wallet,
  authority,
});

const deposit = await buildDepositTransaction({
  client,
  feePayer: feePayer.address,
  recipient: keypair.shieldedAddress(),
  amount: 100_000_000n,
});
await submit(deposit, feePayer);

await syncWallet({
  client,
  wallet,
  authority,
  config: { waitForIndexer: true },
});

console.log(wallet.balance(SOL_MINT).amount);
console.log(getPrivateTransactions(wallet));
```

For an Ed25519 spending wallet, the shielded identity and Solana signer must use
the same owner seed, as shown above.

## Common transactions

These snippets continue from the setup used in quickstart.

### Deposit

The quick start shows a SOL deposit. For an SPL token, provide its mint and the
depositor's source token account:

```ts
const deposit = await buildDepositTransaction({
  client,
  feePayer: feePayer.address,
  recipient: keypair.shieldedAddress(),
  asset: mint,
  splTokenAccount: sourceTokenAccount,
  amount: 1_000_000n,
});
await submit(deposit, feePayer);
```

The standard SPL Token program is used by default. For Token-2022, also pass
`splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID`.

The SDK automatically resolves a registered Solana public key to its shielded
address. Passing a `ShieldedAddress` directly bypasses the lookup.

### Confidential transfer

A transfer normally targets the recipient's registered Solana public key.

```ts
import { buildTransferTransaction } from "@zolana/sdk";

declare const recipientSolanaAddress: Address;

const transfer = await buildTransferTransaction({
  client,
  wallet,
  authority,
  feePayer: feePayer.address,
  recipient: recipientSolanaAddress,
  amount: 25_000_000n,
});
await submit(transfer, feePayer);
await syncWallet({ client, wallet, authority, config: { waitForIndexer: true } });
```

Pass `asset: mint` for an SPL or Token-2022 balance.

### Withdrawal

Withdraw to a public Solana address:

```ts
import { buildWithdrawalTransaction } from "@zolana/sdk";

const withdrawal = await buildWithdrawalTransaction({
  client,
  wallet,
  authority,
  feePayer: feePayer.address,
  recipient: publicRecipient,
  amount: 10_000_000n,
});
await submit(withdrawal, feePayer);
await syncWallet({ client, wallet, authority, config: { waitForIndexer: true } });
```

For an SPL withdrawal, pass `asset: mint`. Token-2022 withdrawals also take
`splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID`; the recipient token account is
created idempotently when needed.

## Wallet sync and persistence

Call `syncWallet`:

- when loading a wallet;
- after each confirmed deposit, transfer, withdrawal, split, or merge; and
- optionally when the app regains focus or on a timer to discover inbound
  transfers.

Do not build another private spend until the wallet has synced after the
previous confirmed transaction.

Persist wallet state with `serializeWallet` and restore it with
`deserializeWallet`. Persist key material separately. Serialized wallet state
contains private note data and must be encrypted at rest.

## Public API

Common exports from `@zolana/sdk` include:

- setup: `createZolanaClient`, `ShieldedKeypair`, `Wallet`,
  `LocalWalletAuthority`;
- transactions: `buildDepositTransaction`, `buildTransferTransaction`,
  `buildWithdrawalTransaction`, `buildSplitTransaction`,
  `buildMergeTransaction`;
- state: `syncWallet`, `getPrivateTokenBalances`, `getPrivateTransactions`,
  `serializeWallet`, `deserializeWallet`; and
- registration: `buildRegistrationTransaction`.

Advanced protocol users can import low-level instruction builders from
`@zolana/sdk/instructions`. PDA helpers are available from
`@zolana/sdk/addresses`; additional typed surfaces are exposed under
`@zolana/sdk/client`, `/interface`, `/keypair`, `/transaction`, and `/wallet`.

## Important notes

- Ed25519 is the supported owner rail for registration and private
  transactions. `ShieldedKeypair.generate()` defaults to Ed25519.
- Viewing keys are P256 on every wallet; this is expected and is separate from
  unsupported P256 owner registration or spending.
- Non-loopback indexer and prover URLs must use HTTPS.
- Protect signer seeds and shielded key material. Encrypt serialized wallet
  state and avoid logging private balances, notes, or keys.
