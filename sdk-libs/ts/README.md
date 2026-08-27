# @heliuslabs/zolana

`@heliuslabs/zolana` is the TypeScript SDK for Zolana shielded assets on Solana. Use it
to:

- shield SOL, SPL Token, and Token-2022 assets;
- read private balances and transaction history;
- send confidential transfers;
- withdraw to public Solana addresses; and
- split or merge private notes when needed.

## Install

```sh
npm install @heliuslabs/zolana @solana/kit
```

Requirements:

- Node.js 24 or newer;
- a unified Zolana endpoint, or separate Solana RPC, indexer, and prover
  endpoints.

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
  KeypairWalletAuthority,
  ShieldedKeypair,
  SigningKey,
  SOL_MINT,
  Wallet,
  buildDepositTransaction,
  createZolanaClient,
  getPrivateTransactions,
  syncWallet,
  type Bytes32,
} from "@heliuslabs/zolana";

// One url serves the RPC, the indexer, and the prover.
// localnet: const client = await createZolanaClient({});
const client = await createZolanaClient({
  solanaRpcUrl: `https://devnet.helius-rpc.com?api-key=${process.env.API_KEY!}`,
});

// Load this from the app wallet or key store.
declare function loadOwnerSeed(): Promise<Bytes32>;
const ownerSeed = await loadOwnerSeed();

const feePayer = await createKeyPairSignerFromPrivateKeyBytes(ownerSeed);
const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(ownerSeed));
ownerSeed.fill(0);

const wallet = new Wallet({ identity: keypair.shieldedAddress() });
const authority = new KeypairWalletAuthority({
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

By default, the indexer and prover use `solanaRpcUrl`. Override either one
independently for separate services or local development:

```ts
const client = await createZolanaClient({
  solanaRpcUrl: "http://127.0.0.1:8899",
  indexerUrl: "http://127.0.0.1:8784",
  proverUrl: "http://127.0.0.1:3001",
});
```

For an Ed25519 spending wallet, the shielded identity and Solana signer must use
the same owner seed, as shown above.

### Endpoints

`solanaRpcUrl` serves the Solana RPC, the indexer, and the prover, which is the
shape a Helius URL takes. A config that names no url reaches the local stack,
where the validator, photon, and the prover listen on 8899, 8784, and 3001:

```ts
const client = await createZolanaClient({});
```

Name a service on its own when it does not sit behind the same host:

```ts
const client = await createZolanaClient({
  solanaRpcUrl: process.env.SOLANA_RPC_URL!,
  indexerUrl: "https://photon.example",
  proverUrl: "https://prover.example",
});
```

A named URL wins over `solanaRpcUrl` and over a local default port, so
`ZOLANA_PORT_OFFSET` shifts the local ports by naming them. Pass `apiKey` when
the URL does not already carry one.

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
import { buildTransferTransaction } from "@heliuslabs/zolana";

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
import { buildWithdrawalTransaction } from "@heliuslabs/zolana";

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

Common exports from `@heliuslabs/zolana` include:

- setup: `createZolanaClient`, `ShieldedKeypair`, `Wallet`,
  `KeypairWalletAuthority`;
- transactions: `buildDepositTransaction`, `buildTransferTransaction`,
  `buildWithdrawalTransaction`, `buildSplitTransaction`,
  `buildMergeTransaction`;
- state: `syncWallet`, `getPrivateTokenBalances`, `getPrivateTransactions`,
  `serializeWallet`, `deserializeWallet`; and
- registration: `buildRegistrationTransaction`.

Advanced protocol users can import low-level instruction builders from
`@heliuslabs/zolana/instructions`. PDA helpers are available from
`@heliuslabs/zolana/addresses`; additional typed surfaces are exposed under
`@heliuslabs/zolana/client`, `/interface`, `/keypair`, `/transaction`, and `/wallet`.

## Important notes

- Ed25519 is the supported owner rail for registration and private
  transactions. `ShieldedKeypair.generate()` defaults to Ed25519.
- Viewing keys are P256 on every wallet; this is expected and is separate from
  unsupported P256 owner registration or spending.
- Non-loopback indexer and prover URLs must use HTTPS.
- Protect signer seeds and shielded key material. Encrypt serialized wallet
  state and avoid logging private balances, notes, or keys.
