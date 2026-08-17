# @heliuslabs/zolana

`@heliuslabs/zolana` is the TypeScript SDK for Solana Rings by Helius. Use it
to:

- deposit SOL, SPL Token, and Token-2022 into a private balance;
- read private balances and transaction history;
- send private transfers; and
- withdraw to public Solana addresses.

## Install

```sh
npm install @heliuslabs/zolana@alpha @solana/kit
```

Requirements:

- Node.js 24 or newer;
- Solana RPC, indexer, and prover endpoints.

## Quick start

This example creates a wallet, syncs it, deposits SOL, and reads the resulting
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
} from "@heliuslabs/zolana";

const client = await createZolanaClient({});

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

By default, the indexer and prover use `solanaRpcUrl`. Override either one
independently for separate services or local development:

```ts
const client = await createZolanaClient({
  solanaRpcUrl: "http://127.0.0.1:8899",
  indexerUrl: "http://127.0.0.1:8784",
  proverUrl: "http://127.0.0.1:3001",
});
```

For an Ed25519 spending wallet, the shielded keypair and the Solana signer must use
the same owner seed, as shown above.

### Endpoints

A config that names no URL reaches the local stack, where the validator,
Photon, and the prover listen on 8899, 8784, and 3001. One URL is enough only
when that host actually serves RPC, indexer, and prover. A Helius RPC URL
does not serve indexer or prover methods; name those separately when they
sit on other hosts.

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

The SDK resolves a registered Solana public key to a shielded address.
Passing a `ShieldedAddress` skips the lookup.

### Private transfer

A private transfer targets the recipient's registered Solana public key.
If that pubkey is not registered, the call fails with
`WALLET_RECIPIENT_NOT_REGISTERED`. It does not withdraw. Use
`buildWithdrawalTransaction` for a public recipient.

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
contains UTXO data and must be encrypted at rest.

## Public API

Common exports from `@heliuslabs/zolana` include:

- setup: `createZolanaClient`, `ShieldedKeypair`, `Wallet`,
  `LocalWalletAuthority`;
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

## API reference

The release workflow publishes the generated TypeDoc reference from
`ts-sdk-v*` tags. The tag version must match this package's version. Published
versions are immutable:

- latest: <https://helius-labs.github.io/zolana/ts-sdk/>;
- explicit version:
  <https://helius-labs.github.io/zolana/ts-sdk/v0.1.0-alpha/>; and
- version index:
  <https://helius-labs.github.io/zolana/ts-sdk/versions.json>.

GitHub Pages must use GitHub Actions as its source before the first release
workflow runs.

The intended long-term canonical location is
`https://www.helius.dev/privacy/api/`, with immutable versions such as
`https://www.helius.dev/privacy/api/v0.1.0-alpha/`. Migrate only after the Helius
website proxies `/privacy/api/*` to the GitHub Pages `/zolana/ts-sdk/*` origin.
At that point, update the release workflow's `PUBLIC_BASE_URL`; existing GitHub
Pages URLs remain available as the backing origin.

## Important notes

- Ed25519 is the supported owner scheme for registration and private
  transactions. `ShieldedKeypair.generate()` defaults to Ed25519.
- Viewing keys use P256; this is separate from unsupported P256 owner
  registration or spending.
- Non-loopback indexer and prover URLs must use HTTPS.
- Protect signer seeds and shielded key material. Encrypt serialized wallet
  state and avoid logging private balances, UTXOs, or keys.
