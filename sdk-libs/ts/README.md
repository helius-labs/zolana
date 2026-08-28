# @heliuslabs/zolana

`@heliuslabs/zolana` is the TypeScript SDK for Solana Privacy Rings.
Solana Privacy Rings are a programmable shielded pool with encrypted onchain balances and execution directly on Solana.

Use it for:

- deposit SOL, SPL Token, and Token-2022 into a private balance;
- read private balances and transaction history;
- send private transfers to a Solana address; and
- private to public withdrawal to a Solana address.

All private transactions are executed in a single Solana transaction.

## Install

```sh
npm install @heliuslabs/zolana @solana/kit
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

const client = await createZolanaClient({});

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

For an Ed25519 spending wallet, the shielded keypair and the Solana signer must use
the same owner seed, as shown above.

### Endpoints

A client needs one URL and a
[Helius API key](https://dashboard.helius.dev/).

The RPC endpoint serves the Solana RPC. The Photon indexer to fetch encrypted
state, and the prover that generates the zero-knowledge proofs currently use aws URLs.
It's planned to make indexer and prover available through using the same Helius RPC URL.

**Devnet:**

| Service    | Host the SDK uses                                                   | Notes                                                                                     |
| ---------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Solana RPC | `https://devnet.helius-rpc.com/?api-key=<API_KEY>`                  | Helius key. Fund the payer with [devnet SOL](https://www.helius.dev/docs/rpc/devnet-sol). |
| Indexer    | `http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com`      | Fetches encrypted state.                                                                  |
| Prover     | `http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com:3001` | Generates ZK proofs                                                                       |

```ts
const client = await createZolanaClient({
  solanaRpcUrl: `https://devnet.helius-rpc.com/?api-key=${process.env.API_KEY!}`,
  indexerUrl: "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com",
  proverUrl: "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com:3001",
  allowInsecureHttp: true,
});
```

On localnet the SDK starts the local test validator (`:8899`), Photon indexer
(`:8784`), and prover (`:3001`), and the client connects to them automatically
without needing endpoint configuration.

```ts
const client = await createZolanaClient({});
```

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

Creating a private wallet registers the Solana address in the onchain registry
and maps it to a shielded address. On every transfer, the SDK looks up the
wallet address in the onchain registry to resolve the shielded address.
Passing a `ShieldedAddress` skips the lookup.

### Private transfer

A private transfer is sent to a Solana wallet address. The SDK looks up that
address in the onchain registry. If it is not registered, the call fails with
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

## Custom Rings

Besides the permissionless default Ring, regulated entities can create custom Rings.
Custom Rings are simple Solana programs for compliance and policy control. Each Ring deploys its own program. It has a program
upgrade authority, a protocol authority, and an auditor key. The default Ring does not have an auditor key.

The auditor key lives in a Ring RPC. The Ring authority grants view access.
Helius can host that RPC; the authority can host it itself. The forester is
shared with the default Ring.

This first iteration supports confidential transactions only. Anonymous
transfers that would use a relayer are not supported. Later iterations add
allowlists, blocklists, and rule-based config on the Ring config account.
The deploy process is expected to stay the same.

Build Ring deposits, transfers, and withdrawals with
`buildRingDepositTransaction`, `buildRingTransferTransaction`, and
`buildRingWithdrawalTransaction`. `RingRpc` reads decrypted Ring transactions
for a granted reader. The same surface is available from
`@heliuslabs/zolana/ring`.

## Public API

Common exports from `@heliuslabs/zolana` include:

- setup: `createZolanaClient`, `ShieldedKeypair`, `Wallet`,
  `KeypairWalletAuthority`;
- transactions: `buildDepositTransaction`, `buildTransferTransaction`,
  `buildWithdrawalTransaction`, `buildSplitTransaction`,
  `buildMergeTransaction`;
- state: `syncWallet`, `getPrivateTokenBalances`, `getPrivateTransactions`,
  `serializeWallet`, `deserializeWallet`;
- registration: `buildRegistrationTransaction`; and
- Rings: `buildRingDepositTransaction`, `buildRingTransferTransaction`,
  `buildRingWithdrawalTransaction`, `listRegisteredRings`, `RingRpc`.

Advanced protocol users can import low-level instruction builders from
`@heliuslabs/zolana/instructions`. PDA helpers are available from
`@heliuslabs/zolana/addresses`; additional typed surfaces are exposed under
`@heliuslabs/zolana/client`, `/interface`, `/keypair`, `/ring`, `/transaction`,
and `/wallet`.

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
