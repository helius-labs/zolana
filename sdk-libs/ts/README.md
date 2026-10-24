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
  LocalKeys,
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
// The wallet's privacy keys, held in this process. A remote key holder
// implements the same `WalletKeys` interface and drops in here.
const keys = LocalKeys.fromKeypair(keypair, client.proofService);

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
  keys,
});

const deposit = await buildDepositTransaction({
  client,
  feePayer: feePayer.address,
  recipient: keypair.shieldedAddress(),
  amount: 100_000_000n,
});
const signature = await submit(deposit, feePayer);
const slot = await client.confirmTransaction(signature);

await syncWallet({
  client,
  wallet,
  keys,
  config: { requireSlot: slot },
});

console.log(wallet.balance(SOL_MINT).amount);
console.log(getPrivateTransactions(wallet));
```

`confirmTransaction` returns the slot the transaction landed in, and
`requireSlot` holds the first indexer read until Photon has that slot. For
direct client calls, `atSlot(slot)` builds the same gate as a per-request
config.

For an Ed25519 spending wallet, the shielded keypair and the Solana signer must use
the same owner seed, as shown above.

Every build and sync takes the wallet's privacy roles as `WalletKeys`: the
wallet derivations (`ShieldedKeys`: `decrypt`, `derive`, `transactionKeys`) and
proving (`ProofAuthority`: `prove`, `proveMerge`). Methods return derived values,
not long-lived secrets, and accept batches so an enclave or hardware wallet can
answer each phase in one round trip. `LocalKeys` provides both roles for keys
held in-process; `LocalKeys.fromDerivationSeed` verifies the wallet signature over
`ed25519DerivationMessage(publicKey)` from `@heliuslabs/zolana/keypair`, where
`publicKey` is the wallet's 32-byte Ed25519 public key. The wallet must sign these
exact off-chain message v0 bytes; signing only `TSPP/derive/v1` or using another
envelope is rejected. A wallet unable to sign these bytes is unsupported for this
derivation. The signature is secret key material. The Solana signature over the
finished transaction remains with the app signer.

### Transaction format

Every builder returns a version 1 transaction, up to 4,096 bytes, which is what
a proof-carrying transfer needs. Version 1 carries the compute unit limit, the
loaded accounts data size limit and the priority fee in the message itself, so a
transaction from this SDK holds no compute budget instruction and no address
lookup table. `ZolanaClientConfig.computeUnitLimit` sets the budget a transact
asks for and `priorityFeeLamports` the fee for the whole transaction, not a
price per compute unit. The RPC and the validator must accept version 1.

### Endpoints

A client needs a
[Helius API key](https://dashboard.helius.dev/).

The Solana RPC, Photon indexer, and prover must target the same devnet release.
The public dashboard reports protocol and service health.

**Devnet:**

| Service    | URL                                                | Notes                                                                                     |
| ---------- | -------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Solana RPC | `https://devnet.helius-rpc.com/?api-key=<API_KEY>` | Helius key. Fund the payer with [devnet SOL](https://www.helius.dev/docs/rpc/devnet-sol). |
| Indexer    | `https://d21d98xh5lgv3b.cloudfront.net`            | Fetches encrypted state.                                                                  |
| Prover     | `https://d1unet9hn0mci0.cloudfront.net`            | Generates ZK proofs in a Nitro Enclave the SDK attests and encrypts every request to.     |
| Dashboard  | `https://djq45ljnl16bl.cloudfront.net`             | Shows public protocol and service health.                                                 |

```ts
const client = await createZolanaClient({
  solanaRpcUrl: `https://devnet.helius-rpc.com/?api-key=${process.env.API_KEY!}`,
  indexerUrl: "https://d21d98xh5lgv3b.cloudfront.net",
  proverUrl: "https://d1unet9hn0mci0.cloudfront.net",
});
```

Every remote prover must attest to `defaultTeePolicy()` before it receives a
witness, and `proverTee` names another policy. A new prover image or key fails
attestation until the client takes the new pins from an SDK release or a
reviewed policy, never from the prover's own answer.

The SDK's default policy pins the indexed `devnet-d-tee-3` enclave measurements and
attested HPKE public key. No `proverTee` policy override is needed for these
endpoints. See the [TEE deployment pin](../../prover/tee/README.md#building-on-it)
for the measured build and verified policy source. Attestation, certificate,
nonce, freshness and HPKE-key verification remain required.

On localnet, start the stack first with `zolana dev start`. The local test
validator (`:8899`), Photon indexer (`:8784`), and prover (`:3001`) then
listen, and the client connects to them automatically without needing
endpoint configuration.

```ts
const client = await createZolanaClient({});
```

The Helius gateway takes client-fetched proof data. Other provers, including
the default Nitro deployment, fetch Merkle data by default. Configure their
`PROVER_INDEXER_URL` for the same network. Set `proofDataSource: "client"` to fetch proof data in
the SDK instead. Both routes support ring transfers, merges and caches.
`LocalKeys` supports both modes. A remote key holder must implement
`IndexedProofAuthority.proveIndexed` for prover fetching. Returned roots
must reproduce the requested public statement before transaction assembly. A
prover started without an indexer refuses these requests with
`CLIENT_PROVER_INDEXER_UNCONFIGURED`.

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

Passing a `ShieldedAddress` skips the lookup.

### Registration

`new Wallet()` builds local state only. The onchain mapping from a Solana
address to a shielded address is a separate signed transaction.

```ts
import { buildRegistrationTransaction } from "@heliuslabs/zolana";

const registration = await buildRegistrationTransaction({
  client,
  owner: feePayer.address,
  address: keypair.shieldedAddress(),
});
if (registration !== undefined) {
  await submit(registration, feePayer);
}
```

`payer` is optional and defaults to `owner`. A sponsor passed as `payer` funds
the record's rent and pays the transaction fee. The owner still signs but needs
no SOL, so the transaction carries two signatures.

`buildRegistrationTransaction` returns `undefined` when that owner is already
registered with the same keys. A recipient that never submitted this
transaction fails a transfer with `WALLET_RECIPIENT_NOT_REGISTERED`.

A registration never replaces keys that are already published. When the owner's
record holds other keys, `buildRegistrationTransaction` rejects with
`WALLET_USER_RECORD_KEYS_MISMATCH`, because payments to that owner would go to
the new keys. `buildKeyUpdateTransaction` takes the same arguments and replaces
the viewing key on purpose. The nullifier key never rotates, so a wallet with
another nullifier key registers under a new owner.

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
  keys,
  feePayer: feePayer.address,
  recipient: recipientSolanaAddress,
  amount: 25_000_000n,
});
const slot = await client.confirmTransaction(await submit(transfer, feePayer));
await syncWallet({ client, wallet, keys, config: { requireSlot: slot } });
```

Pass `asset: mint` for an SPL or Token-2022 balance.

### Several recipients in one transfer

`buildMultiTransferTransaction` pays up to fifteen recipients of one asset in
one private transfer, each as its own output, for example a payment and an
application fee. The approval handler sees a `multiTransfer` intent that lists
the payments in order.

```ts
import { buildMultiTransferTransaction } from "@heliuslabs/zolana";

const transfer = await buildMultiTransferTransaction({
  client,
  wallet,
  keys,
  feePayer: feePayer.address,
  payments: [
    { recipient: merchantSolanaAddress, amount: 25_000_000n },
    { recipient: feeCollectorSolanaAddress, amount: 250_000n },
  ],
});
```

More outputs take a wider proof that accepts fewer UTXOs: two payments spend at
most 24, past which the build fails with `WALLET_TOO_MANY_INPUTS` until the
balance is merged.

### Withdrawal

Withdraw to a public Solana address:

```ts
import { buildWithdrawalTransaction } from "@heliuslabs/zolana";

const withdrawal = await buildWithdrawalTransaction({
  client,
  wallet,
  keys,
  feePayer: feePayer.address,
  recipient: publicRecipient,
  amount: 10_000_000n,
});
const slot = await client.confirmTransaction(await submit(withdrawal, feePayer));
await syncWallet({ client, wallet, keys, config: { requireSlot: slot } });
```

For an SPL withdrawal, pass `asset: mint`. Token-2022 withdrawals also take
`splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID`; the recipient token account is
created idempotently when needed.

### Sponsored fees

`feePayer` on a transfer, withdrawal, or split may be a sponsor other than
the wallet owner. The built transaction then lists the owner as a required
signer, so both keys sign it:

```ts
declare const sponsor: KeyPairSigner;

const sponsored = await buildTransferTransaction({
  client,
  wallet,
  keys,
  feePayer: sponsor.address,
  recipient: recipientSolanaAddress,
  amount: 25_000_000n,
});
const signed = await signTransactionWithSigners([sponsor, feePayer], sponsored);
```

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

`syncPersistedWallet` runs `syncWallet` and, only after the sync commits,
seals the serialized wallet through a `WalletStateCipher` and saves it through
a `WalletStateStore` you provide. `walletSnapshotCipher` is the shipped
cipher, AES-256-GCM keyed from the keypair and bound to the wallet identity
and the snapshot version. Restore from the store on startup so the wallet
resumes from its saved cursors instead of rescanning history:

```ts
import {
  Wallet,
  loadPersistedWallet,
  syncPersistedWallet,
  walletSnapshotCipher,
  type WalletStateStore,
} from "@heliuslabs/zolana";

declare const storage: { get(): Promise<string | undefined>; set(v: string): Promise<void> };

const store: WalletStateStore = {
  load: () => storage.get(),
  save: (snapshot) => storage.set(snapshot),
};
const cipher = walletSnapshotCipher(keypair);

const wallet =
  (await loadPersistedWallet({ store, cipher })) ??
  new Wallet({ identity: keypair.shieldedAddress() });

const { report } = await syncPersistedWallet({ client, wallet, keys, store, cipher });
```

A tampered stored snapshot, or one sealed for another wallet, is refused
with `WALLET_SNAPSHOT` instead of restoring drifted cursors. A failed sync
saves nothing. A failed save rejects with `WALLET_PERSIST`
while the in-memory wallet is already synced and the previously saved
snapshot stays valid, call `syncPersistedWallet` again to retry. That retry
contract requires `save` to replace the stored snapshot atomically or leave
it unchanged, never write it partially. Overlapping calls on one live wallet
run one after the other on the wallet's sync queue, so a slow save cannot
store a stale snapshot. The store is still single-writer across processes,
give each live wallet its own stored snapshot. Snapshots saved before cursors
were serialized still load, the first sync rescans history once and then
saves the current format.

## Public API

Common exports from `@heliuslabs/zolana` include:

- setup: `createZolanaClient`, `ShieldedKeypair`, `Wallet`, `LocalKeys`.
- transactions: `buildDepositTransaction`, `buildTransferTransaction`,
  `buildMultiTransferTransaction`, `buildWithdrawalTransaction`,
  `buildSplitTransaction`, `buildMergeTransaction`.
- state: `syncWallet`, `syncPersistedWallet`, `getPrivateTokenBalances`,
  `getPrivateTransactions`, `serializeWallet`, `deserializeWallet`.
- amounts: `fetchAssetMetadata`, `AssetMetadataCache`, `formatAmount`,
  `parseAmount`.
- registration: `buildRegistrationTransaction`, `buildKeyUpdateTransaction`.

Advanced protocol users can import low-level instruction builders from
`@heliuslabs/zolana/instructions`. PDA helpers are available from
`@heliuslabs/zolana/addresses`; additional typed surfaces are exposed under
`@heliuslabs/zolana/client`, `/interface`, `/keypair`, `/transaction`, and
`/wallet`.

## API reference

The release workflow publishes the generated TypeDoc reference from
`ts-sdk-v*` tags. The tag version must match this package's version. Published
versions are immutable:

- latest: <https://helius-labs.github.io/zolana/ts-sdk/>.
- explicit version:
  <https://helius-labs.github.io/zolana/ts-sdk/v0.1.3-alpha/>.
- version index:
  <https://helius-labs.github.io/zolana/ts-sdk/versions.json>.

GitHub Pages must use GitHub Actions as its source before the first release
workflow runs.

The intended long-term canonical location is
`https://www.helius.dev/privacy/api/`, with immutable versions such as
`https://www.helius.dev/privacy/api/v0.1.3-alpha/`. Migrate only after the Helius
website proxies `/privacy/api/*` to the GitHub Pages `/zolana/ts-sdk/*` origin.
At that point, update the release workflow's `PUBLIC_BASE_URL`; existing GitHub
Pages URLs remain available as the backing origin.

## Important notes

- Ed25519 is the supported owner scheme for registration and private
  transactions. `ShieldedKeypair.generate()` defaults to Ed25519.
- Viewing keys use X25519. P-256-owned notes, registry records, viewing keys
  and wallet snapshots are unsupported.
- Non-loopback indexer and prover URLs must use HTTPS.
- Protect signer seeds and shielded key material. Encrypt serialized wallet
  state and avoid logging private balances, UTXOs, or keys.
