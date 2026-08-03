# @zolana/sdk

The production TypeScript client for Zolana. It is one npm package built on
`@solana/kit`; protocol modules are exposed as subpath exports rather than
separate packages.

```sh
npm install @zolana/sdk @solana/kit
```

## Build, sign, send, sync

`ZolanaClient` owns protocol reads and proving. It does not sign, send, or
confirm Solana transactions. Every transaction builder returns a normal,
unsigned Solana Kit `Transaction`.

```ts
import {
  createKeyPairSignerFromPrivateKeyBytes,
  getSignatureFromTransaction,
  sendAndConfirmTransactionFactory,
  signTransactionWithSigners,
} from "@solana/kit";
import {
  LocalWalletAuthority,
  ShieldedKeypair,
  Wallet,
  buildDepositTransaction,
  buildRegistrationTransaction,
  buildTransferTransaction,
  createZolanaClient,
  syncWallet,
  type Bytes32,
} from "@zolana/sdk";

const client = await createZolanaClient({
  solanaRpcUrl: "https://api.devnet.solana.com",
  indexerUrl: "https://indexer.example.com",
  proverUrl: "https://prover.example.com",
});

declare function loadEd25519Seed(name: string): Promise<Bytes32>;

const fundingSeed = await loadEd25519Seed("funding");
const recipientSeed = await loadEd25519Seed("recipient");
const funding = await createKeyPairSignerFromPrivateKeyBytes(fundingSeed);
const recipient = await createKeyPairSignerFromPrivateKeyBytes(recipientSeed);
const sendAndConfirm = sendAndConfirmTransactionFactory({
  rpc: client.solanaRpc,
  rpcSubscriptions: client.solanaRpcSubscriptions,
});

async function submit(transaction, signers) {
  const signed = await signTransactionWithSigners(signers, transaction);
  await sendAndConfirm(signed, { commitment: "confirmed" });
  return getSignatureFromTransaction(signed);
}

const keypair = ShieldedKeypair.fromEd25519(fundingSeed, 0);
const recipientKeypair = ShieldedKeypair.fromEd25519(recipientSeed, 0);
const wallet = new Wallet({ identity: keypair.shieldedAddress() });
const authority = new LocalWalletAuthority({
  solanaPublicKey: funding.address,
  keypair,
});

const registration = await buildRegistrationTransaction({
  client,
  owner: funding.address,
  address: keypair.shieldedAddress(),
});
if (registration) await submit(registration, [funding]);

const recipientRegistration = await buildRegistrationTransaction({
  client,
  owner: recipient.address,
  address: recipientKeypair.shieldedAddress(),
});
if (recipientRegistration) await submit(recipientRegistration, [recipient]);

const deposit = await buildDepositTransaction({
  client,
  feePayer: funding.address,
  recipient: keypair.shieldedAddress(),
  amount: 100_000_000n,
});
await submit(deposit, [funding]);
await syncWallet({ client, wallet, authority });

const transfer = await buildTransferTransaction({
  client,
  wallet,
  authority,
  feePayer: funding.address,
  recipient: recipient.address,
  amount: 25_000_000n,
});
await submit(transfer, [funding]);
await syncWallet({ client, wallet, authority });
```

The lean SDK supports Ed25519 signing identities for registration and ordinary
transactions. `ShieldedKeypair.generate()` defaults to that rail, but a
registered owner should derive its shielded keypair from the same 32-byte
Ed25519 seed as its Solana signer, as shown above. Viewing keys remain P256.
Explicit `ShieldedKeypair.generate("p256")` remains available for compatibility,
but `buildRegistrationTransaction` rejects it because this SDK does not
construct the required secp256r1 binding proof. Ordinary P256 transact/ring
execution is also unsupported.

There are two separate authorization layers:

1. `buildTransferTransaction`, `buildWithdrawalTransaction`,
   `buildSplitTransaction`, and `buildMergeTransaction` ask the
   `WalletAuthority` for private approval, encrypt outputs, retrieve proofs, and
   assemble the protocol instruction.
2. The application supplies the final Solana signature with ordinary Kit APIs,
   then sends and confirms through its own RPC flow.

After a private transaction lands, call `syncWallet` before building the next
spend. Builders intentionally do not reserve or mark notes as spent. Building
concurrent spends from the same unsynchronized wallet snapshot creates
conflicting transactions; on-chain nullifiers ensure that at most one can land.

Wallet discovery uses two stable tag families: one confidential tag from the
shielded identity signing public key, plus one deposit/bootstrap tag from each
retained viewing public key. For the supported Ed25519 rail, the confidential
tag is the signing public key itself; it is not derived from the Solana fee
payer. Sync also looks up every stored note nullifier, including spent notes, so
transactions submitted by another device can mark local notes spent. A second,
bounded nullifier lookup covers notes first discovered during the same sync.

Call `syncWallet` once when loading persisted wallet state and after each
confirmed transaction. Applications that need unsolicited inbound payments to
appear promptly can add their own polling schedule; the SDK does not start a
background poller.

The public transaction builders are `buildDepositTransaction`,
`buildTransferTransaction`, `buildWithdrawalTransaction`,
`buildSplitTransaction`, and `buildMergeTransaction`. SPL withdrawals include
idempotent recipient ATA creation in the same transaction, including Token-2022
when `splTokenProgram` is supplied.

A transfer performs one user-record lookup when resolving a Solana recipient.
An unregistered Solana recipient is rejected; use
`buildWithdrawalTransaction` for public settlement.

## Instruction builders

Low-level builders follow the Solana program-client naming convention:

```ts
import {
  getCreateTreeInstructionAsync,
  getDepositInstructionAsync,
  getTransactInstruction,
} from "@zolana/sdk/instructions";
```

Builders ending in `Async` derive one or more PDAs. They do not perform network
requests. Signer accounts accept Kit `TransactionSigner` objects, so their
signers are carried into the transaction message automatically; an `Address`
can still be supplied for offline or externally signed flows.

Policy-zone instructions and proving are not exposed by the TypeScript SDK.
Zone metadata is still decoded and persisted for protocol compatibility, while
wallet actions select only unbound notes.

Use `serializeWallet` and `deserializeWallet` to persist resumable wallet state.
Serialized state contains private note plaintext and must be encrypted at rest.

## Package subpaths

- `@zolana/sdk` — common client, key material, wallet, and transaction builders
- `@zolana/sdk/instructions` — instruction builders and instruction data types
- `@zolana/sdk/addresses` — PDA and associated-token address helpers
- `@zolana/sdk/client`, `/interface`, `/keypair`, `/transaction`, `/wallet` —
  advanced protocol surfaces

`createZolanaClient` initializes the dependency-backed Poseidon hasher once.
Applications that only use cryptographic primitives can call
`initializePoseidon()` directly.
Indexer and prover endpoints must use HTTPS; HTTP is accepted only for loopback
hosts during local development.
