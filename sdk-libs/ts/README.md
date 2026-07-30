# @zolana/sdk

The production TypeScript client for Zolana. It is one npm package built on
`@solana/kit`; protocol modules are exposed as subpath exports rather than
separate packages.

```sh
npm install @zolana/sdk @solana/kit
```

## Client and wallet flow

`ZolanaClient` is the single public client. It routes Solana, indexer, and
proving operations to their respective services; `solanaRpc` and
`solanaRpcSubscriptions` expose the underlying Kit clients only when an
application needs a standard Solana method directly.

```ts
import { airdropFactory, generateKeyPairSigner, lamports } from "@solana/kit";
import {
  LocalWalletAuthority,
  ShieldedKeypair,
  Wallet,
  createZolanaClient,
  deposit,
  registerIfAbsent,
  syncWallet,
  transfer,
} from "@zolana/sdk";

const client = await createZolanaClient({
  solanaRpcUrl: "https://api.devnet.solana.com",
  indexerUrl: "https://indexer.example.com",
  proverUrl: "https://prover.example.com",
});

const funding = await generateKeyPairSigner();
const recipient = await generateKeyPairSigner();
const airdrop = airdropFactory({
  rpc: client.solanaRpc,
  rpcSubscriptions: client.solanaRpcSubscriptions,
});
await Promise.all([
  airdrop({
    commitment: "confirmed",
    recipientAddress: funding.address,
    lamports: lamports(2_000_000_000n),
  }),
  airdrop({
    commitment: "confirmed",
    recipientAddress: recipient.address,
    lamports: lamports(1_000_000_000n),
  }),
]);
const keypair = ShieldedKeypair.generate();
const recipientKeypair = ShieldedKeypair.generate();
const wallet = new Wallet({ identity: keypair.shieldedAddress() });
const authority = new LocalWalletAuthority({
  solanaPublicKey: funding.address,
  keypair,
});

await registerIfAbsent({ client, funding, keypair });
await registerIfAbsent({ client, funding: recipient, keypair: recipientKeypair });
await deposit({
  client,
  feePayer: funding,
  recipient: keypair.shieldedAddress(),
  amount: 100_000_000n,
});
await syncWallet({ client, wallet, authority });

await transfer({
  client,
  wallet,
  authority,
  feePayer: funding,
  recipient: recipient.address,
  amount: 25_000_000n,
});
await syncWallet({ client, wallet, authority });
```

Actions fetch only state they cannot derive locally. For example, transfer
performs one user-record lookup to resolve a recipient; PDA and associated-token
addresses require no RPC call. An unregistered Solana recipient is rejected:
`transfer` never changes a private payment into a public withdrawal. Use the
explicit `withdraw` action for public settlement. Build-only functions remain
available when an application needs custody or approval between construction
and submission.

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

`syncWallet` returns `complete: false` if its configured round bound is reached
while discovery is still advancing; call it again to continue. Use
`serializeWallet` and `deserializeWallet` to persist resumable wallet state.
Serialized state contains private note plaintext and must be encrypted at rest.

## Package subpaths

- `@zolana/sdk` — common client, key material, wallet, and actions
- `@zolana/sdk/instructions` — instruction builders and instruction data types
- `@zolana/sdk/addresses` — PDA and associated-token address helpers
- `@zolana/sdk/client`, `/interface`, `/keypair`, `/transaction`, `/wallet` —
  advanced protocol surfaces

`createZolanaClient` initializes the shipped Poseidon WASM once. Applications
that only use cryptographic primitives can call `initializePoseidon()` directly.
Indexer and prover endpoints must use HTTPS; HTTP is accepted only for loopback
hosts during local development.
