# Action and instruction API

This document fixes the callable workflow contract at frozen Rust revision
`43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f` (`43fde8e4`). Package ownership
and names follow [the architecture](architecture-and-api.md) and
[the public export manifest](public-exports.md). Source links refer to the
frozen paths; inspect them with `git show 43fde8e4:<path>`, not from the older
worktree.

## Canonical lifecycle and ownership

Every private spend uses this lifecycle:

```text
create action
  -> unsigned private transaction
  -> authority encryption and approval
  -> proof inputs
  -> Photon Merkle paths
  -> prover result and compressed proof
  -> interface instruction
  -> unsigned native Solana transaction
  -> external signature
  -> RPC submission
  -> on-chain and Photon confirmation
  -> wallet sync
```

`@zolana/wallet` owns intent, input selection, authority calls, action
construction, and sync. `@zolana/transaction` owns deterministic transfer,
encryption-slot, and proof-input math. `@zolana/client` owns Photon/RPC/prover
composition and native transaction assembly. `@zolana/interface` alone owns
instruction accounts and bytes. A native wallet adapter owns the final Solana
signature.

The convenience path `buildPrivateTransaction` collapses authority encryption,
approval, P256 signing when required, Photon proof fetch, witness assembly,
proving, proof compression, `transactInstruction`, blockhash lookup, and native
transaction compilation. It deliberately stops before the native fee-payer
signature. `signPrivateTransaction` includes that signature. Neither submits.
`createDeposit` and `buildDepositTransaction` collapse deposit field derivation
and native transaction compilation but do not sign, submit, confirm, or sync.

The independently usable custody/instruction path retains `prepare`, authority
encryption and approval, `finalize`, Merkle fetch, `assemble`/`intoProver`,
`ProverClient.prove`, `compressProof`, `depositInstruction`/
`transactInstruction`, native compilation, native signing, submission,
confirmation, and decryption. It must not call an action builder in its E2E.

## Canonical declarations

[The public export manifest](public-exports.md) is the sole declaration
allowlist. Workflow snippets import its declarations directly; this document
does not repeat or specialize them. In particular, use:

- [`@zolana/interface`](public-exports.md#zolanainterface) for shared types,
  numeric `InstructionTag`, corrected transact wire types, codecs, and raw
  builders;
- [`@zolana/transaction`](public-exports.md#zolanatransaction) for wallet state,
  spend inputs, transfer preparation, split/merge values, and decryption;
- [`@zolana/client`](public-exports.md#zolanaclient) and
  `@zolana/client/prover` under
  [`@zolana/client`](public-exports.md#zolanaclient) for service
  composition, proof paths, proving, compression, and confirmation;
- [`@zolana/wallet`](public-exports.md#zolanawallet) for authorities, actions,
  submission, ATA creation, sync, balances, and history.

Declaration-equivalence validation compares snippet imports and any annotated
type use to that manifest. A workflow change never creates an implicit export.

## Action flows

### SOL and SPL deposit

Fixture `action-deposit-sol-spl-v1` contains a funded payer/depositor, recipient
wallet, registered SPL mint/interface, depositor ATA, default tree, and isolated
local RPC/Photon services.

```ts
import { SOL_MINT, type Wallet } from "@zolana/transaction";
import type { Address, Signature, Transaction } from "@zolana/interface";
import type { Rpc, ZolanaIndexer } from "@zolana/client";
import {
  buildDepositTransaction,
  createDeposit,
  getPrivateTokenBalances,
  syncWallet,
  type TransactionSigner,
  type WalletAuthority,
} from "@zolana/wallet";

interface DepositFixture {
  rpc: Rpc;
  indexer: ZolanaIndexer;
  recipientWallet: Wallet;
  recipientAuthority: WalletAuthority;
  payer: TransactionSigner;
  depositor: Address;
  tree: Address;
  splMint: Address;
  depositorTokenAccount: Address;
}

function equal(actual: bigint, expected: bigint, label: string): void {
  if (actual !== expected) throw new Error(`${label}: ${actual} !== ${expected}`);
}

async function send(
  rpc: Rpc,
  signer: TransactionSigner,
  transaction: Transaction,
): Promise<Signature> {
  const signed = await signer.signNativeTransaction(transaction);
  const signature = await rpc.sendTransaction(signed);
  if (!(await rpc.confirmTransaction(signature))) {
    throw new Error("deposit was not confirmed on chain");
  }
  return signature;
}

export async function actionDepositSolSpl(f: DepositFixture): Promise<void> {
  if (f.depositor !== f.payer.address) {
    throw new Error("fixture requires one signer as payer and depositor");
  }
  const recipient = await f.recipientAuthority.shieldedAddress();
  const solBefore = f.recipientWallet.balance(SOL_MINT)?.amount ?? 0n;
  const splBefore = f.recipientWallet.balance(f.splMint)?.amount ?? 0n;

  const sol = createDeposit({ recipient, asset: SOL_MINT, amount: 1_000_000n });
  const solNative = await buildDepositTransaction({
    rpc: f.rpc, payer: f.payer.address, tree: f.tree,
    depositor: f.depositor, deposit: sol,
  });
  await send(f.rpc, f.payer, solNative);

  const spl = createDeposit({
    recipient, asset: f.splMint, amount: 25n,
    splTokenAccount: f.depositorTokenAccount,
  });
  const splNative = await buildDepositTransaction({
    rpc: f.rpc, payer: f.payer.address, tree: f.tree,
    depositor: f.depositor, deposit: spl,
  });
  await send(f.rpc, f.payer, splNative);

  await syncWallet({
    wallet: f.recipientWallet, authority: f.recipientAuthority,
    indexer: f.indexer, config: { waitForIndexer: true },
  });
  const balances = getPrivateTokenBalances(f.recipientWallet);
  equal(balances.find((b) => b.mint === SOL_MINT)?.amount ?? 0n, solBefore + 1_000_000n, "SOL");
  equal(balances.find((b) => b.mint === f.splMint)?.amount ?? 0n, splBefore + 25n, "SPL");
}
```

Inputs are public asset/amount, recipient address, tree, payer/depositor, and,
for SPL only, the depositor's source token account. Outputs are an owned
`Deposit`, unsigned native transaction, signature, `SyncReport`, and balance
snapshot. SOL omits `splTokenAccount`; SPL requires it and derives registry,
vault/interface, and token-program accounts. `WalletError` covers asset/source
inconsistency and amount validation, `InterfaceError` covers instruction
layout, and `ClientError` covers blockhash/RPC/indexer failures. The E2E asserts
both exact private deltas and idempotent second sync. Sources:
[`deposit.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/actions/deposit.rs)
and
[`builders/deposit.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/builders/deposit.rs).

### Registered transfer and public fallback

Fixture `action-transfer-routing-v1` has a funded sender wallet, one registered
recipient, one unregistered Solana recipient, and sufficient SOL UTXOs.

```ts
import { SOL_MINT, type Wallet } from "@zolana/transaction";
import type { Address, Transaction } from "@zolana/interface";
import type { Rpc, ZolanaClient } from "@zolana/client";
import {
  buildPrivateTransaction,
  createTransfer,
  syncWallet,
  type CreatedTransfer,
  type TransactionSigner,
  type WalletAuthority,
} from "@zolana/wallet";

interface TransferRoutingFixture {
  rpc: Rpc;
  client: ZolanaClient;
  registeredSenderWallet: Wallet;
  fallbackSenderWallet: Wallet;
  registeredRecipientWallet: Wallet;
  registeredRecipientAuthority: WalletAuthority;
  senderAuthority: WalletAuthority;
  signer: TransactionSigner;
  payer: Address;
  registeredRecipient: Address;
  unregisteredRecipient: Address;
}

function expectKind(
  value: CreatedTransfer,
  kind: CreatedTransfer["recipient"]["kind"],
): void {
  if (value.recipient.kind !== kind) {
    throw new Error(`expected ${kind}, received ${value.recipient.kind}`);
  }
}

async function execute(
  created: CreatedTransfer,
  wallet: Wallet,
  f: TransferRoutingFixture,
): Promise<void> {
  const unsigned: Transaction = await buildPrivateTransaction({
    transaction: created.transaction,
    wallet,
    authority: f.senderAuthority,
    client: f.client,
    feePayer: f.signer.address,
  });
  const signed = await f.signer.signNativeTransaction(unsigned);
  const signature = await f.rpc.sendTransaction(signed);
  await f.client.confirmPrivateTransaction(signature);
}

export async function actionTransferRouting(f: TransferRoutingFixture): Promise<void> {
  if (f.payer !== f.signer.address) {
    throw new Error("fee payer signer does not match private transaction payer");
  }
  const privateBefore =
    f.registeredRecipientWallet.balance(SOL_MINT)?.amount ?? 0n;
  const registered = await createTransfer({
    rpc: f.rpc, wallet: f.registeredSenderWallet, payer: f.payer,
    recipient: f.registeredRecipient, asset: SOL_MINT, amount: 100n,
  });
  expectKind(registered, "registered");
  if (registered.recipient.kind !== "registered") throw new Error("unreachable");
  if (registered.recipient.owner !== f.registeredRecipient) {
    throw new Error("registry owner mismatch");
  }
  await execute(registered, f.registeredSenderWallet, f);
  await syncWallet({
    wallet: f.registeredRecipientWallet,
    authority: f.registeredRecipientAuthority,
    indexer: f.client.indexer,
    config: { waitForIndexer: true },
  });
  const privateAfter =
    f.registeredRecipientWallet.balance(SOL_MINT)?.amount ?? 0n;
  if (privateAfter !== privateBefore + 100n) {
    throw new Error("registered recipient private balance mismatch");
  }

  const publicBefore = await f.rpc.getBalance(f.unregisteredRecipient);
  const fallback = await createTransfer({
    rpc: f.rpc, wallet: f.fallbackSenderWallet, payer: f.payer,
    recipient: f.unregisteredRecipient, asset: SOL_MINT, amount: 50n,
  });
  expectKind(fallback, "publicWithdrawal");
  if (fallback.recipient.kind !== "publicWithdrawal") throw new Error("unreachable");
  if (fallback.recipient.withdrawal.kind !== "sol") {
    throw new Error("unregistered SOL transfer must become SOL withdrawal");
  }
  await execute(fallback, f.fallbackSenderWallet, f);
  const publicAfter = await f.rpc.getBalance(f.unregisteredRecipient);
  if (publicAfter !== publicBefore + 50n) {
    throw new Error("unregistered fallback public balance mismatch");
  }
}
```

`createTransfer` owns registry lookup and input selection. A registered owner
produces a private recipient output. An unregistered owner produces an explicit
`publicWithdrawal` result; callers must not label it private. SPL fallback
instead returns `withdrawal.kind === "spl"` with ATA, vault/interface, CPI
authority, and token program. Typed failures are `WalletError` with nested
`ClientError` for registry/RPC and `TransactionError` for balance, tree, and
shape. The E2E submits each result independently: the registered recipient
decrypts the exact amount; the unregistered recipient's public SOL/SPL balance
increases and no recipient private UTXO appears. Source:
[`actions/transaction.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/actions/transaction.rs).

### SOL/SPL withdrawal, external custody, and authority signing

Fixture `action-withdraw-custody-v1` contains funded private SOL/SPL balances,
recipient SOL and ATA balances, a `LocalWalletAuthority`, and a separate
external `TransactionSigner`.

```ts
import { SOL_MINT, type Wallet } from "@zolana/transaction";
import type { Address, Signature, Transaction } from "@zolana/interface";
import type { ZolanaClient } from "@zolana/client";
import {
  buildPrivateTransaction,
  createWithdrawal,
  signPrivateTransaction,
  type LocalWalletAuthority,
  type TransactionSigner,
} from "@zolana/wallet";

interface WithdrawalFixture {
  client: ZolanaClient;
  wallet: Wallet;
  authority: LocalWalletAuthority;
  externalSigner: TransactionSigner;
  payer: Address;
  recipient: Address;
  splMint: Address;
}

async function submit(
  client: ZolanaClient,
  signed: Transaction,
): Promise<Signature> {
  const signature = await client.rpc.sendTransaction(signed);
  await client.confirmPrivateTransaction(signature);
  return signature;
}

export async function actionWithdrawSolSpl(f: WithdrawalFixture): Promise<void> {
  if (f.payer !== f.externalSigner.address) {
    throw new Error("fee payer signer does not match private transaction payer");
  }
  const sol = createWithdrawal({
    wallet: f.wallet, payer: f.payer, recipient: f.recipient,
    asset: SOL_MINT, amount: 10_000n,
  });
  if (sol.withdrawal.kind !== "sol") throw new Error("expected SOL accounts");

  const unsignedNative = await buildPrivateTransaction({
    transaction: sol.transaction, wallet: f.wallet,
    authority: f.authority, client: f.client, feePayer: f.externalSigner.address,
  });
  const externallySigned = await f.externalSigner.signNativeTransaction(unsignedNative);
  await submit(f.client, externallySigned);

  const spl = createWithdrawal({
    wallet: f.wallet, payer: f.payer, recipient: f.recipient,
    asset: f.splMint, amount: 7n,
  });
  if (spl.withdrawal.kind !== "spl") throw new Error("expected SPL accounts");

  const locallySigned = await signPrivateTransaction({
    transaction: spl.transaction, wallet: f.wallet,
    authority: f.authority, client: f.client, feePayer: f.externalSigner,
  });
  await submit(f.client, locallySigned);
}
```

`buildPrivateTransaction` returns an unsigned native transaction after shielded
authorization/proving and is the HSM/custodian boundary.
`signPrivateTransaction` invokes the supplied native signer as a convenience.
`WalletAuthority` owns shielded encryption, approval, and P256 signing;
`TransactionSigner` owns only the native Solana signature. SOL settlement uses
the SOL interface, recipient, and system program. SPL settlement uses the CPI
authority, SPL vault/interface, recipient owner, recipient ATA, and token
program. The E2E records external balances first, then asserts exact recipient
SOL and ATA increases, exact private decreases, one history row per withdrawal,
and idempotent confirmation. Typed failures are `WalletError`,
`TransactionError`, `KeypairError`, and `ClientError` according to the failing
stage. Sources:
[`actions/transaction.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/actions/transaction.rs),
[`wallet/authority.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/wallet/authority.rs),
and
[`client.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/client.rs).

### Submission, confirmation, sync, balances, and history

Fixture `action-confirm-sync-v1` contains one already built and natively signed
private transaction plus the corresponding wallet and authority.

```ts
import type {
  AssetBalance, PrivateTransaction, SyncReport, Wallet,
} from "@zolana/transaction";
import type { Signature, Transaction } from "@zolana/interface";
import type { ZolanaClient } from "@zolana/client";
import {
  getPrivateTokenBalances,
  getPrivateTransactions,
  syncWallet,
  type WalletAuthority,
} from "@zolana/wallet";

interface ConfirmFixture {
  client: ZolanaClient;
  wallet: Wallet;
  authority: WalletAuthority;
  signedNativeTransaction: Transaction;
}
interface ConfirmResult {
  signature: Signature;
  report: SyncReport;
  balances: readonly AssetBalance[];
  history: readonly PrivateTransaction[];
}

export async function actionConfirmSync(f: ConfirmFixture): Promise<ConfirmResult> {
  const signature = await f.client.rpc.sendTransaction(f.signedNativeTransaction);
  await f.client.confirmPrivateTransaction(signature);
  const report = await syncWallet({
    wallet: f.wallet, authority: f.authority, indexer: f.client.indexer,
    config: { waitForIndexer: true },
  });
  const balances = getPrivateTokenBalances(f.wallet);
  const history = getPrivateTransactions(f.wallet);
  if (!history.some((entry) => entry.id.signature === signature)) {
    throw new Error("submitted signature missing from private history");
  }
  return { signature, report, balances, history };
}
```

`Rpc.sendTransaction` yields the signature. `confirmPrivateTransaction` first
waits for Solana, extracts output view tags from that signature, then waits for
Photon to index the same signature/tag set. `syncWallet` mutates only wallet
state and returns a report; balance/history helpers return snapshots. The E2E
runs sync twice and asserts unchanged balances/history on the second run.
`ClientError` owns submission, confirmation, timeout, and indexer lag;
`WalletError` owns sync orchestration and preserves nested
`TransactionError`. Sources:
[`client.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/client.rs)
and
[`wallet_sync.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/wallet_sync.rs).

## Additional wallet acceptance contracts

These scenarios extend current wallet acceptance. They do not add upstream
example rows and do not prescribe implementation examples.

### Split creation

- **Imports:** `createSplit`, `SplitParams`, `CreatedSplit`,
  `buildPrivateTransaction`, and `signPrivateTransaction` from
  `@zolana/wallet`; `Wallet` from `@zolana/transaction`.
- **Stages and ownership:** `@zolana/wallet` validates `parts`, resolves one
  spend tree, selects one plain UTXO or the named commitment, and returns an
  `UnsignedPrivateTransaction`. Existing wallet/client custody stages then
  authorize, prove, sign, submit, confirm, and sync it.
- **Success:** fixture `action-split-v1` splits one plain divisible UTXO into
  `2..=8` equal outputs; assert `numOutputs`, `perOutputAmount`, unchanged total
  private balance, one spent input, exact output count, and one split history
  row after idempotent sync.
- **Negative:** reject an out-of-range part count, non-divisible amount,
  unavailable/spent or wrong-tree named input, and any input with zone or
  application data using stable `WalletError`/`TransactionError` codes.

Canonical exports are under
[`@zolana/wallet`](public-exports.md#zolanawallet). Frozen behavior:
[`actions/transaction.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/actions/transaction.rs).

### Merge creation

- **Imports:** `createMerge`, `MergeParams`, and `CreatedMerge` from
  `@zolana/wallet`; `Wallet` and `PreparedMerge` from
  `@zolana/transaction`; `ShieldedKeypair` from `@zolana/keypair`.
- **Stages and ownership:** `@zolana/wallet` selects two to eight plain,
  same-owner, same-asset inputs on one tree. `@zolana/transaction` prepares one
  merged output and retains the sensitive merge witness boundary. No
  `UnsignedPrivateTransaction` or authority approval stage is created.
- **Success:** fixture `action-merge-create-v1` asserts `numInputs`,
  `mergedAmount` equals the checked sum, `tree` matches every input, and the
  prepared output has the same asset and amount. Auto-selection consumes the
  smallest eligible UTXOs first.
- **Negative:** reject fewer than two or more than eight explicit inputs,
  duplicates, spent/unavailable/wrong-tree inputs, mixed owner/asset, attached
  data or zone binding, and amount overflow before proving.

Canonical exports are under
[`@zolana/wallet`](public-exports.md#zolanawallet) and
[`@zolana/transaction`](public-exports.md#zolanatransaction). Frozen behavior:
[`actions/transaction.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/actions/transaction.rs).

### Merge submission

- **Imports:** `MergeMaterial`, `SubmitMergeTransaction`, `SubmittedMerge`, and
  `submitMergeTransaction` from `@zolana/wallet`; `Rpc` and `ZolanaClient` from
  `@zolana/client`; `TransactionSigner` from `@zolana/wallet`.
- **Adapter contract:** `SubmitMergeTransaction.indexer` remains typed as
  `Rpc`, matching frozen Rust. The supplied value must implement
  `Rpc.getInputMerkleProofs`; a bare `ZolanaIndexer` is not sufficient.
  Normally one `ZolanaClient` instance is supplied as both `rpc` and `indexer`.
- **Stages and ownership:** `@zolana/wallet` validates the owner's registry
  opt-in and signing/nullifier/viewing identity, calls
  `indexer.getInputMerkleProofs` for the paired inclusion and non-inclusion
  proof of every input, checks every proof tree, builds/proves/compresses the
  merge, delegates final native signing to `TransactionSigner`, submits, and
  returns `{ signature, outputHash }`. The caller waits for `outputHash`
  indexing and syncs; merge does not use transfer tag confirmation.
- **Success:** fixture `action-merge-submit-v1` asserts one
  `mergeTransact` instruction with numeric tag `12`, compute-unit budget,
  confirmed signature, indexed `outputHash`, one merged private UTXO, all
  source nullifiers spent, unchanged total amount, and one merge history row.
- **Negative:** reject disabled merging, signing/viewing/nullifier identity
  mismatch, proof tree mismatch, malformed proof, wrong payer signature, and
  prover/RPC/indexer failure before reporting success.

Canonical exports are under
[`@zolana/wallet`](public-exports.md#zolanawallet). Frozen behavior:
[`actions/submit.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/actions/submit.rs)
and
[`merge_transact.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/builders/merge_transact.rs).

### Idempotent associated-token-account creation

- **Imports:** `createAssociatedTokenAccount` and `TransactionSigner` from
  `@zolana/wallet`; `Rpc` from `@zolana/client`.
- **Stages and ownership:** `@zolana/wallet` derives the canonical ATA, builds
  the SPL associated-token program's idempotent instruction, obtains a
  blockhash through `Rpc`, delegates the payer signature, submits, and returns
  `{ signature, address }`. It performs no preflight existence branch.
- **Success:** fixture `action-ata-idempotent-v1` calls the action twice for the
  same owner/mint. Both calls succeed, both return the same canonical address,
  the account exists after each call, and the instruction discriminator is
  SPL ATA `CreateIdempotent` value `1`.
- **Negative:** reject invalid addresses before I/O and report signer/RPC
  failures through `WalletError` with the underlying cause; never translate an
  already-existing ATA into an error.

Canonical exports are under
[`@zolana/wallet`](public-exports.md#zolanawallet). Frozen behavior:
[`create_associated_token_account.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/actions/create_associated_token_account.rs).

## Instruction support used by every raw spend

The instruction fixtures provide an explicit native adapter because Solana
message compilation and wallet-specific signing do not belong to Zolana's raw
interface package.

```ts
import type {
  Address, Instruction, Signature, Transaction,
} from "@zolana/interface";
import type {
  MerkleProof, NonInclusionProof, ZolanaClient, ZolanaIndexer,
} from "@zolana/client";
import type { ProverClient, SpendProof } from "@zolana/client/prover";
import type { TransactionSigner, WalletAuthority } from "@zolana/wallet";
import type { AssetRegistry, PreparedTransfer, SppProofInputs } from "@zolana/transaction";

export interface NativeTransactionAdapter {
  compile(input: Readonly<{
    feePayer: Address;
    recentBlockhash: string;
    instructions: readonly Instruction[];
  }>): Transaction;
}
export interface InstructionSpendContext {
  client: ZolanaClient;
  prover: ProverClient;
  indexer: ZolanaIndexer;
  authority: WalletAuthority;
  assets: AssetRegistry;
  native: NativeTransactionAdapter;
  feePayer: TransactionSigner;
}

export async function authorizePrepared(
  prepared: PreparedTransfer,
  context: InstructionSpendContext,
  summary: string,
): Promise<SppProofInputs> {
  const encrypted = await context.authority.encryptConfidentialTransfer({
    firstNullifier: prepared.firstNullifier,
    outputs: prepared.outputs,
    assets: context.assets,
  });
  await context.authority.requestUserApproval({
    solanaPublicKey: context.authority.solanaPublicKey(),
    summary,
  });
  const proofInputs = prepared.finalize({
    txViewingPublicKey: encrypted.txViewingPublicKey,
    salt: encrypted.salt,
    payload: encrypted.payload,
  });
  if (prepared.owner.signingPublicKey.signatureType() === "p256") {
    proofInputs.applyP256Signature(
      await context.authority.signP256(proofInputs.messageHash()),
    );
  }
  return proofInputs;
}

function inclusion(value: MerkleProof): SpendProof["state"] {
  return {
    leaf: value.leaf,
    merkleContext: value.merkleContext,
    root: value.root,
    rootSeq: value.rootSeq,
    rootIndex: value.rootIndex,
    path: value.path,
    leafIndex: value.leafIndex,
  };
}
function nonInclusion(
  value: NonInclusionProof,
): SpendProof["nullifier"] {
  return {
    leaf: value.leaf,
    merkleContext: value.merkleContext,
    root: value.root,
    rootSeq: value.rootSeq,
    rootIndex: value.rootIndex,
    path: value.path,
    leafIndex: value.leafIndex,
    lowElement: value.lowElement,
    lowElementIndex: value.lowElementIndex,
    highElement: value.highElement,
    highElementIndex: value.highElementIndex,
  };
}

export async function fetchSpendProofs(
  proofInputs: SppProofInputs,
  tree: Address,
  indexer: ZolanaIndexer,
): Promise<readonly SpendProof[]> {
  const leaves = proofInputs.inputUtxoHashes();
  const state = await indexer.getMerkleProofs(tree, leaves);
  const nullifiers = proofInputs.inputUtxos.map((input) => input.nullifier());
  const absent = await indexer.getNonInclusionProofs(tree, nullifiers);
  if (state.proofs.length !== leaves.length || absent.proofs.length !== leaves.length) {
    throw new Error("Photon returned an incomplete spend-proof set");
  }
  return state.proofs.map((proof, index) => ({
    state: inclusion(proof),
    nullifier: nonInclusion(absent.proofs[index]!),
  }));
}

export async function signSendConfirm(
  instruction: Instruction,
  context: InstructionSpendContext,
): Promise<Signature> {
  const { blockhash } = await context.client.rpc.getLatestBlockhash();
  const unsigned = context.native.compile({
    feePayer: context.feePayer.address,
    recentBlockhash: blockhash,
    instructions: [instruction],
  });
  const signed = await context.feePayer.signNativeTransaction(unsigned);
  const signature = await context.client.rpc.sendTransaction(signed);
  await context.client.confirmPrivateTransaction(signature);
  return signature;
}
```

The `@zolana/client` proof RPC uses `Bytes32` leaves and returns byte-valued
proofs directly; this raw workflow performs no base58 conversion.

## Instruction wire and tag contract

The canonical numeric map and wire declarations are in
[`@zolana/interface`](public-exports.md#zolanainterface):

- `InstructionTag.deposit === 1`; `depositInstructionDataCodec` encodes exactly
  `viewTag`, `owner`, 31-byte `blinding`, `u64` amount, optional UTXO data, and
  optional memo.
- `InstructionTag.transact === 0`; `TransactInstructionData.inputs` use all
  five `InputUtxo` fields: `nullifierHash`, nullifier and UTXO root indexes,
  tree index, and EdDSA signer index.
- Every output carries `utxoHash`, an `OwnerTag` discriminant
  (`inline`, `account`, or `p256SigningKey`), and optional data.
- `relayerFee` is validated `u16` represented as `number`. P256 proof
  `commitment` and `commitmentPok` are compressed `Bytes32`; EdDSA has neither.
  `txViewingPk` is `Bytes33`, and `salt` is `Bytes16`.
- `transactInstruction` appends SOL accounts only for public SOL movement and
  SPL accounts only for public SPL movement. Its `withdrawal` discriminant and
  signed public amount must agree.

Instruction conformance must compare the codec's first byte, complete payload,
account metas, and program address against frozen Rust vectors for deposit,
private transfer, SOL withdrawal, and SPL withdrawal. The snippets consume
`assemble(...).withProof(...)`, so they do not reconstruct any transact field
or proof tag.

Frozen wire sources:
[`event/src/tag.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/event/src/tag.rs),
[`instruction_data/deposit.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/instruction_data/deposit.rs),
[`instruction_data/transact.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/instruction_data/transact.rs),
and
[`builders/transact.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/builders/transact.rs).

## Instruction flows

### Deposit instruction

Fixture `instruction-deposit-sol-spl-v1` supplies a recipient, payer/depositor,
tree, SPL source ATA and vault/interface/registry addresses, and the native
adapter.

```ts
import {
  InstructionTag,
  type Address, type DepositSplAccounts, type Instruction,
  type Signature, type Transaction,
} from "@zolana/interface";
import { depositInstruction } from "@zolana/interface/instructions";
import {
  ownerUtxoHash, SOL_MINT, type Wallet,
} from "@zolana/transaction";
import {
  randomBlinding, type ShieldedAddress,
} from "@zolana/keypair";
import type { Rpc, ZolanaIndexer } from "@zolana/client";
import {
  syncWallet, type TransactionSigner, type WalletAuthority,
} from "@zolana/wallet";

interface DepositInstructionFixture {
  rpc: Rpc;
  native: Readonly<{
    compile(input: Readonly<{
      feePayer: Address; recentBlockhash: string;
      instructions: readonly Instruction[];
    }>): Transaction;
  }>;
  signer: TransactionSigner;
  indexer: ZolanaIndexer;
  recipientWallet: Wallet;
  recipientAuthority: WalletAuthority;
  recipient: ShieldedAddress;
  tree: Address;
  depositor: Address;
  splMint: Address;
  spl: DepositSplAccounts;
  tokenBalance(account: Address): Promise<bigint>;
}

async function submitDeposit(
  fixture: DepositInstructionFixture,
  instruction: Instruction,
): Promise<Signature> {
  const { blockhash } = await fixture.rpc.getLatestBlockhash();
  const unsigned = fixture.native.compile({
    feePayer: fixture.signer.address,
    recentBlockhash: blockhash,
    instructions: [instruction],
  });
  const signed = await fixture.signer.signNativeTransaction(unsigned);
  const signature = await fixture.rpc.sendTransaction(signed);
  if (!(await fixture.rpc.confirmTransaction(signature))) {
    throw new Error("deposit instruction was not confirmed");
  }
  return signature;
}

export async function instructionDeposit(f: DepositInstructionFixture): Promise<void> {
  if (f.depositor !== f.signer.address) {
    throw new Error("fixture requires one signer as fee payer and depositor");
  }
  const owner = f.recipient.ownerHash();
  const viewTag = f.recipient.viewingPublicKey.x();
  const privateSolBefore = f.recipientWallet.balance(SOL_MINT)?.amount ?? 0n;
  const privateSplBefore =
    f.recipientWallet.balance(f.splMint)?.amount ?? 0n;
  const publicSplBefore = await f.tokenBalance(f.spl.userToken);
  const vaultSplBefore = await f.tokenBalance(f.spl.splTokenInterface);

  const solBlinding = randomBlinding();
  const solAmount = 1_000_000n;
  const solHash = ownerUtxoHash({
    owner, asset: SOL_MINT, amount: solAmount, blinding: solBlinding,
  });
  const sol = depositInstruction({
    tree: f.tree, depositor: f.depositor,
    data: { viewTag, owner, blinding: solBlinding, amount: solAmount },
  });
  if (sol.data[0] !== InstructionTag.deposit) {
    throw new Error("deposit instruction tag mismatch");
  }
  await submitDeposit(f, sol);

  const splBlinding = randomBlinding();
  const splAmount = 11n;
  const splHash = ownerUtxoHash({
    owner, asset: f.splMint, amount: splAmount, blinding: splBlinding,
  });
  const spl = depositInstruction({
    tree: f.tree, depositor: f.depositor, spl: f.spl,
    data: { viewTag, owner, blinding: splBlinding, amount: splAmount },
  });
  if (spl.data[0] !== InstructionTag.deposit) {
    throw new Error("SPL deposit instruction tag mismatch");
  }
  await submitDeposit(f, spl);

  await syncWallet({
    wallet: f.recipientWallet,
    authority: f.recipientAuthority,
    indexer: f.indexer,
    config: { waitForIndexer: true },
  });
  const privateSolAfter = f.recipientWallet.balance(SOL_MINT)?.amount ?? 0n;
  const privateSplAfter = f.recipientWallet.balance(f.splMint)?.amount ?? 0n;
  const publicSplAfter = await f.tokenBalance(f.spl.userToken);
  const vaultSplAfter = await f.tokenBalance(f.spl.splTokenInterface);
  if (privateSolAfter !== privateSolBefore + solAmount) {
    throw new Error("raw SOL deposit did not decrypt to the exact amount");
  }
  if (privateSplAfter !== privateSplBefore + splAmount) {
    throw new Error("raw SPL deposit did not decrypt to the exact amount");
  }
  if (publicSplAfter !== publicSplBefore - splAmount) {
    throw new Error("raw SPL deposit source delta mismatch");
  }
  if (vaultSplAfter !== vaultSplBefore + splAmount) {
    throw new Error("raw SPL deposit vault delta mismatch");
  }
  if (solHash.length !== 32 || splHash.length !== 32 || viewTag.length !== 32) {
    throw new Error("invalid deposit commitment or indexing view tag");
  }
}
```

Field outputs are `owner_hash`, fresh 31-byte blinding, commitment hash, and
the recipient bootstrap view tag (the viewing-key x-coordinate). SOL accounts
are tree, signing depositor, zero user-token placeholder, canonical SOL
interface, writable depositor, and program. SPL accounts replace the SOL
settlement triplet with source token account, SPL vault/interface, registry,
and token program. `InterfaceError`, `TransactionError`, `KeypairError`, and
`ClientError` identify derivation, codec, signing, and RPC stages. The E2E
compares exact bytes/accounts with Rust V, queries Photon by `viewTag`, decrypts
the output, and asserts SOL or SPL private amount plus public custody deltas.
Sources:
[`instruction_data/deposit.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/instruction_data/deposit.rs)
and
[`builders/deposit.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/builders/deposit.rs).

### Registered confidential transfer instruction

Fixture `instruction-transfer-registered-v1` supplies sender wallet UTXOs,
sender/recipient addresses, the authority, registry, tree, and service
adapters. The instruction test never calls `createTransfer`,
`buildPrivateTransaction`, or `signPrivateTransaction`.

```ts
import {
  InstructionTag, type Address,
} from "@zolana/interface";
import { transactInstruction } from "@zolana/interface/instructions";
import {
  ConfidentialTransfer, ProofInputUtxo, SOL_MINT, decryptTransactions,
  type Wallet,
} from "@zolana/transaction";
import {
  assemble, compressProof,
  type ProverInputs, type SpendProof,
} from "@zolana/client/prover";
import { hash } from "@zolana/indexer-api";
import type { ShieldedAddress } from "@zolana/keypair";
import {
  authorizePrepared, fetchSpendProofs, signSendConfirm,
  type InstructionSpendContext,
} from "./instruction-fixture.js";
import type { WalletAuthority } from "@zolana/wallet";

interface TransferInstructionFixture extends InstructionSpendContext {
  senderWallet: Wallet;
  recipientWallet: Wallet;
  recipientAuthority: WalletAuthority;
  sender: ShieldedAddress;
  recipient: ShieldedAddress;
  payer: Address;
  tree: Address;
}

function selectSpends(
  wallet: Wallet,
  tree: Address,
  asset: Address,
  amount: bigint,
  nullifierKey: ProofInputUtxo["nullifierKey"],
): readonly ProofInputUtxo[] {
  const selected: ProofInputUtxo[] = [];
  let total = 0n;
  for (const entry of wallet.utxos()) {
    if (
      entry.spent ||
      entry.outputContext.tree !== tree ||
      entry.utxo.asset !== asset
    ) continue;
    selected.push(new ProofInputUtxo({
      utxo: entry.utxo, nullifierKey,
      dataHash: entry.dataHash, zoneDataHash: entry.zoneDataHash,
    }));
    total += entry.utxo.amount;
    if (total >= amount) return selected;
  }
  throw new Error(`insufficient private balance: ${total} < ${amount}`);
}

export async function instructionTransfer(
  f: TransferInstructionFixture,
): Promise<void> {
  const senderBefore = f.senderWallet.balance(SOL_MINT)?.amount ?? 0n;
  const recipientBefore =
    f.recipientWallet.balance(SOL_MINT)?.amount ?? 0n;
  const nullifierKey = await f.authority.spendNullifierKey();
  const spends = selectSpends(
    f.senderWallet, f.tree, SOL_MINT, 100n, nullifierKey,
  );
  const transfer = new ConfidentialTransfer(f.sender, spends, f.payer);
  transfer.send(f.recipient, SOL_MINT, 100n);
  const prepared = transfer.prepare();
  const proofInputs = await authorizePrepared(prepared, f, "transfer 100 private SOL");
  const spendProofs: readonly SpendProof[] =
    await fetchSpendProofs(proofInputs, f.tree, f.indexer);

  const assembled = assemble(proofInputs, spendProofs);
  const proverInput: ProverInputs = assembled.proverInputs;
  const proof = await f.prover.prove(proverInput);
  const compressed = compressProof(proof);
  const data = assembled.withProof(compressed.toTransactProof());
  const instruction = transactInstruction({
    payer: f.payer, tree: f.tree, data,
  });
  if (instruction.data[0] !== InstructionTag.transact) {
    throw new Error("transfer instruction tag mismatch");
  }
  const signature = await signSendConfirm(instruction, f);

  const indexed = await f.indexer.getShieldedTransactionsByTags({
    tags: [hash(
      f.recipient.signingPublicKey.confidentialViewTag(),
    )],
  });
  const matching = indexed.transactions.filter((tx) => tx.txSignature === signature);
  const senderIndexed = await f.indexer.getShieldedTransactionsByTags({
    tags: [hash(
      f.sender.signingPublicKey.confidentialViewTag(),
    )],
  });
  const senderMatching =
    senderIndexed.transactions.filter((tx) => tx.txSignature === signature);
  await decryptTransactions({
    wallet: f.recipientWallet,
    authority: f.recipientAuthority,
    transactions: matching,
  });
  await decryptTransactions({
    wallet: f.senderWallet,
    authority: f.authority,
    transactions: senderMatching,
  });
  if (matching.length !== 1) throw new Error("recipient output was not indexed once");
  const recipientAfter =
    f.recipientWallet.balance(SOL_MINT)?.amount ?? 0n;
  if (recipientAfter !== recipientBefore + 100n) {
    throw new Error("recipient did not decrypt the exact transfer amount");
  }
  const senderAfter = f.senderWallet.balance(SOL_MINT)?.amount ?? 0n;
  if (senderAfter !== senderBefore - 100n) {
    throw new Error("sender change did not preserve the exact balance");
  }
}
```

The fixture module import denotes the complete support declarations in
[Instruction support used by every raw spend](#instruction-support-used-by-every-raw-spend);
it is test infrastructure, not an SDK helper. Selection preserves data and zone
hashes while converting readonly `WalletUtxo` values to `ProofInputUtxo`.
`prepare` adds sender change, recipient output, dummy padding, shape, and public
amounts. The authority encrypts each real slot, approves, and signs only the
P256 rail. Photon returns inclusion and nullifier non-inclusion paths in input
order. `assemble` produces both identical witness commitments and proofless
instruction data; the prover result is compressed once before
`transactInstruction`.

The E2E asserts proof verification, inserted nullifiers, appended outputs,
exact recipient amount, exact sender change, recipient decryption, and
byte/account parity with Rust V. `TransactionError` covers selection, balance,
shape, encryption, and proof-input invariants; `ClientError` covers proof
fetch/order, prover, compression, native assembly, confirmation, and Photon;
`InterfaceError` covers final accounts/bytes. Sources:
[`transfer.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/instructions/transact/transfer.rs),
[`slots.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/instructions/transact/slots.rs),
[`spp_proof_inputs.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs),
[`witness.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/prover/transact/witness.rs),
and
[`builders/transact.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/builders/transact.rs).

### SOL withdrawal instruction

Fixture `instruction-withdraw-sol-v1` uses the same independent spend/prove
support and records the recipient lamports before submission.

```ts
import {
  InstructionTag, type Address,
} from "@zolana/interface";
import { transactInstruction } from "@zolana/interface/instructions";
import {
  ConfidentialTransfer, SOL_MINT,
  type ProofInputUtxo, type Wallet, type WithdrawalTarget,
} from "@zolana/transaction";
import { assemble, compressProof } from "@zolana/client/prover";
import {
  authorizePrepared, fetchSpendProofs, signSendConfirm,
  type InstructionSpendContext,
} from "./instruction-fixture.js";

interface SolWithdrawalFixture extends InstructionSpendContext {
  wallet: Wallet;
  owner: Awaited<ReturnType<InstructionSpendContext["authority"]["shieldedAddress"]>>;
  payer: Address;
  tree: Address;
  recipient: Address;
  solInterface: Address;
  amount: bigint;
  spends: readonly ProofInputUtxo[];
}

export async function instructionWithdrawSol(f: SolWithdrawalFixture): Promise<void> {
  const before = await f.client.rpc.getBalance(f.recipient);
  const custodyBefore = await f.client.rpc.getBalance(f.solInterface);
  const target: WithdrawalTarget = { kind: "sol", recipient: f.recipient };
  const transfer = new ConfidentialTransfer(f.owner, f.spends, f.payer);
  transfer.withdraw(SOL_MINT, f.amount, target);
  const prepared = transfer.prepare();
  const proofInputs = await authorizePrepared(prepared, f, `withdraw ${f.amount} SOL`);
  const paths = await fetchSpendProofs(proofInputs, f.tree, f.indexer);
  const assembled = assemble(proofInputs, paths);
  const compressed = compressProof(await f.prover.prove(assembled.proverInputs));
  const instruction = transactInstruction({
    payer: f.payer, tree: f.tree,
    withdrawal: { kind: "sol", recipient: f.recipient },
    data: assembled.withProof(compressed.toTransactProof()),
  });
  if (instruction.data[0] !== InstructionTag.transact) {
    throw new Error("SOL withdrawal instruction tag mismatch");
  }
  await signSendConfirm(instruction, f);
  const after = await f.client.rpc.getBalance(f.recipient);
  const custodyAfter = await f.client.rpc.getBalance(f.solInterface);
  if (after !== before + f.amount) {
    throw new Error(`SOL withdrawal delta ${after - before} !== ${f.amount}`);
  }
  if (custodyAfter !== custodyBefore - f.amount) {
    throw new Error("SOL interface custody delta mismatch");
  }
}
```

The public SOL amount is negative in proof inputs. The exact settlement suffix
is writable SOL interface, writable recipient, readonly system program, then
the program account. The E2E also asserts private sender decrease/change,
nullifier insertion, proof/instruction vector parity, and rejection when
withdrawal data and accounts disagree. Error ownership matches the transfer
flow. Source:
[`builders/transact.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/builders/transact.rs).

### SPL withdrawal instruction

Fixture `instruction-withdraw-spl-v1` records the recipient ATA amount and
supplies canonical CPI authority, vault/interface, ATA, and token program.

```ts
import {
  InstructionTag,
  type Address, type TransactWithdrawal,
} from "@zolana/interface";
import { transactInstruction } from "@zolana/interface/instructions";
import {
  ConfidentialTransfer,
  type ProofInputUtxo, type Wallet, type WithdrawalTarget,
} from "@zolana/transaction";
import { assemble, compressProof } from "@zolana/client/prover";
import {
  authorizePrepared, fetchSpendProofs, signSendConfirm,
  type InstructionSpendContext,
} from "./instruction-fixture.js";

interface SplWithdrawalFixture extends InstructionSpendContext {
  wallet: Wallet;
  owner: Awaited<ReturnType<InstructionSpendContext["authority"]["shieldedAddress"]>>;
  payer: Address;
  tree: Address;
  mint: Address;
  recipient: Address;
  recipientTokenAccount: Address;
  splTokenInterface: Address;
  cpiAuthority: Address;
  tokenProgram: Address;
  amount: bigint;
  spends: readonly ProofInputUtxo[];
  tokenBalance(account: Address): Promise<bigint>;
}

export async function instructionWithdrawSpl(f: SplWithdrawalFixture): Promise<void> {
  const before = await f.tokenBalance(f.recipientTokenAccount);
  const vaultBefore = await f.tokenBalance(f.splTokenInterface);
  const target: WithdrawalTarget = {
    kind: "spl",
    userTokenAccount: f.recipientTokenAccount,
    splTokenInterface: f.splTokenInterface,
  };
  const accounts: TransactWithdrawal = {
    kind: "spl", cpiAuthority: f.cpiAuthority,
    splTokenInterface: f.splTokenInterface, recipient: f.recipient,
    userTokenAccount: f.recipientTokenAccount, tokenProgram: f.tokenProgram,
  };
  const transfer = new ConfidentialTransfer(f.owner, f.spends, f.payer);
  transfer.withdraw(f.mint, f.amount, target);
  const prepared = transfer.prepare();
  const proofInputs = await authorizePrepared(prepared, f, `withdraw ${f.amount} SPL`);
  const paths = await fetchSpendProofs(proofInputs, f.tree, f.indexer);
  const assembled = assemble(proofInputs, paths);
  const compressed = compressProof(await f.prover.prove(assembled.proverInputs));
  const instruction = transactInstruction({
    payer: f.payer, tree: f.tree, withdrawal: accounts,
    data: assembled.withProof(compressed.toTransactProof()),
  });
  if (instruction.data[0] !== InstructionTag.transact) {
    throw new Error("SPL withdrawal instruction tag mismatch");
  }
  await signSendConfirm(instruction, f);
  const after = await f.tokenBalance(f.recipientTokenAccount);
  const vaultAfter = await f.tokenBalance(f.splTokenInterface);
  if (after !== before + f.amount) {
    throw new Error(`SPL withdrawal delta ${after - before} !== ${f.amount}`);
  }
  if (vaultAfter !== vaultBefore - f.amount) {
    throw new Error("SPL vault delta mismatch");
  }
}
```

The public SPL amount is negative and the circuit binds one public SPL asset.
The exact settlement suffix is optional readonly CPI authority, writable SPL
vault/interface, writable recipient, writable recipient ATA, readonly token
program, then program account. A withdrawal includes the CPI authority; an SPL
shield omits it. The E2E asserts exact vault decrease and ATA increase, private
change, byte/account parity, and failures for wrong CPI authority, vault, ATA,
mint, or token program. Sources:
[`transfer.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/instructions/transact/transfer.rs)
and
[`builders/transact.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/builders/transact.rs).

## Prover boundary invariant

Instruction implementations must choose exactly one of these equivalent
boundaries:

1. `assemble(proofInputs, spendProofs)` returns `proverInputs` plus
   instruction data with `withProof`.
2. `intoProver(proofInputs, spendProofs)` returns only `ProverInputs`; the
   caller then needs the same canonical assembly output before building the
   instruction.

The standard instruction examples use `assemble` to prevent duplicate public
input, nullifier, root-index, private-transaction-hash, or output-tag math.
`ProverClient.prove` owns HTTP/prover JSON and returns uncompressed points.
`compressProof` validates and compresses them; `toTransactProof` preserves the
P256 BSB22 commitment and omits it for EdDSA. `transactInstruction` accepts only
the compressed wire proof. See
[`witness.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/prover/transact/witness.rs),
[`prover/client.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/prover/client.rs),
and
[`prover/proof.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/prover/proof.rs).

## Independent E2E gate

Action E2Es may call wallet actions but no instruction fixture/helper.
Instruction E2Es may call transaction, prover, interface, native adapter, RPC,
and indexer APIs but no wallet action builder. Each runs from a fresh isolated
stack, records public/private balances before execution, confirms on chain and
in Photon, decrypts/syncs independently, and compares bytes/accounts and
prover inputs with frozen Rust fixtures. Passing one level cannot satisfy the
other.
