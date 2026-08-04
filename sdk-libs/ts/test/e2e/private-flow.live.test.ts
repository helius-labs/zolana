import { beforeAll, describe, expect, it } from "vitest";
import {
  signTransactionWithSigners,
  type Signature,
  type TransactionModifyingSigner,
  type TransactionPartialSigner,
} from "@solana/kit";

import {
  ClientError,
  DEFAULT_TREE_ADDRESS,
  SOL_MINT,
  ShieldedKeypair,
  SPL_TOKEN_2022_PROGRAM_ID,
  Wallet,
  buildDepositTransaction,
  buildMergeTransaction,
  buildRegistrationTransaction,
  buildSetMergingEnabledTransaction,
  buildSplitTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
  createZolanaClient,
  deserializeWallet,
  serializeWallet,
  syncWallet,
  type Bytes32,
  type DepositTransactionParams,
  type RequestContext,
  type SplitTransactionParams,
  type TransferTransactionParams,
  type WalletAuthority,
  type WithdrawalTransactionParams,
} from "../../src/index.js";
import { getAssociatedTokenAddress, getSplAssetVaultAddress } from "../../src/addresses.js";
import type { ZolanaClient } from "../../src/client/client.js";
import type { WalletUtxo } from "../../src/transaction/wallet/state.js";
import {
  fetchUserRecord,
  fetchUserRecordChecked,
  validateRegisteredKeypair,
} from "../../src/wallet/registry.js";
import {
  actor,
  fund,
  hex,
  historyKey,
  indexedTransaction,
  liveHarness,
  signSendAndConfirm,
  sync,
  tokenBalance,
  type Actor,
  type LiveHarness,
} from "./live-helpers.js";

function unspent(owner: Actor, asset = SOL_MINT): readonly WalletUtxo[] {
  return owner.wallet.utxos().filter((entry) => !entry.spent && entry.utxo.asset === asset);
}

function assertSpent(owner: Actor, entries: readonly WalletUtxo[]): void {
  const spent = new Map(
    owner.wallet.utxos().map((entry) => [hex(entry.outputContext.hash), entry]),
  );
  for (const entry of entries) {
    expect(spent.get(hex(entry.outputContext.hash))?.spent).toBe(true);
  }
}

function assertIndexedNullifiers(
  transaction: Readonly<{ nullifiers: readonly Bytes32[] }>,
  entries: readonly WalletUtxo[],
): void {
  const nullifiers = new Set(transaction.nullifiers.map(hex));
  for (const entry of entries) expect(nullifiers.has(hex(entry.nullifier))).toBe(true);
}

function assertHistory(
  owner: Actor,
  expected: Readonly<{
    kind: "deposit" | "privateTransfer" | "publicWithdrawal" | "split" | "merge";
    direction: "inbound" | "outbound" | "selfTransfer";
    amount: bigint;
    asset?: string;
  }>,
): void {
  expect(
    owner.wallet
      .privateTransactions()
      .some(
        (transaction) =>
          transaction.kind === expected.kind &&
          transaction.direction === expected.direction &&
          transaction.amount === expected.amount &&
          transaction.asset === (expected.asset ?? SOL_MINT),
      ),
  ).toBe(true);
}

function assertUniqueWalletState(wallet: Wallet): void {
  const utxos = wallet.utxos().map((entry) => hex(entry.outputContext.hash));
  const history = wallet.privateTransactions().map(historyKey);
  expect(new Set(utxos).size).toBe(utxos.length);
  expect(new Set(history).size).toBe(history.length);
}

type SolanaSigner = TransactionModifyingSigner | TransactionPartialSigner;

function uniqueSigners(signers: readonly SolanaSigner[]): readonly SolanaSigner[] {
  return [...new Map(signers.map((signer) => [signer.address, signer])).values()];
}

async function deposit(
  input: Omit<DepositTransactionParams, "feePayer" | "depositor"> & {
    readonly feePayer: SolanaSigner;
    readonly depositor?: SolanaSigner;
    readonly waitForIndexer?: boolean;
  },
  context?: RequestContext,
): Promise<Readonly<{ signature: Signature }>> {
  const transaction = await buildDepositTransaction(
    {
      client: input.client,
      feePayer: input.feePayer.address,
      ...(input.depositor === undefined ? {} : { depositor: input.depositor.address }),
      ...(input.tree === undefined ? {} : { tree: input.tree }),
      recipient: input.recipient,
      ...(input.asset === undefined ? {} : { asset: input.asset }),
      amount: input.amount,
      ...(input.sourceTokenAccount === undefined
        ? {}
        : { sourceTokenAccount: input.sourceTokenAccount }),
      ...(input.splTokenProgram === undefined ? {} : { splTokenProgram: input.splTokenProgram }),
      ...(input.memo === undefined ? {} : { memo: input.memo }),
    },
    context,
  );
  const signature = await signSendAndConfirm(
    input.client,
    transaction,
    uniqueSigners([input.feePayer, ...(input.depositor === undefined ? [] : [input.depositor])]),
  );
  return Object.freeze({ signature });
}

async function transfer(
  input: Omit<TransferTransactionParams, "feePayer"> & {
    readonly feePayer: SolanaSigner;
    readonly skipPreflight?: boolean;
    readonly waitForIndexer?: boolean;
  },
  context?: RequestContext,
): Promise<Readonly<{ signature: Signature }>> {
  const transaction = await buildTransferTransaction(
    {
      client: input.client,
      wallet: input.wallet,
      authority: input.authority,
      feePayer: input.feePayer.address,
      recipient: input.recipient,
      ...(input.asset === undefined ? {} : { asset: input.asset }),
      amount: input.amount,
    },
    context,
  );
  return Object.freeze({
    signature: await signSendAndConfirm(input.client, transaction, [input.feePayer]),
  });
}

async function withdraw(
  input: Omit<WithdrawalTransactionParams, "feePayer"> & {
    readonly feePayer: SolanaSigner;
    readonly skipPreflight?: boolean;
    readonly waitForIndexer?: boolean;
  },
  context?: RequestContext,
): Promise<Readonly<{ signature: Signature }>> {
  const transaction = await buildWithdrawalTransaction(
    {
      client: input.client,
      wallet: input.wallet,
      authority: input.authority,
      feePayer: input.feePayer.address,
      recipient: input.recipient,
      ...(input.asset === undefined ? {} : { asset: input.asset }),
      amount: input.amount,
      ...(input.splTokenProgram === undefined ? {} : { splTokenProgram: input.splTokenProgram }),
    },
    context,
  );
  return Object.freeze({
    signature: await signSendAndConfirm(input.client, transaction, [input.feePayer]),
  });
}

async function split(
  input: Omit<SplitTransactionParams, "feePayer"> & {
    readonly feePayer: SolanaSigner;
    readonly skipPreflight?: boolean;
    readonly waitForIndexer?: boolean;
  },
  context?: RequestContext,
): Promise<Readonly<{ signature: Signature }>> {
  const transaction = await buildSplitTransaction(
    {
      client: input.client,
      wallet: input.wallet,
      authority: input.authority,
      feePayer: input.feePayer.address,
      ...(input.asset === undefined ? {} : { asset: input.asset }),
      ...(input.parts === undefined ? {} : { parts: input.parts }),
      ...(input.input === undefined ? {} : { input: input.input }),
    },
    context,
  );
  return Object.freeze({
    signature: await signSendAndConfirm(input.client, transaction, [input.feePayer]),
  });
}

async function registerIfAbsent(
  input: Readonly<{
    client: ZolanaClient;
    funding: SolanaSigner;
    keypair: ShieldedKeypair;
  }>,
): Promise<
  | Readonly<{ kind: "written"; signature: Signature }>
  | Readonly<{ kind: "current" }>
  | Readonly<{ kind: "mismatch" }>
> {
  const existing = await fetchUserRecord({ rpc: input.client, owner: input.funding.address });
  if (existing !== undefined) {
    try {
      await validateRegisteredKeypair({
        rpc: input.client,
        owner: input.funding.address,
        keypair: input.keypair,
      });
      return Object.freeze({ kind: "current" });
    } catch {
      return Object.freeze({ kind: "mismatch" });
    }
  }
  const transaction = await buildRegistrationTransaction({
    client: input.client,
    owner: input.funding.address,
    address: input.keypair.shieldedAddress(),
  });
  if (transaction === undefined) return Object.freeze({ kind: "current" });
  const signature = await signSendAndConfirm(input.client, transaction, [input.funding]);
  return Object.freeze({ kind: "written", signature });
}

async function setMergingEnabled(
  input: Readonly<{
    client: ZolanaClient;
    owner: SolanaSigner;
    enabled: boolean;
  }>,
): Promise<Signature> {
  const transaction = await buildSetMergingEnabledTransaction({
    client: input.client,
    owner: input.owner.address,
    enabled: input.enabled,
  });
  return signSendAndConfirm(input.client, transaction, [input.owner]);
}

async function register(client: ZolanaClient, owner: Actor): Promise<void> {
  await expect(
    registerIfAbsent({
      client,
      funding: owner.signer,
      keypair: owner.keypair,
    }),
  ).resolves.toMatchObject({ kind: "written" });
}

function rejectingAuthority(authority: WalletAuthority): WalletAuthority {
  return new Proxy(authority, {
    get(target, property) {
      if (property === "requestUserApproval") {
        return async () => {
          throw new Error("approval rejected");
        };
      }
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function fetchUrl(input: URL | RequestInfo): string {
  return input instanceof Request ? input.url : input.toString();
}

describe.sequential("live SDK lifecycle", () => {
  let harness: LiveHarness;

  beforeAll(async () => {
    harness = await liveHarness();
    expect(harness.tree).toBe(DEFAULT_TREE_ADDRESS);
    expect(await harness.client.getAccount(harness.tree)).toBeDefined();
  }, 60_000);

  it("covers SOL registration, multiple owners, sender change, spent state, and history", async () => {
    const alice = await actor(71);
    const bob = await actor(72);
    const carol = await actor(73);
    await fund(harness.client, alice, bob, carol);
    await register(harness.client, alice);
    await register(harness.client, bob);
    await register(harness.client, carol);

    await expect(
      registerIfAbsent({
        client: harness.client,
        funding: alice.signer,
        keypair: alice.keypair,
      }),
    ).resolves.toEqual({ kind: "current" });
    await expect(
      registerIfAbsent({
        client: harness.client,
        funding: alice.signer,
        keypair: ShieldedKeypair.generate(),
      }),
    ).resolves.toEqual({ kind: "mismatch" });

    await deposit({
      client: harness.client,
      feePayer: alice.signer,
      recipient: alice.signer.address,
      amount: 100_000_000n,
    });
    await sync(harness.client, alice);
    expect(alice.wallet.balance(SOL_MINT).amount).toBe(100_000_000n);

    const aliceDeposit = unspent(alice);
    const toBob = await transfer({
      client: harness.client,
      wallet: alice.wallet,
      authority: alice.authority,
      feePayer: alice.signer,
      recipient: bob.signer.address,
      amount: 20_000_000n,
    });
    assertIndexedNullifiers(
      await indexedTransaction(harness.client, toBob.signature),
      aliceDeposit,
    );
    await sync(harness.client, alice);
    assertSpent(alice, aliceDeposit);
    await sync(harness.client, bob);
    expect(alice.wallet.balance(SOL_MINT).amount).toBe(80_000_000n);
    expect(bob.wallet.balance(SOL_MINT).amount).toBe(20_000_000n);
    expect(unspent(alice)).toHaveLength(1);
    expect(unspent(alice)[0]?.utxo.amount).toBe(80_000_000n);

    const aliceChange = unspent(alice);
    const toCarol = await transfer({
      client: harness.client,
      wallet: alice.wallet,
      authority: alice.authority,
      feePayer: alice.signer,
      recipient: carol.signer.address,
      amount: 30_000_000n,
    });
    assertIndexedNullifiers(
      await indexedTransaction(harness.client, toCarol.signature),
      aliceChange,
    );
    await sync(harness.client, alice);
    assertSpent(alice, aliceChange);
    await sync(harness.client, carol);
    expect(alice.wallet.balance(SOL_MINT).amount).toBe(50_000_000n);
    expect(carol.wallet.balance(SOL_MINT).amount).toBe(30_000_000n);
    expect(unspent(alice)).toHaveLength(1);
    expect(unspent(alice)[0]?.utxo.amount).toBe(50_000_000n);

    const carolInput = unspent(carol);
    const carolToBob = await transfer({
      client: harness.client,
      wallet: carol.wallet,
      authority: carol.authority,
      feePayer: carol.signer,
      recipient: bob.signer.address,
      amount: 10_000_000n,
    });
    assertIndexedNullifiers(
      await indexedTransaction(harness.client, carolToBob.signature),
      carolInput,
    );
    await sync(harness.client, carol);
    assertSpent(carol, carolInput);
    await sync(harness.client, bob);
    expect(carol.wallet.balance(SOL_MINT).amount).toBe(20_000_000n);
    expect(bob.wallet.balance(SOL_MINT).amount).toBe(30_000_000n);
    expect(unspent(carol)).toHaveLength(1);
    expect(unspent(carol)[0]?.utxo.amount).toBe(20_000_000n);

    assertHistory(alice, { kind: "deposit", direction: "inbound", amount: 100_000_000n });
    assertHistory(alice, {
      kind: "privateTransfer",
      direction: "outbound",
      amount: 20_000_000n,
    });
    assertHistory(alice, {
      kind: "privateTransfer",
      direction: "outbound",
      amount: 30_000_000n,
    });
    assertHistory(bob, {
      kind: "privateTransfer",
      direction: "inbound",
      amount: 20_000_000n,
    });
    assertHistory(bob, {
      kind: "privateTransfer",
      direction: "inbound",
      amount: 10_000_000n,
    });
    assertHistory(carol, {
      kind: "privateTransfer",
      direction: "inbound",
      amount: 30_000_000n,
    });
    assertHistory(carol, {
      kind: "privateTransfer",
      direction: "outbound",
      amount: 10_000_000n,
    });
  }, 900_000);

  it("covers a multi-input SOL withdrawal", async () => {
    const owner = await actor(81);
    const recipient = await actor(101);
    await fund(harness.client, owner);

    for (const amount of [30_000_000n, 40_000_000n]) {
      await deposit({
        client: harness.client,
        feePayer: owner.signer,
        recipient: owner.keypair.shieldedAddress(),
        amount,
      });
    }
    await sync(harness.client, owner, { pageLimit: 1 });
    const inputs = unspent(owner);
    expect(inputs).toHaveLength(2);

    const before = await harness.client.getBalance(recipient.signer.address);
    const submitted = await withdraw({
      client: harness.client,
      wallet: owner.wallet,
      authority: owner.authority,
      feePayer: owner.signer,
      recipient: recipient.signer.address,
      amount: 50_000_000n,
    });
    const transaction = await indexedTransaction(harness.client, submitted.signature);
    assertIndexedNullifiers(transaction, inputs);
    expect(transaction.nullifiers.length).toBeGreaterThanOrEqual(2);

    await sync(harness.client, owner, { pageLimit: 1 });
    assertSpent(owner, inputs);
    expect(await harness.client.getBalance(recipient.signer.address)).toBe(before + 50_000_000n);
    expect(owner.wallet.balance(SOL_MINT).amount).toBe(20_000_000n);
    expect(unspent(owner)).toHaveLength(1);
    assertHistory(owner, {
      kind: "publicWithdrawal",
      direction: "outbound",
      amount: 50_000_000n,
    });
  }, 900_000);

  it("covers the SPL deposit, transfer, missing and existing ATA withdrawal paths", async () => {
    const alice = await actor(91);
    const bob = await actor(92);
    const publicRecipient = await actor(93);
    await fund(harness.client, alice, bob);
    await register(harness.client, bob);

    const authorityBefore = await tokenBalance(harness.client, harness.testTokenAccount);
    await deposit({
      client: harness.client,
      feePayer: harness.testAuthority,
      depositor: harness.testAuthority,
      recipient: alice.keypair.shieldedAddress(),
      asset: harness.mint,
      amount: 300_000n,
      sourceTokenAccount: harness.testTokenAccount,
    });
    await sync(harness.client, alice, { pageLimit: 1 });
    expect(alice.wallet.balance(harness.mint).amount).toBe(300_000n);

    await transfer({
      client: harness.client,
      wallet: alice.wallet,
      authority: alice.authority,
      feePayer: alice.signer,
      recipient: bob.signer.address,
      asset: harness.mint,
      amount: 100_000n,
    });
    await sync(harness.client, alice);
    await sync(harness.client, bob);
    expect(alice.wallet.balance(harness.mint).amount).toBe(200_000n);
    expect(bob.wallet.balance(harness.mint).amount).toBe(100_000n);

    const missingAta = await getAssociatedTokenAddress(
      publicRecipient.signer.address,
      harness.mint,
    );
    expect(await harness.client.getAccount(missingAta)).toBeUndefined();
    await withdraw({
      client: harness.client,
      wallet: bob.wallet,
      authority: bob.authority,
      feePayer: bob.signer,
      recipient: publicRecipient.signer.address,
      asset: harness.mint,
      amount: 40_000n,
    });
    await sync(harness.client, bob);
    expect(await tokenBalance(harness.client, missingAta)).toBe(40_000n);
    expect(bob.wallet.balance(harness.mint).amount).toBe(60_000n);

    const existingAta = await getAssociatedTokenAddress(
      harness.testAuthority.address,
      harness.mint,
    );
    expect(existingAta).toBe(harness.testTokenAccount);
    await withdraw({
      client: harness.client,
      wallet: alice.wallet,
      authority: alice.authority,
      feePayer: alice.signer,
      recipient: harness.testAuthority.address,
      asset: harness.mint,
      amount: 50_000n,
    });
    await sync(harness.client, alice);
    expect(await tokenBalance(harness.client, existingAta)).toBe(authorityBefore - 250_000n);
    expect(alice.wallet.balance(harness.mint).amount).toBe(150_000n);

    const vault = await getSplAssetVaultAddress(harness.mint);
    expect(await tokenBalance(harness.client, vault)).toBe(210_000n);
    expect(
      alice.wallet.balance(harness.mint).amount + bob.wallet.balance(harness.mint).amount,
    ).toBe(210_000n);
    assertHistory(alice, {
      kind: "deposit",
      direction: "inbound",
      amount: 300_000n,
      asset: harness.mint,
    });
    assertHistory(alice, {
      kind: "privateTransfer",
      direction: "outbound",
      amount: 100_000n,
      asset: harness.mint,
    });
    assertHistory(alice, {
      kind: "publicWithdrawal",
      direction: "outbound",
      amount: 50_000n,
      asset: harness.mint,
    });
    assertHistory(bob, {
      kind: "privateTransfer",
      direction: "inbound",
      amount: 100_000n,
      asset: harness.mint,
    });
    assertHistory(bob, {
      kind: "publicWithdrawal",
      direction: "outbound",
      amount: 40_000n,
      asset: harness.mint,
    });
  }, 900_000);

  it("creates and transfers a plain Token-2022 asset", async () => {
    const alice = await actor(94);
    const bob = await actor(95);
    const publicRecipient = await actor(96);
    await fund(harness.client, alice, bob);
    await register(harness.client, bob);

    expect(
      await getAssociatedTokenAddress(
        harness.testAuthority.address,
        harness.token2022Mint,
        SPL_TOKEN_2022_PROGRAM_ID,
      ),
    ).toBe(harness.testToken2022Account);

    await deposit({
      client: harness.client,
      feePayer: harness.testAuthority,
      depositor: harness.testAuthority,
      recipient: alice.keypair.shieldedAddress(),
      asset: harness.token2022Mint,
      amount: 200_000n,
      sourceTokenAccount: harness.testToken2022Account,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
    await sync(harness.client, alice);

    await transfer({
      client: harness.client,
      wallet: alice.wallet,
      authority: alice.authority,
      feePayer: alice.signer,
      recipient: bob.signer.address,
      asset: harness.token2022Mint,
      amount: 75_000n,
    });
    await sync(harness.client, alice);
    await sync(harness.client, bob);
    expect(alice.wallet.balance(harness.token2022Mint).amount).toBe(125_000n);
    expect(bob.wallet.balance(harness.token2022Mint).amount).toBe(75_000n);

    const recipientAta = await getAssociatedTokenAddress(
      publicRecipient.signer.address,
      harness.token2022Mint,
      SPL_TOKEN_2022_PROGRAM_ID,
    );
    expect(await harness.client.getAccount(recipientAta)).toBeUndefined();
    await withdraw({
      client: harness.client,
      wallet: bob.wallet,
      authority: bob.authority,
      feePayer: bob.signer,
      recipient: publicRecipient.signer.address,
      asset: harness.token2022Mint,
      amount: 25_000n,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
    await sync(harness.client, bob);
    expect(await tokenBalance(harness.client, recipientAta)).toBe(25_000n);
    expect(bob.wallet.balance(harness.token2022Mint).amount).toBe(50_000n);
  }, 900_000);

  it("covers a real 1x8 split and merges all eight notes back to one", async () => {
    const owner = await actor(101);
    await fund(harness.client, owner);
    await register(harness.client, owner);
    await deposit({
      client: harness.client,
      feePayer: owner.signer,
      recipient: owner.keypair.shieldedAddress(),
      amount: 80_000_000n,
    });
    await sync(harness.client, owner);

    await split({
      client: harness.client,
      wallet: owner.wallet,
      authority: owner.authority,
      feePayer: owner.signer,
      parts: 8,
    });
    expect(unspent(owner)).toHaveLength(1);
    await sync(harness.client, owner, { pageLimit: 1 });
    expect(unspent(owner)).toHaveLength(8);
    expect(unspent(owner).every((entry) => entry.utxo.amount === 10_000_000n)).toBe(true);
    assertHistory(owner, {
      kind: "split",
      direction: "selfTransfer",
      amount: 80_000_000n,
    });

    await setMergingEnabled({
      client: harness.client,
      owner: owner.signer,
      enabled: true,
    });
    expect(
      (await fetchUserRecordChecked({ rpc: harness.client, owner: owner.signer.address }))
        .mergingEnabled,
    ).toBe(true);
    const mergeTransaction = await buildMergeTransaction({
      client: harness.client,
      wallet: owner.wallet,
      authority: owner.authority,
      feePayer: owner.signer.address,
    });
    expect(unspent(owner)).toHaveLength(8);
    expect(unspent(owner).every((entry) => !entry.spent)).toBe(true);
    await signSendAndConfirm(harness.client, mergeTransaction, [owner.signer]);
    expect(unspent(owner)).toHaveLength(8);
    await sync(harness.client, owner, { pageLimit: 1 });
    expect(unspent(owner)).toHaveLength(1);
    expect(unspent(owner)[0]?.utxo.amount).toBe(80_000_000n);
    assertHistory(owner, {
      kind: "merge",
      direction: "selfTransfer",
      amount: 80_000_000n,
    });
    await setMergingEnabled({
      client: harness.client,
      owner: owner.signer,
      enabled: false,
    });
    expect(
      (await fetchUserRecordChecked({ rpc: harness.client, owner: owner.signer.address }))
        .mergingEnabled,
    ).toBe(false);
  }, 1_200_000);

  it("keeps wallet spend state unchanged across build and signing failures", async () => {
    const owner = await actor(111);
    const recipient = await actor(112);
    await fund(harness.client, owner, recipient);
    await register(harness.client, recipient);
    await deposit({
      client: harness.client,
      feePayer: owner.signer,
      recipient: owner.keypair.shieldedAddress(),
      amount: 50_000_000n,
    });
    await sync(harness.client, owner);
    const inputHash = hex(unspent(owner)[0]!.outputContext.hash);

    await expect(
      transfer({
        client: harness.client,
        wallet: owner.wallet,
        authority: rejectingAuthority(owner.authority),
        feePayer: owner.signer,
        recipient: recipient.signer.address,
        amount: 10_000_000n,
      }),
    ).rejects.toMatchObject({ code: "WALLET_BUILD_TRANSFER" });
    expect(owner.wallet.balance(SOL_MINT).amount).toBe(50_000_000n);
    expect(
      owner.wallet.utxos().find((entry) => hex(entry.outputContext.hash) === inputHash)?.spent,
    ).toBe(false);

    let reachedProver!: () => void;
    const proverReached = new Promise<void>((resolve) => {
      reachedProver = resolve;
    });
    const baseFetch = globalThis.fetch.bind(globalThis);
    const abortingClient = await createZolanaClient({
      fetch: async (input, init) => {
        if (fetchUrl(input).startsWith(harness.proverUrl) && init?.method === "POST") {
          reachedProver();
          return new Promise<Response>((_resolve, reject) => {
            const signal = init.signal;
            const rejectAborted = () => reject(signal?.reason ?? new Error("aborted"));
            if (signal?.aborted) rejectAborted();
            else signal?.addEventListener("abort", rejectAborted, { once: true });
          });
        }
        return baseFetch(input, init);
      },
    });
    const abort = new AbortController();
    const proving = transfer(
      {
        client: abortingClient,
        wallet: owner.wallet,
        authority: owner.authority,
        feePayer: owner.signer,
        recipient: recipient.signer.address,
        amount: 10_000_000n,
      },
      { signal: abort.signal },
    );
    await Promise.race([
      proverReached,
      new Promise<never>((_resolve, reject) =>
        setTimeout(() => reject(new Error("prover request was not reached")), 30_000),
      ),
    ]);
    abort.abort();
    await expect(proving).rejects.toMatchObject({ code: "WALLET_BUILD_TRANSFER" });
    expect(owner.wallet.balance(SOL_MINT).amount).toBe(50_000_000n);
    expect(
      owner.wallet.utxos().find((entry) => hex(entry.outputContext.hash) === inputHash)?.spent,
    ).toBe(false);

    const transaction = await buildTransferTransaction({
      client: harness.client,
      wallet: owner.wallet,
      authority: owner.authority,
      feePayer: owner.signer.address,
      recipient: recipient.signer.address,
      amount: 10_000_000n,
    });
    const rejectingSigner: TransactionPartialSigner = {
      address: owner.signer.address,
      signTransactions: async () => {
        throw new Error("signing rejected");
      },
    };
    await expect(signTransactionWithSigners([rejectingSigner], transaction)).rejects.toThrow(
      "signing rejected",
    );
    expect(owner.wallet.balance(SOL_MINT).amount).toBe(50_000_000n);
    expect(
      owner.wallet.utxos().find((entry) => hex(entry.outputContext.hash) === inputHash)?.spent,
    ).toBe(false);
  }, 1_200_000);

  it("reconciles a post-broadcast sync failure and persists paginated state without duplicates", async () => {
    const owner = await actor(121);
    const recipient = await actor(122);
    await fund(harness.client, owner, recipient);
    await register(harness.client, recipient);
    await deposit({
      client: harness.client,
      feePayer: owner.signer,
      recipient: owner.keypair.shieldedAddress(),
      amount: 50_000_000n,
    });
    await sync(harness.client, owner, { pageLimit: 1 });
    const submittedInput = unspent(owner);

    const broadcast = await transfer({
      client: harness.client,
      wallet: owner.wallet,
      authority: owner.authority,
      feePayer: owner.signer,
      recipient: recipient.signer.address,
      amount: 10_000_000n,
    });
    expect(owner.wallet.balance(SOL_MINT).amount).toBe(50_000_000n);
    expect(submittedInput.every((entry) => !entry.spent)).toBe(true);
    const timeoutClient = new Proxy(harness.client, {
      get(target, property) {
        if (property === "getEncryptedUtxosByTags") {
          return async () => {
            throw new ClientError("CLIENT_INDEXER_TIMEOUT", {
              details: { signature: broadcast.signature, attempts: 1 },
            });
          };
        }
        const value = Reflect.get(target, property);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    await expect(
      syncWallet({
        client: timeoutClient,
        wallet: owner.wallet,
        authority: owner.authority,
        config: { waitForIndexer: true, pageLimit: 1 },
      }),
    ).rejects.toMatchObject({
      code: "WALLET_SYNC",
      causeCode: "CLIENT_INDEXER_TIMEOUT",
    });
    expect(owner.wallet.balance(SOL_MINT).amount).toBe(50_000_000n);

    await sync(harness.client, owner, { pageLimit: 1 });
    assertSpent(owner, submittedInput);
    expect(owner.wallet.balance(SOL_MINT).amount).toBe(40_000_000n);

    const fresh = new Wallet({ identity: owner.keypair.shieldedAddress() });
    await syncWallet({
      client: harness.client,
      wallet: fresh,
      authority: owner.authority,
      config: { waitForIndexer: true, pageLimit: 1 },
    });
    expect(fresh.balance(SOL_MINT).amount).toBe(40_000_000n);
    assertUniqueWalletState(fresh);

    const restored = deserializeWallet(serializeWallet(fresh));
    await deposit({
      client: harness.client,
      feePayer: owner.signer,
      recipient: owner.keypair.shieldedAddress(),
      amount: 5_000_000n,
    });
    await syncWallet({
      client: harness.client,
      wallet: restored,
      authority: owner.authority,
      config: { waitForIndexer: true, pageLimit: 1 },
    });
    expect(restored.balance(SOL_MINT).amount).toBe(45_000_000n);
    assertUniqueWalletState(restored);
    const beforeUtxos = restored.utxos().length;
    const beforeHistory = restored.privateTransactions().length;
    await syncWallet({
      client: harness.client,
      wallet: restored,
      authority: owner.authority,
      config: { waitForIndexer: true, pageLimit: 1 },
    });
    expect(restored.utxos()).toHaveLength(beforeUtxos);
    expect(restored.privateTransactions()).toHaveLength(beforeHistory);

    await transfer({
      client: harness.client,
      wallet: restored,
      authority: owner.authority,
      feePayer: owner.signer,
      recipient: recipient.signer.address,
      amount: 5_000_000n,
    });
    await syncWallet({
      client: harness.client,
      wallet: restored,
      authority: owner.authority,
      config: { waitForIndexer: true, pageLimit: 1 },
    });
    expect(restored.balance(SOL_MINT).amount).toBe(40_000_000n);
    assertUniqueWalletState(restored);
  }, 1_200_000);
});
