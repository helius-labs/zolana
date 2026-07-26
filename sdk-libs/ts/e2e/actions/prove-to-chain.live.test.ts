/// <reference types="node" />

/**
 * PKP-07 / P5 — prove-to-chain acceptance.
 *
 * Opt-in: `ZOLANA_TEST_P5=1`. Starts a same-revision local stack, creates a real
 * protocol config and pool tree, deposits SOL, syncs through Photon, and builds
 * a confidential Ed25519 transfer in TypeScript against indexer Merkle context.
 *
 * Default path is pure TypeScript (`compressProof` with EIP-197 A1||A0 G2 limbs).
 * `ZOLANA_TEST_P5_RUST_COMPRESS=1` keeps the historical hybrid oracle fallback.
 */

import type { Rpc, ZolanaClient } from "@zolana/client";
import { createAndSendTransaction, createIndexerRpcConfig } from "@zolana/client";
import {
  assemble,
  compressProof,
  compressedProof,
  type ProverClient,
} from "@zolana/client/prover";
import type { Address, Bytes32, Signature } from "@zolana/interface";
import { TREE_ACCOUNT_SIZE } from "@zolana/interface";
import { ShieldedKeypair } from "@zolana/keypair";
import { SOL_MINT, SppProofInputs } from "@zolana/transaction";
import {
  createDeposit,
  createTransfer,
  createWithdrawal,
  deposit,
  ensureRegistered,
  getPrivateTokenBalances,
  signPrivateTransaction,
  syncWallet,
  type TransactionSigner,
  type UnsignedPrivateTransaction,
} from "@zolana/wallet";
import { createTestWallet, startLocalStack } from "@zolana/test-kit";
import {
  createE2eHarness,
  createProtocolConfigInstructions,
  createTestNativeSigner,
  createTreeInstructions,
  signTestTransaction,
} from "@zolana/test-kit/node";
import { describe, expect, it } from "vitest";

import {
  proofWire,
  rustCompressProof,
} from "../../client/test/helpers/groth16-verify-oracle.js";

const LIVE = process.env["ZOLANA_TEST_P5"] === "1";
const RUST_COMPRESS = process.env["ZOLANA_TEST_P5_RUST_COMPRESS"] === "1";
const DEPOSIT_AMOUNT = 1_000_000_000n;
const TRANSFER_AMOUNT = 400_000_000n;
const WITHDRAW_AMOUNT = 400_000_000n;
const DEFAULT_OFFSET = 300;

function bytes32(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

async function airdrop(url: URL, address: Address, lamports: bigint): Promise<Signature> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "requestAirdrop",
      params: [address, Number(lamports)],
    }),
  });
  const envelope = (await response.json()) as { result?: Signature; error?: unknown };
  if (envelope.result === undefined) {
    throw new Error(`airdrop failed: ${JSON.stringify(envelope.error)}`);
  }
  return envelope.result;
}

async function confirm(rpc: Rpc, signature: Signature, timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await rpc.confirmTransaction(signature)) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`transaction confirmation timed out: ${signature}`);
}

async function waitForAccount(rpc: Rpc, address: Address, timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if ((await rpc.getAccount(address)) !== undefined) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`account did not appear: ${address}`);
}

async function syncUntil(
  input: Parameters<typeof syncWallet>[0],
  predicate: () => boolean,
  timeoutMs = 120_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await syncWallet({
      ...input,
      config: { waitForIndexer: true, ...(input.config ?? {}) },
    });
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("wallet sync predicate timed out");
}

function isProofPointFailure(error: unknown): boolean {
  let current: unknown = error;
  for (let depth = 0; depth < 8; depth++) {
    if (typeof current !== "object" || current === null) return false;
    const record = current as Readonly<{ code?: unknown; causeCode?: unknown; cause?: unknown }>;
    if (record.code === "CLIENT_PROOF_POINT" || record.causeCode === "CLIENT_PROOF_POINT") {
      return true;
    }
    current = record.cause;
  }
  return false;
}

function installRustCompressProveTransact(
  client: ZolanaClient,
  prover: ProverClient,
): () => void {
  const original = client.proveTransact.bind(client);
  client.proveTransact = async (proofInputs, config, context) => {
    if (!(proofInputs instanceof SppProofInputs)) {
      return original(proofInputs, config, context);
    }
    const proofs = await client.getInputMerkleProofs(
      proofInputs.inputUtxoHashes(),
      config,
      context,
    );
    const assembled = assemble(proofInputs, proofs);
    const proof = await prover.prove(assembled.proverInputs, context);
    try {
      return assembled.withProof(compressProof(proof).toTransactProof());
    } catch (error) {
      if (!isProofPointFailure(error)) throw error;
      const wire = rustCompressProof(proofWire(proof));
      return assembled.withProof(
        compressedProof({
          a: Uint8Array.from(Buffer.from(wire.a, "hex")),
          b: Uint8Array.from(Buffer.from(wire.b, "hex")),
          c: Uint8Array.from(Buffer.from(wire.c, "hex")),
        }).toTransactProof(),
      );
    }
  };
  return () => {
    client.proveTransact = original;
  };
}

const suite = LIVE ? describe : describe.skip;

suite("P5 prove-to-chain (confidential Ed25519)", () => {
  it(
    RUST_COMPRESS
      ? "hybrid: TypeScript assemble + Rust compress lands on the shielded-pool program"
      : "pure TypeScript path lands on the shielded-pool program",
    async () => {
      const offset = Number(process.env["ZOLANA_PORT_OFFSET"] ?? String(DEFAULT_OFFSET));
      expect(offset).toBe(DEFAULT_OFFSET);

      const stack = await startLocalStack({ portOffset: offset });
      const authoritySeed = bytes32(51);
      const payerSeed = bytes32(52);
      const treeSeed = bytes32(53);
      const senderSeed = bytes32(54);
      const recipientSeed = bytes32(55);
      const withdrawSeed = bytes32(56);

      const authority = createTestNativeSigner(authoritySeed);
      const payer = createTestNativeSigner(payerSeed);
      const treeSigner = createTestNativeSigner(treeSeed);
      const senderSigner = createTestNativeSigner(senderSeed);
      const recipientSigner = createTestNativeSigner(recipientSeed);
      const withdrawSigner = createTestNativeSigner(withdrawSeed);
      const tree = treeSigner.address;

      const sender = createTestWallet(senderSeed);
      const recipient = createTestWallet(recipientSeed);
      const senderKeypair = ShieldedKeypair.fromEd25519(senderSeed, 0);
      const recipientKeypair = ShieldedKeypair.fromEd25519(recipientSeed, 0);

      const harness = createE2eHarness(stack, tree);
      const restoreProve = RUST_COMPRESS
        ? installRustCompressProveTransact(harness.client, harness.prover)
        : undefined;
      try {
        for (const [address, lamports] of [
          [authority.address, 2_000_000_000n],
          [payer.address, 20_000_000_000n],
          [senderSigner.address, 5_000_000_000n],
          [recipientSigner.address, 2_000_000_000n],
          [withdrawSigner.address, 1_000_000_000n],
        ] as const) {
          await confirm(harness.rpc, await airdrop(stack.rpcUrl, address, lamports));
        }

        const configSig = await createAndSendTransaction({
          rpc: harness.rpc,
          feePayer: authority.address,
          instructions: [...createProtocolConfigInstructions({ authority: authority.address })],
          sign: (transaction) => signTestTransaction(transaction, [authority]),
        });
        await confirm(harness.rpc, configSig);

        const treeIxs = await createTreeInstructions(harness.rpc, {
          payer: payer.address,
          authority: authority.address,
          tree,
          accountSize: TREE_ACCOUNT_SIZE,
        });
        const treeSig = await createAndSendTransaction({
          rpc: harness.rpc,
          feePayer: payer.address,
          instructions: [...treeIxs],
          sign: (transaction) =>
            signTestTransaction(transaction, [payer, treeSigner, authority]),
        });
        await confirm(harness.rpc, treeSig);
        await waitForAccount(harness.rpc, tree);
        expect((await harness.rpc.getAccount(tree))?.data[0]).toBe(1);

        for (const [signer, keypair] of [
          [senderSigner, senderKeypair],
          [recipientSigner, recipientKeypair],
        ] as const) {
          const registration = await ensureRegistered({
            rpc: harness.rpc,
            funding: signer,
            keypair,
          });
          expect(registration).toBeTypeOf("string");
          await confirm(harness.rpc, registration as Signature);
        }

        const note = createDeposit({
          recipient: await sender.authority.shieldedAddress(),
          asset: SOL_MINT,
          amount: DEPOSIT_AMOUNT,
        });
        const depositSig = await deposit({
          rpc: harness.rpc,
          payer: senderSigner,
          depositor: senderSigner,
          tree,
          deposit: note,
        });
        await confirm(harness.rpc, depositSig);

        await syncUntil(
          {
            wallet: sender.wallet,
            authority: sender.authority,
            indexer: harness.indexer,
            registryRpc: harness.rpc,
          },
          () =>
            sender.wallet.utxos().some(
              (entry) =>
                !entry.spent &&
                entry.outputContext.tree === tree &&
                entry.utxo.amount === DEPOSIT_AMOUNT,
            ),
        );
        expect(getPrivateTokenBalances(sender.wallet)).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ mint: SOL_MINT, amount: DEPOSIT_AMOUNT }),
          ]),
        );

        const created = await createTransfer({
          rpc: harness.rpc,
          wallet: sender.wallet,
          payer: senderSigner.address,
          recipient: recipientSigner.address,
          asset: SOL_MINT,
          amount: TRANSFER_AMOUNT,
        });
        expect(created.recipient.kind).toBe("registered");
        expect(created.transaction.inputCount()).toBe(1);

        await runSettlement({
          harness,
          sender,
          recipient,
          senderSigner,
          recipientSigner,
          withdrawSigner,
          tree,
          transfer: created.transaction,
        });
      } finally {
        restoreProve?.();
        await harness.stop();
      }
      await expect(fetch(stack.rpcUrl)).rejects.toThrow();
    },
    600_000,
  );
});

async function runSettlement(
  input: Readonly<{
    harness: ReturnType<typeof createE2eHarness>;
    sender: ReturnType<typeof createTestWallet>;
    recipient: ReturnType<typeof createTestWallet>;
    senderSigner: TransactionSigner;
    recipientSigner: TransactionSigner;
    withdrawSigner: TransactionSigner;
    tree: Address;
    transfer: UnsignedPrivateTransaction;
  }>,
): Promise<void> {
  const signedTransfer = await signPrivateTransaction({
    transaction: input.transfer,
    wallet: input.sender.wallet,
    authority: input.sender.authority,
    client: input.harness.client,
    feePayer: input.senderSigner,
  });
  const transferSig = await input.harness.rpc.sendTransaction(signedTransfer);
  await input.harness.client.confirmPrivateTransaction(transferSig);

  await syncUntil(
    {
      wallet: input.sender.wallet,
      authority: input.sender.authority,
      indexer: input.harness.indexer,
      registryRpc: input.harness.rpc,
    },
    () => {
      const spent = input.sender.wallet.utxos().filter((entry) => entry.spent);
      const unspent = input.sender.wallet
        .utxos()
        .filter((entry) => !entry.spent && entry.utxo.asset === SOL_MINT);
      const change = DEPOSIT_AMOUNT - TRANSFER_AMOUNT;
      return (
        spent.length >= 1 &&
        unspent.reduce((sum, entry) => sum + entry.utxo.amount, 0n) === change
      );
    },
  );

  await syncUntil(
    {
      wallet: input.recipient.wallet,
      authority: input.recipient.authority,
      indexer: input.harness.indexer,
      registryRpc: input.harness.rpc,
    },
    () =>
      input.recipient.wallet.utxos().some(
        (entry) =>
          !entry.spent &&
          entry.outputContext.tree === input.tree &&
          entry.utxo.amount === TRANSFER_AMOUNT &&
          entry.utxo.asset === SOL_MINT,
      ),
  );

  const stranger = createTestWallet(bytes32(99));
  await syncWallet({
    wallet: stranger.wallet,
    authority: stranger.authority,
    indexer: input.harness.indexer,
    registryRpc: input.harness.rpc,
    config: { waitForIndexer: true },
  });
  expect(stranger.wallet.utxos()).toHaveLength(0);

  const indexed = await input.harness.indexer.getShieldedTransactionsByTags({
    tags: [input.recipient.wallet.identity.confidentialViewTag()],
    limit: 50,
  });
  expect(
    indexed.transactions.some((transaction) => transaction.txSignature === transferSig),
  ).toBe(true);
  const transferRecord = indexed.transactions.find(
    (transaction) => transaction.txSignature === transferSig,
  );
  expect(transferRecord?.proofless).toBe(false);
  expect(transferRecord?.nullifiers.length).toBeGreaterThan(0);
  expect(transferRecord?.outputSlots.length).toBeGreaterThan(0);

  const merkle = await input.harness.indexer.getMerkleProofs(
    input.tree,
    [
      input.recipient.wallet
        .utxos()
        .find((entry) => !entry.spent && entry.utxo.amount === TRANSFER_AMOUNT)!
        .outputContext.hash,
    ],
    createIndexerRpcConfig(true),
  );
  expect(merkle.proofs).toHaveLength(1);
  expect(merkle.proofs[0]?.merkleContext.tree).toBe(input.tree);

  const publicBefore = await input.harness.rpc.getBalance(input.withdrawSigner.address);
  const withdrawal = createWithdrawal({
    wallet: input.recipient.wallet,
    payer: input.recipientSigner.address,
    recipient: input.withdrawSigner.address,
    asset: SOL_MINT,
    amount: WITHDRAW_AMOUNT,
  });
  const signedWithdraw = await signPrivateTransaction({
    transaction: withdrawal.transaction,
    wallet: input.recipient.wallet,
    authority: input.recipient.authority,
    client: input.harness.client,
    feePayer: input.recipientSigner,
  });
  const withdrawSig = await input.harness.rpc.sendTransaction(signedWithdraw);
  await input.harness.client.confirmPrivateTransaction(withdrawSig);
  const publicAfter = await input.harness.rpc.getBalance(input.withdrawSigner.address);
  expect(publicAfter - publicBefore).toBe(WITHDRAW_AMOUNT);

  await syncUntil(
    {
      wallet: input.recipient.wallet,
      authority: input.recipient.authority,
      indexer: input.harness.indexer,
      registryRpc: input.harness.rpc,
    },
    () =>
      input.recipient.wallet
        .utxos()
        .filter((entry) => !entry.spent && entry.utxo.asset === SOL_MINT)
        .reduce((sum, entry) => sum + entry.utxo.amount, 0n) === 0n,
  );

  await input.harness.client.confirmPrivateTransaction(transferSig);
  await syncWallet({
    wallet: input.recipient.wallet,
    authority: input.recipient.authority,
    indexer: input.harness.indexer,
    registryRpc: input.harness.rpc,
    config: { waitForIndexer: true },
  });
}
