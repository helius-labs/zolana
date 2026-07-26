/// <reference types="node" />

/**
 * Gate 3 — named SDK flows against a real local stack.
 *
 * Opt-in: `ZOLANA_TEST_GATE3=1`. Boots validator + Photon + prover via
 * `@zolana/test-kit` (same stack as P5). Covers registration, deposit, sync,
 * split, merge submission, and private-transaction submission without mocking
 * the prover. Spend paths prove and submit through pure TypeScript
 * `compressProof` (no Rust compress fallback).
 *
 * Deposit / private transfer / withdraw against this stack are also exercised
 * in `prove-to-chain.live.test.ts` (P5). This suite owns the flows P5 left out:
 * split, merge submit, registration assertions, and production submit for
 * spend paths beyond transfer/withdraw.
 */

import { createAndSendTransaction, createIndexerRpcConfig } from "@zolana/client";
import type { Bytes32, Signature } from "@zolana/interface";
import { TREE_ACCOUNT_SIZE } from "@zolana/interface";
import { ShieldedKeypair } from "@zolana/keypair";
import { SOL_MINT } from "@zolana/transaction";
import {
  createDeposit,
  createMerge,
  createSplit,
  createTransfer,
  decodeUserRecordAccount,
  deposit,
  ensureRegistered,
  fetchUserRecord,
  getPrivateTokenBalances,
  isWalletRegistered,
  MergeMaterial,
  signPrivateTransaction,
  submitMergeTransaction,
  syncWallet,
} from "@zolana/wallet";
import { createTestWallet, startLocalStack } from "@zolana/test-kit";
import {
  createE2eHarness,
  createProtocolConfigInstructions,
  createTestNativeSigner,
  createTreeInstructions,
  enableMerging,
  signTestTransaction,
  userRecordAddress,
} from "@zolana/test-kit/node";
import { describe, expect, it } from "vitest";

import { airdrop, bytes32, confirm, syncUntil, waitForAccount } from "./support/live-helpers.js";

const LIVE = process.env["ZOLANA_TEST_GATE3"] === "1";
const DEPOSIT_AMOUNT = 1_000_000_000n;
const SPLIT_PARTS = 2;
const PER_PART = DEPOSIT_AMOUNT / BigInt(SPLIT_PARTS);
const TRANSFER_AMOUNT = 100_000_000n;
/** Distinct from P5 so two suites can run on one machine. */
const DEFAULT_OFFSET = 300;

const suite = LIVE ? describe : describe.skip;

suite("Gate 3 flows (real prover + validator)", () => {
  it(
    "registration, deposit, sync, split, merge submit, and private submit",
    async () => {
      const offset = Number(process.env["ZOLANA_PORT_OFFSET"] ?? String(DEFAULT_OFFSET));
      expect(offset).toBe(DEFAULT_OFFSET);

      const stack = await startLocalStack({ portOffset: offset });
      const authoritySeed = bytes32(61);
      const payerSeed = bytes32(62);
      const treeSeed = bytes32(63);
      const ownerSeed = bytes32(64);
      const recipientSeed = bytes32(65);

      const authority = createTestNativeSigner(authoritySeed);
      const payer = createTestNativeSigner(payerSeed);
      const treeSigner = createTestNativeSigner(treeSeed);
      const ownerSigner = createTestNativeSigner(ownerSeed);
      const recipientSigner = createTestNativeSigner(recipientSeed);
      const tree = treeSigner.address;

      const owner = createTestWallet(ownerSeed);
      const recipient = createTestWallet(recipientSeed);
      const ownerKeypair = ShieldedKeypair.fromEd25519(ownerSeed, 0);
      const recipientKeypair = ShieldedKeypair.fromEd25519(recipientSeed, 0);

      const harness = createE2eHarness(stack, tree);
      const evidence: Record<string, string> = {};
      try {
        for (const [address, lamports] of [
          [authority.address, 2_000_000_000n],
          [payer.address, 20_000_000_000n],
          [ownerSigner.address, 5_000_000_000n],
          [recipientSigner.address, 2_000_000_000n],
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
        evidence.protocolConfig = configSig;

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
        evidence.poolTree = treeSig;

        // --- registration ---
        expect(await isWalletRegistered({ rpc: harness.rpc, owner: ownerSigner.address })).toBe(
          false,
        );
        const registration = await ensureRegistered({
          rpc: harness.rpc,
          funding: ownerSigner,
          keypair: ownerKeypair,
        });
        expect(registration).toBeTypeOf("string");
        await confirm(harness.rpc, registration as Signature);
        evidence.registration = registration as string;
        expect(await isWalletRegistered({ rpc: harness.rpc, owner: ownerSigner.address })).toBe(
          true,
        );
        expect(
          await fetchUserRecord({ rpc: harness.rpc, owner: ownerSigner.address }),
        ).toBeDefined();
        const recordAddress = userRecordAddress(ownerSigner.address).address;
        const beforeMergeOptIn = await harness.rpc.getAccount(recordAddress);
        expect(beforeMergeOptIn).toBeDefined();
        expect(mergingFlag(beforeMergeOptIn!)).toBe(false);

        const recipientRegistration = await ensureRegistered({
          rpc: harness.rpc,
          funding: recipientSigner,
          keypair: recipientKeypair,
        });
        expect(recipientRegistration).toBeTypeOf("string");
        await confirm(harness.rpc, recipientRegistration as Signature);
        evidence.recipientRegistration = recipientRegistration as string;

        const merging = await enableMerging({
          rpc: harness.rpc,
          owner: ownerSigner.address,
          signer: ownerSigner,
        });
        expect(merging.changed).toBe(true);
        const afterMergeOptIn = await harness.rpc.getAccount(recordAddress);
        expect(afterMergeOptIn).toBeDefined();
        expect(mergingFlag(afterMergeOptIn!)).toBe(true);

        const shielded = await owner.authority.shieldedAddress();
        for (let index = 0; index < 2; index++) {
          const depositSig = await deposit({
            rpc: harness.rpc,
            payer: ownerSigner,
            depositor: ownerSigner,
            tree,
            deposit: createDeposit({
              recipient: shielded,
              asset: SOL_MINT,
              amount: DEPOSIT_AMOUNT,
            }),
          });
          await confirm(harness.rpc, depositSig);
          evidence[`deposit${index}`] = depositSig;
        }

        // --- sync ---
        await syncUntil(
          {
            wallet: owner.wallet,
            authority: owner.authority,
            indexer: harness.indexer,
            registryRpc: harness.rpc,
          },
          () =>
            owner.wallet.utxos().filter(
              (entry) =>
                !entry.spent &&
                entry.outputContext.tree === tree &&
                entry.utxo.amount === DEPOSIT_AMOUNT,
            ).length >= 2,
        );
        expect(getPrivateTokenBalances(owner.wallet)).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ mint: SOL_MINT, amount: DEPOSIT_AMOUNT * 2n }),
          ]),
        );
        const utxoCountAfterDeposit = owner.wallet.utxos().filter((entry) => !entry.spent).length;
        await syncWallet({
          wallet: owner.wallet,
          authority: owner.authority,
          indexer: harness.indexer,
          registryRpc: harness.rpc,
          config: { waitForIndexer: true },
        });
        expect(owner.wallet.utxos().filter((entry) => !entry.spent)).toHaveLength(
          utxoCountAfterDeposit,
        );

        const stranger = createTestWallet(bytes32(99));
        await syncWallet({
          wallet: stranger.wallet,
          authority: stranger.authority,
          indexer: harness.indexer,
          registryRpc: harness.rpc,
          config: { waitForIndexer: true },
        });
        expect(stranger.wallet.utxos()).toHaveLength(0);

        // --- split (real prover + chain submit) ---
        const splitInput = owner.wallet
          .utxos()
          .find(
            (entry) =>
              !entry.spent &&
              entry.outputContext.tree === tree &&
              entry.utxo.amount === DEPOSIT_AMOUNT,
          );
        expect(splitInput).toBeDefined();
        const split = createSplit({
          wallet: owner.wallet,
          payer: ownerSigner.address,
          asset: SOL_MINT,
          parts: SPLIT_PARTS,
          input: splitInput!.outputContext.hash,
        });
        expect(split.numOutputs).toBe(SPLIT_PARTS);
        expect(split.perOutputAmount).toBe(PER_PART);

        const splitSigned = await signPrivateTransaction({
          transaction: split.transaction,
          wallet: owner.wallet,
          authority: owner.authority,
          client: harness.client,
          feePayer: ownerSigner,
        });
        const splitSig = await harness.rpc.sendTransaction(splitSigned);
        await harness.client.confirmPrivateTransaction(splitSig);
        evidence.split = splitSig;
        await syncUntil(
          {
            wallet: owner.wallet,
            authority: owner.authority,
            indexer: harness.indexer,
            registryRpc: harness.rpc,
          },
          () =>
            owner.wallet.utxos().filter(
              (entry) =>
                !entry.spent &&
                entry.utxo.asset === SOL_MINT &&
                entry.utxo.amount === PER_PART,
            ).length >= SPLIT_PARTS,
        );

        // --- merge submit (real prover via production proveMerge) ---
        const unspentForMerge = owner.wallet
          .utxos()
          .filter((entry) => !entry.spent && entry.utxo.asset === SOL_MINT);
        expect(unspentForMerge.length).toBeGreaterThanOrEqual(2);
        const createdMerge = createMerge({
          wallet: owner.wallet,
          keypair: ownerKeypair,
          asset: SOL_MINT,
          tree,
          inputs: unspentForMerge.slice(0, 2).map((entry) => entry.outputContext.hash),
        });
        expect(createdMerge.numInputs).toBe(2);

        // Spend proofs live on `ZolanaClient.getInputMerkleProofs`, not on the
        // Photon-facing `ZolanaIndexer` surface.
        const submitted = await submitMergeTransaction({
          rpc: harness.client,
          indexer: harness.client,
          owner: ownerSigner.address,
          payer: ownerSigner,
          material: MergeMaterial.fromKeypair(ownerKeypair),
          tree,
          prepared: createdMerge.prepared,
        });
        await confirm(harness.rpc, submitted.signature);
        await harness.client.confirmPrivateTransaction(submitted.signature);
        evidence.merge = submitted.signature;
        expect(submitted.outputHash).toEqual(createdMerge.prepared.output.hash());
        await syncUntil(
          {
            wallet: owner.wallet,
            authority: owner.authority,
            indexer: harness.indexer,
            registryRpc: harness.rpc,
          },
          () =>
            owner.wallet
              .utxos()
              .some(
                (entry) =>
                  !entry.spent &&
                  entry.utxo.asset === SOL_MINT &&
                  equalBytes(entry.outputContext.hash, submitted.outputHash),
              ),
        );

        // --- private transfer submit (production sign path; also covered by P5) ---
        const transferable = owner.wallet
          .utxos()
          .filter((entry) => !entry.spent && entry.utxo.asset === SOL_MINT)
          .reduce((sum, entry) => sum + entry.utxo.amount, 0n);
        expect(transferable).toBeGreaterThanOrEqual(TRANSFER_AMOUNT);
        const transfer = await createTransfer({
          rpc: harness.rpc,
          wallet: owner.wallet,
          payer: ownerSigner.address,
          recipient: recipientSigner.address,
          asset: SOL_MINT,
          amount: TRANSFER_AMOUNT,
        });
        expect(transfer.recipient.kind).toBe("registered");

        const transferSigned = await signPrivateTransaction({
          transaction: transfer.transaction,
          wallet: owner.wallet,
          authority: owner.authority,
          client: harness.client,
          feePayer: ownerSigner,
        });
        const transferSig = await harness.rpc.sendTransaction(transferSigned);
        await harness.client.confirmPrivateTransaction(transferSig);
        evidence.privateTransfer = transferSig;

        await syncUntil(
          {
            wallet: recipient.wallet,
            authority: recipient.authority,
            indexer: harness.indexer,
            registryRpc: harness.rpc,
          },
          () =>
            recipient.wallet.utxos().some(
              (entry) =>
                !entry.spent &&
                entry.utxo.amount === TRANSFER_AMOUNT &&
                entry.utxo.asset === SOL_MINT,
            ),
        );

        const indexed = await harness.indexer.getShieldedTransactionsByTags({
          tags: [recipient.wallet.identity.confidentialViewTag()],
          limit: 50,
        });
        expect(
          indexed.transactions.some((transaction) => transaction.txSignature === transferSig),
        ).toBe(true);
        const merkle = await harness.indexer.getMerkleProofs(
          tree,
          [
            recipient.wallet
              .utxos()
              .find((entry) => !entry.spent && entry.utxo.amount === TRANSFER_AMOUNT)!
              .outputContext.hash,
          ],
          createIndexerRpcConfig(true),
        );
        expect(merkle.proofs).toHaveLength(1);

        expect(
          owner.wallet.utxos().some((entry) => !entry.spent && entry.utxo.amount === PER_PART),
        ).toBe(true);

        // eslint-disable-next-line no-console -- gate evidence for the row-update report
        console.log("gate3-flow-signatures", JSON.stringify(evidence));
      } finally {
        await harness.stop();
      }
      await expect(fetch(stack.rpcUrl)).rejects.toThrow();
    },
    600_000,
  );
});

function mergingFlag(
  account: Readonly<{ owner: string; data: Uint8Array; lamports: bigint }>,
): boolean {
  // decodeUserRecordAccount returns the runtime `mergingEnabled` field; the
  // public `UserRecord` type omits it.
  return (
    (decodeUserRecordAccount(account as never) as { mergingEnabled?: boolean }).mergingEnabled ===
    true
  );
}

function equalBytes(left: Bytes32, right: Bytes32): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}
