/// <reference types="node" />

import { SolanaRpc, waitForIndexer, ZolanaClient } from "@zolana/client";
import { depositInstruction, transactInstruction } from "@zolana/interface/instructions";
import { randomBlinding, type ShieldedKeypair } from "@zolana/keypair";
import {
  AssetRegistry,
  ConfidentialTransfer,
  SppProofInputUtxo,
  SOL_MINT,
  Wallet,
  decryptTransactions,
} from "@zolana/transaction";
import { createSolanaSigner, LocalWalletAuthority, syncWallet } from "@zolana/wallet";
import { describe, expect, it } from "vitest";

import { setup } from "./setup.js";

const DEPOSIT_AMOUNT = 1_000_000_000n;
const TRANSFER_AMOUNT = 300_000_000n;
const WITHDRAW_AMOUNT = 300_000_000n;
// The fee payer pays ordinary Solana fees on the withdraw transaction, so the
// on-chain lamport delta is WITHDRAW_AMOUNT minus those fees. Cap the slack so
// a missed or under-sized withdrawal still fails the lower-bound check.
const WITHDRAW_FEE_ALLOWANCE = 1_000_000n;

function inputUtxo(wallet: Wallet, keypair: ShieldedKeypair): SppProofInputUtxo {
  const utxo = wallet.balance(SOL_MINT).utxos[0];
  if (utxo === undefined) {
    throw new Error("expected at least one spendable SOL UTXO");
  }
  return SppProofInputUtxo.fromKeypair(utxo, keypair);
}

describe("example: deposit, transfer, withdraw", () => {
  it("moves SOL into the pool, to a second wallet, and back out", async () => {
    const stack = await setup({
      portOffset: Number(process.env["ZOLANA_PORT_OFFSET"] ?? "500"),
    });
    const { rpcUrl, indexerUrl, proverUrl, tree, sender, recipient } = stack;
    try {
      const client = ZolanaClient.fromUrls({
        rpc: new SolanaRpc({ url: rpcUrl }),
        indexerUrl,
        proverUrl,
        tree,
      });
      const assets = new AssetRegistry();

      const senderSigner = createSolanaSigner(sender);
      const senderAuthority = new LocalWalletAuthority({
        solanaPublicKey: senderSigner.address,
        keypair: sender,
      });
      const senderAddress = sender.shieldedAddress();
      const senderWallet = new Wallet({
        identity: senderAddress,
        registry: assets,
      });

      const recipientSigner = createSolanaSigner(recipient);
      const recipientAuthority = new LocalWalletAuthority({
        solanaPublicKey: recipientSigner.address,
        keypair: recipient,
      });
      const recipientAddress = recipient.shieldedAddress();

      // 1. The sender deposits SOL into their confidential balance.
      const blinding = randomBlinding();
      const owner = senderAddress.ownerHash();
      await client.createAndSendTransaction({
        instructions: [
          depositInstruction({
            tree,
            depositor: senderSigner.address,
            data: {
              viewTag: senderAddress.confidentialViewTag(),
              owner,
              blinding,
              amount: DEPOSIT_AMOUNT,
            },
          }),
        ],
        feePayer: senderSigner,
      });

      // High-level read: keep a Wallet current with syncWallet (sender path).
      await syncWallet({
        wallet: senderWallet,
        authority: senderAuthority,
        indexer: client.indexer,
        config: { waitForIndexer: true },
      });
      expect(senderWallet.balance(SOL_MINT).amount).toBe(DEPOSIT_AMOUNT);
      expect(senderWallet.balance(SOL_MINT).utxos).toHaveLength(1);

      // 2. The sender transfers part of it to the recipient's confidential balance.
      const transfer = new ConfidentialTransfer(
        senderAddress,
        [inputUtxo(senderWallet, sender)],
        senderSigner.address,
      );
      transfer.send(recipientAddress, SOL_MINT, TRANSFER_AMOUNT);
      const transferData = await client.proveTransact(
        transfer.sign(sender, assets),
        waitForIndexer(),
      );
      const transferSignature = await client.createAndSendTransaction({
        instructions: [
          transactInstruction({ payer: senderSigner.address, tree, data: transferData }),
        ],
        feePayer: senderSigner,
      });
      await client.confirmPrivateTransaction(transferSignature);

      // Low-level read (matches Rust Bob): fetch by view tag, then
      // decryptTransactions over that page — no long-lived Wallet.
      const recipientResponse = await client.getShieldedTransactionsByTags(
        { tags: [recipientAddress.confidentialViewTag()] },
        waitForIndexer(),
      );
      const recipientBalances = await decryptTransactions({
        authority: recipientAuthority,
        transactions: recipientResponse.transactions,
        registry: assets,
      });
      const recipientBalance = recipientBalances.find((balance) => balance.mint === SOL_MINT);
      expect(recipientBalance?.amount).toBe(TRANSFER_AMOUNT);
      expect(recipientBalance?.utxos).toHaveLength(1);

      // High-level read: syncWallet again for the sender's change note.
      await syncWallet({
        wallet: senderWallet,
        authority: senderAuthority,
        indexer: client.indexer,
        config: { waitForIndexer: true },
      });
      expect(senderWallet.balance(SOL_MINT).amount).toBe(DEPOSIT_AMOUNT - TRANSFER_AMOUNT);
      expect(senderWallet.balance(SOL_MINT).utxos).toHaveLength(1);

      // 3. The sender withdraws back to their own Solana account.
      const solanaBalanceBefore = await client.getBalance(senderSigner.address);
      const withdrawal = new ConfidentialTransfer(
        senderAddress,
        [inputUtxo(senderWallet, sender)],
        senderSigner.address,
      );
      withdrawal.withdraw(SOL_MINT, WITHDRAW_AMOUNT, {
        kind: "sol",
        recipient: senderSigner.address,
      });
      const withdrawalData = await client.proveTransact(
        withdrawal.sign(sender, assets),
        waitForIndexer(),
      );
      const withdrawalSignature = await client.createAndSendTransaction({
        instructions: [
          transactInstruction({
            payer: senderSigner.address,
            tree,
            withdrawal: { kind: "sol", recipient: senderSigner.address },
            data: withdrawalData,
          }),
        ],
        feePayer: senderSigner,
      });
      await client.confirmPrivateTransaction(withdrawalSignature);

      // High-level read: syncWallet for the sender's post-withdraw note.
      await syncWallet({
        wallet: senderWallet,
        authority: senderAuthority,
        indexer: client.indexer,
        config: { waitForIndexer: true },
      });
      expect(senderWallet.balance(SOL_MINT).amount).toBe(
        DEPOSIT_AMOUNT - TRANSFER_AMOUNT - WITHDRAW_AMOUNT,
      );
      expect(senderWallet.balance(SOL_MINT).utxos).toHaveLength(1);

      const solanaBalanceAfter = await client.getBalance(senderSigner.address);
      expect(solanaBalanceAfter - solanaBalanceBefore).toBeGreaterThanOrEqual(
        WITHDRAW_AMOUNT - WITHDRAW_FEE_ALLOWANCE,
      );
    } finally {
      await stack.stop();
    }
  }, 600_000);
});
