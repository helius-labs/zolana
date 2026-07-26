/// <reference types="node" />

import {
  AssetRegistry,
  ConfidentialTransfer,
  createSolanaSigner,
  decryptTransactions,
  depositInstruction,
  LocalWalletAuthority,
  randomBlinding,
  SOL_MINT,
  SolanaRpc,
  SppProofInputUtxo,
  syncWallet,
  transactInstruction,
  wait,
  Wallet,
  ZolanaClient,
  type ShieldedKeypair,
} from "@helius/zolana";
import { describe, expect, it } from "vitest";

import { setup } from "./setup.js";

const DEPOSIT_AMOUNT = 1_000_000_000n;
const TRANSFER_AMOUNT = 300_000_000n;
const WITHDRAW_AMOUNT = 300_000_000n;

function inputUtxo(wallet: Wallet, keypair: ShieldedKeypair): SppProofInputUtxo {
  const utxo = wallet.balance(SOL_MINT).utxos[0];
  if (utxo === undefined) {
    throw new Error("expected at least one spendable SOL UTXO");
  }
  return SppProofInputUtxo.fromKeypair(utxo, keypair);
}

describe("example: deposit, transfer, withdraw", () => {
  it("deposit SOL into a private balance, transfer confidentially to a second wallet, and withdraw to a public balance", async () => {
    const stack = await setup({
      portOffset: Number(process.env["ZOLANA_PORT_OFFSET"] ?? "500"),
    });
    const { rpcUrl, indexerUrl, proverUrl, tree, sender, recipient } = stack;
    try {
      // Load the fee payer and localnet settings, then connect.
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

      // Deposit to a private balance.
      // 1. Move public SOL into the sender's private balance.
      const blinding = randomBlinding();
      const owner = senderAddress.ownerHash();
      // 2. Send like any Solana transaction.
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

      // Sync the wallet, then read the private balance.
      await syncWallet({
        wallet: senderWallet,
        authority: senderAuthority,
        indexer: client.indexer,
        config: { waitForIndexer: true },
      });
      expect(senderWallet.balance(SOL_MINT).amount).toBe(DEPOSIT_AMOUNT);
      expect(senderWallet.balance(SOL_MINT).utxos).toHaveLength(1);

      // Transfer to a private balance.
      // 1. Select Private Token Accounts to spend.
      // 2. Build and sign the transfer; signing encrypts asset and amount.
      const transfer = new ConfidentialTransfer(
        senderAddress,
        [inputUtxo(senderWallet, sender)],
        senderSigner.address,
      );
      transfer.send(recipientAddress, SOL_MINT, TRANSFER_AMOUNT);
      // 3. Fetch zk proof to prove the sender can spend the balance without revealing asset and amount.
      const transferData = await client.proveTransact(
        transfer.sign(sender, assets),
        wait(),
      );
      // 4. Wrap the proof and encrypted outputs in a single Solana instruction.
      // 5. Send and confirm like any Solana transaction.
      const transferSignature = await client.createAndSendTransaction({
        instructions: [
          transactInstruction({ payer: senderSigner.address, tree, data: transferData }),
        ],
        feePayer: senderSigner,
      });
      await client.confirmPrivateTransaction(transferSignature);

      // Fetch and decrypt the recipient's balance.
      const recipientResponse = await client.getShieldedTransactionsByTags(
        { tags: [recipientAddress.confidentialViewTag()] },
        wait(),
      );
      const recipientBalances = await decryptTransactions({
        authority: recipientAuthority,
        transactions: recipientResponse.transactions,
        assets,
      });
      const recipientBalance = recipientBalances.getBalance(SOL_MINT);
      expect(recipientBalance?.amount).toBe(TRANSFER_AMOUNT);
      expect(recipientBalance?.utxos).toHaveLength(1);

      // Sync the private balance and read what remains.
      await syncWallet({
        wallet: senderWallet,
        authority: senderAuthority,
        indexer: client.indexer,
        config: { waitForIndexer: true },
      });
      expect(senderWallet.balance(SOL_MINT).amount).toBe(DEPOSIT_AMOUNT - TRANSFER_AMOUNT);
      expect(senderWallet.balance(SOL_MINT).utxos).toHaveLength(1);

      // Withdraw to a public balance.
      // 1. Select Private Token Accounts to spend.
      // 2. Build and sign the withdrawal; signing encrypts the change that stays private.
      const withdrawal = new ConfidentialTransfer(
        senderAddress,
        [inputUtxo(senderWallet, sender)],
        senderSigner.address,
      );
      withdrawal.withdraw(SOL_MINT, WITHDRAW_AMOUNT, {
        kind: "sol",
        recipient: senderSigner.address,
      });
      // 3. Fetch zk proof to prove the sender can spend the balance.
      const withdrawalData = await client.proveTransact(
        withdrawal.sign(sender, assets),
        wait(),
      );
      // 4. Combine the proof and the withdrawal accounts in a single Solana instruction.
      // 5. Send and confirm like any Solana transaction.
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

      // Sync the private balance and read what remains.
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

      // Report the public SOL withdrawal.
      const solanaBalance = await client.getBalance(senderSigner.address);
      console.log(`withdraw solana_balance=${solanaBalance} tx=${withdrawalSignature}`);
    } finally {
      await stack.stop();
    }
  }, 600_000);
});
