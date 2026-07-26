/// <reference types="node" />

import {
  AssetRegistry,
  ConfidentialTransfer,
  createKitRpc,
  createSolanaSigner,
  decryptTransactions,
  depositInstruction,
  fromKitInstruction,
  fromKitSigner,
  LocalWalletAuthority,
  randomBlinding,
  SOL_MINT,
  SppProofInputUtxo,
  syncWallet,
  toKitSigner,
  transactInstruction,
  wait,
  Wallet,
  ZolanaClient,
  type Instruction,
  type ShieldedKeypair,
  type Signature,
} from "@helius/zolana/kit";
import { createSolanaRpc, type Instruction as KitInstruction } from "@solana/kit";
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

function submittable(instruction: KitInstruction): Instruction {
  return fromKitInstruction(instruction);
}

describe("example: deposit, transfer, withdraw through @solana/kit", () => {
  it("deposit SOL into a private balance, transfer confidentially to a second wallet, and withdraw to a public balance", async () => {
    const stack = await setup({
      portOffset: Number(process.env["ZOLANA_PORT_OFFSET"] ?? "500"),
    });
    const { rpcUrl, indexerUrl, proverUrl, tree, sender, recipient } = stack;
    try {
      // Load the fee payer and localnet settings, then connect.
      const client = ZolanaClient.fromUrls({
        rpc: createKitRpc(createSolanaRpc(rpcUrl.href)),
        indexerUrl,
        proverUrl,
        tree,
      });
      const assets = new AssetRegistry();

      const senderSigner = fromKitSigner(toKitSigner(createSolanaSigner(sender)));
      const senderAuthority = new LocalWalletAuthority({
        solanaPublicKey: senderSigner.address,
        keypair: sender,
      });
      const senderAddress = sender.shieldedAddress();
      const senderWallet = new Wallet({ identity: senderAddress, registry: assets });

      const recipientAuthority = new LocalWalletAuthority({
        solanaPublicKey: createSolanaSigner(recipient).address,
        keypair: recipient,
      });
      const recipientAddress = recipient.shieldedAddress();

      async function send(instructions: readonly KitInstruction[]): Promise<Signature> {
        return client.createAndSendTransaction({
          instructions: instructions.map(submittable),
          feePayer: senderSigner,
        });
      }

      async function syncSender(): Promise<void> {
        await syncWallet({
          wallet: senderWallet,
          authority: senderAuthority,
          indexer: client.indexer,
          config: { waitForIndexer: true },
        });
      }

      // Deposit to a private balance.
      // 1. Move public SOL into the sender's private balance.
      // 2. Send like any Solana transaction.
      await send([
        depositInstruction({
          tree,
          depositor: senderSigner.address,
          data: {
            viewTag: senderAddress.confidentialViewTag(),
            owner: senderAddress.ownerHash(),
            blinding: randomBlinding(),
            amount: DEPOSIT_AMOUNT,
          },
        }),
      ]);

      // Sync the wallet, then read the private balance.
      await syncSender();
      expect(senderWallet.balance(SOL_MINT).amount).toBe(DEPOSIT_AMOUNT);

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
      const transferData = await client.proveTransact(transfer.sign(sender, assets), wait());
      // 4. Wrap the proof and encrypted outputs in a single Solana instruction.
      // 5. Send and confirm like any Solana transaction.
      const transferSignature = await send([
        transactInstruction({ payer: senderSigner.address, tree, data: transferData }),
      ]);
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
      expect(recipientBalances.getBalance(SOL_MINT)?.amount).toBe(TRANSFER_AMOUNT);

      // Sync the private balance and read what remains.
      await syncSender();
      expect(senderWallet.balance(SOL_MINT).amount).toBe(DEPOSIT_AMOUNT - TRANSFER_AMOUNT);

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
      const withdrawalData = await client.proveTransact(withdrawal.sign(sender, assets), wait());
      // 4. Combine the proof and the withdrawal accounts in a single Solana instruction.
      // 5. Send and confirm like any Solana transaction.
      const withdrawalSignature = await send([
        transactInstruction({
          payer: senderSigner.address,
          tree,
          withdrawal: { kind: "sol", recipient: senderSigner.address },
          data: withdrawalData,
        }),
      ]);
      await client.confirmPrivateTransaction(withdrawalSignature);

      // Sync the private balance and read what remains.
      await syncSender();
      expect(senderWallet.balance(SOL_MINT).amount).toBe(
        DEPOSIT_AMOUNT - TRANSFER_AMOUNT - WITHDRAW_AMOUNT,
      );

      // Report the public SOL withdrawal.
      const solanaBalance = await client.getBalance(senderSigner.address);
      console.log(`withdraw solana_balance=${solanaBalance} tx=${withdrawalSignature}`);
    } finally {
      await stack.stop();
    }
  }, 600_000);
});
