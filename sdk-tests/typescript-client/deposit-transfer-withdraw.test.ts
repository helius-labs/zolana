/// <reference types="node" />

import { SolanaRpc, waitForIndexer, ZolanaClient } from "@zolana/client";
import { depositInstruction, transactInstruction } from "@zolana/interface/instructions";
import { randomBlinding, type ShieldedKeypair } from "@zolana/keypair";
import {
  AssetRegistry,
  ConfidentialTransfer,
  ProofInputUtxo,
  SOL_MINT,
  Wallet,
} from "@zolana/transaction";
import { createSolanaSigner, LocalWalletAuthority, syncWallet } from "@zolana/wallet";
import { describe, it } from "vitest";

import { setup } from "./setup.js";

const DEPOSIT_AMOUNT = 1_000_000_000n;
const TRANSFER_AMOUNT = 300_000_000n;
const WITHDRAW_AMOUNT = 300_000_000n;

function inputUtxo(wallet: Wallet, keypair: ShieldedKeypair): ProofInputUtxo {
  return ProofInputUtxo.fromKeypair(wallet.balance(SOL_MINT).utxos[0]!, keypair);
}

describe("example: deposit, transfer, withdraw", () => {
  it("moves SOL into the pool, to a second wallet, and back out", async () => {
    const { rpcUrl, indexerUrl, proverUrl, tree, sender, recipient, stop } = await setup({
      portOffset: Number(process.env["ZOLANA_PORT_OFFSET"] ?? "500"),
    });
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

      await syncWallet({
        wallet: senderWallet,
        authority: senderAuthority,
        indexer: client.indexer,
        config: { waitForIndexer: true },
      });

      // 2. The sender transfers part of it to the recipient's confidential balance.
      const transfer = new ConfidentialTransfer(
        senderAddress,
        [inputUtxo(senderWallet, sender)],
        senderSigner.address,
      );
      transfer.send(recipient.shieldedAddress(), SOL_MINT, TRANSFER_AMOUNT);
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

      await syncWallet({
        wallet: senderWallet,
        authority: senderAuthority,
        indexer: client.indexer,
        config: { waitForIndexer: true },
      });

      // 3. The sender withdraws back to their own Solana account.
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
    } finally {
      await stop();
    }
  }, 600_000);
});
