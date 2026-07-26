/// <reference types="node" />

import { waitForIndexer } from "@zolana/client";
import { depositInstruction, transactInstruction } from "@zolana/interface/instructions";
import { randomBlinding } from "@zolana/keypair";
import {
  ConfidentialTransfer,
  ProofInputUtxo,
  SOL_MINT,
  Wallet,
  ownerUtxoHash,
} from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import { setup, type ExampleContext, type ExampleParticipant } from "./setup.js";

const DEPOSIT_AMOUNT = 1_000_000_000n;
const TRANSFER_AMOUNT = 300_000_000n;
const WITHDRAW_AMOUNT = 300_000_000n;

/**
 * Read a participant's confidential balance the way Rust's example does: pull
 * the transactions carrying their view tag, then decrypt them into a wallet of
 * their own.
 *
 * `syncWallet` is the alternative, and the one an application wants: it walks
 * the tag ranges, pages both indexer endpoints, and keeps one wallet up to
 * date. This example stays at the level Rust's does, one query and one decrypt.
 */
async function balances(
  context: ExampleContext,
  participant: ExampleParticipant,
): Promise<Wallet> {
  const response = await context.client.getShieldedTransactionsByTags(
    { tags: [participant.keypair.shieldedAddress().confidentialViewTag()], limit: 50 },
    waitForIndexer(),
  );
  return await Wallet.decrypt({
    authority: participant.authority,
    transactions: response.transactions,
    assets: context.assets,
  });
}

function spendable(wallet: Wallet, participant: ExampleParticipant): ProofInputUtxo {
  const utxo = wallet.balance(SOL_MINT).utxos[0];
  if (utxo === undefined) throw new Error("no spendable SOL note");
  return ProofInputUtxo.fromKeypair(utxo, participant.keypair);
}

describe("example: deposit, transfer, withdraw", () => {
  it("moves SOL into the pool, to a second wallet, and back out", async () => {
    const context = await setup({ portOffset: Number(process.env["ZOLANA_PORT_OFFSET"] ?? "500") });
    const { client, tree, sender, recipient } = context;
    try {
      // 1. The sender deposits SOL into their confidential balance.
      const senderAddress = sender.keypair.shieldedAddress();
      const blinding = randomBlinding();
      const owner = senderAddress.ownerHash();
      await client.createAndSendTransaction({
        instructions: [
          depositInstruction({
            tree,
            depositor: sender.address,
            data: {
              viewTag: senderAddress.confidentialViewTag(),
              owner,
              blinding,
              amount: DEPOSIT_AMOUNT,
            },
          }),
        ],
        feePayer: sender.signer,
      });

      const afterDeposit = await balances(context, sender);
      expect(afterDeposit.balance(SOL_MINT).amount).toBe(DEPOSIT_AMOUNT);
      expect(afterDeposit.balance(SOL_MINT).utxos).toHaveLength(1);
      // A deposit note is public, so its commitment is reproducible.
      expect(afterDeposit.utxos()[0]?.outputContext.hash).toEqual(
        ownerUtxoHash({ owner, asset: SOL_MINT, amount: DEPOSIT_AMOUNT, blinding }),
      );

      // 2. The sender transfers part of it to the recipient's confidential balance.
      const transfer = new ConfidentialTransfer(
        senderAddress,
        [spendable(afterDeposit, sender)],
        sender.address,
      );
      transfer.send(recipient.keypair.shieldedAddress(), SOL_MINT, TRANSFER_AMOUNT);
      const transferData = await client.proveTransact(
        transfer.sign(sender.keypair, context.assets),
        waitForIndexer(),
      );
      const transferSignature = await client.createAndSendTransaction({
        instructions: [transactInstruction({ payer: sender.address, tree, data: transferData })],
        feePayer: sender.signer,
      });
      await client.confirmPrivateTransaction(transferSignature);

      expect((await balances(context, recipient)).balance(SOL_MINT).amount).toBe(TRANSFER_AMOUNT);
      const afterTransfer = await balances(context, sender);
      expect(afterTransfer.balance(SOL_MINT).amount).toBe(DEPOSIT_AMOUNT - TRANSFER_AMOUNT);
      expect(afterTransfer.balance(SOL_MINT).utxos).toHaveLength(1);

      // 3. The sender withdraws back to their own Solana account.
      const solanaBefore = await client.getBalance(sender.address);
      const withdrawal = new ConfidentialTransfer(
        senderAddress,
        [spendable(afterTransfer, sender)],
        sender.address,
      );
      withdrawal.withdraw(SOL_MINT, WITHDRAW_AMOUNT, { kind: "sol", recipient: sender.address });
      const withdrawalData = await client.proveTransact(
        withdrawal.sign(sender.keypair, context.assets),
        waitForIndexer(),
      );
      const withdrawalSignature = await client.createAndSendTransaction({
        instructions: [
          transactInstruction({
            payer: sender.address,
            tree,
            withdrawal: { kind: "sol", recipient: sender.address },
            data: withdrawalData,
          }),
        ],
        feePayer: sender.signer,
      });
      await client.confirmPrivateTransaction(withdrawalSignature);

      const afterWithdrawal = await balances(context, sender);
      expect(afterWithdrawal.balance(SOL_MINT).amount).toBe(
        DEPOSIT_AMOUNT - TRANSFER_AMOUNT - WITHDRAW_AMOUNT,
      );
      // Fees come out of the same account, so the withdrawal only has to leave
      // the sender better off than they started.
      expect(await client.getBalance(sender.address)).toBeGreaterThan(solanaBefore);
    } finally {
      await context.stop();
    }
  }, 600_000);
});
