/// <reference types="node" />

import { depositInstruction, transactInstruction } from "@zolana/interface/instructions";
import { randomBlinding } from "@zolana/keypair";
import {
  ConfidentialTransfer,
  ProofInputUtxo,
  SOL_MINT,
  ownerUtxoHash,
  type SppProofInputs,
} from "@zolana/transaction";
import { syncWallet } from "@zolana/wallet";
import { sendAndConfirm } from "@zolana/test-kit/node";
import { describe, expect, it } from "vitest";

import { setup, type ExampleContext, type ExampleParticipant } from "./setup.js";

const DEPOSIT_AMOUNT = 1_000_000_000n;
const TRANSFER_AMOUNT = 300_000_000n;
const WITHDRAW_AMOUNT = 300_000_000n;

/**
 * Reading a balance means decrypting the notes the indexer has for this
 * wallet's view tags. `syncWallet` owns the tag walk and the two indexer
 * endpoints deposits and transfers arrive on, so the example reads through it
 * even though it builds every instruction by hand.
 */
async function sync(context: ExampleContext, participant: ExampleParticipant): Promise<void> {
  await syncWallet({
    wallet: participant.wallet,
    authority: participant.authority,
    indexer: context.client.indexer,
    config: { waitForIndexer: true },
  });
}

function spendable(participant: ExampleParticipant): ProofInputUtxo {
  const entry = participant.wallet
    .utxos()
    .find((candidate) => !candidate.spent && candidate.utxo.asset === SOL_MINT);
  if (entry === undefined) throw new Error("no spendable SOL note");
  return new ProofInputUtxo({
    utxo: entry.utxo,
    nullifierKey: participant.keypair.nullifierKey(),
    ...(entry.dataHash === undefined ? {} : { dataHash: entry.dataHash }),
    ...(entry.zoneDataHash === undefined ? {} : { zoneDataHash: entry.zoneDataHash }),
  });
}

/**
 * Turns a built transfer into proof inputs. Rust folds these three steps into
 * `ConfidentialTransfer::sign`; in TypeScript the output ciphertexts come from
 * the wallet authority, so preparing, encrypting, and finalizing are separate.
 */
async function proofInputs(
  context: ExampleContext,
  participant: ExampleParticipant,
  transfer: ConfidentialTransfer,
): Promise<SppProofInputs> {
  const prepared = transfer.prepare();
  const encrypted = await participant.authority.encryptConfidentialTransfer({
    firstNullifier: prepared.firstNullifier,
    outputs: prepared.outputs,
    assets: context.assets,
  });
  return prepared.finalize({
    txViewingPublicKey: encrypted.txViewingPublicKey,
    salt: encrypted.salt,
    payload: encrypted.payload,
  });
}

describe("example: deposit, transfer, withdraw", () => {
  it("moves SOL into the pool, to a second wallet, and back out", async () => {
    const context = await setup({ portOffset: Number(process.env["ZOLANA_PORT_OFFSET"] ?? "500") });
    const { client, tree, sender, recipient } = context;
    try {
      // 1. The sender deposits SOL into their confidential balance.
      {
        const senderAddress = sender.keypair.shieldedAddress();
        const blinding = randomBlinding();
        const owner = senderAddress.ownerHash();
        await sendAndConfirm({
          rpc: client,
          feePayer: sender.address,
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
          keypairs: [sender.native],
        });
        await sync(context, sender);

        expect(sender.wallet.balance(SOL_MINT)?.amount).toBe(DEPOSIT_AMOUNT);
        expect(sender.wallet.utxos()).toHaveLength(1);
        // The deposit note is public, so its commitment is reproducible.
        expect(sender.wallet.utxos()[0]?.outputContext.hash).toEqual(
          ownerUtxoHash({ owner, asset: SOL_MINT, amount: DEPOSIT_AMOUNT, blinding }),
        );
      }

      // 2. The sender transfers part of it to the recipient's confidential balance.
      {
        const transfer = new ConfidentialTransfer(
          sender.keypair.shieldedAddress(),
          [spendable(sender)],
          sender.address,
        );
        transfer.send(recipient.keypair.shieldedAddress(), SOL_MINT, TRANSFER_AMOUNT);
        const data = await proofInputs(context, sender, transfer).then((inputs) =>
          client.proveTransact(inputs),
        );

        const signature = await sendAndConfirm({
          rpc: client,
          feePayer: sender.address,
          instructions: [transactInstruction({ payer: sender.address, tree, data })],
          keypairs: [sender.native],
        });
        await client.confirmPrivateTransaction(signature);

        await sync(context, recipient);
        expect(recipient.wallet.balance(SOL_MINT)?.amount).toBe(TRANSFER_AMOUNT);

        await sync(context, sender);
        expect(sender.wallet.balance(SOL_MINT)?.amount).toBe(DEPOSIT_AMOUNT - TRANSFER_AMOUNT);
      }

      // 3. The sender withdraws back to their own Solana account.
      {
        const before = await client.getBalance(sender.address);
        const withdrawal = new ConfidentialTransfer(
          sender.keypair.shieldedAddress(),
          [spendable(sender)],
          sender.address,
        );
        withdrawal.withdraw(SOL_MINT, WITHDRAW_AMOUNT, {
          kind: "sol",
          recipient: sender.address,
        });
        const data = await proofInputs(context, sender, withdrawal).then((inputs) =>
          client.proveTransact(inputs),
        );

        const signature = await sendAndConfirm({
          rpc: client,
          feePayer: sender.address,
          instructions: [
            transactInstruction({
              payer: sender.address,
              tree,
              withdrawal: { kind: "sol", recipient: sender.address },
              data,
            }),
          ],
          keypairs: [sender.native],
        });
        await client.confirmPrivateTransaction(signature);

        await sync(context, sender);
        expect(sender.wallet.balance(SOL_MINT)?.amount).toBe(
          DEPOSIT_AMOUNT - TRANSFER_AMOUNT - WITHDRAW_AMOUNT,
        );
        // Fees come out of the same account, so the withdrawal only has to
        // leave the sender better off than the amount it moved less fees.
        expect(await client.getBalance(sender.address)).toBeGreaterThan(before);
      }
    } finally {
      await context.stop();
    }
  }, 600_000);
});
