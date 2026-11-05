import { expect, it } from "vitest";

import { atSlot } from "../../src/client/index.js";
import { compileUnsignedTransaction } from "../../src/flows/compile.js";
import { transactInstruction } from "../../src/interface/index.js";
import { ViewingKey, randomSalt } from "../../src/keypair/index.js";
import {
  AssetRegistry,
  ConfidentialTransfer,
  ProofInputUtxo,
  SOL_MINT,
  decryptToBalances,
  encodeConfidentialSlots,
} from "../../src/transaction/index.js";
import { buildDepositTransaction } from "../../src/wallet/index.js";
import { actor, fund, hex, liveHarness, signSendAndConfirm, sync } from "./live-helpers.js";

it("sends an encrypted payment memo, fetches the transaction, and decrypts it as the recipient", async () => {
  const { client, tree } = await liveHarness();
  const sender = await actor(client, 201);
  const recipient = await actor(client, 202);
  const senderAddress = sender.keypair.shieldedAddress();
  const recipientAddress = recipient.keypair.shieldedAddress();
  const senderViewing = sender.keypair.viewingKey();
  const recipientViewing = recipient.keypair.viewingKey();
  let transactionViewing: ViewingKey | undefined;

  try {
    await fund(client, sender);
    const deposit = await buildDepositTransaction({
      client,
      feePayer: sender.signer.address,
      recipient: senderAddress,
      amount: 1_000_000n,
    });
    await signSendAndConfirm(client, deposit, [sender.signer]);
    await sync(client, sender);
    const [deposited] = sender.wallet
      .utxos()
      .filter((entry) => !entry.spent && entry.utxo.asset === SOL_MINT && entry.utxo.amount > 0n);
    if (deposited === undefined) throw new Error("expected the deposited SOL UTXO");

    const input = ProofInputUtxo.fromKeypair(deposited.utxo, sender.keypair);
    const transfer = new ConfidentialTransfer(
      senderAddress,
      [input],
      sender.signer.address,
    ).withShape({ inputs: 1, outputs: 4 });
    transfer.send(recipientAddress, SOL_MINT, 300_000n);
    const prepared = transfer.prepare();
    const outputs = prepared.proofOutputs();
    transactionViewing = senderViewing.transactionViewingKey(prepared.firstNullifier);
    const salt = randomSalt();
    const payload = encodeConfidentialSlots(
      outputs,
      sender.wallet.registry,
      transactionViewing,
      salt,
    );
    const memo = new TextEncoder().encode("invoice:1042");
    // Messages continue the ciphertext ordinals after outputs, including padding.
    const proofInputs = prepared.finalize({
      txViewingPublicKey: transactionViewing.publicKey(),
      salt,
      payload,
      messages: [
        {
          viewTag: recipientAddress.confidentialViewTag(),
          data: transactionViewing.encryptSlot(
            recipientAddress.viewingPublicKey,
            memo,
            salt,
            outputs.length,
          ),
        },
      ],
    });

    const proved = await client.proveTransact(proofInputs, sender.keys);
    const instruction = await transactInstruction({
      payer: sender.signer,
      ownerSigners: [sender.signer],
      inputTree: tree,
      outputTree: tree,
      data: proved,
    });
    const transaction = compileUnsignedTransaction({
      feePayer: sender.signer.address,
      lifetime: await client.getLatestBlockhash(),
      instructions: [instruction],
      computeUnitLimit: 450_000,
    });
    const signature = await signSendAndConfirm(client, transaction, [sender.signer]);
    const landedSlot = await client.confirmTransaction(signature);

    // Fetch the confirmed transaction from Photon; decryption below uses fetched fields.
    const response = await client.getShieldedTransactionsBySignature(signature, atSlot(landedSlot));
    const fetched = response.transactions[0]?.transaction;
    if (
      fetched === undefined ||
      fetched.txViewingPublicKey === undefined ||
      fetched.salt === undefined
    ) {
      throw new Error("expected the indexed transfer and its encryption metadata");
    }
    const recipientTag = hex(recipientAddress.confidentialViewTag());
    const messageIndex = fetched.messages.findIndex(
      (message) => hex(message.viewTag) === recipientTag,
    );
    const message = fetched.messages[messageIndex];
    if (message === undefined) throw new Error("expected the recipient's indexed memo message");
    const outputCiphertexts = fetched.outputSlots.filter((slot) => slot.payload.length > 0).length;
    const decryptedMemo = recipientViewing.decryptUtxo(
      message.data,
      fetched.txViewingPublicKey,
      fetched.salt,
      outputCiphertexts + messageIndex,
    );

    expect(fetched.txSignature).toBe(signature);
    expect(fetched.messages).toHaveLength(1);
    expect(outputCiphertexts).toBe(4);
    expect(message.data).not.toEqual(memo);
    expect(new TextDecoder().decode(decryptedMemo)).toBe("invoice:1042");

    const balances = await decryptToBalances({
      keypair: recipient.keypair,
      registry: new AssetRegistry(),
      transactions: [fetched],
    });
    const payment = balances.balance(SOL_MINT);
    expect(payment.amount).toBe(300_000n);
    expect(payment.utxos.map((utxo) => utxo.data.records())).toEqual([[]]);
  } finally {
    transactionViewing?.destroy();
    recipientViewing.destroy();
    senderViewing.destroy();
    recipient.keypair.destroy();
    sender.keypair.destroy();
  }
}, 600_000);
