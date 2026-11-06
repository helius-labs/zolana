import { expect, it } from "vitest";

import {
  ShieldedKeypair,
  ViewingKey,
  randomBlinding,
  randomSalt,
} from "../../src/keypair/index.js";
import {
  AssetRegistry,
  ConfidentialTransfer,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  createExternalData,
  encodeConfidentialSlots,
} from "../../src/transaction/index.js";

it("encrypts a payment memo in transaction messages while keeping UTXO data empty", () => {
  const sender = ShieldedKeypair.generate();
  const recipient = ShieldedKeypair.generate();
  const senderViewing = sender.viewingKey();
  const recipientViewing = recipient.viewingKey();
  let transactionViewing: ViewingKey | undefined;

  try {
    const senderAddress = sender.shieldedAddress();
    const recipientAddress = recipient.shieldedAddress();
    const input = ProofInputUtxo.fromKeypair(
      new Utxo({
        owner: sender.signingPublicKey(),
        asset: SOL_MINT,
        amount: 100n,
        blinding: randomBlinding(),
      }),
      sender,
    );
    const transfer = new ConfidentialTransfer(
      senderAddress,
      [input],
      senderAddress.solanaAddress(),
    ).withShape({ inputs: 1, outputs: 4 });
    transfer.send(recipientAddress, SOL_MINT, 30n);
    const prepared = transfer.prepare();
    const outputs = prepared.proofOutputs();
    transactionViewing = senderViewing.transactionViewingKey(prepared.firstNullifier);
    const salt = randomSalt();
    const payload = encodeConfidentialSlots(outputs, new AssetRegistry(), transactionViewing, salt);

    // Message ordinals follow the output ciphertexts, including padded outputs.
    const memoSlot = outputs.length;
    const memo = new TextEncoder().encode("invoice:1042");
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
            memoSlot,
          ),
        },
      ],
    });

    // The recipient reads these fields from the indexed transaction.
    const externalData = proofInputs.externalData;
    const [message] = externalData.messages;
    if (message === undefined) throw new Error("expected the payment memo message");
    const decryptedMemo = recipientViewing.decryptUtxo(
      message.data,
      externalData.txViewingPublicKey,
      externalData.salt,
      externalData.outputs.filter((output) => output.data !== undefined).length,
    );

    expect(externalData.messages).toHaveLength(1);
    expect(message.viewTag).toEqual(recipientAddress.confidentialViewTag());
    expect(message.data).not.toEqual(memo);
    expect(new TextDecoder().decode(decryptedMemo)).toBe("invoice:1042");
    expect(externalData.outputs).toHaveLength(4);
    expect(proofInputs.outputs.map((output) => output.amount)).toEqual([70n, 30n, 0n, 0n]);
    expect(proofInputs.outputs.map((output) => output.data.records())).toEqual([[], [], [], []]);

    // The transaction authorizes the message bytes through its external data hash.
    const withoutMemo = createExternalData({ ...externalData, messages: [] });
    expect(externalData.hash()).not.toEqual(withoutMemo.hash());
  } finally {
    transactionViewing?.destroy();
    recipientViewing.destroy();
    senderViewing.destroy();
    recipient.destroy();
    sender.destroy();
  }
});
