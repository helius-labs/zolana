import { p256 } from "@noble/curves/nist.js";
import { address, getAddressDecoder, getAddressEncoder, type Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { InstructionTag } from "../src/interface/program.js";
import type { Bytes32, Signature } from "../src/interface/types.js";
import {
  AUDIT_ENC_INFO,
  auditSharedSecret,
  auditorViewTag,
  parseAuditorMessage,
} from "../src/keypair/audit.js";
import { bigIntToBytes, bytesToBigInt } from "../src/keypair/bytes.js";
import { symmetricApply } from "../src/keypair/merge/index.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { SigningKey } from "../src/keypair/signing-key.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import {
  auditRing,
  auditRingTransaction,
  auditorMessage,
  recoverTransactionViewingKey,
} from "../src/ring/audit.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../src/interface/program.js";
import { StateDiscriminator } from "../src/interface/state.js";
import { assemble, ownerSignerAddresses } from "../src/client/prover/assembly.js";
import { ringAuditReader, ringTransferClient, transactionsPage } from "./helpers/clients.js";
import type { SpendProof } from "../src/client/rpc.js";
import { hashBytesBigInt } from "../src/client/internal.js";
import {
  frameDummyOutputs,
  checkRingMembership,
  proveCustomRingTransfer,
} from "../src/ring/transfer.js";
import {
  ConfidentialTransfer,
  type IndexedShieldedTransaction,
  type PreparedTransfer,
  type SppProofInputs,
} from "../src/transaction/instructions/transact.js";
import { EncryptedScheme, readOutputData } from "../src/transaction/serialization/codecs.js";
import { ProofInputUtxo, Utxo } from "../src/transaction/utxo.js";
import { AssetRegistry, SOL_MINT } from "../src/transaction/asset.js";
import { KeypairWalletAuthority } from "../src/transaction/wallet/authority.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");

function scalar(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}

function actor(seed: number) {
  const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(scalar(seed)));
  const solanaPublicKey = getAddressDecoder().decode(
    keypair.signingPublicKey().toBytes().subarray(1),
  );
  return {
    keypair,
    authority: new KeypairWalletAuthority({ solanaPublicKey, keypair }),
    address: keypair.shieldedAddress(),
  };
}

/** A 10 SOL ring UTXO of `sender` sending `amount` to `recipient` and `others`. */
function preparedTransfer(
  amount: bigint,
  others: readonly bigint[] = [],
  exits: readonly bigint[] = [],
  inputRing: typeof RING | null = RING,
  asset: Address = SOL_MINT,
  payer?: Address,
): Readonly<{
  prepared: PreparedTransfer;
  sender: ReturnType<typeof actor>;
  recipient: ReturnType<typeof actor>;
}> {
  const sender = actor(3);
  const recipient = actor(4);
  const input = new ProofInputUtxo({
    utxo: new Utxo({
      owner: sender.keypair.signingPublicKey(),
      asset,
      amount: 10n,
      blinding: scalar(6),
      ...(inputRing === null ? {} : { ringProgramId: inputRing }),
    }),
    nullifierKey: sender.keypair.nullifierKey(),
  });
  const transfer = new ConfidentialTransfer(
    sender.address,
    [input],
    payer ?? sender.address.solanaAddress(),
  )
    .withCompactChange()
    .withRingProgramId(RING);
  transfer.send(recipient.address, asset, amount);
  others.forEach((other, index) => transfer.send(actor(5 + index).address, asset, other));
  exits.forEach((exit, index) => transfer.sendDefaultRing(actor(20 + index).address, asset, exit));
  return { prepared: transfer.prepare(), sender, recipient };
}

async function auditedProofInputs(
  amount: bigint,
  auditor: ViewingKey,
  others: readonly bigint[] = [],
  exits: readonly bigint[] = [],
  inputRing: typeof RING | null = RING,
  asset: Address = SOL_MINT,
  assets: AssetRegistry = new AssetRegistry(),
  payer?: Address,
): Promise<Readonly<{ proofInputs: SppProofInputs; recipient: ReturnType<typeof actor> }>> {
  const {
    prepared: ring,
    sender,
    recipient,
  } = preparedTransfer(amount, others, exits, inputRing, asset, payer);
  const encrypted = await sender.authority.withSpendSession((session) =>
    session.encryptCustomRingTransfer({
      firstNullifier: ring.firstNullifier,
      outputs: ring.outputs,
      assets,
      auditorPublicKey: auditor.publicKey(),
    }),
  );
  const proofInputs = frameDummyOutputs(
    ring.finalize({
      txViewingPublicKey: encrypted.txViewingPublicKey,
      salt: encrypted.salt,
      payload: encrypted.payload,
      messages: [encrypted.auditorMessage],
      instructionDiscriminator: InstructionTag.ringTransact,
    }),
  );
  return { proofInputs, recipient };
}

function indexed(proofInputs: SppProofInputs): IndexedShieldedTransaction {
  const external = proofInputs.externalData;
  return {
    slot: 5n,
    txSignature: "1".repeat(87) as Signature,
    txViewingPublicKey: external.txViewingPublicKey,
    salt: external.salt,
    outputSlots: external.outputs.map((output, index) => ({
      viewTag: external.resolvedOwnerTags[index] ?? scalar(0),
      outputContext: { hash: output.utxoHash, tree: RING, leafIndex: BigInt(index) },
      payload: output.data ?? new Uint8Array(),
    })),
    messages: external.messages,
    nullifiers: proofInputs.inputUtxos.map((input) => input.nullifier()),
    proofless: false,
  };
}

describe("withCompactChange", () => {
  it("removes unused change slots like Rust `compact_change_removes_unused_change_slots`", () => {
    const compact = preparedTransfer(4n).prepared;
    expect(compact.changeLayout).toBe("compact");
    expect(compact.shape).toEqual({ inputs: 1, outputs: 2 });
    expect(compact.outputs.map((output) => output.amount)).toEqual([6n, 4n]);
    expect(compact.senderOutputCount).toBe(1);
  });

  it("keeps only the recipient after a full spend like Rust `compact_change_keeps_only_the_recipient_after_a_full_spend`", () => {
    const compact = preparedTransfer(10n).prepared;
    expect(compact.shape).toEqual({ inputs: 1, outputs: 1 });
    expect(compact.outputs.map((output) => output.amount)).toEqual([10n]);
    expect(compact.senderOutputCount).toBe(0);
  });

  it("keeps both slots under the padded default like Rust `padded_change_keeps_both_slots`", () => {
    const sender = actor(3);
    const recipient = actor(4);
    const input = new ProofInputUtxo({
      utxo: new Utxo({
        owner: sender.keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 10n,
        blinding: scalar(6),
        ringProgramId: RING,
      }),
      nullifierKey: sender.keypair.nullifierKey(),
    });
    const transfer = new ConfidentialTransfer(
      sender.address,
      [input],
      sender.address.solanaAddress(),
    );
    transfer.send(recipient.address, SOL_MINT, 4n);
    const padded = transfer.prepare();
    expect(padded.changeLayout).toBe("padded");
    expect(padded.senderOutputCount).toBe(2);
    expect(padded.outputs).toHaveLength(3);
  });

  it("binds the change and the recipients to the ring the transfer runs in", () => {
    const ring = preparedTransfer(4n).prepared;
    expect(ring.outputs.every((output) => output.ringProgramId === RING)).toBe(true);
  });

  it("moves an exact amount into a ring and keeps default change", () => {
    const sender = actor(3);
    const input = new ProofInputUtxo({
      utxo: new Utxo({
        owner: sender.keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 10n,
        blinding: scalar(6),
      }),
      nullifierKey: sender.keypair.nullifierKey(),
    });
    const transfer = new ConfidentialTransfer(
      sender.address,
      [input],
      sender.address.solanaAddress(),
    ).withCompactChange();
    transfer.sendToRing(sender.address, SOL_MINT, 4n, RING);

    const prepared = transfer.prepare();

    expect(prepared.senderOutputCount).toBe(1);
    expect(prepared.outputs.map((output) => [output.amount, output.ringProgramId])).toEqual([
      [6n, undefined],
      [4n, RING],
    ]);
  });

  it("keeps a default-ring recipient out of the ring and refuses a foreign one", () => {
    const sender = actor(3);
    const input = new ProofInputUtxo({
      utxo: new Utxo({
        owner: sender.keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 10n,
        blinding: scalar(6),
        ringProgramId: RING,
      }),
      nullifierKey: sender.keypair.nullifierKey(),
    });
    const transfer = new ConfidentialTransfer(
      sender.address,
      [input],
      sender.address.solanaAddress(),
    )
      .withCompactChange()
      .withRingProgramId(RING);
    transfer.sendDefaultRing(actor(4).address, SOL_MINT, 4n);
    const prepared = transfer.prepare();
    expect(prepared.outputs.map((output) => output.ringProgramId)).toEqual([RING, undefined]);

    const foreign = prepared.outputs[1]?.withRingProgramId(actor(9).address.solanaAddress());
    expect(() =>
      checkRingMembership({ ...prepared, outputs: [prepared.outputs[0]!, foreign!] }, RING),
    ).toThrow("RING_FOREIGN_RING");
  });

  it("refuses ring data on a default UTXO like Rust `RingMembership`", () => {
    const sender = actor(3);
    const tainted = new ProofInputUtxo({
      utxo: new Utxo({
        owner: sender.keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 10n,
        blinding: scalar(6),
      }),
      nullifierKey: sender.keypair.nullifierKey(),
      ringDataHash: scalar(9),
    });
    const transfer = new ConfidentialTransfer(
      sender.address,
      [tainted],
      sender.address.solanaAddress(),
    )
      .withCompactChange()
      .withRingProgramId(RING);
    transfer.send(actor(4).address, SOL_MINT, 4n);
    // The builder refuses before membership runs.
    expect(() => transfer.prepare()).toThrow("TRANSACTION_MISSING_RING_PROGRAM_ID");

    const { prepared } = preparedTransfer(4n);
    expect(() => checkRingMembership({ ...prepared, inputs: [tainted] }, RING)).toThrow(
      "RING_DATA_OUTSIDE_RING",
    );
  });
});

describe("frameDummyOutputs", () => {
  it("frames dummy slots as confidential bodies of the real length like Rust `frame_dummy_outputs`", async () => {
    // Five real outputs pad to the (1, 8) shape.
    const { proofInputs } = await auditedProofInputs(4n, ViewingKey.generate(), [1n, 1n, 1n]);
    expect(proofInputs.outputs).toHaveLength(8);
    const external = proofInputs.externalData;
    const lengths = external.outputs.map((output) => output.data?.length);
    expect(new Set(lengths).size).toBe(1);
    const dummies = proofInputs.outputs.flatMap((output, index) =>
      output.isDummy() ? [index] : [],
    );
    expect(dummies.length).toBeGreaterThanOrEqual(1);
    const keys = dummies.map((index) => {
      const frame = readOutputData(external.outputs[index]?.data ?? new Uint8Array());
      expect(frame.encoding).toBe("encrypted");
      expect(frame.scheme).toBe(EncryptedScheme.confidential);
      expect([2, 3]).toContain(frame.body[0]);
      return Buffer.from(frame.body.subarray(0, 33)).toString("hex");
    });
    expect(new Set(keys).size).toBe(keys.length);
    for (const [index, output] of proofInputs.outputs.entries()) {
      if (output.isDummy()) continue;
      const frame = readOutputData(external.outputs[index]?.data ?? new Uint8Array());
      expect(frame.scheme).toBe(EncryptedScheme.ringConfidential);
    }
    expect(external.instructionDiscriminator).toBe(InstructionTag.ringTransact);
    expect(external.messages).toHaveLength(1);
  });
});

describe("frameDummyOutputs with an exit", () => {
  it("frames a dummy after the default-ring slot, 32 bytes shorter than a ring slot", async () => {
    const { proofInputs } = await auditedProofInputs(3n, ViewingKey.generate(), [1n, 1n], [1n]);
    expect(proofInputs.outputs).toHaveLength(8);
    const external = proofInputs.externalData;
    const lengthOf = (index: number): number => external.outputs[index]?.data?.length ?? 0;
    const ringSlot = proofInputs.outputs.findIndex(
      (output) => !output.isDummy() && output.ringProgramId === RING,
    );
    const exitSlot = proofInputs.outputs.findIndex(
      (output) => !output.isDummy() && output.ringProgramId === undefined,
    );
    expect(lengthOf(ringSlot) - lengthOf(exitSlot)).toBe(32);
    for (const [index, output] of proofInputs.outputs.entries()) {
      if (!output.isDummy()) continue;
      expect(lengthOf(index)).toBe(lengthOf(exitSlot));
      const frame = readOutputData(external.outputs[index]?.data ?? new Uint8Array());
      expect(frame.scheme).toBe(EncryptedScheme.confidential);
    }
  });
});

function spendProofFor(input: ProofInputUtxo): SpendProof {
  return {
    state: {
      leaf: input.hash(),
      merkleContext: { treeType: 0, tree: RING },
      path: Array.from({ length: 32 }, () => scalar(0)),
      leafIndex: 0n,
      root: scalar(3),
      rootSeq: 1n,
      rootIndex: 4,
    },
    nullifier: {
      leaf: input.nullifier(),
      merkleContext: { treeType: 1, tree: RING },
      path: Array.from({ length: 40 }, () => scalar(0)),
      lowElement: scalar(4),
      lowElementIndex: 0n,
      highElement: scalar(5),
      highElementIndex: 1n,
      root: scalar(6),
      rootSeq: 1n,
      rootIndex: 7,
    },
  };
}

describe("ring witness", () => {
  it("publishes owner hashes only for `Confidential` slots like Rust `confidential_marked_output_owner_pk_hashes`", async () => {
    const { proofInputs } = await auditedProofInputs(4n, ViewingKey.generate(), [1n, 1n, 1n]);
    const input = proofInputs.inputUtxos[0];
    if (!input) throw new Error("input");
    const spendProof = spendProofFor(input);
    const assembled = assemble(proofInputs, [spendProof], [], RING);
    const published = assembled.proverInputs.payload.publishedOutputOwnerPublicKeyHashes;
    const tags = proofInputs.externalData.resolvedOwnerTags;
    expect(published).toHaveLength(8);
    proofInputs.outputs.forEach((output, index) => {
      const tag = tags[index];
      if (!tag) throw new Error("owner tag");
      expect(published[index]).toBe(output.isDummy() ? hashBytesBigInt(tag) : 0n);
    });
    expect(assembled.proverInputs.circuit).toBe("transferRing");
    expect(assembled.proverInputs.payload.ringProgramId).toBe(
      hashBytesBigInt(new Uint8Array(getAddressEncoder().encode(RING))),
    );
    expect(assembled.instructionData.circuit.kind).toBe("ringEddsa");
  });

  it("assembles a foreign fee payer with the owner as an appended signer", async () => {
    const payer = actor(8).address.solanaAddress();
    const owner = actor(3);
    const { proofInputs } = await auditedProofInputs(
      4n,
      ViewingKey.generate(),
      [],
      [],
      RING,
      SOL_MINT,
      new AssetRegistry(),
      payer,
    );
    const input = proofInputs.inputUtxos[0];
    if (!input) throw new Error("input");
    const assembled = assemble(proofInputs, [spendProofFor(input)], [], RING);
    const vector = assembled.proverInputs.payload.signerPublicKeyHashes;
    const hashOf = (target: Address) =>
      hashBytesBigInt(new Uint8Array(getAddressEncoder().encode(target)));
    expect(vector[0]).toBe(hashOf(payer));
    expect(vector[1]).toBe(hashOf(owner.address.solanaAddress()));
    expect(vector.slice(2).every((entry) => entry === 0n)).toBe(true);
    expect(ownerSignerAddresses(proofInputs.inputUtxos, payer)).toEqual([
      owner.address.solanaAddress(),
    ]);
  });

  it("refuses a tree the client does not prove from, before any fetch", async () => {
    const client = ringTransferClient({ tree: RING });
    await expect(
      proveCustomRingTransfer({
        client,
        ringProgramId: RING,
        prepared: {} as PreparedTransfer,
        session: {
          encryptCustomRingTransfer: (request) =>
            actor(3).authority.withSpendSession((session) =>
              session.encryptCustomRingTransfer(request),
            ),
        },
        assets: new AssetRegistry(),
        tree: actor(8).address.solanaAddress(),
      }),
    ).rejects.toThrow("RING_TREE_MISMATCH");
  });

  it("destroys only its own clone of the nullifier key", () => {
    const owner = actor(3);
    const nullifierKey = owner.keypair.nullifierKey();
    const input = new ProofInputUtxo({
      utxo: new Utxo({
        owner: owner.keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 5n,
        blinding: scalar(1),
      }),
      nullifierKey,
    });
    input.destroy();
    expect(() => input.nullifierKey.publicKey()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
    expect(nullifierKey.publicKey()).toEqual(owner.keypair.nullifierKey().publicKey());
  });

  it("derives non-payer owner signers like Rust `owner_signer_pubkeys`", () => {
    const owner = actor(3);
    const payer = actor(8).address.solanaAddress();
    const input = (blinding: number) =>
      new ProofInputUtxo({
        utxo: new Utxo({
          owner: owner.keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: 5n,
          blinding: scalar(blinding),
        }),
        nullifierKey: owner.keypair.nullifierKey(),
      });
    const ownerAddress = owner.address.solanaAddress();
    expect(ownerSignerAddresses([input(1), input(2)], payer)).toEqual([ownerAddress]);
    expect(ownerSignerAddresses([input(1), input(2)], ownerAddress)).toEqual([]);
  });

  it("keeps a default UTXO's zero ring fields under the signing ring public input", async () => {
    const { proofInputs } = await auditedProofInputs(4n, ViewingKey.generate(), [], [], null);
    const input = proofInputs.inputUtxos[0];
    if (!input) throw new Error("input");
    const assembled = assemble(proofInputs, [spendProofFor(input)], [], RING);
    const slot = assembled.proverInputs.payload.inputs[0];
    if (!slot) throw new Error("input slot");
    expect(slot.circuit.ringProgramId).toBe(0n);
    expect(slot.circuit.ringDataHash).toBe(0n);
    const vector = assembled.proverInputs.payload.signerPublicKeyHashes;
    expect(vector.slice(1).every((entry) => entry === 0n)).toBe(true);
    expect(assembled.proverInputs.payload.ringProgramId).toBe(
      hashBytesBigInt(new Uint8Array(getAddressEncoder().encode(RING))),
    );
    proofInputs.outputs
      .filter((output) => !output.isDummy())
      .forEach((output) => expect(output.ringProgramId).toBe(RING));
  });
});

describe("ring audit", () => {
  it("opens every real slot with the recovered transaction key like Rust `TransactionAudit`", async () => {
    const auditor = ViewingKey.generate();
    const { proofInputs, recipient } = await auditedProofInputs(4n, auditor, [1n, 1n, 1n]);
    const transaction = indexed(proofInputs);
    const audited = auditRingTransaction({ auditor, transaction, assets: new AssetRegistry() });
    expect(audited.signature).toBe(transaction.txSignature);
    expect(audited.txViewingPublicKey.toBytes()).toEqual(
      proofInputs.externalData.txViewingPublicKey.toBytes(),
    );
    expect(audited.outputs.map((output) => [output.slotIndex, output.amount])).toEqual([
      [0, 3n],
      [1, 4n],
      [2, 1n],
      [3, 1n],
      [4, 1n],
    ]);
    expect(audited.outputs[1]?.recipientViewingPublicKey.toBytes()).toEqual(
      recipient.address.viewingPublicKey.toBytes(),
    );
    expect(audited.outputs.every((output) => output.ringProgramId === RING)).toBe(true);
    expect(audited.undecryptableSlots).toEqual([5, 6, 7]);
  });

  it("accepts the auditor message only as the unique last entry", async () => {
    const auditor = ViewingKey.generate();
    const { proofInputs } = await auditedProofInputs(4n, auditor);
    const transaction = indexed(proofInputs);
    const message = transaction.messages[0];
    if (!message) throw new Error("auditor message");
    const other = { viewTag: scalar(1), data: Uint8Array.of(9) };
    expect(() => auditorMessage({ ...transaction, messages: [] }, auditor.publicKey())).toThrow(
      "RING_AUDIT_MESSAGE",
    );
    expect(() =>
      auditorMessage({ ...transaction, messages: [message, message] }, auditor.publicKey()),
    ).toThrow("RING_AUDIT_MESSAGE");
    expect(() =>
      auditorMessage({ ...transaction, messages: [message, other] }, auditor.publicKey()),
    ).toThrow("RING_AUDIT_MESSAGE");
    expect(
      auditorMessage(
        { ...transaction, messages: [other, message] },
        auditor.publicKey(),
      ).ephemeralPublicKey.toBytes(),
    ).toEqual(parseAuditorMessage(message.data).ephemeralPublicKey.toBytes());
    expect(() =>
      auditRingTransaction({
        auditor,
        transaction: { ...transaction, txViewingPublicKey: auditor.publicKey() },
        assets: new AssetRegistry(),
      }),
    ).toThrow("RING_AUDIT_KEY_MISMATCH");
    expect(auditorViewTag(auditor.publicKey())).toEqual(message.viewTag);
  });

  it("resolves an SPL output through the registry and refuses an unknown id", async () => {
    const auditor = ViewingKey.generate();
    const mint = getAddressDecoder().decode(scalar(41));
    const registry = new AssetRegistry([[2n, mint]]);
    const { proofInputs } = await auditedProofInputs(4n, auditor, [], [], RING, mint, registry);
    const transaction = indexed(proofInputs);
    expect(() =>
      auditRingTransaction({ auditor, transaction, assets: new AssetRegistry() }),
    ).toThrow("TRANSACTION_UNKNOWN_ASSET");
    const audited = auditRingTransaction({ auditor, transaction, assets: registry });
    expect(audited.outputs.length).toBeGreaterThan(0);
    expect(audited.outputs.every((output) => output.asset === mint)).toBe(true);
  });

  it("refreshes the registry once from the chain on an unknown asset id", async () => {
    const auditor = ViewingKey.generate();
    const mint = getAddressDecoder().decode(scalar(41));
    const { proofInputs } = await auditedProofInputs(
      4n,
      auditor,
      [],
      [],
      RING,
      mint,
      new AssetRegistry([[2n, mint]]),
    );
    const transaction = indexed(proofInputs);
    const registryBytes = new Uint8Array(48);
    registryBytes[0] = StateDiscriminator.splAssetRegistry;
    registryBytes.set(new Uint8Array(getAddressEncoder().encode(mint)), 8);
    new DataView(registryBytes.buffer).setBigUint64(40, 2n, true);
    const getProgramAccounts = vi.fn(() => ({
      send: async () => [
        {
          account: {
            owner: SHIELDED_POOL_PROGRAM_ID,
            data: [Buffer.from(registryBytes).toString("base64"), "base64"],
          },
        },
      ],
    }));
    const client = ringAuditReader({
      getShieldedTransactionsByTags: async () =>
        transactionsPage({ transactions: [transaction, transaction] }),
      solanaRpc: { getProgramAccounts },
      commitment: "confirmed",
    });

    const assets = new AssetRegistry();
    const page = await auditRing({
      client,
      auditor,
      ringProgramId: RING,
      assets,
      origin: { ringInvoked: async () => true },
    });

    expect(page.transactions).toHaveLength(2);
    for (const audited of page.transactions) {
      expect(audited.outputs.length).toBeGreaterThan(0);
      expect(audited.outputs.every((output) => output.asset === mint)).toBe(true);
    }
    expect(getProgramAccounts).toHaveBeenCalledTimes(1);
    expect(assets.resolve(2n)).toBe(mint);
  });

  it("throws after one refresh when the chain does not know the id either", async () => {
    const auditor = ViewingKey.generate();
    const mint = getAddressDecoder().decode(scalar(41));
    const { proofInputs } = await auditedProofInputs(
      4n,
      auditor,
      [],
      [],
      RING,
      mint,
      new AssetRegistry([[2n, mint]]),
    );
    const transaction = indexed(proofInputs);
    const getProgramAccounts = vi.fn(() => ({ send: async () => [] }));
    const client = ringAuditReader({
      getShieldedTransactionsByTags: async () => transactionsPage({ transactions: [transaction] }),
      solanaRpc: { getProgramAccounts },
      commitment: "confirmed",
    });

    await expect(
      auditRing({
        client,
        auditor,
        ringProgramId: RING,
        assets: new AssetRegistry(),
        origin: { ringInvoked: async () => true },
      }),
    ).rejects.toThrow("TRANSACTION_UNKNOWN_ASSET");
    expect(getProgramAccounts).toHaveBeenCalledTimes(1);
  });

  it("reduces a noncanonical scalar like Rust `recovery_reduces_a_noncanonical_scalar`", () => {
    const auditor = ViewingKey.generate();
    const secret = bigIntToBytes(0x0123_4567_89ab_cdefn) as Bytes32;
    const viewingKey = ViewingKey.fromBytes(secret);
    const shifted = bigIntToBytes(bytesToBigInt(secret) + p256.Point.Fn.ORDER) as Bytes32;
    const ephemeral = ViewingKey.generate();
    const shared = auditSharedSecret(
      ephemeral.ecdh(auditor.publicKey()),
      ephemeral.publicKey(),
      auditor.publicKey(),
    );
    const ciphertext = symmetricApply(shared, AUDIT_ENC_INFO, shifted) as Bytes32;
    const recovered = recoverTransactionViewingKey(auditor, {
      ephemeralPublicKey: ephemeral.publicKey(),
      ciphertext,
    });
    expect(recovered.publicKey().toBytes()).toEqual(viewingKey.publicKey().toBytes());
  });
});
