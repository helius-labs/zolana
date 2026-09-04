import { p256 } from "@noble/curves/nist.js";
import {
  ADDRESS_LOOKUP_TABLE_PROGRAM_ADDRESS,
  getAddressLookupTableEncoder,
  getExtendLookupTableInstructionDataDecoder,
} from "@solana-program/address-lookup-table";
import {
  address,
  getAddressDecoder,
  getAddressEncoder,
  getBase64Decoder,
  getCompiledTransactionMessageDecoder,
  getProgramDerivedAddress,
  type Address,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { InstructionTag, SHIELDED_POOL_PROGRAM_ID } from "../src/interface/program.js";
import { StateDiscriminator } from "../src/interface/state.js";
import type {
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes64,
  Signature,
  TransactInstructionData,
} from "../src/interface/types.js";
import {
  AUDIT_ENC_INFO,
  auditPublicInputHash,
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
import { assemble, ownerSignerAddresses, ringOpenings } from "../src/client/prover/assembly.js";
import type {
  CustomRingBaseProofRequest,
  CustomRingPolicyProofRequest,
} from "../src/client/prover/types.js";
import {
  ringAuditReader,
  ringTransferClient,
  solanaRpcReads,
  transactionsPage,
} from "./helpers/clients.js";
import type { SpendProof } from "../src/client/rpc.js";
import { bigintToBytes, hashBytesBigInt, hashChain, poseidon } from "../src/client/internal.js";
import { hashBytes } from "../src/hasher/index.js";
import { ringLookupTableAddresses } from "../src/ring/instructions.js";
import {
  buildRingLookupTableTransaction,
  fetchRingLookupTable,
  type RingLookupTable,
} from "../src/ring/lookup-table.js";
import {
  checkRingMembership,
  frameDummyOutputs,
  proveCustomRingTransfer,
  ringAddressChain,
  ringNamespaceOwnerHash,
  RING_EMPTY_RULES_POLICY_HASH,
  type CustomRingTransferParams,
} from "../src/ring/transfer.js";
import {
  ConfidentialTransfer,
  SppProofInputs,
  privateTxHash,
  type IndexedShieldedTransaction,
  type PreparedTransfer,
} from "../src/transaction/instructions/transact.js";
import { EncryptedScheme, readOutputData } from "../src/transaction/serialization/codecs.js";
import { ProofInputUtxo, Utxo, createProofOutput } from "../src/transaction/utxo.js";
import { AssetRegistry, SOL_MINT } from "../src/transaction/asset.js";
import {
  KeypairWalletAuthority,
  type WalletAuthority,
} from "../src/transaction/wallet/authority.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const ACTIVE_TREE = getAddressDecoder().decode(new Uint8Array(32).fill(44));

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

function spendSession(authority: WalletAuthority): CustomRingTransferParams["session"] {
  return {
    encryptCustomRingTransfer: (request) =>
      authority.withSpendSession((session) => session.encryptCustomRingTransfer(request)),
  };
}

/** The ring's config and, for a policy ring, a policy config over `ACTIVE_TREE` under the empty-table hash with `ruleCount` rows of ones. */
async function ringAccounts(auditor: ViewingKey, hasPolicy: boolean, ruleCount = 0) {
  const encoder = new TextEncoder();
  const pda = (seed: string) =>
    getProgramDerivedAddress({ programAddress: RING, seeds: [encoder.encode(seed)] });
  const [configAddress, configBump] = await pda("config");
  const [policyAddress, policyBump] = await pda("policy");
  const read: Address[] = [];
  const getAccount = async (account: Address) => {
    read.push(account);
    if (account === configAddress) {
      return {
        owner: RING,
        lamports: 1n,
        data: Uint8Array.from([
          1,
          ...new Uint8Array(32),
          ...auditor.publicKey().toBytes(),
          configBump,
          hasPolicy ? 1 : 0,
        ]),
      };
    }
    if (hasPolicy && account === policyAddress) {
      return {
        owner: RING,
        lamports: 1n,
        data: Uint8Array.from([
          3,
          ...RING_EMPTY_RULES_POLICY_HASH,
          ...getAddressEncoder().encode(ACTIVE_TREE),
          0,
          policyBump,
          ...new Uint8Array(33 * 8),
          ruleCount,
          ...new Uint8Array(32 * 16).fill(1, 0, 32 * ruleCount),
          0,
          ...new Uint8Array(32 * 8),
          ...new Uint8Array(4 + 8),
        ]),
      };
    }
    return undefined;
  };
  return { getAccount, read, policyAddress };
}

const SPP_ROOTS = {
  stateRoot: scalar(92),
  stateRootIndex: 4,
  nullifierRoot: scalar(93),
  nullifierRootIndex: 5,
};

function ringInstructionData(txHash: Bytes32): TransactInstructionData {
  return {
    expiryUnixTs: 0n,
    privateTxHash: txHash,
    circuit: { kind: "ringEddsa", inputs: 2, outputs: 3, publicAssetSlots: 3 },
    txViewingPk: new Uint8Array(33) as Bytes33,
    salt: new Uint8Array(16) as Bytes16,
    proof: {
      a: new Uint8Array(32) as Bytes32,
      b: new Uint8Array(64) as Bytes64,
      c: new Uint8Array(32) as Bytes32,
    },
    inputs: [],
    interfaceTransfers: [],
    outputs: [],
    messages: [],
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
    // The first input's roots and indices, the pair a ring statement binds.
    expect(assembled.roots).toEqual({
      stateRoot: scalar(3),
      stateRootIndex: 4,
      nullifierRoot: scalar(6),
      nullifierRootIndex: 7,
    });
  });
});

describe("ring openings", () => {
  const zeroOpening = (domain: number) => ({
    domain: scalar(domain),
    ownerPkHash: scalar(0),
    nullifierPk: scalar(0),
    asset: scalar(0),
    amount: scalar(0),
    blinding: scalar(0),
    dataHash: scalar(0),
    ringDataHash: scalar(0),
    ringProgramId: scalar(0),
  });

  it("opens every slot like Rust `CustomRingWitnessInput`", async () => {
    // Change 5, recipient 4, other 1 fill the (2, 3) shape with one dummy input.
    const { proofInputs, recipient } = await auditedProofInputs(4n, ViewingKey.generate(), [1n]);
    const openings = ringOpenings(proofInputs);
    expect(openings.nIn).toBe(2);
    expect(openings.nOut).toBe(3);

    const spend = proofInputs.inputUtxos[0];
    if (!spend) throw new Error("input");
    expect(openings.inputs[0]).toEqual({
      domain: scalar(3),
      ownerPkHash: hashBytes(spend.utxo.owner.confidentialViewTag()),
      nullifierPk: spend.nullifierKey.publicKey(),
      asset: hashBytes(new Uint8Array(getAddressEncoder().encode(SOL_MINT))),
      amount: scalar(10),
      blinding: scalar(6),
      dataHash: scalar(0),
      ringDataHash: scalar(0),
      ringProgramId: hashBytes(new Uint8Array(getAddressEncoder().encode(RING))),
    });
    // A dummy slot is the DUMMY-domain all-zero opening, its blinding included.
    expect(openings.inputs[1]).toEqual(zeroOpening(1));
    expect(openings.inputs.slice(2)).toEqual([zeroOpening(0), zeroOpening(0), zeroOpening(0)]);

    const change = openings.outputs[0];
    const paid = openings.outputs[1];
    if (!change || !paid) throw new Error("outputs");
    expect(change.domain).toEqual(scalar(3));
    expect(change.amount).toEqual(scalar(5));
    expect(paid.amount).toEqual(scalar(4));
    expect(paid.ownerPkHash).toEqual(hashBytes(recipient.address.confidentialViewTag()));
    expect(paid.nullifierPk).toEqual(recipient.address.nullifierPublicKey);
    expect(openings.outputs[3]).toEqual(zeroOpening(0));
  });

  it("opens an owner-tagged slot without an address as a dummy, like Rust", async () => {
    const { proofInputs } = await auditedProofInputs(4n, ViewingKey.generate(), [1n]);
    const outputs = [...proofInputs.outputs];
    outputs[2] = createProofOutput({
      asset: SOL_MINT,
      amount: 0n,
      blinding: scalar(9),
      ownerTag: scalar(7),
    });
    const swapped = new SppProofInputs({
      payer: proofInputs.payer,
      inputUtxos: proofInputs.inputUtxos,
      outputs,
      externalData: proofInputs.externalData,
    });
    // Never the `hashBytes(ownerTag)` fallback the SPP owner field publishes.
    expect(ringOpenings(swapped).outputs[2]).toEqual(zeroOpening(1));
  });

  it("refuses a transfer wider than the ring slots", async () => {
    const { proofInputs } = await auditedProofInputs(4n, ViewingKey.generate(), [1n, 1n, 1n]);
    expect(proofInputs.outputs).toHaveLength(8);
    expect(() => ringOpenings(proofInputs)).toThrow("CLIENT_PROVER_INPUT");
  });

  it("derives the namespace owner hash the Go policy fixture pins", () => {
    const namespacePda = getAddressDecoder().decode(new Uint8Array(32).fill(0x11));
    expect(ringNamespaceOwnerHash(namespacePda)).toEqual(
      Uint8Array.from(
        Buffer.from("1e99b255125d8e5d1a8ee78945c3197b227182301b2c5d263dd5410b5ff476be", "hex"),
      ),
    );
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
        session: spendSession(actor(3).authority),
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

describe("ring proof folded fields", () => {
  function assertFoldedFields(proofInputs: SppProofInputs, nIn: number): void {
    const externalDataHash = proofInputs.externalData.hash();
    const addressChain = ringAddressChain(nIn);
    expect(addressChain).toEqual(bigintToBytes(hashChain(Array.from({ length: nIn }, () => 0n))));

    const inputHashes = proofInputs.inputUtxos.map((input) =>
      input.isDummy() ? (new Uint8Array(32) as Bytes32) : input.hash(),
    );
    const outputHashes = proofInputs.outputs.map((output) =>
      output.isDummy() ? (new Uint8Array(32) as Bytes32) : output.hash(),
    );
    const canonical = privateTxHash({ inputHashes, outputHashes, externalDataHash });
    const reconstructed = bigintToBytes(
      poseidon([
        hashChain(inputHashes.map(bytesToBigInt)),
        hashChain(outputHashes.map(bytesToBigInt)),
        bytesToBigInt(addressChain),
        bytesToBigInt(externalDataHash),
      ]),
    );
    expect(reconstructed).toEqual(canonical);
  }

  it("folds the real external-data hash and the zero address chain for one input", async () => {
    const { proofInputs } = await auditedProofInputs(4n, ViewingKey.generate());
    expect(proofInputs.inputUtxos).toHaveLength(1);
    assertFoldedFields(proofInputs, 1);
    // hashChain([0]) == 0.
    expect(ringAddressChain(1)).toEqual(new Uint8Array(32));
  });

  it("folds a nonzero address chain for a multi-input transfer", async () => {
    const { proofInputs } = await auditedProofInputs(4n, ViewingKey.generate(), [1n]);
    expect(proofInputs.inputUtxos).toHaveLength(2);
    assertFoldedFields(proofInputs, 2);
    // hashChain([0, 0]) == Poseidon(0, 0) != 0.
    expect(ringAddressChain(2)).not.toEqual(new Uint8Array(32));
    expect(ringAddressChain(2)).toEqual(bigintToBytes(hashChain([0n, 0n])));
  });

  it("pins the empty-rule policy hash to Rust `EMPTY_POLICY_HASH`", () => {
    expect(Buffer.from(RING_EMPTY_RULES_POLICY_HASH).toString("hex")).toBe(
      "1fdd9c12850df78caef73299c35baf2a64eb41a13b6374e3684a8dc29f3343d4",
    );
  });

  it("sends the finalized SPP external hash and address chain to the custom prover", async () => {
    const { prepared, sender } = preparedTransfer(4n, [1n]);
    const accounts = await ringAccounts(ViewingKey.generate(), true);
    const txHash = scalar(91);
    const data = ringInstructionData(txHash);
    let finalized: SppProofInputs | undefined;
    const proveRingTransact = vi.fn(async (proofInputs: SppProofInputs) => {
      finalized = proofInputs;
      return { data, roots: SPP_ROOTS };
    });
    let request: CustomRingPolicyProofRequest | undefined;
    const proveCustomRingPolicy = vi.fn(async (input: CustomRingPolicyProofRequest) => {
      request = input;
      return new Uint8Array(192);
    });
    const base = {
      client: ringTransferClient({
        tree: RING,
        getAccount: accounts.getAccount,
        proveRingTransact,
        proveCustomRingPolicy,
      }),
      ringProgramId: RING,
      prepared,
      session: spendSession(sender.authority),
      assets: new AssetRegistry(),
      tree: RING,
      outputTree: ACTIVE_TREE,
    } as const;
    await expect(proveCustomRingTransfer(base)).rejects.toMatchObject({
      code: "RING_ENTRIES_ROOTS_REQUIRED",
    });
    expect(proveRingTransact).not.toHaveBeenCalled();

    const entriesStateRoot = scalar(94);
    const entriesNullifierRoot = scalar(95);
    const proven = await proveCustomRingTransfer({
      ...base,
      entriesRoots: {
        stateRoot: entriesStateRoot,
        stateRootIndex: 7,
        nullifierRoot: entriesNullifierRoot,
        nullifierRootIndex: 8,
      },
    });

    expect(finalized).toBeDefined();
    expect(request).toBeDefined();
    expect(request?.externalDataHash).toEqual(finalized?.externalData.hash());
    expect(request?.addressChain).toEqual(ringAddressChain(finalized?.inputUtxos.length ?? 0));
    expect(request?.privateTxHash).toEqual(txHash);
    expect(request?.stateRoot).toEqual(entriesStateRoot);
    expect(request?.nullifierRoot).toEqual(entriesNullifierRoot);
    expect(proven).toMatchObject({ hasPolicy: true, entriesTree: ACTIVE_TREE });
    expect(proven.tree).toBe(RING);
    expect(proven.outputTree).toBe(ACTIVE_TREE);
    expect(proven.stateRootIndex).toBe(7);
    expect(proven.nullifierRootIndex).toBe(8);
    expect(proven.ownerSigners).toEqual([]);
  });

  it("refuses a policy config with rule rows before any proof, even under the empty-table hash", async () => {
    const { prepared, sender } = preparedTransfer(4n, [1n]);
    const accounts = await ringAccounts(ViewingKey.generate(), true, 1);
    const proveRingTransact = vi.fn(async () => ({
      data: ringInstructionData(scalar(91)),
      roots: SPP_ROOTS,
    }));
    await expect(
      proveCustomRingTransfer({
        client: ringTransferClient({
          tree: RING,
          getAccount: accounts.getAccount,
          proveRingTransact,
        }),
        ringProgramId: RING,
        prepared,
        session: spendSession(sender.authority),
        assets: new AssetRegistry(),
        tree: RING,
        outputTree: ACTIVE_TREE,
      }),
    ).rejects.toMatchObject({
      code: "RING_RULES_UNSUPPORTED",
      details: { ruleCount: 1, inlineCount: 0 },
    });
    expect(proveRingTransact).not.toHaveBeenCalled();
  });

  it("proves the audit statement alone for a no-policy ring like Rust `finish_audit`", async () => {
    const { prepared, sender } = preparedTransfer(4n, [1n]);
    const auditor = ViewingKey.generate();
    const accounts = await ringAccounts(auditor, false);
    const txHash = scalar(91);
    const data = ringInstructionData(txHash);
    let finalized: SppProofInputs | undefined;
    let request: CustomRingBaseProofRequest | undefined;

    const proven = await proveCustomRingTransfer({
      client: ringTransferClient({
        tree: RING,
        getAccount: accounts.getAccount,
        proveRingTransact: async (proofInputs) => {
          finalized = proofInputs;
          return { data, roots: SPP_ROOTS };
        },
        proveCustomRingBase: async (input) => {
          request = input;
          return new Uint8Array(192);
        },
      }),
      ringProgramId: RING,
      prepared,
      session: spendSession(sender.authority),
      assets: new AssetRegistry(),
      tree: RING,
      outputTree: ACTIVE_TREE,
    });

    if (finalized === undefined) throw new Error("finalized");
    const message = finalized.externalData.messages[0];
    if (message === undefined) throw new Error("auditor message");
    // The policy config account is never read for an audit-only ring.
    expect(accounts.read).not.toContain(accounts.policyAddress);
    expect(request?.privateTxHash).toEqual(txHash);
    expect(request?.auditorPublicKey).toEqual(auditor.publicKey().toUncompressed());
    expect(request?.publicInputHash).toEqual(
      auditPublicInputHash({
        privateTxHash: txHash,
        txViewingPublicKey: finalized.externalData.txViewingPublicKey,
        auditorPublicKey: auditor.publicKey(),
        message: parseAuditorMessage(message.data),
      }),
    );
    expect(proven).toMatchObject({ hasPolicy: false });
    expect(proven).not.toHaveProperty("entriesTree");
    expect(proven.stateRootIndex).toBe(0);
    expect(proven.nullifierRootIndex).toBe(0);
    expect(proven.tree).toBe(RING);
    expect(proven.outputTree).toBe(ACTIVE_TREE);
  });
});

describe("ring lookup table", () => {
  const FEE_PAYER = getAddressDecoder().decode(new Uint8Array(32).fill(45));
  const TABLE = getAddressDecoder().decode(new Uint8Array(32).fill(46));

  function lookupTableReads(tables: ReadonlyMap<Address, readonly Address[]>) {
    return solanaRpcReads({
      getSlot: () => ({ send: async () => 100n }),
      getAccountInfo: (account: Address) => ({
        send: async () => {
          const addresses = tables.get(account);
          if (addresses === undefined) return { context: { slot: 100n }, value: null };
          const data = getAddressLookupTableEncoder().encode({
            deactivationSlot: 0xffff_ffff_ffff_ffffn,
            lastExtendedSlot: 100n,
            lastExtendedSlotStartIndex: 0,
            authority: FEE_PAYER,
            addresses: [...addresses],
          });
          return {
            context: { slot: 100n },
            value: {
              data: [getBase64Decoder().decode(data), "base64"],
              executable: false,
              lamports: 1n,
              owner: ADDRESS_LOOKUP_TABLE_PROGRAM_ADDRESS,
              rentEpoch: 0n,
              space: BigInt(data.length),
            },
          };
        },
      }),
    });
  }

  function extendedAddresses(table: RingLookupTable): readonly Address[] {
    const message = getCompiledTransactionMessageDecoder().decode(table.transaction.messageBytes);
    const extend = "instructions" in message ? message.instructions[1] : undefined;
    if (extend?.data === undefined) throw new Error("no extend instruction");
    return getExtendLookupTableInstructionDataDecoder().decode(extend.data).addresses;
  }

  it("builds a policy ring's table from its own accounts and the fetch accepts the same trees", async () => {
    const accounts = await ringAccounts(ViewingKey.generate(), true);
    const tables = new Map<Address, readonly Address[]>();
    const client = ringTransferClient({
      tree: RING,
      getAccount: accounts.getAccount,
      solanaRpc: lookupTableReads(tables),
    });

    const table = await buildRingLookupTableTransaction({
      client,
      ringProgramId: RING,
      feePayer: FEE_PAYER,
      outputTree: ACTIVE_TREE,
    });
    tables.set(table.address, extendedAddresses(table));

    expect(accounts.read).toContain(accounts.policyAddress);
    const held = await fetchRingLookupTable({
      client,
      ringProgramId: RING,
      address: table.address,
      trees: { tree: RING, outputTree: ACTIVE_TREE, hasPolicy: true, entriesTree: ACTIVE_TREE },
    });
    expect(held).toContain(accounts.policyAddress);
    expect(held).toContain(ACTIVE_TREE);
  });

  it("builds an audit-only ring's table without the policy accounts", async () => {
    const accounts = await ringAccounts(ViewingKey.generate(), false);
    const client = ringTransferClient({
      tree: RING,
      getAccount: accounts.getAccount,
      solanaRpc: lookupTableReads(new Map()),
    });

    const table = await buildRingLookupTableTransaction({
      client,
      ringProgramId: RING,
      feePayer: FEE_PAYER,
    });

    expect(accounts.read).not.toContain(accounts.policyAddress);
    expect(extendedAddresses(table)).not.toContain(accounts.policyAddress);
  });

  it("refuses a tree-only table for a policy ring", async () => {
    const accounts = await ringAccounts(ViewingKey.generate(), true);
    const treeOnly = await ringLookupTableAddresses({
      ringProgramId: RING,
      trees: { tree: ACTIVE_TREE, outputTree: ACTIVE_TREE, hasPolicy: false },
    });
    const tables = new Map<Address, readonly Address[]>([[TABLE, treeOnly]]);
    const client = ringTransferClient({
      tree: ACTIVE_TREE,
      getAccount: accounts.getAccount,
      solanaRpc: lookupTableReads(tables),
    });
    const trees = {
      tree: ACTIVE_TREE,
      outputTree: ACTIVE_TREE,
      hasPolicy: true,
      entriesTree: ACTIVE_TREE,
    };

    await expect(
      fetchRingLookupTable({ client, ringProgramId: RING, address: TABLE, trees }),
    ).rejects.toMatchObject({ code: "RING_LOOKUP_TABLE_INCOMPLETE", details: { address: TABLE } });

    tables.set(TABLE, [...treeOnly, accounts.policyAddress]);
    await expect(
      fetchRingLookupTable({ client, ringProgramId: RING, address: TABLE, trees }),
    ).resolves.toContain(accounts.policyAddress);
  });
});
