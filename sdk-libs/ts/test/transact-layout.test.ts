import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import vector from "../../../test-vectors/external_data_hash.json" with { type: "json" };
import { encodeTransactInstructionData } from "../src/interface/codecs/index.js";
import { externalDataHash } from "../src/interface/external-data-hash.js";
import { P256PublicKey } from "../src/keypair/public-key.js";
import {
  createExternalData,
  type ExternalData,
  type ExternalDataInit,
} from "../src/transaction/instructions/transact.js";
import type {
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes64,
  InterfaceTransfer,
  OwnerTag,
  TransactOutput,
} from "../src/interface/types.js";

function bytes(length: number, value: number): Uint8Array {
  return Uint8Array.from({ length }, () => value);
}

function bytes16(value: number): Bytes16 {
  const result = bytes(16, value);
  if (result.length !== 16) throw new TypeError("expected 16 bytes");
  return result as Bytes16;
}

function bytes32(value: number): Bytes32 {
  const result = bytes(32, value);
  if (result.length !== 32) throw new TypeError("expected 32 bytes");
  return result as Bytes32;
}

function bytes64(value: number): Bytes64 {
  const result = bytes(64, value);
  if (result.length !== 64) throw new TypeError("expected 64 bytes");
  return result as Bytes64;
}

function hexBytes(value: string): Uint8Array {
  if (value.length % 2 !== 0) throw new TypeError("expected an even-length hex string");
  return Uint8Array.from({ length: value.length / 2 }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  );
}

function hex16(value: string): Bytes16 {
  const result = hexBytes(value);
  if (result.length !== 16) throw new TypeError("expected 16 bytes");
  return result as Bytes16;
}

function hex32(value: string): Bytes32 {
  const result = hexBytes(value);
  if (result.length !== 32) throw new TypeError("expected 32 bytes");
  return result as Bytes32;
}

function hex33(value: string): Bytes33 {
  const result = hexBytes(value);
  if (result.length !== 33) throw new TypeError("expected 33 bytes");
  return result as Bytes33;
}

type VectorInterfaceTransfer = (typeof vector.interfaceTransfers)[number];
type VectorOutput = (typeof vector.outputs)[number];

function vectorInterfaceTransfer(transfer: VectorInterfaceTransfer): InterfaceTransfer {
  const amount = BigInt(transfer.amount);
  switch (transfer.kind) {
    case "solDeposit":
    case "solWithdrawal":
      return { kind: transfer.kind, amount };
    case "splDeposit":
    case "splWithdrawal":
      if (transfer.splInterfaceBump === undefined) {
        throw new TypeError("expected an SPL interface bump");
      }
      return { kind: transfer.kind, amount, splInterfaceBump: transfer.splInterfaceBump };
    default:
      throw new TypeError(`unknown interface transfer kind ${transfer.kind}`);
  }
}

function vectorOwnerTag(tag: VectorOutput["ownerTag"]): OwnerTag {
  switch (tag.kind) {
    case "inline":
      if (tag.value === undefined) throw new TypeError("expected an inline owner tag value");
      return { kind: "inline", value: hex32(tag.value) };
    case "account":
      if (tag.index === undefined) throw new TypeError("expected an owner tag account index");
      return { kind: "account", index: tag.index };
    default:
      throw new TypeError(`unknown owner tag kind ${tag.kind}`);
  }
}

function vectorOutput(output: VectorOutput): TransactOutput {
  const utxoHash = hex32(output.utxoHash);
  const ownerTag = vectorOwnerTag(output.ownerTag);
  return output.data === undefined
    ? { utxoHash, ownerTag }
    : { utxoHash, ownerTag, data: hexBytes(output.data) };
}

function vectorCommittedAddresses(): string[] {
  const addresses: string[] = [];
  for (const transfer of vector.interfaceTransfers) {
    addresses.push(transfer.userAccount);
    if (transfer.splInterfaceAccount !== undefined) addresses.push(transfer.splInterfaceAccount);
  }
  for (const output of vector.outputs) {
    if (output.ownerTag.kind === "account" && output.ownerTag.address !== undefined) {
      addresses.push(output.ownerTag.address);
    }
  }
  return addresses;
}

function externalDataInit(): ExternalDataInit {
  const publicKeyBytes = hexBytes(
    "02039b852db622408abe58a18c0f056631a6ca4b2cfeec198aae25017cad09d4e8",
  );
  if (publicKeyBytes.length !== 33) throw new TypeError("expected a compressed P256 key");
  return {
    txViewingPublicKey: P256PublicKey.fromBytes(publicKeyBytes as Bytes33),
    salt: bytes16(0x12),
    outputs: [],
    resolvedOwnerTags: [],
    messages: [],
  };
}

function encodeExternalDataView(externalData: ExternalData): Uint8Array {
  const dataHash = externalData.dataHash;
  const ringDataHash = externalData.ringDataHash;
  return encodeTransactInstructionData({
    expiryUnixTs: externalData.expiryUnixTs,
    txViewingPk: externalData.txViewingPublicKey.toBytes(),
    salt: externalData.salt,
    interfaceTransfers: externalData.interfaceTransfers.map((transfer) =>
      transfer.kind === "sol"
        ? {
            kind: transfer.isDeposit ? ("solDeposit" as const) : ("solWithdrawal" as const),
            amount: transfer.amount,
          }
        : {
            kind: transfer.isDeposit ? ("splDeposit" as const) : ("splWithdrawal" as const),
            amount: transfer.amount,
            splInterfaceBump: transfer.splInterfaceBump,
          },
    ),
    ...(dataHash === undefined ? {} : { dataHash }),
    ...(ringDataHash === undefined ? {} : { ringDataHash }),
    outputs: externalData.outputs,
    messages: externalData.messages,
    privateTxHash: bytes32(0),
    circuit: { kind: "confidentialEddsa", inputs: 0, outputs: 0, publicAssetSlots: 0 },
    proof: { a: bytes32(0), b: bytes64(0), c: bytes32(0) },
    inputs: [],
  });
}

describe("transact instruction layout", () => {
  it("matches the shared Rust and Go external-data hash vector", () => {
    expect(vectorCommittedAddresses()).toEqual(vector.committedAddresses);

    const externalData = {
      expiryUnixTs: BigInt(vector.expiryUnixTs),
      txViewingPk: hex33(vector.txViewingPk),
      salt: hex16(vector.salt),
      interfaceTransfers: vector.interfaceTransfers.map(vectorInterfaceTransfer),
      dataHash: hex32(vector.dataHash),
      ringDataHash: hex32(vector.ringDataHash),
      outputs: vector.outputs.map(vectorOutput),
      messages: vector.messages.map((message) => ({
        viewTag: hex32(message.viewTag),
        data: hexBytes(message.data),
      })),
    };

    const expectedPrefix = hexBytes(vector.externalDataPrefix);
    const encoded = encodeTransactInstructionData({
      ...externalData,
      privateTxHash: bytes32(0),
      circuit: { kind: "confidentialEddsa", inputs: 0, outputs: 0, publicAssetSlots: 0 },
      proof: { a: bytes32(0), b: bytes64(0), c: bytes32(0) },
      inputs: [],
    });
    expect(encoded.slice(0, expectedPrefix.length)).toEqual(expectedPrefix);

    const digest = externalDataHash({
      ...externalData,
      instructionDiscriminator: vector.instructionDiscriminator,
      committedAddresses: vector.committedAddresses.map(hex32),
    });
    expect(digest).toEqual(hex32(vector.externalDataHash));
  });

  it("binds both optional transaction-level hashes into externalDataHash", () => {
    const common = externalDataInit();

    const baseline = createExternalData(common).hash();
    const withDataHash = createExternalData({ ...common, dataHash: bytes32(0x34) }).hash();
    const withRingDataHash = createExternalData({
      ...common,
      ringDataHash: bytes32(0x56),
    }).hash();

    expect(withDataHash).not.toEqual(baseline);
    expect(withRingDataHash).not.toEqual(baseline);
    expect(withRingDataHash).not.toEqual(withDataHash);
  });

  it("keeps caller and exposed typed-array mutations out of the private snapshot", () => {
    const dataHash = bytes32(0x34);
    const ringDataHash = bytes32(0x56);
    const salt = bytes16(0x12);
    const outputHash = bytes32(0x78);
    const outputData = Uint8Array.of(0x9a, 0xbc);
    const resolvedOwnerTag = bytes32(0xde);
    const inlineOwnerTag = bytes32(0xe1);
    const messageViewTag = bytes32(0xf0);
    const messageData = Uint8Array.of(0x12, 0x34);
    const externalData = createExternalData({
      ...externalDataInit(),
      dataHash,
      ringDataHash,
      salt,
      outputs: [
        {
          utxoHash: outputHash,
          ownerTag: { kind: "account", index: 0 },
          data: outputData,
        },
        {
          utxoHash: bytes32(0xe2),
          ownerTag: { kind: "inline", value: inlineOwnerTag },
        },
      ],
      resolvedOwnerTags: [resolvedOwnerTag, inlineOwnerTag],
      messages: [{ viewTag: messageViewTag, data: messageData }],
    });
    const initialHash = externalData.hash();
    const initialInstruction = encodeExternalDataView(externalData);

    dataHash.fill(0xaa);
    ringDataHash.fill(0xbb);
    salt.fill(0xcc);
    outputHash.fill(0xdd);
    outputData.fill(0xee);
    resolvedOwnerTag.fill(0xff);
    inlineOwnerTag.fill(0x10);
    messageViewTag.fill(0x11);
    messageData.fill(0x22);

    expect(externalData.dataHash).toEqual(bytes32(0x34));
    expect(externalData.ringDataHash).toEqual(bytes32(0x56));
    expect(externalData.hash()).toEqual(initialHash);

    externalData.dataHash?.fill(1);
    externalData.ringDataHash?.fill(2);
    externalData.salt.fill(3);
    externalData.outputs[0]?.utxoHash.fill(4);
    externalData.outputs[0]?.data?.fill(5);
    const exposedInlineTag = externalData.outputs[1]?.ownerTag;
    if (exposedInlineTag?.kind === "inline") exposedInlineTag.value.fill(9);
    externalData.resolvedOwnerTags[0]?.fill(6);
    externalData.messages[0]?.viewTag.fill(7);
    externalData.messages[0]?.data.fill(8);

    expect(externalData.hash()).toEqual(initialHash);
    expect(encodeExternalDataView(externalData)).toEqual(initialInstruction);
    const derived = externalData.withInterfaceTransfers([]);
    expect(derived.dataHash).toEqual(bytes32(0x34));
    expect(derived.ringDataHash).toEqual(bytes32(0x56));
    expect(derived.salt).toEqual(bytes16(0x12));
    expect(derived.outputs[0]?.utxoHash).toEqual(bytes32(0x78));
    expect(derived.outputs[0]?.data).toEqual(Uint8Array.of(0x9a, 0xbc));
    expect(derived.outputs[1]?.ownerTag).toEqual({ kind: "inline", value: bytes32(0xe1) });
    expect(derived.resolvedOwnerTags[0]).toEqual(bytes32(0xde));
    expect(derived.messages[0]?.viewTag).toEqual(bytes32(0xf0));
    expect(derived.messages[0]?.data).toEqual(Uint8Array.of(0x12, 0x34));
    expect(derived.hash()).toEqual(initialHash);
  });

  it("enforces the protocol and encoding count bounds", () => {
    const transfer = {
      kind: "sol" as const,
      isDeposit: true,
      amount: 1n,
      userSolAccount: address("11111111111111111111111111111111"),
    };
    expect(() =>
      createExternalData({
        ...externalDataInit(),
        interfaceTransfers: Array.from({ length: 32 }, () => transfer),
      }).hash(),
    ).not.toThrow();
    expect(() =>
      createExternalData({
        ...externalDataInit(),
        interfaceTransfers: Array.from({ length: 33 }, () => transfer),
      }).hash(),
    ).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_TOO_MANY_INTERFACE_TRANSFERS",
        details: { got: 33, max: 32 },
      }),
    );

    const output = {
      utxoHash: bytes32(0x78),
      ownerTag: { kind: "inline" as const, value: bytes32(0x9a) },
    };
    expect(() =>
      createExternalData({
        ...externalDataInit(),
        outputs: Array.from({ length: 256 }, () => output),
        resolvedOwnerTags: Array.from({ length: 256 }, () => bytes32(0x9a)),
      }).hash(),
    ).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_TOO_MANY_OUTPUTS",
        details: { got: 256, max: 255 },
      }),
    );

    const message = { viewTag: bytes32(0xbc), data: new Uint8Array() };
    expect(() =>
      createExternalData({
        ...externalDataInit(),
        messages: Array.from({ length: 256 }, () => message),
      }).hash(),
    ).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_TOO_MANY_MESSAGES",
        details: { got: 256, max: 255 },
      }),
    );
  });
});
