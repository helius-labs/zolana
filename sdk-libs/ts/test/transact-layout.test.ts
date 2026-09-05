import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { encodeTransactInstructionData } from "../src/interface/codecs/index.js";
import { externalDataHash } from "../src/interface/external-data-hash.js";
import { sha256 } from "../src/interface/internal.js";
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
  TransactInstructionData,
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

function bytes33(value: number): Bytes33 {
  const result = bytes(33, value);
  if (result.length !== 33) throw new TypeError("expected 33 bytes");
  return result as Bytes33;
}

function bytes64(value: number): Bytes64 {
  const result = bytes(64, value);
  if (result.length !== 64) throw new TypeError("expected 64 bytes");
  return result as Bytes64;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function hexBytes(value: string): Uint8Array {
  if (value.length % 2 !== 0) throw new TypeError("expected an even-length hex string");
  return Uint8Array.from({ length: value.length / 2 }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  );
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
  it("matches the pinned Rust and Go external-data hash vector", () => {
    const digest = externalDataHash({
      instructionDiscriminator: 15,
      expiryUnixTs: 42n,
      txViewingPk: bytes33(26),
      salt: bytes16(27),
      interfaceTransfers: [
        { kind: "solDeposit", amount: 1n },
        { kind: "splWithdrawal", amount: 2n, splInterfaceBump: 255 },
      ],
      dataHash: bytes32(24),
      ringDataHash: bytes32(25),
      outputs: [
        {
          utxoHash: bytes32(28),
          ownerTag: { kind: "inline", value: bytes32(29) },
          data: Uint8Array.of(30, 31),
        },
        {
          utxoHash: bytes32(32),
          ownerTag: { kind: "account", index: 7 },
        },
      ],
      messages: [{ viewTag: bytes32(34), data: Uint8Array.of(35, 36) }],
      committedAddresses: [bytes32(20), bytes32(22), bytes32(23), bytes32(33)],
    });

    expect(digest).toEqual(
      hexBytes("00de2f61ad44fd62cdbd1b610a8cc6edd422d96274d02e9e4b659924f02ac29b"),
    );
  });

  it("encodes the external-data prefix and remaining flat fields in Rust wire order", () => {
    const value = {
      expiryUnixTs: 0x0807_0605_0403_0201n,
      txViewingPk: bytes33(0x11),
      salt: bytes16(0x22),
      interfaceTransfers: [{ kind: "solDeposit", amount: 0x100f_0e0d_0c0b_0a09n }],
      dataHash: bytes32(0x33),
      ringDataHash: bytes32(0x44),
      outputs: [
        {
          utxoHash: bytes32(0x55),
          ownerTag: { kind: "inline", value: bytes32(0x66) },
          data: Uint8Array.of(0x67, 0x68),
        },
      ],
      messages: [{ viewTag: bytes32(0x77), data: Uint8Array.of(0x78, 0x79) }],
      privateTxHash: bytes32(0x88),
      circuit: { kind: "ringEddsa", inputs: 1, outputs: 1, publicAssetSlots: 0 },
      proof: { a: bytes32(0x99), b: bytes64(0xaa), c: bytes32(0xbb) },
      inputs: [
        {
          nullifierHash: bytes32(0xcc),
          nullifierTreeRootIndex: 0x0201,
          utxoTreeRootIndex: 0x0403,
        },
      ],
    } satisfies TransactInstructionData;
    const expectedExternalData = concat([
      Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8),
      bytes33(0x11),
      bytes16(0x22),
      Uint8Array.of(1, 0, 9, 10, 11, 12, 13, 14, 15, 16),
      Uint8Array.of(1),
      bytes32(0x33),
      Uint8Array.of(1),
      bytes32(0x44),
      Uint8Array.of(1),
      bytes32(0x55),
      Uint8Array.of(0),
      bytes32(0x66),
      Uint8Array.of(1, 2, 0, 0x67, 0x68),
      Uint8Array.of(1),
      bytes32(0x77),
      Uint8Array.of(2, 0, 0x78, 0x79),
    ]);
    const expectedRemainder = concat([
      bytes32(0x88),
      Uint8Array.of(1, 0, 1, 1, 0),
      bytes32(0x99),
      bytes64(0xaa),
      bytes32(0xbb),
      Uint8Array.of(1),
      bytes32(0xcc),
      Uint8Array.of(1, 2, 3, 4),
    ]);

    const encoded = encodeTransactInstructionData(value);
    const privateTxHashOffset = expectedExternalData.length;
    expect(encoded.slice(0, privateTxHashOffset)).toEqual(expectedExternalData);
    expect(encoded.slice(privateTxHashOffset)).toEqual(expectedRemainder);

    const committedAddress = bytes32(0xdd);
    const expectedHash = sha256(
      concat([Uint8Array.of(19), expectedExternalData, committedAddress]),
    );
    expectedHash[0] = 0;
    expect(
      externalDataHash({
        instructionDiscriminator: 19,
        expiryUnixTs: value.expiryUnixTs,
        txViewingPk: value.txViewingPk,
        salt: value.salt,
        interfaceTransfers: value.interfaceTransfers,
        dataHash: value.dataHash,
        ringDataHash: value.ringDataHash,
        outputs: value.outputs,
        messages: value.messages,
        committedAddresses: [committedAddress],
      }),
    ).toEqual(expectedHash);
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

  it("enforces the protocol and wire count bounds", () => {
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
