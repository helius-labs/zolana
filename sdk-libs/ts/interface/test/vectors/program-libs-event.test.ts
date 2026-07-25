import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/program-libs-parity-v1.json" with { type: "json" };
import { transactInstructionDataCodec } from "../../src/codecs/index.js";
import {
  InstructionTag,
  type Bytes16,
  type Bytes32,
  type Bytes33,
  type Bytes64,
  type MessageData,
  type TransactInstructionData,
} from "../../src/index.js";

// `program-libs/event` is re-exported through `program-libs/interface`, so the
// tags and `MessageData` are part of the interface crate's public surface even
// though they are defined a crate lower down. Nothing compared them before.

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const b = (byte: number, length: number): Uint8Array => new Uint8Array(length).fill(byte);

/// A transact payload whose only variable is `messages`, so the encoding's tail
/// isolates the `MessageData` bytes.
function transactWithMessages(messages: readonly MessageData[]): TransactInstructionData {
  return {
    proof: { rail: "eddsa", a: b(1, 32) as Bytes32, b: b(2, 64) as Bytes64, c: b(3, 32) as Bytes32 },
    expiryUnixTs: 42n,
    relayerFee: 7,
    privateTxHash: b(4, 32) as Bytes32,
    txViewingPk: b(5, 33) as Bytes33,
    salt: b(6, 16) as Bytes16,
    inputs: [],
    outputs: [],
    messages,
  };
}

/// Everything the codec writes before the message list, so the message bytes can
/// be lifted out without hard-coding an offset.
function messagePrefixLength(): number {
  const empty = transactInstructionDataCodec.encode(transactWithMessages([]));
  // The last byte is the `u8` message count; the prefix is everything before it.
  return empty.length - 1;
}

function encodeMessage(message: MessageData): Uint8Array {
  const encoded = transactInstructionDataCodec.encode(transactWithMessages([message]));
  // prefix + u8(1) + message bytes
  return encoded.slice(messagePrefixLength() + 1);
}

describe("program-libs/event/src/tag.rs against InstructionTag", () => {
  const tags = fixture.event.tag;

  it("mirrors every Rust tag constant by name and value", () => {
    expect(InstructionTag).toEqual(tags.values);
  });

  it("declares exactly the eighteen tags Rust declares", () => {
    expect(Object.keys(InstructionTag)).toHaveLength(tags.count);
  });

  it("covers precisely the bytes Rust's TryFrom<u8> accepts", () => {
    const accepted = [...new Set(Object.values(InstructionTag))].sort((a, b) => a - b);
    expect(accepted).toEqual(tags.acceptedBytes);
  });

  it("claims no byte Rust rejects", () => {
    const values = new Set<number>(Object.values(InstructionTag));
    for (const byte of tags.rejectedSample) {
      expect(values.has(byte)).toBe(false);
    }
  });

  it("keeps batchUpdateNullifierTree in its own 51 slot above the dispatch block", () => {
    expect(InstructionTag.batchUpdateNullifierTree).toBe(51);
    expect(InstructionTag.createAssetCounter).toBe(16);
  });
});

describe("program-libs/event/src/output_data.rs against MessageData", () => {
  // The wincode encoding is the one the program parses: `view_tag` then a
  // `FixIntLen<u16>` length prefix. Borsh would write a `u32` prefix, and the
  // fixture carries both so a port cannot pass by matching the wrong one.
  for (const vector of fixture.event.outputData.vectors) {
    it(`encodes ${vector.name} exactly as wincode does`, () => {
      const message: MessageData = {
        viewTag: hexToBytes(vector.value.viewTag) as Bytes32,
        data: hexToBytes(vector.value.data),
      };
      expect(bytesToHex(encodeMessage(message))).toBe(vector.wincode);
    });

    it(`round trips ${vector.name} through the codec`, () => {
      const message: MessageData = {
        viewTag: hexToBytes(vector.value.viewTag) as Bytes32,
        data: hexToBytes(vector.value.data),
      };
      const value = transactWithMessages([message]);
      const decoded = transactInstructionDataCodec.decode(
        transactInstructionDataCodec.encode(value),
      );
      expect(decoded.messages).toEqual([message]);
    });
  }

  it("uses a u16 length prefix, not borsh's u32", () => {
    const vector = fixture.event.outputData.vectors.find((entry) => entry.name === "short-data");
    expect(vector).toBeDefined();
    if (vector === undefined) return;
    expect(vector.wincode).not.toBe(vector.borsh);
    // 32 view-tag bytes, then the two-byte length.
    expect(vector.wincode.slice(64, 68)).toBe("0500");
    expect(vector.borsh.slice(64, 72)).toBe("05000000");
  });

  it("carries data past the 255-byte boundary that a u8 prefix would truncate", () => {
    const long = fixture.event.outputData.vectors.find((entry) => entry.name === "long-data-300");
    expect(long?.dataLen).toBe(300);
    if (long === undefined) return;
    const message: MessageData = {
      viewTag: hexToBytes(long.value.viewTag) as Bytes32,
      data: hexToBytes(long.value.data),
    };
    expect(bytesToHex(encodeMessage(message))).toBe(long.wincode);
  });
});
