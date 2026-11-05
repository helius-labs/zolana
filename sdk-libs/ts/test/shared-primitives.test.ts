import { beforeAll, describe, expect, it } from "vitest";

import {
  BN254_SCALAR_ORDER,
  HasherFailure,
  MAX_POSEIDON_INPUTS,
  initializePoseidon,
  poseidon,
} from "../src/hasher/index.js";
import { poseidon as clientPoseidon } from "../src/client/internal.js";
import { poseidon as interfacePoseidon } from "../src/interface/merge-utils.js";
import { Reader, Writer } from "../src/interface/internal.js";
import { bigIntToBytes } from "../src/keypair/bytes.js";
import { poseidon as keypairPoseidon } from "../src/keypair/poseidon.js";
import { signedToField } from "../src/transaction/instructions/transact.js";
import {
  commitmentPoseidon,
  poseidon as transactionPoseidon,
} from "../src/transaction/internal.js";
import { decodeConfidential } from "../src/transaction/serialization/codecs.js";

const ORDER = bigIntToBytes(BN254_SCALAR_ORDER);
const BELOW_ORDER = bigIntToBytes(BN254_SCALAR_ORDER - 1n);

beforeAll(async () => {
  await initializePoseidon();
});

describe("one Poseidon", () => {
  it("rejects an input at the scalar order before the module sees it", () => {
    const failure = (() => {
      try {
        poseidon([BELOW_ORDER, ORDER]);
      } catch (error) {
        return error;
      }
      return undefined;
    })();
    expect(failure).toBeInstanceOf(HasherFailure);
    expect(failure).toMatchObject({ code: "Poseidon", details: { index: 1 } });
  });

  it("hashes the same bytes through every layer's wrapper", () => {
    const inputs = [bigIntToBytes(1n), bigIntToBytes(2n)];
    const expected = poseidon(inputs);
    expect(keypairPoseidon(inputs)).toEqual(expected);
    expect(transactionPoseidon(inputs)).toEqual(expected);
    expect(commitmentPoseidon(inputs)).toEqual(expected);
    expect(interfacePoseidon(inputs)).toEqual(expected);
    expect(bigIntToBytes(clientPoseidon([1n, 2n]))).toEqual(expected);
  });

  it("maps a rejection into each layer's own error", () => {
    const tooMany = Array.from({ length: MAX_POSEIDON_INPUTS + 1 }, () => bigIntToBytes(1n));
    expect(() => keypairPoseidon([ORDER])).toThrow(
      expect.objectContaining({ code: "KEYPAIR_POSEIDON", details: { index: 0 } }),
    );
    expect(() => keypairPoseidon(tooMany)).toThrow(
      expect.objectContaining({ code: "KEYPAIR_POSEIDON" }),
    );
    expect(() => transactionPoseidon([ORDER])).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_KEYPAIR",
        details: { index: 0, reason: "invalidField" },
      }),
    );
    expect(() => commitmentPoseidon(tooMany)).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_POSEIDON",
        details: { inputCount: MAX_POSEIDON_INPUTS + 1 },
      }),
    );
    expect(() => interfacePoseidon([new Uint8Array(33)])).toThrow(
      expect.objectContaining({ code: "INTERFACE_HASH", details: { index: 0, length: 33 } }),
    );
    expect(() => clientPoseidon([BN254_SCALAR_ORDER])).toThrow(
      expect.objectContaining({ code: "CLIENT_INVALID_FIELD" }),
    );
    expect(() => clientPoseidon([])).toThrow(
      expect.objectContaining({ code: "CLIENT_HASHER", details: { code: "InvalidNumFields" } }),
    );
  });
});

describe("bigIntToBytes", () => {
  it("throws on a value wider than the array or below zero instead of wrapping", () => {
    expect(() => bigIntToBytes(1n << 256n)).toThrow(
      expect.objectContaining({ code: "KEYPAIR_INVALID_LENGTH" }),
    );
    expect(() => bigIntToBytes(0x100n, 1)).toThrow(
      expect.objectContaining({ code: "KEYPAIR_INVALID_LENGTH" }),
    );
    expect(() => bigIntToBytes(-1n)).toThrow(
      expect.objectContaining({ code: "KEYPAIR_INVALID_LENGTH" }),
    );
    expect(bigIntToBytes(0xffn, 1)).toEqual(Uint8Array.of(0xff));
  });

  it("encodes a negative public amount as its field negation", () => {
    expect(signedToField(-1n)).toEqual(BELOW_ORDER);
    expect(signedToField(-(1n << 63n))).toEqual(bigIntToBytes(BN254_SCALAR_ORDER - (1n << 63n)));
  });
});

describe("Reader and Writer", () => {
  it("round-trip little-endian integers, options and bytes", () => {
    const bytes = new Writer()
      .u8(0xab, "u8")
      .u16(0xbeef, "u16")
      .u32(0xdeadbeef, "u32")
      .u64(0x0102_0304_0506_0708n, "u64")
      .i64(-2n, "i64")
      .option(Uint8Array.of(9, 8), (writer, value) => writer.bytes(value, 2, "value"))
      .option<number>(undefined, (writer, value) => writer.u8(value, "absent"))
      .finish();
    const reader = new Reader(bytes);
    expect(reader.u8("u8")).toBe(0xab);
    expect(reader.u16("u16")).toBe(0xbeef);
    expect(reader.u32("u32")).toBe(0xdeadbeef);
    expect(reader.u64("u64")).toBe(0x0102_0304_0506_0708n);
    expect(reader.i64("i64")).toBe(-2n);
    expect(reader.option("value", (input) => input.bytes(2, "value"))).toEqual(Uint8Array.of(9, 8));
    expect(reader.option("absent", (input) => input.u8("absent"))).toBeUndefined();
    reader.done();
  });

  it("raises each layer's own codes through its error factory", () => {
    expect(() => new Reader(Uint8Array.of(1)).u16("short")).toThrow(
      expect.objectContaining({
        code: "INTERFACE_CODEC",
        details: { name: "short", offset: 0, expected: 2, remaining: 1 },
      }),
    );
    expect(() => new Writer().u8(0x100, "byte")).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_INTEGER" }),
    );
    expect(() => decodeConfidential(new Uint8Array(4))).toThrow(
      expect.objectContaining({ code: "TRANSACTION_DESERIALIZE" }),
    );
    const custom = new Error("custom");
    expect(() => new Reader(Uint8Array.of(1, 2), () => custom).done()).toThrow(custom);
  });
});
