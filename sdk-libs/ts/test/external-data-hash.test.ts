import { getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  encodeTransactExternalData,
  encodeTransactInstructionData,
} from "../src/interface/codecs/index.js";
import { InterfaceError } from "../src/interface/errors.js";
import { externalDataHash } from "../src/interface/external-data-hash.js";
import { InstructionTag, SOL_INTERFACE } from "../src/interface/program.js";
import type {
  Bytes16,
  Bytes32,
  Bytes33,
  Bytes64,
  TransactExternalData,
  TransactInstructionData,
} from "../src/interface/types.js";

const sequence = (length: number, from: number): Uint8Array =>
  Uint8Array.from({ length }, (_, index) => (from + index) & 0xff);
const bytes32 = (from: number): Bytes32 => sequence(32, from) as Bytes32;
const lastByte = (value: number): Bytes32 => {
  const hash = new Uint8Array(32);
  hash[31] = value;
  return hash as Bytes32;
};
const addressOf = (from: number) => getAddressDecoder().decode(sequence(32, from));
const hexOf = (value: Uint8Array): string => Buffer.from(value).toString("hex");

const INLINE_OWNER = bytes32(0);
const SOL_RECIPIENT = addressOf(0x20);
const SPL_USER = addressOf(0x40);
const MINT = addressOf(0x60);

const FIRST_OUTPUT: TransactExternalData["outputs"][number] = {
  utxoHash: lastByte(1),
  ownerTag: { kind: "inline", value: INLINE_OWNER },
  data: Uint8Array.from([
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  ]),
};
const PARITY_EXTERNAL_DATA: TransactExternalData = {
  expiryUnixTs: 1_234_567_890n,
  txViewingPk: sequence(33, 0x90) as Bytes33,
  salt: sequence(16, 0xf0) as Bytes16,
  interfaceTransfers: [
    { kind: "solWithdrawal", amount: 1_234_567_890n },
    { kind: "splDeposit", amount: 987_654_321n, splInterfaceBump: 255 },
  ],
  outputs: [
    FIRST_OUTPUT,
    { utxoHash: lastByte(2), ownerTag: { kind: "inline", value: INLINE_OWNER } },
  ],
  messages: [],
};
const PARITY_INPUT = {
  ...PARITY_EXTERNAL_DATA,
  instructionDiscriminator: InstructionTag.transact,
  settlementAccounts: [
    { asset: SOL_INTERFACE, user: SOL_RECIPIENT },
    { asset: MINT, user: SPL_USER },
  ],
  resolvedOwnerTags: [INLINE_OWNER, INLINE_OWNER],
};
const PARITY_DIGEST = "008e8259154c81c2233306b9d9aa4cbf0148173357a5969abfebb886027904de";

describe("externalDataHash", () => {
  it("reproduces the Rust parity digest", () => {
    expect(hexOf(externalDataHash(PARITY_INPUT))).toBe(PARITY_DIGEST);
  });

  it("appends the resolved address of an account owner tag only", () => {
    const withTag = (index: number, resolved: Bytes32) =>
      externalDataHash({
        ...PARITY_INPUT,
        outputs: [FIRST_OUTPUT, { utxoHash: lastByte(2), ownerTag: { kind: "account", index } }],
        resolvedOwnerTags: [INLINE_OWNER, resolved],
      });
    expect(withTag(1, bytes32(0x70))).not.toEqual(withTag(1, bytes32(0x71)));
    expect(withTag(1, bytes32(0x70))).not.toEqual(withTag(2, bytes32(0x70)));
    const inline = externalDataHash({
      ...PARITY_INPUT,
      resolvedOwnerTags: [INLINE_OWNER, bytes32(0x71)],
    });
    expect(hexOf(inline)).toBe(PARITY_DIGEST);
  });

  it("binds the settlement accounts of every leg", () => {
    const swapped = externalDataHash({
      ...PARITY_INPUT,
      settlementAccounts: [
        { asset: SOL_INTERFACE, user: SPL_USER },
        { asset: MINT, user: SOL_RECIPIENT },
      ],
    });
    expect(hexOf(swapped)).not.toBe(PARITY_DIGEST);
  });

  it("refuses settlement accounts or resolved tags that do not pair with the data", () => {
    expect(() =>
      externalDataHash({
        ...PARITY_INPUT,
        settlementAccounts: PARITY_INPUT.settlementAccounts.slice(1),
      }),
    ).toThrow(InterfaceError);
    expect(() => externalDataHash({ ...PARITY_INPUT, resolvedOwnerTags: [INLINE_OWNER] })).toThrow(
      InterfaceError,
    );
  });
});

describe("encodeTransactInstructionData", () => {
  it("starts with the encoded external data", () => {
    const instruction: TransactInstructionData = {
      ...PARITY_EXTERNAL_DATA,
      privateTxHash: bytes32(0xc0),
      circuit: { kind: "confidentialEddsa", inputs: 1, outputs: 2, publicAssetSlots: 3 },
      proof: { a: bytes32(0x01), b: sequence(64, 0x02) as Bytes64, c: bytes32(0x03) },
      inputs: [{ nullifierHash: bytes32(0x04), nullifierTreeRootIndex: 5, utxoTreeRootIndex: 6 }],
    };
    const prefix = encodeTransactExternalData(PARITY_EXTERNAL_DATA);
    const encoded = encodeTransactInstructionData(instruction);
    expect(encoded.subarray(0, prefix.length)).toEqual(prefix);
    expect(encoded.length).toBe(prefix.length + 32 + 5 + 128 + 1 + 36);
    expect(prefix.length).toBe(
      8 + 33 + 16 + 1 + 9 + 10 + 1 + 1 + 1 + (32 + 33 + 3 + 16) + (32 + 33 + 1) + 1,
    );
  });
});
