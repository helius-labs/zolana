import { beforeEach, describe, expect, it, vi } from "vitest";

import { BN254_SCALAR_ORDER, initializePoseidon } from "../src/hasher/index.js";
import {
  ANONYMOUS_SLOT_BYTES,
  DISCLOSURE_CHUNK_BYTES,
  DISCLOSURE_SENDER_KEY_BYTES,
  anonymousFields,
  deliveredFields,
  disclosureFieldCount,
  type DisclosureLayout,
} from "../src/interface/ring-disclosure-layout.js";
import type { Bytes16, Bytes32 } from "../src/interface/types.js";
import type * as Audit from "../src/keypair/audit.js";
import { maskDisclosure, unmaskDisclosure } from "../src/keypair/audit.js";
import { bigIntToBytes } from "../src/keypair/bytes.js";
import { isCanonicalField } from "../src/interface/canonical-field.js";
import {
  anonymousCommitments,
  decodeDisclosure,
  disclosureFields,
  disclosureLayout,
  inputPrefix,
  inputPrefixPair,
  splitInputPrefixPair,
  type InputPrefix,
  type RingDisclosure,
} from "../src/keypair/ring-disclosure.js";
import { RingDomain } from "../src/keypair/ring-domain.js";

const packing = vi.hoisted(
  (): { blocks: Uint8Array[]; chunks: Uint8Array[]; unpacked: Uint8Array[] } => ({
    blocks: [],
    chunks: [],
    unpacked: [],
  }),
);
vi.mock("../src/keypair/audit.js", async (importOriginal) => {
  const actual = await importOriginal<typeof Audit>();
  return {
    ...actual,
    packDisclosure: (plaintext: Uint8Array) => {
      packing.blocks.push(plaintext);
      const chunks = actual.packDisclosure(plaintext);
      packing.chunks.push(...chunks);
      return chunks;
    },
    unpackDisclosure: (fields: readonly Bytes32[], length: number) => {
      const plaintext = actual.unpackDisclosure(fields, length);
      packing.unpacked.push(plaintext);
      return plaintext;
    },
  };
});

await initializePoseidon();

const MODULUS = bigIntToBytes(BN254_SCALAR_ORDER) as Bytes32;

function field(byte: number): Bytes32 {
  const out = new Uint8Array(32).fill(byte);
  out[0] = 0;
  return out as Bytes32;
}

function bytes(byte: number): Bytes32 {
  return new Uint8Array(32).fill(byte) as Bytes32;
}

function wiped(buffer: Uint8Array): boolean {
  return buffer.every((byte) => byte === 0);
}

function setPacked(fields: readonly Bytes32[], start: number, at: number, value: number): void {
  fields[start + Math.floor(at / DISCLOSURE_CHUNK_BYTES)]![1 + (at % DISCLOSURE_CHUNK_BYTES)] =
    value;
}

/** Rust `delivered`. */
function delivered(): Extract<RingDisclosure, { kind: "delivered" }> {
  const ring = (byte: number) => ({
    kind: "ring" as const,
    ownerKey: bytes(byte),
    nullifierPk: field(byte),
  });
  const exit = (byte: number, amount: bigint) => ({
    kind: "exit" as const,
    nullifierPk: field(byte),
    asset: field(byte + 1),
    amount,
  });
  const dummy = { kind: "dummy" as const };
  return {
    kind: "delivered",
    layout: { outputs: 8, exits: true, keyEscrow: false },
    seedOut: field(1),
    outputs: [
      ring(0xb0),
      exit(0x20, 0n),
      dummy,
      ring(0xb3),
      exit(0x24, 40n),
      dummy,
      ring(0xb6),
      ring(0xb7),
    ],
  };
}
const DELIVERED_EXITS = [false, true, false, false, true, false, false, false];

/** Rust `anonymous`. */
function anonymous(): Extract<RingDisclosure, { kind: "anonymous" }> {
  return {
    kind: "anonymous",
    layout: { key: { kind: "entry" }, inputs: 2, outputs: 4, exits: true },
    seedOut: field(1),
    outputs: [
      { kind: "ring", ownerKey: bytes(0xb5), nullifierPk: field(0x25), recipientU: bytes(0x15) },
      { kind: "exit", nullifierPk: field(0x26), asset: field(0x27), amount: 0n },
      { kind: "dummy" },
      { kind: "ring", ownerKey: bytes(0xa1), nullifierPk: field(0x5a), recipientU: bytes(0x17) },
    ],
    inputs: {
      kind: "openings",
      senderKey: bytes(0xa1),
      senderNullifierPk: field(0x5a),
      inputs: [{ asset: field(0x60), amount: 5000n, blinding: field(0x61) }, undefined],
    },
  };
}
const ANONYMOUS_EXITS = [false, true, false, false];

function commitments(): Extract<RingDisclosure, { kind: "anonymous" }> {
  return {
    ...anonymous(),
    layout: { key: { kind: "commitment", class: 4 }, inputs: 4, outputs: 4, exits: true },
    inputs: anonymousCommitments([field(0x60), field(0x61), undefined, field(0x63)]),
  };
}

function packed(): Extract<RingDisclosure, { kind: "packed" }> {
  const opening = (byte: number) => ({
    ownerKey: bytes(byte),
    nullifierPk: field(byte),
    asset: field(byte + 1),
    amount: BigInt(byte),
    dataHash: field(byte + 2),
    ringDataHash: new Uint8Array(32) as Bytes32,
  });
  return {
    kind: "packed",
    layout: { outputs: 3, exits: true, keyEscrow: false, dataFree: false },
    seedOut: field(1),
    outputs: [opening(0x30), undefined, opening(0x40)],
  };
}
const PACKED_EXITS = [false, false, true];

function zeros(layout: DisclosureLayout): Bytes32[] {
  return Array.from({ length: disclosureFieldCount(layout) }, () => new Uint8Array(32) as Bytes32);
}

describe("ring disclosure codec", () => {
  beforeEach(() => {
    packing.blocks.length = 0;
    packing.chunks.length = 0;
    packing.unpacked.length = 0;
  });

  it.each([
    ["packed", packed, PACKED_EXITS],
    ["delivered", delivered, DELIVERED_EXITS],
    ["anonymous", anonymous, ANONYMOUS_EXITS],
    ["commitment", commitments, ANONYMOUS_EXITS],
  ] as const)("wipes every %s block it packs or unpacks and round trips", (_, build, exits) => {
    const disclosure = build();
    const plaintext = disclosureFields(disclosure);

    expect(packing.blocks.length).toBeGreaterThan(0);
    expect(packing.blocks.filter((block) => !wiped(block))).toEqual([]);
    expect(decodeDisclosure({ layout: disclosureLayout(disclosure), exits }, plaintext)).toEqual(
      disclosure,
    );
    expect(packing.unpacked.length).toBeGreaterThan(0);
    expect(packing.unpacked.filter((block) => !wiped(block))).toEqual([]);
  });

  it("wipes every field it placed when a later part is refused", () => {
    const entry = anonymous();
    if (entry.inputs.kind !== "openings") throw new Error("entry fixture");
    const disclosure = { ...entry, inputs: { ...entry.inputs, senderNullifierPk: MODULUS } };

    expect(() => disclosureFields(disclosure)).toThrow("KEYPAIR_DISCLOSURE_FIELD");
    expect(packing.chunks.length).toBeGreaterThan(0);
    expect(packing.chunks.filter((chunk) => !wiped(chunk))).toEqual([]);
    expect(packing.blocks.filter((block) => !wiped(block))).toEqual([]);
  });

  it("marks an empty delivered slot by its disclosed key, by its zero slot under key escrow", () => {
    const disclosure = delivered();
    const layout = disclosureLayout(disclosure);
    const at = deliveredFields(disclosure.layout);
    const decode = (plaintext: readonly Bytes32[]) =>
      decodeDisclosure({ layout, exits: DELIVERED_EXITS }, plaintext);

    const zeroKey = disclosureFields(disclosure);
    zeroKey[at.nullifierPks!.start] = new Uint8Array(32) as Bytes32;
    expect(() => decode(zeroKey)).toThrow("KEYPAIR_DISCLOSURE_PADDING");

    const zeroOwner = disclosureFields(disclosure);
    for (let byte = 0; byte < 32; byte++) setPacked(zeroOwner, at.slots.start, byte, 0);
    const opened = decode(zeroOwner);
    expect(opened.kind === "delivered" && opened.outputs[0]).toEqual({
      kind: "ring",
      ownerKey: new Uint8Array(32),
      nullifierPk: field(0xb0),
    });

    const escrowed = {
      ...disclosure,
      layout: { ...disclosure.layout, keyEscrow: true },
      outputs: disclosure.outputs.map((output) =>
        output.kind === "dummy" ? output : { ...output, nullifierPk: undefined },
      ),
    };
    const escrowedAt = deliveredFields(escrowed.layout);
    const empty = disclosureFields(escrowed);
    for (let byte = 0; byte < 32; byte++) setPacked(empty, escrowedAt.slots.start, byte, 0);
    const reopened = decodeDisclosure(
      { layout: disclosureLayout(escrowed), exits: DELIVERED_EXITS },
      empty,
    );
    expect(reopened.kind === "delivered" && reopened.outputs[0]).toEqual({ kind: "dummy" });
  });

  it("names spent UTXO 0 by its hash and packs two later prefixes a field", () => {
    const disclosure = commitments();
    const at = anonymousFields(disclosure.layout);
    if (at.inputs.kind !== "commitments") throw new Error("commitment layout");
    const plaintext = disclosureFields(disclosure);
    const prefix = (hash: Bytes32) =>
      BigInt(`0x${Buffer.from(hash.subarray(0, 16)).toString("hex")}`);
    expect(plaintext[at.inputs.first]).toEqual(field(0x60));
    expect(plaintext.slice(at.inputs.prefixPairs.start, at.inputs.prefixPairs.end)).toEqual([
      bigIntToBytes(prefix(field(0x61)) << 126n),
      bigIntToBytes(prefix(field(0x63)) << 126n),
    ]);
    // No sender key leads the slots of a commitment key.
    expect(packing.blocks.at(-1)?.length).toBe(4 * ANONYMOUS_SLOT_BYTES);
  });

  it("refuses spent UTXO 0 as a dummy, a later hash below 2^128 and a pair it cannot split", () => {
    const short = new Uint8Array(32) as Bytes32;
    short[31] = 1;
    expect(() => anonymousCommitments([undefined, field(0x61)])).toThrow(
      "KEYPAIR_DISCLOSURE_SHAPE",
    );
    expect(() => anonymousCommitments([field(0x60), short])).toThrow("KEYPAIR_DISCLOSURE_FIELD");
    const disclosure = commitments();
    const layout = disclosureLayout(disclosure);
    const at = anonymousFields(disclosure.layout);
    if (at.inputs.kind !== "commitments") throw new Error("commitment layout");
    const decode = (change: (plaintext: Bytes32[]) => void) => () => {
      const plaintext = disclosureFields(disclosure);
      change(plaintext);
      return decodeDisclosure({ layout, exits: ANONYMOUS_EXITS }, plaintext);
    };
    const { first, prefixPairs } = at.inputs;
    expect(decode((plaintext) => (plaintext[first] = new Uint8Array(32) as Bytes32))).toThrow(
      "KEYPAIR_DISCLOSURE_SHAPE",
    );
    expect(decode((plaintext) => (plaintext[prefixPairs.end - 1]![31] = 1))).toThrow(
      "KEYPAIR_DISCLOSURE_PADDING",
    );
    expect(
      decode(
        (plaintext) =>
          (plaintext[prefixPairs.start] = bigIntToBytes(
            ((BN254_SCALAR_ORDER >> 128n) + 1n) << 126n,
          ) as Bytes32),
      ),
    ).toThrow("KEYPAIR_DISCLOSURE_FIELD");
  });

  it("packs two input prefixes below 2^252 and splits them back", () => {
    const top = inputPrefix(bigIntToBytes(BN254_SCALAR_ORDER - 1n) as Bytes32);
    expect(top).toBe(BN254_SCALAR_ORDER >> 128n);
    expect(inputPrefix(MODULUS)).toBeUndefined();
    const short = new Uint8Array(32) as Bytes32;
    short[16] = 1;
    expect(inputPrefix(short)).toBeUndefined();
    const low = inputPrefix(new Uint8Array(32).fill(1) as Bytes32);
    for (const pair of [
      [top, top],
      [low, undefined],
      [undefined, top],
      [undefined, undefined],
    ] as const satisfies readonly (readonly [InputPrefix | undefined, InputPrefix | undefined])[]) {
      const packed = inputPrefixPair(pair[0], pair[1]);
      expect(isCanonicalField(packed)).toBe(true);
      expect(splitInputPrefixPair(packed)).toEqual(pair);
    }
    const over = inputPrefixPair(undefined, top);
    over[31] = (over[31] ?? 0) + 1;
    expect(splitInputPrefixPair(over)).toBeUndefined();
    const wide = new Uint8Array(32) as Bytes32;
    wide[0] = 0x10;
    expect(splitInputPrefixPair(wide)).toBeUndefined();
  });

  it("refuses an anonymous dummy slot with a nonzero byte", () => {
    const disclosure = anonymous();
    const at = anonymousFields(disclosure.layout);
    const plaintext = disclosureFields(disclosure);
    setPacked(
      plaintext,
      at.slots.start,
      DISCLOSURE_SENDER_KEY_BYTES + 2 * ANONYMOUS_SLOT_BYTES + 5,
      1,
    );

    expect(() =>
      decodeDisclosure({ layout: disclosureLayout(disclosure), exits: ANONYMOUS_EXITS }, plaintext),
    ).toThrow("KEYPAIR_DISCLOSURE_PADDING");
  });

  it("refuses a field at or above the modulus instead of reducing it", () => {
    const disclosure = delivered();
    const plaintext = disclosureFields(disclosure);
    plaintext[1] = MODULUS;
    const pad = {
      key: field(9),
      salt: new Uint8Array(16).fill(7) as Bytes16,
      domain: RingDomain.disclosurePad,
      fields: plaintext,
    };

    expect(() =>
      decodeDisclosure({ layout: disclosureLayout(disclosure), exits: DELIVERED_EXITS }, plaintext),
    ).toThrow("KEYPAIR_DISCLOSURE_FIELD");
    expect(() => unmaskDisclosure(pad)).toThrow("KEYPAIR_DISCLOSURE_FIELD");
    expect(() => maskDisclosure(pad)).toThrow("KEYPAIR_DISCLOSURE_FIELD");
  });

  it.each([
    { kind: "packed", outputs: 2, exits: false, keyEscrow: false, dataFree: false },
    { kind: "delivered", outputs: 8, exits: false, keyEscrow: false },
    {
      kind: "anonymous",
      key: { kind: "commitment", class: 4 },
      inputs: 2,
      outputs: 4,
      exits: false,
    },
  ] as const satisfies readonly DisclosureLayout[])(
    "refuses an exit its $kind layout does not flag",
    (layout) => {
      const exits = Array.from({ length: layout.outputs }, (_, index) => index === 1);

      expect(() => decodeDisclosure({ layout, exits }, zeros(layout))).toThrow(
        "KEYPAIR_DISCLOSURE_SHAPE",
      );
    },
  );
});
