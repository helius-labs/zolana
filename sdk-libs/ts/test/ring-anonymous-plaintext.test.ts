import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import vector from "../../../test-vectors/ring_anonymous_plaintext.json" with { type: "json" };
import { encodeBase58 } from "../src/interface/internal.js";
import type { Bytes32 } from "../src/interface/types.js";
import { X25519_PUBLIC_KEY_LENGTH } from "../src/keypair/constants.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import { Data } from "../src/transaction/data.js";
import { TransactionError } from "../src/transaction/error.js";
import {
  decodeConfidential,
  decodeRingAnonymous,
  encodeConfidential,
  encodeRingAnonymous,
  type RingAnonymousOutputPlaintext,
} from "../src/transaction/serialization/codecs.js";

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

const plaintext: RingAnonymousOutputPlaintext = {
  output: {
    assetId: BigInt(vector.asset_id),
    amount: BigInt(vector.amount),
    blinding: hex(vector.blinding) as Bytes32,
    ringProgramId: address(encodeBase58(hex(vector.ring_program_id))),
    data: new Data(),
  },
  pairPublicKey: X25519Keypair.fromBytes(hex(vector.pair_secret)).publicKey(),
};

describe("ring anonymous plaintext", () => {
  it("matches the shared vector", () => {
    expect(Buffer.from(plaintext.pairPublicKey.toBytes()).toString("hex")).toBe(vector.pair_pk);
    const bytes = encodeRingAnonymous(plaintext);
    expect(Buffer.from(bytes).toString("hex")).toBe(vector.plaintext);
    const decoded = decodeRingAnonymous(bytes);
    expect(decoded.output).toEqual(plaintext.output);
    expect(decoded.pairPublicKey.equals(plaintext.pairPublicKey)).toBe(true);
  });

  it("keeps the scheme-3 layout in front of the pair key", () => {
    const scheme3 = encodeConfidential(plaintext.output);
    const scheme9 = encodeRingAnonymous(plaintext);
    expect(scheme9.length).toBe(scheme3.length + X25519_PUBLIC_KEY_LENGTH);
    expect(scheme9.subarray(0, scheme3.length)).toEqual(scheme3);
    expect(() => decodeConfidential(scheme9)).toThrow(TransactionError);
    expect(() => decodeRingAnonymous(scheme3)).toThrow(TransactionError);
  });

  it("rejects a truncated body and an untagged pair key", () => {
    const bytes = encodeRingAnonymous(plaintext);
    expect(() => decodeRingAnonymous(bytes.subarray(0, bytes.length - 1))).toThrow(
      TransactionError,
    );
    expect(() => decodeRingAnonymous(bytes.subarray(0, 32))).toThrow(
      expect.objectContaining({ code: "TRANSACTION_INVALID_LENGTH" }),
    );
    const untagged = Uint8Array.from(bytes);
    untagged[bytes.length - X25519_PUBLIC_KEY_LENGTH] = 5;
    expect(() => decodeRingAnonymous(untagged)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_KEYPAIR" }),
    );
  });
});
