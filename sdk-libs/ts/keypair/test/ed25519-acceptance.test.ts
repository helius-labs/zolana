import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import signingFixture from "../../fixtures/keypair/signing_key.json" with { type: "json" };
import type { Bytes32, Bytes64 } from "../src/bytes.js";
import { SigningKey } from "../src/index.js";

// Each case asserts the outcome the Solana runtime gives, that is
// `ed25519_dalek::VerifyingKey::verify_strict`. `sdk-libs/keypair/src/signing_key.rs`
// asserts the same three vectors and the same outcomes.
const SECRET = signingFixture.inputs.ed25519SecretBytes;
const VALID_SIGNATURE = signingFixture.expected.ed25519.signatureBytes;

// R is the identity point and s is `k * x mod L`, so `[s]B - [k]A` recompresses
// to R and the plain verification equation holds. The runtime refuses it because
// R has small order.
const SMALL_ORDER_R_SIGNATURE =
  "0100000000000000000000000000000000000000000000000000000000000000" +
  "756cf9b1d6f0d7a979b9d2af3dc2bc1294ec7cb6daa20eaff534c024fc57920f";

// R encodes y = p + 3, which decodes to a point of full order rather than being
// refused outright. R is compared as bytes, so only its canonical encoding can
// verify.
const NON_CANONICAL_R_SIGNATURE =
  "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" + VALID_SIGNATURE.slice(64);

function fromHex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/.{2}/gu) ?? [], (byte) => Number.parseInt(byte, 16));
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const key = SigningKey.fromEd25519Bytes(fromHex(SECRET) as Bytes32);
const message = new Uint8Array();

describe("Ed25519 acceptance mirrors the Solana runtime", () => {
  it("accepts the committed signature", () => {
    expect(key.verify(message, fromHex(VALID_SIGNATURE) as Bytes64)).toBe(true);
  });

  it("refuses a small-order R that the plain verification equation accepts", () => {
    const signature = fromHex(SMALL_ORDER_R_SIGNATURE);
    expect(ed25519.verify(signature, message, key.publicKey().ed25519())).toBe(true);
    expect(key.verify(message, signature as Bytes64)).toBe(false);
  });

  it("refuses a non-canonical R encoding", () => {
    const r = fromHex(NON_CANONICAL_R_SIGNATURE).subarray(0, 32);
    expect(ed25519.Point.fromBytes(r, true).isSmallOrder()).toBe(false);
    expect(key.verify(message, fromHex(NON_CANONICAL_R_SIGNATURE) as Bytes64)).toBe(false);
  });

  it("derives the small-order R vector from the committed secret", () => {
    const order = ed25519.Point.Fn.ORDER;
    const publicKey = key.publicKey().ed25519();
    const r = new Uint8Array(32);
    r[0] = 1;
    const le = (bytes: Uint8Array): bigint => {
      let value = 0n;
      for (let index = bytes.length - 1; index >= 0; index--) {
        value = (value << 8n) | BigInt(bytes[index] as number);
      }
      return value;
    };
    const k = le(sha512(Uint8Array.from([...r, ...publicKey, ...message]))) % order;
    const s = (k * ed25519.utils.getExtendedPublicKey(key.secretBytes()).scalar) % order;
    const signature = new Uint8Array(64);
    signature.set(r);
    for (let index = 0, remaining = s; index < 32; index++, remaining >>= 8n) {
      signature[32 + index] = Number(remaining & 0xffn);
    }

    expect(toHex(signature)).toBe(SMALL_ORDER_R_SIGNATURE);
  });
});
