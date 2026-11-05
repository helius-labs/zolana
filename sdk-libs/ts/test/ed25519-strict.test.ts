import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { concatBytes } from "../src/interface/bytes.js";
import { ed25519DerivationMessage, SigningKey, type Bytes32 } from "../src/keypair/index.js";
import { verifyEd25519Strict } from "../src/keypair/ed25519.js";
import { LocalShieldedKeys } from "../src/transaction/index.js";

const SECRET = new Uint8Array(32).fill(7);
const ORDER = ed25519.Point.Fn.ORDER;
// A point of order 8.
const TORSION = ed25519.Point.fromHex(
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
);

function le(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index--) {
    value = (value << 8n) | BigInt(bytes[index] as number);
  }
  return value;
}

function toLe(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  for (let index = 0, rest = value; index < 32; index++, rest >>= 8n) {
    bytes[index] = Number(rest & 0xffn);
  }
  return bytes;
}

/** A signature whose R carries a torsion component: it holds only under the cofactored equation. */
function mixedOrderSignature(
  message: Uint8Array,
): Readonly<{ publicKey: Bytes32; signature: Uint8Array }> {
  const { scalar, pointBytes } = ed25519.utils.getExtendedPublicKey(SECRET);
  const r = 12_345n;
  const nonce = ed25519.Point.BASE.multiply(r).add(TORSION).toBytes();
  const k = le(sha512(concatBytes(nonce, pointBytes, message))) % ORDER;
  const s = (r + k * scalar) % ORDER;
  return { publicKey: pointBytes as Bytes32, signature: concatBytes(nonce, toLe(s)) };
}

describe("verifyEd25519Strict", () => {
  const message = new TextEncoder().encode("strict");

  it("accepts an honest signature", () => {
    const signer = SigningKey.fromEd25519Bytes(SECRET.slice() as Bytes32);
    const signature = signer.sign(message);
    expect(verifyEd25519Strict(signature, message, signer.publicKey().ed25519())).toBe(true);
    expect(signer.verify(message, signature)).toBe(true);
  });

  it("refuses a cofactored-only signature that noble's verify accepts", () => {
    const { publicKey, signature } = mixedOrderSignature(message);
    expect(ed25519.verify(signature, message, publicKey, { zip215: false })).toBe(true);
    expect(verifyEd25519Strict(signature, message, publicKey)).toBe(false);
  });

  it("refuses a small-order key and malformed input", () => {
    const identity = new Uint8Array(32);
    identity[0] = 1;
    expect(verifyEd25519Strict(concatBytes(identity, new Uint8Array(32)), message, identity)).toBe(
      false,
    );
    expect(verifyEd25519Strict(new Uint8Array(63), message, identity)).toBe(false);
    expect(verifyEd25519Strict(new Uint8Array(64), message, new Uint8Array(31))).toBe(false);
  });

  it("refuses a cofactored-only derivation seed", () => {
    const { publicKey } = mixedOrderSignature(new Uint8Array());
    const { signature } = mixedOrderSignature(ed25519DerivationMessage(publicKey));
    expect(() =>
      LocalShieldedKeys.fromDerivationSeed({
        solanaPublicKey: getAddressDecoder().decode(publicKey),
        derivationSeed: signature,
      }),
    ).toThrow(expect.objectContaining({ code: "TRANSACTION_INVALID_DERIVATION_SEED" }));
  });
});
