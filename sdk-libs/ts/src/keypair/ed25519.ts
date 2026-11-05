import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";

import { concatBytes, equalBytes } from "../interface/bytes.js";

const ED25519_ORDER = ed25519.Point.Fn.ORDER;

function leBytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index--) {
    value = (value << 8n) | BigInt(bytes[index] as number);
  }
  return value;
}

/**
 * The SDK's one Ed25519 verifier. The Solana runtime accepts a signature
 * exactly when ed25519-dalek `verify_strict` does, and so does this: the
 * cofactorless equation compared over the compressed R bytes, with a
 * small-order R or public key refused and an unreduced y decoded, not
 * rejected. A signature that holds only under the cofactored equation, which
 * noble's `verify` accepts, is refused. Malformed input is `false`.
 */
export function verifyEd25519Strict(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (
    !(signature instanceof Uint8Array) ||
    signature.length !== 64 ||
    !(publicKey instanceof Uint8Array) ||
    publicKey.length !== 32
  ) {
    return false;
  }
  try {
    const r = signature.subarray(0, 32);
    const s = leBytesToBigInt(signature.subarray(32));
    if (s >= ED25519_ORDER) return false;
    const a = ed25519.Point.fromBytes(publicKey, true);
    if (a.isSmallOrder() || ed25519.Point.fromBytes(r, true).isSmallOrder()) return false;
    const k = leBytesToBigInt(sha512(concatBytes(r, publicKey, message))) % ED25519_ORDER;
    const expected = ed25519.Point.BASE.multiplyUnsafe(s).subtract(a.multiplyUnsafe(k));
    return equalBytes(expected.toBytes(), r);
  } catch {
    return false;
  }
}
