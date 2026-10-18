import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";

import {
  type Bytes32,
  type Bytes64,
  checkedBytes,
  concatBytes,
  copyBytes,
  randomBytes,
} from "./bytes.js";
import { ed25519DerivationMessage, isDerivationInput } from "./derivation.js";
import { KeypairError, wrapKeypairError } from "./error.js";
import { ShieldedPublicKey, type SignatureType } from "./public-key.js";

const ED25519_ORDER = ed25519.Point.Fn.ORDER;

function leBytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index--) {
    value = (value << 8n) | BigInt(bytes[index] as number);
  }
  return value;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  return left.every((byte, index) => byte === right[index]);
}

// The Solana runtime accepts an Ed25519 signature exactly when `verify_strict`
// does, so this helper answers the same question the runtime would: the
// cofactorless equation compared over the compressed R bytes, with a
// small-order R or public key refused and an unreduced y decoded, not rejected.
function verifyEd25519Strict(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  const r = signature.subarray(0, 32);
  const s = leBytesToBigInt(signature.subarray(32));
  if (s >= ED25519_ORDER) return false;
  const a = ed25519.Point.fromBytes(publicKey, true);
  if (a.isSmallOrder() || ed25519.Point.fromBytes(r, true).isSmallOrder()) return false;
  const k = leBytesToBigInt(sha512(concatBytes(r, publicKey, message))) % ED25519_ORDER;
  const expected = ed25519.Point.BASE.multiplyUnsafe(s).subtract(a.multiplyUnsafe(k));
  return bytesEqual(expected.toBytes(), r);
}

export class SigningKey {
  #secret: Uint8Array;
  #destroyed = false;

  private constructor(secret: Uint8Array) {
    this.#secret = secret;
  }

  static generate(type: "ed25519" = "ed25519"): SigningKey {
    if (type !== "ed25519") throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { type });
    return new SigningKey(randomBytes(32));
  }

  static fromEd25519Bytes(bytes: Bytes32): SigningKey {
    return new SigningKey(checkedBytes<Bytes32>(bytes, 32, "Ed25519 signing secret"));
  }

  /** Mirrors `SigningKey::is_ed25519`: which rail this key signs on. */
  isEd25519(): boolean {
    return true;
  }

  signatureType(): SignatureType {
    return "ed25519";
  }

  publicKey(): ShieldedPublicKey {
    this.#assertUsable();
    return ShieldedPublicKey.fromEd25519(ed25519.getPublicKey(this.#secret) as Bytes32);
  }

  sign(message: Uint8Array): Bytes64 {
    this.#assertUsable();
    if (isDerivationInput(message)) {
      throw new KeypairError("KEYPAIR_DERIVATION_INPUT");
    }
    try {
      return ed25519.sign(message, this.#secret) as Bytes64;
    } catch (error) {
      throw wrapKeypairError("KEYPAIR_INVALID_SECRET_KEY", error);
    }
  }

  /** Deterministic off-chain signature that seeds the nullifier and viewing roles. */
  derivationSeed(): Uint8Array {
    this.#assertUsable();
    const message = ed25519DerivationMessage(ed25519.getPublicKey(this.#secret) as Bytes32);
    return ed25519.sign(message, this.#secret);
  }

  verify(message: Uint8Array, signature: Bytes64): boolean {
    this.#assertUsable();
    if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
    try {
      return verifyEd25519Strict(signature, message, this.publicKey().ed25519());
    } catch {
      return false;
    }
  }

  secretBytes(): Bytes32 {
    this.#assertUsable();
    return copyBytes(this.#secret) as Bytes32;
  }

  destroy(): void {
    this.#secret.fill(0);
    this.#destroyed = true;
  }

  #assertUsable(): void {
    if (this.#destroyed) {
      throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY", { reason: "destroyed" });
    }
  }
}
