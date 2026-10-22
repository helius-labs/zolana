import { x25519 } from "@noble/curves/ed25519.js";

import { type Bytes32, type Bytes33, checkedBytes, concatBytes, randomBytes } from "./bytes.js";
import { KeypairError } from "./error.js";

/** Tagged X25519 public key with one canonical little-endian u encoding. */
export class X25519PublicKey {
  readonly #bytes: Bytes33;

  private constructor(bytes: Bytes33) {
    this.#bytes = bytes;
  }

  static fromBytes(bytes: Uint8Array): X25519PublicKey {
    const key = checkedBytes<Bytes33>(bytes, 33, "X25519 public key");
    let u = 0n;
    for (let i = 32; i >= 1; i--) u = (u << 8n) | BigInt(key[i] ?? 0);
    if (key[0] !== 4 || u >= (1n << 255n) - 19n) {
      throw new KeypairError("KEYPAIR_INVALID_PUBLIC_KEY");
    }
    return new X25519PublicKey(key);
  }

  /** The inverse of `u`. */
  static fromU(u: Bytes32): X25519PublicKey {
    return X25519PublicKey.fromBytes(concatBytes(Uint8Array.of(4), u));
  }

  equals(other: X25519PublicKey): boolean {
    return this.#bytes.every((b, i) => b === other.#bytes[i]);
  }
  toBytes(): Bytes33 {
    return checkedBytes<Bytes33>(this.#bytes, 33, "X25519 public key");
  }
  u(): Bytes32 {
    return checkedBytes<Bytes32>(this.#bytes.subarray(1), 32, "X25519 coordinate");
  }

  /** The u-coordinate used as the public bootstrap view tag. */
  x(): Bytes32 {
    return this.u();
  }
}

const SMALL_ORDER_PROBE = new Uint8Array(32).fill(1);

/** X25519 maps a small-order key to zero under every clamped scalar, any viewing key included. */
export function isSmallOrder(key: X25519PublicKey): boolean {
  try {
    x25519.getSharedSecret(SMALL_ORDER_PROBE, key.u()).fill(0);
    return false;
  } catch {
    return true;
  }
}

/** RFC 7748 secret for X25519 agreement. ViewingKey clamps its own byte form. */
export class X25519Keypair {
  #secret: Bytes32 | undefined;
  private constructor(secret: Bytes32) {
    this.#secret = secret;
  }

  static generate(): X25519Keypair {
    const secret = randomBytes(32);
    try {
      return X25519Keypair.fromBytes(secret);
    } finally {
      secret.fill(0);
    }
  }
  static fromBytes(bytes: Uint8Array): X25519Keypair {
    return new X25519Keypair(checkedBytes<Bytes32>(bytes, 32, "X25519 secret"));
  }
  #usable(): Bytes32 {
    if (this.#secret === undefined) throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY");
    return this.#secret;
  }
  publicKey(): X25519PublicKey {
    return X25519PublicKey.fromBytes(
      concatBytes(Uint8Array.of(4), x25519.getPublicKey(this.#usable())),
    );
  }
  secretBytes(): Bytes32 {
    return checkedBytes<Bytes32>(this.#usable(), 32, "X25519 secret");
  }
  clone(): X25519Keypair {
    return X25519Keypair.fromBytes(this.#usable());
  }
  ecdh(peer: X25519PublicKey): Bytes32 {
    const secret = this.#usable();
    try {
      // Noble rejects the all-zero result, including every low-order peer.
      const shared = x25519.getSharedSecret(secret, peer.u());
      try {
        return checkedBytes<Bytes32>(shared, 32, "X25519 shared secret");
      } finally {
        shared.fill(0);
      }
    } catch {
      throw new KeypairError("KEYPAIR_NON_CONTRIBUTORY_KEY");
    }
  }
  destroy(): void {
    this.#secret?.fill(0);
    this.#secret = undefined;
  }
}
