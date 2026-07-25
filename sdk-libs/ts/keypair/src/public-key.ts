import { p256 } from "@noble/curves/nist.js";
import { ownerPkFieldCompressed, pkFieldCompressed } from "@zolana/interface";

import { type Bytes32, type Bytes33, type Bytes34, checkedBytes, copyBytes } from "./bytes.js";
import { P256_PUBLIC_KEY_LENGTH, SHIELDED_PUBLIC_KEY_LENGTH } from "./constants.js";
import { KeypairError, wrapKeypairError } from "./error.js";
import { hashField } from "./hash.js";

export type SignatureType = "p256" | "ed25519";
export type ViewTag = Bytes32;

export class P256PublicKey {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  static fromBytes(bytes: Bytes33): P256PublicKey {
    const owned = checkedBytes<Bytes33>(bytes, P256_PUBLIC_KEY_LENGTH, "P256 public key");
    try {
      p256.Point.fromBytes(owned);
    } catch (error) {
      throw wrapKeypairError("KEYPAIR_INVALID_PUBLIC_KEY", error);
    }
    return new P256PublicKey(owned);
  }

  static fromSecret(secret: Uint8Array): P256PublicKey {
    return P256PublicKey.fromBytes(p256.getPublicKey(secret, true) as Bytes33);
  }

  toBytes(): Bytes33 {
    return copyBytes(this.#bytes) as Bytes33;
  }

  x(): Bytes32 {
    return copyBytes(this.#bytes.subarray(1)) as Bytes32;
  }

  yIsOdd(): boolean {
    return this.#bytes[0] === 3;
  }

  /** Mirrors the derived `PartialEq` on Rust's `P256Pubkey`: compressed bytes. */
  equals(other: P256PublicKey): boolean {
    const left = this.#bytes;
    const right = other.#bytes;
    return left.length === right.length && left.every((byte, index) => byte === right[index]);
  }
}

export class ShieldedPublicKey {
  readonly #bytes: Uint8Array;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  static zeroed(): ShieldedPublicKey {
    return new ShieldedPublicKey(new Uint8Array(SHIELDED_PUBLIC_KEY_LENGTH));
  }

  static fromP256(key: P256PublicKey): ShieldedPublicKey {
    const bytes = new Uint8Array(SHIELDED_PUBLIC_KEY_LENGTH);
    bytes.set(key.toBytes(), 1);
    return new ShieldedPublicKey(bytes);
  }

  static fromEd25519(publicKey: Bytes32): ShieldedPublicKey {
    const bytes = new Uint8Array(SHIELDED_PUBLIC_KEY_LENGTH);
    bytes[0] = 1;
    bytes.set(checkedBytes<Bytes32>(publicKey, 32, "Ed25519 public key"), 1);
    return new ShieldedPublicKey(bytes);
  }

  static fromBytes(bytes: Bytes34): ShieldedPublicKey {
    const owned = checkedBytes<Uint8Array>(
      bytes,
      SHIELDED_PUBLIC_KEY_LENGTH,
      "shielded public key",
    );
    if (owned[0] === 0) {
      P256PublicKey.fromBytes(owned.subarray(1) as Bytes33);
    } else if (owned[0] === 1) {
      if (owned[SHIELDED_PUBLIC_KEY_LENGTH - 1] !== 0) {
        throw new KeypairError("KEYPAIR_INVALID_PUBLIC_KEY", { reason: "nonzeroPadding" });
      }
    } else {
      throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { prefix: owned[0] ?? 0 });
    }
    return new ShieldedPublicKey(owned);
  }

  toBytes(): Bytes34 {
    return copyBytes(this.#bytes) as Bytes34;
  }

  /** Mirrors the derived `PartialEq` on Rust's `PublicKey`: all 34 tagged bytes. */
  equals(other: ShieldedPublicKey): boolean {
    const left = this.#bytes;
    const right = other.#bytes;
    return left.length === right.length && left.every((byte, index) => byte === right[index]);
  }

  isZero(): boolean {
    return this.#bytes.every((byte) => byte === 0);
  }

  signatureType(): SignatureType {
    if (this.#bytes[0] === 0) return "p256";
    if (this.#bytes[0] === 1) return "ed25519";
    throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { prefix: this.#bytes[0] ?? 0 });
  }

  confidentialViewTag(): ViewTag {
    if (this.signatureType() === "p256") return this.p256().x();
    return copyBytes(this.#bytes.subarray(1, 33)) as ViewTag;
  }

  hash(): Bytes32 {
    if (this.signatureType() === "p256") {
      try {
        return pkFieldCompressed(this.p256().toBytes()) as Bytes32;
      } catch (error) {
        throw wrapKeypairError("KEYPAIR_HASH", error);
      }
    }
    return hashField(this.confidentialViewTag()) as Bytes32;
  }

  ownerPublicKeyField(): Bytes32 {
    if (this.signatureType() === "p256") {
      try {
        return ownerPkFieldCompressed(this.p256().toBytes()) as Bytes32;
      } catch (error) {
        throw wrapKeypairError("KEYPAIR_HASH", error);
      }
    }
    return hashField(this.confidentialViewTag()) as Bytes32;
  }

  ed25519(): Bytes32 {
    if (this.signatureType() !== "ed25519") {
      throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { expected: "ed25519" });
    }
    return copyBytes(this.#bytes.subarray(1, 33)) as Bytes32;
  }

  p256(): P256PublicKey {
    if (this.signatureType() !== "p256") {
      throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { expected: "p256" });
    }
    return P256PublicKey.fromBytes(this.#bytes.subarray(1) as Bytes33);
  }
}
