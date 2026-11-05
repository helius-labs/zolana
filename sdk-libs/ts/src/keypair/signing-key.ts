import { ed25519 } from "@noble/curves/ed25519.js";

import { type Bytes32, type Bytes64, checkedBytes, copyBytes, randomBytes } from "./bytes.js";
import { ed25519DerivationMessage, isDerivationInput } from "./derivation.js";
import { verifyEd25519Strict } from "./ed25519.js";
import { KeypairError, wrapKeypairError } from "./error.js";
import { ShieldedPublicKey, type SignatureType } from "./public-key.js";

export class SigningKey {
  #secret: Uint8Array;
  #destroyed = false;

  private constructor(secret: Uint8Array) {
    this.#secret = secret;
  }

  static generate(type: SignatureType = "ed25519"): SigningKey {
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
    return verifyEd25519Strict(signature, message, this.publicKey().ed25519());
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
