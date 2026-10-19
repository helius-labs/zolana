import { type Bytes32, type Bytes34, checkedBytes, copyBytes } from "./bytes.js";
import { SHIELDED_PUBLIC_KEY_LENGTH, SIGNATURE_TYPE_PDA } from "./constants.js";
import { solanaOwnerIdentity } from "../hasher/index.js";
import { KeypairError } from "./error.js";

/** Wire type 0 remains reserved and cannot construct an owner key. */
export type SignatureType = "ed25519" | "pda";
export type ViewTag = Bytes32;

export class ShieldedPublicKey {
  readonly #bytes: Uint8Array;
  #ownerHash: Uint8Array | undefined;

  private constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  static zeroed(): ShieldedPublicKey {
    return new ShieldedPublicKey(new Uint8Array(SHIELDED_PUBLIC_KEY_LENGTH));
  }

  static fromEd25519(publicKey: Bytes32): ShieldedPublicKey {
    const bytes = new Uint8Array(SHIELDED_PUBLIC_KEY_LENGTH);
    bytes[0] = 1;
    bytes.set(checkedBytes<Bytes32>(publicKey, 32, "Ed25519 public key"), 1);
    return new ShieldedPublicKey(bytes);
  }

  /** Mirrors Rust `PublicKey::from_pda`. */
  static fromPda(address: Bytes32): ShieldedPublicKey {
    const bytes = new Uint8Array(SHIELDED_PUBLIC_KEY_LENGTH);
    bytes[0] = SIGNATURE_TYPE_PDA;
    bytes.set(checkedBytes<Bytes32>(address, 32, "PDA address"), 1);
    return new ShieldedPublicKey(bytes);
  }

  static fromBytes(bytes: Bytes34): ShieldedPublicKey {
    const owned = checkedBytes<Uint8Array>(
      bytes,
      SHIELDED_PUBLIC_KEY_LENGTH,
      "shielded public key",
    );
    if (owned[0] === 1 || owned[0] === SIGNATURE_TYPE_PDA) {
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
    if (this.#bytes[0] === 1) return "ed25519";
    if (this.#bytes[0] === SIGNATURE_TYPE_PDA) return "pda";
    throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { prefix: this.#bytes[0] ?? 0 });
  }

  confidentialViewTag(): ViewTag {
    this.signatureType();
    return copyBytes(this.#bytes.subarray(1, 33)) as ViewTag;
  }

  /** The Solana-tagged owner identity bound by the proof and shielded pool. */
  ownerProofInputHash(): Bytes32 {
    this.#ownerHash ??= solanaOwnerIdentity(this.confidentialViewTag());
    return copyBytes(this.#ownerHash) as Bytes32;
  }

  ed25519(): Bytes32 {
    if (this.signatureType() !== "ed25519") {
      throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { expected: "ed25519" });
    }
    return copyBytes(this.#bytes.subarray(1, 33)) as Bytes32;
  }

  pda(): Bytes32 {
    if (this.signatureType() !== "pda") {
      throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { expected: "pda" });
    }
    return copyBytes(this.#bytes.subarray(1, 33)) as Bytes32;
  }
}
