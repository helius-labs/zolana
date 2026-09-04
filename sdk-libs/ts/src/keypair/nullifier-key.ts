import { type Bytes31, type Bytes32, checkedBytes, copyBytes } from "./bytes.js";
import { BLINDING_LENGTH } from "./constants.js";
import { KeypairError } from "./error.js";
import { poseidon } from "./poseidon.js";

function rightAlign(bytes: Uint8Array): Bytes32 {
  const output = new Uint8Array(32);
  output.set(bytes, 32 - bytes.length);
  return output as Bytes32;
}

/** Poseidon over the commitment, the blinding and the right-aligned secret: the one nullifier derivation. */
function deriveNullifier(utxoHash: Bytes32, blinding: Bytes32, secret: Bytes32): Bytes32 {
  const hash = checkedBytes<Bytes32>(utxoHash, 32, "UTXO hash");
  const blind = checkedBytes<Bytes32>(blinding, 32, "blinding");
  return poseidon([hash, blind, secret]) as Bytes32;
}

/**
 * The nullifier of an unused proof slot: the derivation under an all-zero
 * secret, which no wallet holds, so it can be computed and checked without a
 * key. The circuit expects it on every slot marked dummy.
 */
export function zeroKeyNullifier(utxoHash: Bytes32, blinding: Bytes32): Bytes32 {
  return deriveNullifier(utxoHash, blinding, new Uint8Array(32) as Bytes32);
}

export class NullifierKey {
  #secret: Uint8Array;
  #destroyed = false;

  private constructor(secret: Uint8Array) {
    this.#secret = secret;
  }

  static fromSecret(bytes: Bytes31): NullifierKey {
    return new NullifierKey(checkedBytes<Bytes31>(bytes, BLINDING_LENGTH, "nullifier secret"));
  }

  publicKey(): Bytes32 {
    this.#assertUsable();
    return poseidon([rightAlign(this.#secret)]) as Bytes32;
  }

  nullifier(utxoHash: Bytes32, blinding: Bytes32): Bytes32 {
    this.#assertUsable();
    return deriveNullifier(utxoHash, blinding, rightAlign(this.#secret));
  }

  /** An independent copy of the key; destroying either leaves the other usable. */
  clone(): NullifierKey {
    this.#assertUsable();
    return new NullifierKey(copyBytes(this.#secret));
  }

  secretBytes(): Bytes31 {
    this.#assertUsable();
    return copyBytes(this.#secret) as Bytes31;
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
