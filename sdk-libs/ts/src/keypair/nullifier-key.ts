import { type Bytes31, type Bytes32, checkedBytes, copyBytes } from "./bytes.js";
import { BLINDING_LENGTH } from "./constants.js";
import { KeypairError } from "./error.js";
import { poseidon } from "./poseidon.js";

function rightAlign(bytes: Uint8Array): Bytes32 {
  const output = new Uint8Array(32);
  output.set(bytes, 32 - bytes.length);
  return output as Bytes32;
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
    const hash = checkedBytes<Bytes32>(utxoHash, 32, "UTXO hash");
    const blind = checkedBytes<Bytes32>(blinding, 32, "blinding");
    return poseidon([hash, blind, rightAlign(this.#secret)]) as Bytes32;
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
