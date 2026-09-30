import { getProgramDerivedAddress, type Address, type ReadonlyUint8Array } from "@solana/kit";

import { type Bytes32, bytes31, bytes32 } from "../../keypair/bytes.js";
import { BLINDING_LENGTH } from "../../keypair/constants.js";
import { ownerHash } from "../../keypair/hash.js";
import { NullifierKey } from "../../keypair/nullifier-key.js";
import { type P256PublicKey, ShieldedPublicKey } from "../../keypair/public-key.js";
import { ShieldedAddress } from "../../keypair/shielded.js";

import { TransactionError } from "../error.js";

export type ProgramOwnerSeed = string | ReadonlyUint8Array;

export class ProgramOwner {
  readonly pda: Address;
  readonly #publicKey: ShieldedPublicKey;

  constructor(pda: Address) {
    try {
      this.#publicKey = ShieldedPublicKey.fromPda(pda);
    } catch (cause) {
      throw new TransactionError("TRANSACTION_INVALID_ADDRESS", { reason: "programOwner" }, cause);
    }
    this.pda = pda;
    Object.freeze(this);
  }

  static async find(seeds: readonly ProgramOwnerSeed[], programId: Address): Promise<ProgramOwner> {
    let pda: Address;
    try {
      [pda] = await getProgramDerivedAddress({ programAddress: programId, seeds: [...seeds] });
    } catch (cause) {
      throw new TransactionError(
        "TRANSACTION_INVALID_ADDRESS",
        { reason: "programDerivedAddress" },
        cause,
      );
    }
    return new ProgramOwner(pda);
  }

  static nullifierKey(): NullifierKey {
    return NullifierKey.fromSecret(bytes31(new Uint8Array(BLINDING_LENGTH)));
  }

  static nullifierPublicKey(): Bytes32 {
    const key = ProgramOwner.nullifierKey();
    try {
      return key.publicKey();
    } finally {
      key.destroy();
    }
  }

  publicKey(): ShieldedPublicKey {
    return this.#publicKey;
  }

  ownerTag(): Bytes32 {
    return this.#publicKey.confidentialViewTag();
  }

  ownerHash(): Bytes32 {
    return bytes32(
      ownerHash(this.#publicKey.ownerProofInputHash(), ProgramOwner.nullifierPublicKey()),
    );
  }

  address(viewingPublicKey: P256PublicKey): ShieldedAddress {
    return ShieldedAddress.forPda({
      pda: this.pda,
      nullifierPublicKey: ProgramOwner.nullifierPublicKey(),
      viewingPublicKey,
    });
  }
}
