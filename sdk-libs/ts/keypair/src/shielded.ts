import bs58 from "bs58";

import {
  type Address,
  type Bytes31,
  type Bytes32,
  type Bytes64,
  checkedBytes,
  concatBytes,
  copyBytes,
} from "./bytes.js";
import { ownerHash } from "./hash.js";
import { NullifierKey } from "./nullifier-key.js";
import { P256PublicKey, ShieldedPublicKey, type ViewTag } from "./public-key.js";
import { SigningKey } from "./signing-key.js";
import { ViewingKey } from "./viewing-key.js";

export interface ShieldedAddress {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly nullifierPublicKey: Bytes32;
  readonly viewingPublicKey: P256PublicKey;
  ownerHash(): Bytes32;
  solanaAddress(): Address;
  confidentialViewTag(): ViewTag;
}

export interface CompressedShieldedAddress {
  readonly bytes: Uint8Array;
}

export interface ShieldedKeypairLike {
  shieldedAddress(): ShieldedAddress;
  sign(message: Uint8Array): Bytes64 | Promise<Bytes64>;
  nullifier(utxoHash: Bytes32, blinding: Bytes31): Bytes32 | Promise<Bytes32>;
}

export interface ViewingKeyLike {
  publicKey(): P256PublicKey;
  transactionViewingKey(firstNullifier: Bytes32): ViewingKey | Promise<ViewingKey>;
}

function createAddress(
  signingPublicKey: ShieldedPublicKey,
  nullifierPublicKey: Bytes32,
  viewingPublicKey: P256PublicKey,
): ShieldedAddress {
  const nullifier = copyBytes(nullifierPublicKey) as Bytes32;
  return Object.freeze({
    signingPublicKey,
    nullifierPublicKey: nullifier,
    viewingPublicKey,
    ownerHash(): Bytes32 {
      return ownerHash(signingPublicKey.ownerPublicKeyField(), nullifier) as Bytes32;
    },
    solanaAddress(): Address {
      return bs58.encode(signingPublicKey.ed25519()) as Address;
    },
    confidentialViewTag(): ViewTag {
      return signingPublicKey.confidentialViewTag();
    },
  });
}

export class ShieldedKeypair implements ShieldedKeypairLike {
  readonly #signing: SigningKey;
  readonly #nullifier: NullifierKey;
  readonly #viewing: ViewingKey;

  private constructor(signing: SigningKey, nullifier: NullifierKey, viewing: ViewingKey) {
    this.#signing = signing;
    this.#nullifier = nullifier;
    this.#viewing = viewing;
  }

  static generate(): ShieldedKeypair {
    const signing = SigningKey.generate();
    return ShieldedKeypair.fromKeys(
      signing,
      NullifierKey.fromSigningKey(signing),
      ViewingKey.generate(),
    );
  }

  static fromKeys(
    signing: SigningKey,
    nullifier: NullifierKey,
    viewing: ViewingKey,
  ): ShieldedKeypair {
    return new ShieldedKeypair(signing, nullifier, viewing);
  }

  static fromEd25519(secret: Bytes32, account: number): ShieldedKeypair {
    const owned = checkedBytes<Bytes32>(secret, 32, "Ed25519 signing secret");
    const signing = SigningKey.fromEd25519Bytes(owned);
    const nullifier = NullifierKey.fromSigningSecret(owned);
    const viewing = ViewingKey.fromSeed(owned, account);
    owned.fill(0);
    return new ShieldedKeypair(signing, nullifier, viewing);
  }

  signingPublicKey(): ShieldedPublicKey {
    return this.#signing.publicKey();
  }

  viewingPublicKey(): P256PublicKey {
    return this.#viewing.publicKey();
  }

  shieldedAddress(): ShieldedAddress {
    return createAddress(
      this.signingPublicKey(),
      this.#nullifier.publicKey(),
      this.viewingPublicKey(),
    );
  }

  compressedAddress(): CompressedShieldedAddress {
    const address = this.shieldedAddress();
    return Object.freeze({
      bytes: concatBytes(address.ownerHash(), address.viewingPublicKey.toBytes()),
    });
  }

  sign(message: Uint8Array): Bytes64 {
    return this.#signing.sign(message);
  }

  nullifier(utxoHash: Bytes32, blinding: Bytes31): Bytes32 {
    return this.#nullifier.nullifier(utxoHash, blinding);
  }

  destroy(): void {
    this.#signing.destroy();
    this.#nullifier.destroy();
    this.#viewing.destroy();
  }
}
