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

export class ShieldedAddress {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly viewingPublicKey: P256PublicKey;

  readonly #nullifierPublicKey: Bytes32;

  private constructor(
    signingPublicKey: ShieldedPublicKey,
    nullifierPublicKey: Bytes32,
    viewingPublicKey: P256PublicKey,
  ) {
    this.signingPublicKey = signingPublicKey;
    this.#nullifierPublicKey = nullifierPublicKey;
    this.viewingPublicKey = viewingPublicKey;
    Object.freeze(this);
  }

  static fromPublicKeys(
    signingPublicKey: ShieldedPublicKey,
    nullifierPublicKey: Bytes32,
    viewingPublicKey: P256PublicKey,
  ): ShieldedAddress {
    return new ShieldedAddress(
      ShieldedPublicKey.fromBytes(signingPublicKey.toBytes()),
      checkedBytes<Bytes32>(nullifierPublicKey, 32, "nullifier public key"),
      P256PublicKey.fromBytes(viewingPublicKey.toBytes()),
    );
  }

  get nullifierPublicKey(): Bytes32 {
    return copyBytes(this.#nullifierPublicKey) as Bytes32;
  }

  ownerHash(): Bytes32 {
    return ownerHash(
      this.signingPublicKey.ownerPublicKeyField(),
      this.#nullifierPublicKey,
    ) as Bytes32;
  }

  solanaAddress(): Address {
    return bs58.encode(this.signingPublicKey.ed25519()) as Address;
  }

  confidentialViewTag(): ViewTag {
    return this.signingPublicKey.confidentialViewTag();
  }
}

export interface CompressedShieldedAddress {
  readonly bytes: Uint8Array;
}

export interface P256Signature {
  readonly publicKey: P256PublicKey;
  readonly r: Bytes32;
  readonly s: Bytes32;
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

  viewingKey(): ViewingKey {
    const secret = this.#viewing.secretBytes();
    try {
      return ViewingKey.fromBytes(secret);
    } finally {
      secret.fill(0);
    }
  }

  nullifierKey(): NullifierKey {
    const secret = this.#nullifier.secretBytes();
    try {
      return NullifierKey.fromSecret(secret);
    } finally {
      secret.fill(0);
    }
  }

  shieldedAddress(): ShieldedAddress {
    return ShieldedAddress.fromPublicKeys(
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

  signP256(messageHash: Bytes32): P256Signature {
    const publicKey = this.#signing.publicKey().p256();
    const signature = this.#signing.sign(
      checkedBytes<Bytes32>(messageHash, 32, "P256 message hash"),
    );
    return Object.freeze({
      publicKey,
      r: signature.slice(0, 32) as Bytes32,
      s: signature.slice(32) as Bytes32,
    });
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
