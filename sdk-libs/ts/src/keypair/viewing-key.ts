import { p256 } from "@noble/curves/nist.js";
import { expand, extract, hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import {
  type Bytes16,
  type Bytes32,
  bytesToBigInt,
  checkedBytes,
  concatBytes,
  copyBytes,
  randomBytes,
  u32be,
  u64be,
} from "./bytes.js";
import {
  INFO_MERGE_VIEW_TAG_PREFIX,
  INFO_MERGE_VIEW_TAG_SECRET,
  INFO_PAIR_DOMAIN_PREFIX,
  INFO_PAIR_HINT_PREFIX,
  INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX,
  INFO_RECIPIENT_VIEW_TAG_SECRET,
  INFO_SENDER_VIEW_TAG_PREFIX,
  INFO_SENDER_VIEW_TAG_SECRET,
  INFO_TX_VIEWING,
  P_CONST_SEC1,
} from "./constants.js";
import { applyTransferCipher, ecdhX } from "./encryption.js";
import { KeypairError } from "./error.js";
import { decryptVerifiableSecret, encryptVerifiableSecret } from "./merge/core.js";
import { P256PublicKey, type ViewTag } from "./public-key.js";
import type { ViewingKeyLike } from "./shielded.js";

export type Salt = Bytes16;

const encoder = new TextEncoder();
const P256_ORDER =
  115_792_089_210_356_248_762_697_446_949_407_573_529_996_955_224_135_760_342_422_259_061_068_512_044_369n;
const P_CONST = P256PublicKey.fromBytes(P_CONST_SEC1 as import("./bytes.js").Bytes33);

// Rust separates `ZeroScalar` from `InvalidSecretKey`: the first says the
// derivation landed on zero, the second says the caller supplied an out-of-range
// secret. Collapsing them would hide which one a wallet hit.
function scalarFromOkm(okm: Uint8Array): Bytes32 {
  const scalar = bytesToBigInt(okm) % P256_ORDER;
  if (scalar === 0n) {
    throw new KeypairError("KEYPAIR_ZERO_SCALAR");
  }
  const bytes = new Uint8Array(32);
  let value = scalar;
  for (let index = 31; index >= 0; index--) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes as Bytes32;
}

/** Every HKDF failure surfaces as Rust's `Hkdf`, not as a generic key error. */
function expandOrThrow(
  ikm: Uint8Array,
  info: Uint8Array,
  length: number,
  salt?: Uint8Array,
): Uint8Array {
  try {
    return hkdf(sha256, ikm, salt, info, length);
  } catch (error) {
    throw new KeypairError("KEYPAIR_HKDF", { actual: length }, error);
  }
}

function checkCounter(value: bigint, name: string): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new KeypairError("KEYPAIR_INVALID_LENGTH", {
      name,
      minimum: "0",
      maximum: "18446744073709551615",
    });
  }
  return u64be(value);
}

function checkSlotIndex(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new KeypairError("KEYPAIR_INVALID_LENGTH", {
      name: "slotIndex",
      minimum: 0,
      maximum: 0xffff_ffff,
    });
  }
  return value;
}

export class ViewingKey implements ViewingKeyLike {
  #secret: Uint8Array;
  #viewRoot: Uint8Array;
  #destroyed = false;

  private constructor(secret: Uint8Array) {
    this.#secret = secret;
    const shared = ecdhX(secret, P_CONST);
    this.#viewRoot = extract(sha256, shared);
    shared.fill(0);
  }

  static generate(): ViewingKey {
    let secret: Uint8Array;
    do secret = randomBytes(32);
    while (!p256.utils.isValidSecretKey(secret));
    return new ViewingKey(secret);
  }

  static fromBytes(bytes: Bytes32): ViewingKey {
    const secret = checkedBytes<Bytes32>(bytes, 32, "viewing secret");
    if (!p256.utils.isValidSecretKey(secret)) {
      secret.fill(0);
      throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY", { type: "p256" });
    }
    return new ViewingKey(secret);
  }

  static fromSeed(walletSeed: Bytes32, account: number): ViewingKey {
    if (!Number.isInteger(account) || account < 0 || account > 0xffff_ffff) {
      throw new KeypairError("KEYPAIR_INVALID_LENGTH", {
        name: "account",
        minimum: 0,
        maximum: 0xffff_ffff,
      });
    }
    const seed = checkedBytes<Bytes32>(walletSeed, 32, "wallet seed");
    const info = concatBytes(encoder.encode("TSPP/seed/p256_viewing"), u32be(account));
    return ViewingKey.fromBytes(scalarFromOkm(expandOrThrow(seed, info, 48)));
  }

  publicKey(): P256PublicKey {
    this.#assertUsable();
    return P256PublicKey.fromSecret(this.#secret);
  }

  secretBytes(): Bytes32 {
    this.#assertUsable();
    return copyBytes(this.#secret) as Bytes32;
  }

  ecdh(counterparty: P256PublicKey): Bytes32 {
    this.#assertUsable();
    return copyBytes(ecdhX(this.#secret, counterparty)) as Bytes32;
  }

  senderViewTag(txCount: bigint): ViewTag {
    return this.#viewTag(
      INFO_SENDER_VIEW_TAG_SECRET,
      INFO_SENDER_VIEW_TAG_PREFIX,
      checkCounter(txCount, "txCount"),
    );
  }

  recipientRequestViewTag(requestCount: bigint): ViewTag {
    return this.#viewTag(
      INFO_RECIPIENT_VIEW_TAG_SECRET,
      INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX,
      checkCounter(requestCount, "requestCount"),
    );
  }

  mergeViewTag(mergeCount: bigint): ViewTag {
    return this.#viewTag(
      INFO_MERGE_VIEW_TAG_SECRET,
      INFO_MERGE_VIEW_TAG_PREFIX,
      checkCounter(mergeCount, "mergeCount"),
    );
  }

  sendSharedViewTag(counterparty: P256PublicKey, index: bigint): ViewTag {
    return this.#sharedViewTag(counterparty, counterparty, checkCounter(index, "index"));
  }

  recipientSharedViewTag(counterparty: P256PublicKey, index: bigint): ViewTag {
    return this.#sharedViewTag(counterparty, this.publicKey(), checkCounter(index, "index"));
  }

  recipientBootstrapViewTag(): ViewTag {
    return this.publicKey().x();
  }

  transactionViewingKey(firstNullifier: Bytes32): ViewingKey {
    this.#assertUsable();
    const nullifier = checkedBytes<Bytes32>(firstNullifier, 32, "first nullifier");
    const txViewingSecret = this.#viewSecret(INFO_TX_VIEWING);
    try {
      const salted = expandOrThrow(txViewingSecret, encoder.encode(INFO_TX_VIEWING), 48, nullifier);
      return ViewingKey.fromBytes(scalarFromOkm(salted));
    } finally {
      txViewingSecret.fill(0);
    }
  }

  encryptSlot(
    recipientPublicKey: P256PublicKey,
    plaintext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array {
    this.#assertUsable();
    return applyTransferCipher(
      this.#secret,
      recipientPublicKey,
      this.publicKey(),
      recipientPublicKey,
      plaintext,
      checkedBytes<Bytes16>(salt, 16, "salt"),
      checkSlotIndex(slotIndex),
    );
  }

  decryptUtxo(
    ciphertext: Uint8Array,
    txViewingPublicKey: P256PublicKey,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array {
    this.#assertUsable();
    return applyTransferCipher(
      this.#secret,
      txViewingPublicKey,
      txViewingPublicKey,
      this.publicKey(),
      ciphertext,
      checkedBytes<Bytes16>(salt, 16, "salt"),
      checkSlotIndex(slotIndex),
    );
  }

  decryptSlotEphemeral(
    recipientPublicKey: P256PublicKey,
    ciphertext: Uint8Array,
    salt: Salt,
    slotIndex: number,
  ): Uint8Array {
    return this.encryptSlot(recipientPublicKey, ciphertext, salt, slotIndex);
  }

  encryptVerifiable(
    userViewingPublicKey: P256PublicKey,
    plaintext: Uint8Array,
  ): Readonly<{ ciphertext: Uint8Array; txViewingPublicKey: P256PublicKey }> {
    this.#assertUsable();
    return encryptVerifiableSecret(this.#secret, userViewingPublicKey, plaintext);
  }

  decryptVerifiable(txViewingPublicKey: P256PublicKey, ciphertext: Uint8Array): Uint8Array {
    this.#assertUsable();
    return decryptVerifiableSecret(this.#secret, txViewingPublicKey, ciphertext);
  }

  destroy(): void {
    this.#secret.fill(0);
    this.#viewRoot.fill(0);
    this.#destroyed = true;
  }

  #viewSecret(info: string): Uint8Array {
    this.#assertUsable();
    try {
      return expand(sha256, this.#viewRoot, encoder.encode(info), 32);
    } catch (error) {
      throw new KeypairError("KEYPAIR_HKDF", { name: info }, error);
    }
  }

  #viewTag(secretInfo: string, prefix: string, counter: Uint8Array): ViewTag {
    const secret = this.#viewSecret(secretInfo);
    try {
      const tag = new Uint8Array(32);
      tag.set(expandOrThrow(secret, concatBytes(encoder.encode(prefix), counter), 31), 1);
      return tag as ViewTag;
    } finally {
      secret.fill(0);
    }
  }

  #sharedViewTag(
    counterparty: P256PublicKey,
    recipientPublicKey: P256PublicKey,
    counter: Uint8Array,
  ): ViewTag {
    const shared = this.ecdh(counterparty);
    let domain: Uint8Array | undefined;
    try {
      domain = expandOrThrow(
        shared,
        concatBytes(encoder.encode(INFO_PAIR_DOMAIN_PREFIX), recipientPublicKey.toBytes()),
        32,
      );
      const tag = new Uint8Array(32);
      tag.set(
        expandOrThrow(domain, concatBytes(encoder.encode(INFO_PAIR_HINT_PREFIX), counter), 31),
        1,
      );
      return tag as ViewTag;
    } finally {
      shared.fill(0);
      domain?.fill(0);
    }
  }

  #assertUsable(): void {
    if (this.#destroyed) {
      throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY", { reason: "destroyed" });
    }
  }
}
