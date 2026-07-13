import { randomBytes } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf, extract, expand } from "@noble/hashes/hkdf.js";
import { sha256 as sha256Hash } from "@noble/hashes/sha2.js";
import { ctr } from "@noble/ciphers/aes.js";
import {
  BLINDING_LEN,
  CTR_NONCE_LEN,
  ED25519_PUBKEY_LEN,
  ENC_INFO_TRANSFER,
  HPKE_PREFIX,
  INFO_MERGE_VIEW_TAG_PREFIX,
  INFO_MERGE_VIEW_TAG_SECRET,
  INFO_NULLIFIER,
  INFO_PAIR_DOMAIN_PREFIX,
  INFO_PAIR_HINT_PREFIX,
  INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX,
  INFO_RECIPIENT_VIEW_TAG_SECRET,
  INFO_SENDER_VIEW_TAG_PREFIX,
  INFO_SENDER_VIEW_TAG_SECRET,
  INFO_TX_VIEWING,
  P256_PUBKEY_LEN,
  P_CONST_SEC1,
  PUBLIC_KEY_LEN,
  SALT_LEN,
  SIGNATURE_TYPE_ED25519,
  SIGNATURE_TYPE_P256,
  VIEW_TAG_LEN,
} from "./constants.js";
import { assertLength, concatBytes, copyBytes, rightAlign, u32Be, u64Be } from "./bytes.js";
import { boolFe, feRightAlign, hashField, poseidon } from "./hash.js";

export type SignatureType = "p256" | "ed25519";
export type Signature = Uint8Array;
export type EcdsaSignature = Uint8Array;
export type ViewTag = Uint8Array;
export type Salt = Uint8Array;

export function randomSalt(): Salt {
  return randomBytes(SALT_LEN);
}

export function randomBlinding(): Uint8Array {
  return randomBytes(BLINDING_LEN);
}

function hkdfExpand(salt: Uint8Array | undefined, ikm: Uint8Array, info: Uint8Array[], len: number) {
  return hkdf(sha256Hash, ikm, salt, concatBytes(...info), len);
}

function expandViewTag(ikm: Uint8Array, info: Uint8Array[]): ViewTag {
  const out = new Uint8Array(VIEW_TAG_LEN);
  out.set(hkdfExpand(undefined, ikm, info, VIEW_TAG_LEN - 1), 1);
  return out;
}

function ecdhX(secretKey: Uint8Array, publicKey: P256Pubkey): Uint8Array {
  const shared = p256.getSharedSecret(secretKey, publicKey.asBytes(), true);
  return shared.slice(1);
}

function viewRoot(secretKey: Uint8Array): Uint8Array {
  const shared = p256.getSharedSecret(secretKey, P_CONST_SEC1, true).slice(1);
  return extract(sha256Hash, shared);
}

function ctrApply(key: Uint8Array, nonce: Uint8Array, bytes: Uint8Array): Uint8Array {
  assertLength(key, 32, "AES key");
  assertLength(nonce, CTR_NONCE_LEN, "CTR nonce");
  const iv = new Uint8Array(16);
  iv.set(nonce);
  iv[15] = 2;
  return ctr(key, iv).encrypt(bytes);
}

function deriveKeyNonce(
  dh: Uint8Array,
  ephemeralPubkey: P256Pubkey,
  recipientPubkey: P256Pubkey,
  info: Uint8Array,
  salt: Uint8Array,
  slot: number,
): { key: Uint8Array; nonce: Uint8Array } {
  assertLength(dh, 32, "ECDH x-coordinate");
  assertLength(salt, SALT_LEN, "salt");
  const ikm = concatBytes(dh, ephemeralPubkey.asBytes(), recipientPubkey.asBytes());
  const okm = hkdfExpand(undefined, ikm, [HPKE_PREFIX, info, salt, u32Be(slot)], 32 + CTR_NONCE_LEN);
  return { key: okm.slice(0, 32), nonce: okm.slice(32) };
}

export class P256Pubkey {
  private readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    assertLength(bytes, P256_PUBKEY_LEN, "P256 public key");
    p256.getSharedSecret(p256.utils.randomSecretKey(new Uint8Array(48).fill(7)), bytes, true);
    this.bytes = copyBytes(bytes);
  }

  static fromBytes(bytes: Uint8Array): P256Pubkey {
    return new P256Pubkey(bytes);
  }

  static fromSecret(secret: Uint8Array): P256Pubkey {
    return new P256Pubkey(p256.getPublicKey(secret, true));
  }

  asBytes(): Uint8Array {
    return copyBytes(this.bytes);
  }

  x(): Uint8Array {
    return this.bytes.slice(1);
  }

  yIsOdd(): boolean {
    return this.bytes[0] === 0x03;
  }
}

export class PublicKey {
  private readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    assertLength(bytes, PUBLIC_KEY_LEN, "shielded public key");
    if (bytes.every((byte) => byte === 0)) {
      this.bytes = copyBytes(bytes);
      return;
    }
    if (bytes[0] === SIGNATURE_TYPE_P256) {
      new P256Pubkey(bytes.slice(1));
    } else if (bytes[0] === SIGNATURE_TYPE_ED25519) {
      if (bytes[PUBLIC_KEY_LEN - 1] !== 0) {
        throw new Error("invalid ed25519 shielded public key padding");
      }
    } else {
      throw new Error(`invalid signature type ${bytes[0]}`);
    }
    this.bytes = copyBytes(bytes);
  }

  static fromP256(pubkey: P256Pubkey): PublicKey {
    const out = new Uint8Array(PUBLIC_KEY_LEN);
    out[0] = SIGNATURE_TYPE_P256;
    out.set(pubkey.asBytes(), 1);
    return new PublicKey(out);
  }

  static fromEd25519(pubkey: Uint8Array): PublicKey {
    assertLength(pubkey, ED25519_PUBKEY_LEN, "ed25519 public key");
    const out = new Uint8Array(PUBLIC_KEY_LEN);
    out[0] = SIGNATURE_TYPE_ED25519;
    out.set(pubkey, 1);
    return new PublicKey(out);
  }

  static zeroed(): PublicKey {
    return new PublicKey(new Uint8Array(PUBLIC_KEY_LEN));
  }

  asBytes(): Uint8Array {
    return copyBytes(this.bytes);
  }

  isZero(): boolean {
    return this.bytes.every((byte) => byte === 0);
  }

  signatureType(): SignatureType {
    if (this.bytes[0] === SIGNATURE_TYPE_P256) return "p256";
    if (this.bytes[0] === SIGNATURE_TYPE_ED25519) return "ed25519";
    throw new Error(`invalid signature type ${this.bytes[0]}`);
  }

  asP256(): P256Pubkey {
    if (this.signatureType() !== "p256") throw new Error("public key is not P256");
    return new P256Pubkey(this.bytes.slice(1));
  }

  asEd25519(): Uint8Array {
    if (this.signatureType() !== "ed25519") throw new Error("public key is not Ed25519");
    return this.bytes.slice(1, 1 + ED25519_PUBKEY_LEN);
  }

  confidentialViewTag(): Uint8Array {
    return this.signatureType() === "p256" ? this.asP256().x() : this.asEd25519();
  }

  hash(): Uint8Array {
    if (this.signatureType() === "p256") {
      const pubkey = this.asP256();
      const xHash = hashField(pubkey.x());
      return poseidon([boolFe(pubkey.yIsOdd()), xHash]);
    }
    return hashField(this.asEd25519());
  }

  ownerPkField(): Uint8Array {
    return hashField(this.confidentialViewTag());
  }
}

export class SigningKey {
  private constructor(
    private readonly kind: SignatureType,
    private readonly secret: Uint8Array,
  ) {}

  static new(): SigningKey {
    return SigningKey.fromBytes(p256.utils.randomSecretKey());
  }

  static fromBytes(bytes: Uint8Array): SigningKey {
    assertLength(bytes, 32, "P256 secret key");
    P256Pubkey.fromSecret(bytes);
    return new SigningKey("p256", copyBytes(bytes));
  }

  static fromEd25519(bytes: Uint8Array): SigningKey {
    assertLength(bytes, 32, "ed25519 secret key");
    return new SigningKey("ed25519", copyBytes(bytes));
  }

  secretBytes(): Uint8Array {
    return copyBytes(this.secret);
  }

  pubkey(): PublicKey {
    if (this.kind === "p256") return PublicKey.fromP256(P256Pubkey.fromSecret(this.secret));
    return PublicKey.fromEd25519(ed25519.getPublicKey(this.secret));
  }

  sign(message: Uint8Array): Signature {
    if (this.kind === "p256") {
      return p256.sign(message, this.secret, { prehash: false, lowS: false });
    }
    return ed25519.sign(message, this.secret);
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    assertLength(signature, 64, "signature");
    if (this.kind === "p256") {
      return p256.verify(signature, message, this.pubkey().asP256().asBytes(), { prehash: false });
    }
    return ed25519.verify(signature, message, this.pubkey().asEd25519());
  }
}

export class NullifierKey {
  private readonly secret: Uint8Array;

  constructor(secret: Uint8Array) {
    assertLength(secret, BLINDING_LEN, "nullifier secret");
    this.secret = copyBytes(secret);
  }

  static fromSigningKey(signingKey: SigningKey): NullifierKey {
    return NullifierKey.fromSigningSecretKeyBytes(signingKey.secretBytes());
  }

  static fromSigningSecretKeyBytes(ikm: Uint8Array): NullifierKey {
    return new NullifierKey(hkdfExpand(undefined, ikm, [INFO_NULLIFIER], BLINDING_LEN));
  }

  secretBytes(): Uint8Array {
    return copyBytes(this.secret);
  }

  pubkey(): Uint8Array {
    return poseidon([feRightAlign(this.secret)]);
  }

  nullifier(utxoHash: Uint8Array, blinding: Uint8Array): Uint8Array {
    assertLength(utxoHash, 32, "utxo hash");
    assertLength(blinding, BLINDING_LEN, "blinding");
    return poseidon([utxoHash, rightAlign(blinding, 32), rightAlign(this.secret, 32)]);
  }
}

export class ViewingKey {
  private readonly secret: Uint8Array;
  private readonly root: Uint8Array;

  private constructor(secret: Uint8Array) {
    assertLength(secret, 32, "P256 viewing secret");
    P256Pubkey.fromSecret(secret);
    this.secret = copyBytes(secret);
    this.root = viewRoot(secret);
  }

  static new(): ViewingKey {
    return ViewingKey.fromBytes(p256.utils.randomSecretKey());
  }

  static fromBytes(bytes: Uint8Array): ViewingKey {
    return new ViewingKey(bytes);
  }

  secretBytes(): Uint8Array {
    return copyBytes(this.secret);
  }

  pubkey(): P256Pubkey {
    return P256Pubkey.fromSecret(this.secret);
  }

  ecdh(counterparty: P256Pubkey): Uint8Array {
    return ecdhX(this.secret, counterparty);
  }

  deriveSecret32(info: Uint8Array): Uint8Array {
    return expand(sha256Hash, this.root, info, 32);
  }

  senderViewTagSecret(): Uint8Array {
    return this.deriveSecret32(INFO_SENDER_VIEW_TAG_SECRET);
  }

  recipientViewTagSecret(): Uint8Array {
    return this.deriveSecret32(INFO_RECIPIENT_VIEW_TAG_SECRET);
  }

  mergeViewTagSecret(): Uint8Array {
    return this.deriveSecret32(INFO_MERGE_VIEW_TAG_SECRET);
  }

  txViewingSecret(): Uint8Array {
    return this.deriveSecret32(INFO_TX_VIEWING);
  }

  getSenderViewTag(txCount: bigint | number): ViewTag {
    return expandViewTag(this.senderViewTagSecret(), [
      INFO_SENDER_VIEW_TAG_PREFIX,
      u64Be(txCount),
    ]);
  }

  getRecipientRequestViewTag(requestCount: bigint | number): ViewTag {
    return expandViewTag(this.recipientViewTagSecret(), [
      INFO_RECIPIENT_REQUEST_VIEW_TAG_PREFIX,
      u64Be(requestCount),
    ]);
  }

  getMergeViewTag(mergeCount: bigint | number): ViewTag {
    return expandViewTag(this.mergeViewTagSecret(), [INFO_MERGE_VIEW_TAG_PREFIX, u64Be(mergeCount)]);
  }

  private sharedViewTag(counterparty: P256Pubkey, recipientPubkey: P256Pubkey, i: bigint | number) {
    const domain = hkdfExpand(undefined, this.ecdh(counterparty), [
      INFO_PAIR_DOMAIN_PREFIX,
      recipientPubkey.asBytes(),
    ], 32);
    return expandViewTag(domain, [INFO_PAIR_HINT_PREFIX, u64Be(i)]);
  }

  getSendSharedViewTag(counterparty: P256Pubkey, i: bigint | number): ViewTag {
    return this.sharedViewTag(counterparty, counterparty, i);
  }

  getRecipientSharedViewTag(counterparty: P256Pubkey, i: bigint | number): ViewTag {
    return this.sharedViewTag(counterparty, this.pubkey(), i);
  }

  recipientBootstrapViewTag(): ViewTag {
    return this.pubkey().x();
  }

  getTransactionViewingKey(firstNullifier: Uint8Array): ViewingKey {
    assertLength(firstNullifier, 32, "first nullifier");
    const okm = hkdfExpand(firstNullifier, this.txViewingSecret(), [INFO_TX_VIEWING], 48);
    return ViewingKey.fromBytes(p256.utils.randomSecretKey(okm));
  }

  encryptSlot(
    recipientPubkey: P256Pubkey,
    plaintext: Uint8Array,
    salt: Uint8Array,
    slotIndex: number,
  ): Uint8Array {
    const ephemeralPubkey = this.pubkey();
    const { key, nonce } = deriveKeyNonce(
      this.ecdh(recipientPubkey),
      ephemeralPubkey,
      recipientPubkey,
      ENC_INFO_TRANSFER,
      salt,
      slotIndex,
    );
    return ctrApply(key, nonce, plaintext);
  }

  decryptUtxo(
    ciphertext: Uint8Array,
    txViewingPubkey: P256Pubkey,
    salt: Uint8Array,
    slotIndex: number,
  ): Uint8Array {
    const recipientPubkey = this.pubkey();
    const { key, nonce } = deriveKeyNonce(
      this.ecdh(txViewingPubkey),
      txViewingPubkey,
      recipientPubkey,
      ENC_INFO_TRANSFER,
      salt,
      slotIndex,
    );
    return ctrApply(key, nonce, ciphertext);
  }

  decryptSlotEphemeral(
    recipientPubkey: P256Pubkey,
    ciphertext: Uint8Array,
    salt: Uint8Array,
    slotIndex: number,
  ): Uint8Array {
    return this.encryptSlot(recipientPubkey, ciphertext, salt, slotIndex);
  }
}

export interface ShieldedAddressFields {
  signingPubkey: PublicKey;
  nullifierPubkey: Uint8Array;
  viewingPubkey: P256Pubkey;
}

export class ShieldedAddress {
  readonly signingPubkey: PublicKey;
  readonly nullifierPubkey: Uint8Array;
  readonly viewingPubkey: P256Pubkey;

  constructor(fields: ShieldedAddressFields) {
    assertLength(fields.nullifierPubkey, 32, "nullifier pubkey");
    this.signingPubkey = fields.signingPubkey;
    this.nullifierPubkey = copyBytes(fields.nullifierPubkey);
    this.viewingPubkey = fields.viewingPubkey;
  }

  ownerHash(): Uint8Array {
    return ownerHash(this.signingPubkey, this.nullifierPubkey);
  }
}

export interface CompressedShieldedAddress {
  ownerHash: Uint8Array;
  viewingPubkey: P256Pubkey;
}

export class ShieldedKeypair {
  constructor(
    readonly signingKey: SigningKey,
    readonly nullifierKey: NullifierKey,
    readonly viewingKey: ViewingKey,
  ) {}

  static new(): ShieldedKeypair {
    return ShieldedKeypair.fromKeys(SigningKey.new(), ViewingKey.new());
  }

  static fromKeys(signingKey: SigningKey, viewingKey: ViewingKey): ShieldedKeypair {
    return new ShieldedKeypair(signingKey, NullifierKey.fromSigningKey(signingKey), viewingKey);
  }

  static fromParts(
    signingKey: SigningKey,
    nullifierKey: NullifierKey,
    viewingKey: ViewingKey,
  ): ShieldedKeypair {
    return new ShieldedKeypair(signingKey, nullifierKey, viewingKey);
  }

  static fromEd25519(signingSecret: Uint8Array, viewingKey: ViewingKey): ShieldedKeypair {
    const signingKey = SigningKey.fromEd25519(signingSecret);
    return new ShieldedKeypair(
      signingKey,
      NullifierKey.fromSigningSecretKeyBytes(signingSecret),
      viewingKey,
    );
  }

  signingPubkey(): PublicKey {
    return this.signingKey.pubkey();
  }

  viewingPubkey(): P256Pubkey {
    return this.viewingKey.pubkey();
  }

  shieldedAddress(): ShieldedAddress {
    return new ShieldedAddress({
      signingPubkey: this.signingPubkey(),
      nullifierPubkey: this.nullifierKey.pubkey(),
      viewingPubkey: this.viewingPubkey(),
    });
  }

  ownerHash(): Uint8Array {
    return ownerHash(this.signingPubkey(), this.nullifierKey.pubkey());
  }

  compressedAddress(): CompressedShieldedAddress {
    return {
      ownerHash: this.ownerHash(),
      viewingPubkey: this.viewingPubkey(),
    };
  }

  sign(message: Uint8Array): Uint8Array {
    return this.signingKey.sign(message);
  }

  nullifier(utxoHash: Uint8Array, blinding: Uint8Array): Uint8Array {
    return this.nullifierKey.nullifier(utxoHash, blinding);
  }

  decryptUtxo(
    ciphertext: Uint8Array,
    txViewingPubkey: P256Pubkey,
    salt: Uint8Array,
    slotIndex: number,
  ): Uint8Array {
    return this.viewingKey.decryptUtxo(ciphertext, txViewingPubkey, salt, slotIndex);
  }
}

export function ownerHash(signingPubkey: PublicKey, nullifierPubkey: Uint8Array): Uint8Array {
  assertLength(nullifierPubkey, 32, "nullifier pubkey");
  return poseidon([signingPubkey.ownerPkField(), nullifierPubkey]);
}
