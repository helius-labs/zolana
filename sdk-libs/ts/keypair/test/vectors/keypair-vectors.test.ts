import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import {
  NullifierKey,
  P256PublicKey,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
} from "../../src/index.js";
import type { Bytes16, Bytes31, Bytes32 } from "../../src/bytes.js";
import {
  decryptVerifiable,
  encryptVerifiable,
  mergeCiphertextHash,
  mergePublicContribution,
} from "../../src/merge/index.js";

function hex(value: string): Uint8Array {
  return Uint8Array.from((value.match(/../g) ?? []).map((byte) => Number.parseInt(byte, 16)));
}

function hexString(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function scalar(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  new DataView(bytes.buffer).setUint32(28, value, false);
  return bytes as Bytes32;
}

describe("frozen Rust keypair vectors", () => {
  it("matches P256 public key, owner field, and signature vectors", () => {
    const key = SigningKey.fromBytes(scalar(1));
    expect(hexString(key.publicKey().toBytes())).toBe(
      "00036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    );
    expect(hexString(key.publicKey().hash())).toBe(
      "044773b2681cec700fdb631cf2ca84410447986764b430e88ac2e83e81b4a665",
    );
    const digest = sha256(new TextEncoder().encode("same"));
    const signature = key.sign(digest);
    expect(hexString(signature)).toBe(
      "713fa6868b5470a38fb53394ed4b655b71f953152b9d32d70a7df3966ddb1f4150681d3874925756b2cdd14759090ab2bd88334b1c497961f33cfc02ff9db6ba",
    );
    expect(key.verify(digest, signature)).toBe(true);
  });

  it("matches RFC 8032 Ed25519 and Rust tagged encoding", () => {
    const secret = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const key = SigningKey.fromEd25519Bytes(secret as Bytes32);
    expect(hexString(key.publicKey().confidentialViewTag())).toBe(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );
    expect(hexString(key.sign(new Uint8Array()))).toBe(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    expect(key.publicKey().toBytes().length).toBe(34);
    expect(key.publicKey().toBytes()[33]).toBe(0);
  });

  it("matches nullifier and viewing-tag vectors", () => {
    const nullifier = NullifierKey.fromSecret(new Uint8Array(31).fill(7) as Bytes31);
    expect(hexString(nullifier.publicKey())).toBe(
      "2ece7cecb48850fb1762bea0a87c4f8290c40f90ac43b9dae85eed13b2e9af8c",
    );
    const viewing = ViewingKey.fromBytes(scalar(1));
    expect(hexString(viewing.senderViewTag(0n))).toBe(
      "00d0ae24b9136f852f8f59671cd297f2804d021483a225b98607faa73755b474",
    );
    expect(viewing.recipientBootstrapViewTag()).toEqual(viewing.publicKey().x());
  });

  it("matches deterministic seed, tag-stream, and transaction-key vectors", () => {
    const viewing = ViewingKey.fromSeed(new Uint8Array(32).fill(7) as Bytes32, 9);
    expect(hexString(viewing.secretBytes())).toBe(
      "26bb58e3768586699b54ce7b8e3ad33402e41bf389d078c7e3b8525f25b76608",
    );
    expect(hexString(viewing.publicKey().toBytes())).toBe(
      "036fc3e973f5ebfee86c796993ee93471fb5fbab46d7d851a3f88d3aac94549f90",
    );
    expect(hexString(viewing.senderViewTag(11n))).toBe(
      "00e42294b549776348ef9f1e4bdb2998d65d40738936b60c88ebdb2215d7163f",
    );
    expect(hexString(viewing.recipientRequestViewTag(11n))).toBe(
      "0083d4ea50cb3507fe076cfb8175757dca3f313f348cbaedbdfff8f5f1647920",
    );
    expect(hexString(viewing.mergeViewTag(11n))).toBe(
      "0074b60704cc73c5fb6b7f7d182c637b2721cce4f0277dc99bc9c3bb4bb1d053",
    );
    expect(
      hexString(viewing.transactionViewingKey(new Uint8Array(32).fill(8) as Bytes32).secretBytes()),
    ).toBe("b1abdb85ef72cf0d2bd172aa67dc291baab4146c292f086824b93a5611e2f221");
  });

  it("decrypts the frozen slot ciphertext", () => {
    const ephemeral = ViewingKey.fromBytes(scalar(1));
    const recipient = ViewingKey.fromBytes(scalar(2));
    const ciphertext = hex("0dedf6fb1c2c64f57a31740887");
    const plaintext = recipient.decryptUtxo(
      ciphertext,
      ephemeral.publicKey(),
      new Uint8Array(16) as Bytes16,
      0,
    );
    expect(new TextDecoder().decode(plaintext)).toBe("deterministic");
  });

  it("matches the circuit merge vector and public inputs", () => {
    const txSecret = scalar(123_456_789);
    const userSecret = scalar(7);
    const userPublicKey = ViewingKey.fromBytes(userSecret).publicKey();
    const plaintext = Uint8Array.from({ length: 71 }, (_, index) => index);
    const encrypted = encryptVerifiable(txSecret, userPublicKey, plaintext);
    expect(hexString(encrypted.txViewingPublicKey.toBytes())).toBe(
      "02fb50388f29498d0a93ad25ec4c34037b9d3cc3cca4787eb6fedabe2b3003eac8",
    );
    expect(hexString(encrypted.ciphertext)).toBe(
      "d52cccc7053c653d83c840fcb12c3a1dd6ac2263a9f4c705d784dfd894234b6b5271590160bddbb7191a0eeb96646aa5397e0acb27b605aec6f1ceadcd2726cab1a675d511f202",
    );
    expect(hexString(mergeCiphertextHash(encrypted.ciphertext))).toBe(
      "2418c4f8d103a80bcc365a28f6172e7cd9cbfe71a301c19f775a64187ed2f453",
    );
    expect(
      decryptVerifiable(userSecret, encrypted.txViewingPublicKey, encrypted.ciphertext),
    ).toEqual(plaintext);
    const contribution = mergePublicContribution(
      encrypted.txViewingPublicKey,
      encrypted.ciphertext,
    );
    expect(contribution.txViewingPublicKeyLow).toEqual(
      hex("0002fb50388f29498d0a93ad25ec4c34037b9d3cc3cca4787eb6fedabe2b3003e"),
    );
    expect(contribution.txViewingPublicKeyHigh).toEqual(
      hex("000000000000000000000000000000000000000000000000000000000000eac8"),
    );
  });

  it("round-trips the complete shielded facade on both rails", () => {
    const signing = SigningKey.fromBytes(scalar(3));
    const nullifier = NullifierKey.fromSigningKey(signing);
    const viewing = ViewingKey.fromBytes(scalar(4));
    const keypair = ShieldedKeypair.fromKeys(signing, nullifier, viewing);
    const address = keypair.shieldedAddress();
    expect(address.signingPublicKey.signatureType()).toBe("p256");
    expect(address.ownerHash()).toHaveLength(32);
    expect(keypair.compressedAddress().bytes).toHaveLength(65);

    const ed = ShieldedKeypair.fromEd25519(new Uint8Array(32).fill(5) as Bytes32, 9);
    expect(ed.signingPublicKey().signatureType()).toBe("ed25519");
    expect(ed.shieldedAddress().solanaAddress()).toMatch(/^[1-9A-HJ-NP-Za-km-z]+$/);
  });

  it("parses exact public-key encodings", () => {
    const p256 = ViewingKey.fromBytes(scalar(8)).publicKey();
    expect(P256PublicKey.fromBytes(p256.toBytes()).toBytes()).toEqual(p256.toBytes());
    const tagged = ShieldedPublicKey.fromP256(p256);
    expect(ShieldedPublicKey.fromBytes(tagged.toBytes()).confidentialViewTag()).toEqual(p256.x());
  });
});
