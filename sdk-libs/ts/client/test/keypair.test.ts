import { describe, expect, it } from "vitest";
import {
  NullifierKey,
  P256Pubkey,
  PublicKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  ownerHash,
  randomSalt,
} from "../src/index.js";

describe("keypair", () => {
  it("builds shielded addresses and owner hashes", () => {
    const signing = SigningKey.fromBytes(new Uint8Array(32).fill(1));
    const viewing = ViewingKey.fromBytes(new Uint8Array(32).fill(2));
    const keypair = ShieldedKeypair.fromKeys(signing, viewing);
    const address = keypair.shieldedAddress();

    expect(address.signingPubkey.signatureType()).toBe("p256");
    expect(address.signingPubkey.asBytes()).toHaveLength(34);
    expect(address.nullifierPubkey).toHaveLength(32);
    expect(address.viewingPubkey.asBytes()).toHaveLength(33);
    expect(address.ownerHash()).toEqual(ownerHash(address.signingPubkey, address.nullifierPubkey));
  });

  it("supports ed25519 owners with p256 viewing keys", () => {
    const signingSecret = new Uint8Array(32).fill(3);
    const viewing = ViewingKey.fromBytes(new Uint8Array(32).fill(4));
    const keypair = ShieldedKeypair.fromEd25519(signingSecret, viewing);

    expect(keypair.signingPubkey().signatureType()).toBe("ed25519");
    expect(keypair.shieldedAddress().viewingPubkey.asBytes()).toEqual(viewing.pubkey().asBytes());
  });

  it("signs and verifies both owner rails", () => {
    const msg = new Uint8Array(32).fill(9);
    const p256 = SigningKey.fromBytes(new Uint8Array(32).fill(5));
    const ed = SigningKey.fromEd25519(new Uint8Array(32).fill(6));

    expect(p256.verify(msg, p256.sign(msg))).toBe(true);
    expect(ed.verify(msg, ed.sign(msg))).toBe(true);
  });

  it("encrypts and decrypts transfer slots", () => {
    const sender = ViewingKey.fromBytes(new Uint8Array(32).fill(7));
    const recipient = ViewingKey.fromBytes(new Uint8Array(32).fill(8));
    const salt = randomSalt();
    const plaintext = new TextEncoder().encode("hello private note");

    const ciphertext = sender.encryptSlot(recipient.pubkey(), plaintext, salt, 3);
    expect(ciphertext).not.toEqual(plaintext);
    expect(recipient.decryptUtxo(ciphertext, sender.pubkey(), salt, 3)).toEqual(plaintext);
  });

  it("derives nullifier pubkeys and nullifiers deterministically", () => {
    const secret = new Uint8Array(31).fill(11);
    const nullifierKey = new NullifierKey(secret);
    const utxoHash = new Uint8Array(32).fill(12);
    const blinding = new Uint8Array(31).fill(13);

    expect(nullifierKey.pubkey()).toEqual(new NullifierKey(secret).pubkey());
    expect(nullifierKey.nullifier(utxoHash, blinding)).toEqual(
      new NullifierKey(secret).nullifier(utxoHash, blinding),
    );
  });

  it("validates public key encodings", () => {
    const p256 = P256Pubkey.fromSecret(new Uint8Array(32).fill(14));
    expect(PublicKey.fromP256(p256).confidentialViewTag()).toEqual(p256.x());
    expect(() => new P256Pubkey(new Uint8Array(33))).toThrow();
  });
});
