import { sha256 } from "@noble/hashes/sha2.js";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { NullifierKey, SigningKey, ViewingKey } from "../../src/index.js";
import type { Bytes16, Bytes31, Bytes32 } from "../../src/bytes.js";
import { decryptVerifiable, encryptVerifiable } from "../../src/merge/index.js";

function scalar(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  new DataView(bytes.buffer).setUint32(28, value, false);
  return bytes as Bytes32;
}

describe("keypair properties", () => {
  it("verifies generated messages across both signature rails", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 255 }),
        fc.uint8Array({ minLength: 1, maxLength: 128 }),
        (secret, message) => {
          const p256 = SigningKey.fromBytes(scalar(secret));
          const digest = sha256(message);
          expect(p256.verify(digest, p256.sign(digest))).toBe(true);

          const ed25519 = SigningKey.fromEd25519Bytes(scalar(secret));
          expect(ed25519.verify(message, ed25519.sign(message))).toBe(true);
        },
      ),
    );
  });

  it("signs and verifies across P256 and Ed25519 keys", () => {
    for (let index = 1; index <= 64; index++) {
      const digest = sha256(Uint8Array.of(index));
      const p256 = SigningKey.fromBytes(scalar(index));
      const p256Signature = p256.sign(digest);
      expect(p256.verify(digest, p256Signature)).toBe(true);
      digest[0] ^= 1;
      expect(p256.verify(digest, p256Signature)).toBe(false);

      const ed25519 = SigningKey.fromEd25519Bytes(scalar(index));
      const message = Uint8Array.of(index, index ^ 0xff);
      const ed25519Signature = ed25519.sign(message);
      expect(ed25519.verify(message, ed25519Signature)).toBe(true);
      ed25519Signature[index % 64] ^= 1;
      expect(ed25519.verify(message, ed25519Signature)).toBe(false);
    }
  });

  it("round-trips every slot direction with salt and index separation", () => {
    const salt = Uint8Array.from({ length: 16 }, (_, index) => index) as Bytes16;
    for (let index = 1; index <= 32; index++) {
      const sender = ViewingKey.fromBytes(scalar(index));
      const recipient = ViewingKey.fromBytes(scalar(index + 100));
      const tx = sender.transactionViewingKey(scalar(index + 200));
      const plaintext = Uint8Array.from({ length: index + 3 }, (_, offset) => offset ^ index);
      const ciphertext = tx.encryptSlot(recipient.publicKey(), plaintext, salt, index);
      expect(recipient.decryptUtxo(ciphertext, tx.publicKey(), salt, index)).toEqual(plaintext);
      expect(tx.decryptSlotEphemeral(recipient.publicKey(), ciphertext, salt, index)).toEqual(
        plaintext,
      );
      expect(tx.encryptSlot(recipient.publicKey(), plaintext, salt, index + 1)).not.toEqual(
        ciphertext,
      );
      const otherSalt = new Uint8Array(salt) as Bytes16;
      otherSalt[0] ^= 1;
      expect(tx.encryptSlot(recipient.publicKey(), plaintext, otherSalt, index)).not.toEqual(
        ciphertext,
      );
    }
  });

  it("keeps shared tags symmetric and separates purpose and counters", () => {
    for (let index = 1; index <= 32; index++) {
      const sender = ViewingKey.fromBytes(scalar(index));
      const recipient = ViewingKey.fromBytes(scalar(index + 64));
      expect(sender.ecdh(recipient.publicKey())).toEqual(recipient.ecdh(sender.publicKey()));
      expect(sender.sendSharedViewTag(recipient.publicKey(), 0n)).toEqual(
        recipient.recipientSharedViewTag(sender.publicKey(), 0n),
      );
      expect(sender.sendSharedViewTag(recipient.publicKey(), 0n)).not.toEqual(
        sender.sendSharedViewTag(recipient.publicKey(), 1n),
      );
      expect(sender.senderViewTag(0n)).not.toEqual(sender.recipientRequestViewTag(0n));
      expect(sender.senderViewTag(0n)).not.toEqual(sender.mergeViewTag(0n));
    }
  });

  it("binds nullifiers to all three inputs", () => {
    for (let index = 1; index <= 32; index++) {
      const key = NullifierKey.fromSecret(new Uint8Array(31).fill(index) as Bytes31);
      const hash = new Uint8Array(32).fill(index) as Bytes32;
      const blinding = new Uint8Array(31).fill(index + 1) as Bytes31;
      const base = key.nullifier(hash, blinding);
      const otherHash = new Uint8Array(hash) as Bytes32;
      otherHash[31] ^= 1;
      const otherBlinding = new Uint8Array(blinding) as Bytes31;
      otherBlinding[30] ^= 1;
      expect(key.nullifier(otherHash, blinding)).not.toEqual(base);
      expect(key.nullifier(hash, otherBlinding)).not.toEqual(base);
      expect(
        NullifierKey.fromSecret(new Uint8Array(31).fill(index + 1) as Bytes31).nullifier(
          hash,
          blinding,
        ),
      ).not.toEqual(base);
    }
  });

  it("round-trips merge encryption and rejects wrong keys by content", () => {
    for (let index = 1; index <= 16; index++) {
      const txSecret = scalar(index);
      const userSecret = scalar(index + 32);
      const user = ViewingKey.fromBytes(userSecret);
      const plaintext = Uint8Array.from({ length: index * 3 }, (_, offset) => offset);
      const encrypted = encryptVerifiable(txSecret, user.publicKey(), plaintext);
      expect(
        decryptVerifiable(userSecret, encrypted.txViewingPublicKey, encrypted.ciphertext),
      ).toEqual(plaintext);
      expect(
        decryptVerifiable(scalar(index + 64), encrypted.txViewingPublicKey, encrypted.ciphertext),
      ).not.toEqual(plaintext);
    }
  });
});
