import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it, vi } from "vitest";

import {
  KeypairError,
  NullifierKey,
  P256PublicKey,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
  randomBlinding,
  randomSalt,
} from "../src/index.js";
import type { Bytes16, Bytes31, Bytes32, Bytes33, Bytes64 } from "../src/bytes.js";
import { decryptVerifiable, encryptVerifiable, mergeCiphertextHash } from "../src/merge/index.js";

function scalar(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}

function expectCode(operation: () => unknown, code: string): void {
  try {
    operation();
    throw new Error("expected operation to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(KeypairError);
    expect((error as KeypairError).code).toBe(code);
  }
}

describe("validation and secret lifecycle", () => {
  it("rejects malformed lengths, points, scalars, tags, and field values", () => {
    expectCode(
      () => P256PublicKey.fromBytes(new Uint8Array(32) as Bytes33),
      "KEYPAIR_INVALID_LENGTH",
    );
    expectCode(
      () => P256PublicKey.fromBytes(new Uint8Array(33).fill(7) as Bytes33),
      "KEYPAIR_INVALID_PUBLIC_KEY",
    );
    expectCode(
      () => SigningKey.fromBytes(new Uint8Array(32) as Bytes32),
      "KEYPAIR_INVALID_SECRET_KEY",
    );
    const tagged = new Uint8Array(34);
    tagged[0] = 9;
    expectCode(
      () => ShieldedPublicKey.fromBytes(tagged as Bytes33),
      "KEYPAIR_INVALID_SIGNATURE_TYPE",
    );
    tagged[0] = 1;
    tagged[33] = 1;
    expectCode(() => ShieldedPublicKey.fromBytes(tagged as Bytes33), "KEYPAIR_INVALID_PUBLIC_KEY");
    const nullifier = NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);
    expectCode(
      () =>
        nullifier.nullifier(
          new Uint8Array(32).fill(0xff) as Bytes32,
          new Uint8Array(31) as Bytes31,
        ),
      "KEYPAIR_HASH",
    );
    expectCode(() => mergeCiphertextHash(new Uint8Array()), "KEYPAIR_HASH");
  });

  it("returns copies and makes destroyed keys unusable", () => {
    const source = scalar(3);
    const signing = SigningKey.fromBytes(source);
    source.fill(0);
    expect(signing.publicKey().signatureType()).toBe("p256");
    const exported = signing.secretBytes();
    exported.fill(0);
    expect(signing.secretBytes()).toEqual(scalar(3));

    const nullifier = NullifierKey.fromSigningKey(signing);
    const viewing = ViewingKey.fromBytes(scalar(4));
    const keypair = ShieldedKeypair.fromKeys(signing, nullifier, viewing);
    keypair.destroy();
    expectCode(() => signing.secretBytes(), "KEYPAIR_INVALID_SECRET_KEY");
    expectCode(() => nullifier.publicKey(), "KEYPAIR_INVALID_SECRET_KEY");
    expectCode(() => viewing.publicKey(), "KEYPAIR_INVALID_SECRET_KEY");
    expectCode(() => keypair.shieldedAddress(), "KEYPAIR_INVALID_SECRET_KEY");
  });

  it("rejects signature tampering and malformed signatures", () => {
    const key = SigningKey.fromBytes(scalar(5));
    const digest = sha256(Uint8Array.of(1, 2, 3));
    const signature = key.sign(digest);
    signature[0] ^= 1;
    expect(key.verify(digest, signature)).toBe(false);
    expect(key.verify(digest, new Uint8Array(63) as Bytes64)).toBe(false);
  });

  it("separates wrong-key, tampered-slot, and tampered-merge plaintext", () => {
    const tx = ViewingKey.fromBytes(scalar(6));
    const recipient = ViewingKey.fromBytes(scalar(7));
    const stranger = ViewingKey.fromBytes(scalar(8));
    const salt = new Uint8Array(16) as Bytes16;
    const plaintext = new TextEncoder().encode("sensitive");
    const ciphertext = tx.encryptSlot(recipient.publicKey(), plaintext, salt, 2);
    const tampered = new Uint8Array(ciphertext);
    tampered[0] ^= 1;
    expect(recipient.decryptUtxo(tampered, tx.publicKey(), salt, 2)).not.toEqual(plaintext);
    expect(stranger.decryptUtxo(ciphertext, tx.publicKey(), salt, 2)).not.toEqual(plaintext);

    const merge = encryptVerifiable(scalar(9), recipient.publicKey(), plaintext);
    merge.ciphertext[0] ^= 1;
    expect(decryptVerifiable(scalar(7), merge.txViewingPublicKey, merge.ciphertext)).not.toEqual(
      plaintext,
    );
  });

  it("supports deterministic randomness injection without Math.random", () => {
    let counter = 0;
    const random = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((array) => {
      const output = array as Uint8Array;
      output.fill(++counter);
      return array;
    });
    expect(randomBlinding()).toEqual(new Uint8Array(31).fill(1));
    expect(randomSalt()).toEqual(new Uint8Array(16).fill(2));
    expect(SigningKey.generate().secretBytes()).toEqual(new Uint8Array(32).fill(3));
    expect(ViewingKey.generate().secretBytes()).toEqual(new Uint8Array(32).fill(4));
    random.mockRestore();
  });

  it("does not retain secret material in typed error diagnostics", () => {
    const secret = "ab".repeat(32);
    const error = (() => {
      try {
        SigningKey.fromBytes(new Uint8Array(32) as Bytes32);
      } catch (caught) {
        return caught as KeypairError;
      }
      throw new Error("unreachable");
    })();
    expect(JSON.stringify(error.details)).not.toContain(secret);
    expect(error.message).not.toContain(secret);
  });
});
