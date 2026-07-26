import { describe, expect, it } from "vitest";

import certification from "../../../vectors/keypair-crypto-cert-v1.json" with { type: "json" };
import type { Bytes32, Bytes33 } from "../../src/bytes.js";
import { P256PublicKey, ViewingKey } from "../../src/index.js";
import {
  MERGE_INFO,
  mergeCiphertextHash,
  mergePublicContribution,
  symmetricApply,
} from "../../src/merge/index.js";

/**
 * K7, merge verifiable encryption, against
 * `sdk-libs/keypair/tests/crypto_certification.rs`.
 *
 * The Poseidon key schedule assembles its AES key from the low halves of two
 * hashes, high half first, and takes the nonce from the last twelve bytes of a
 * third. None of those three values is public in Rust, so as in K6 they are
 * certified jointly through a keystream. `symmetricApply` isolates the schedule
 * from the ECDH above it, which is why the schedule is pinned twice: once from
 * a pre-shared secret and once through the full `encryptVerifiable` path.
 */

const recorded = certification.mergeEncryption;

function fromHex(value: string): Uint8Array {
  return Uint8Array.from((value.match(/../g) ?? []).map((byte) => Number.parseInt(byte, 16)));
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const viewing = (hex: string) => ViewingKey.fromBytes(fromHex(hex) as Bytes32);
const publicKey = (hex: string) => P256PublicKey.fromBytes(fromHex(hex) as Bytes33);

const tx = () => viewing(recorded.txSecretBytes);
const user = () => viewing(recorded.userSecretBytes);
const stranger = () => viewing(recorded.strangerSecretBytes);
const zeros = () => new Uint8Array(recorded.keystreamLength);

describe("K7 merge verifiable encryption against current Rust", () => {
  it("derives the shared x-coordinate Rust derives, in both directions", () => {
    expect(toHex(tx().ecdh(user().publicKey()))).toBe(recorded.ecdhBytes);
    expect(toHex(user().ecdh(publicKey(recorded.txViewingPublicKeyBytes)))).toBe(
      recorded.ecdhReverseBytes,
    );
  });

  it("produces Rust's keystream through the full encrypt path", () => {
    const encrypted = tx().encryptVerifiable(user().publicKey(), zeros());
    expect(toHex(encrypted.ciphertext)).toBe(recorded.mergeKeystreamBytes);
    expect(toHex(encrypted.txViewingPublicKey.toBytes())).toBe(recorded.txViewingPublicKeyBytes);
  });

  it("produces Rust's keystream from the key schedule alone", () => {
    const shared = fromHex(recorded.symmetricSharedSecretBytes) as Bytes32;
    expect(toHex(symmetricApply(shared, MERGE_INFO, zeros()))).toBe(
      recorded.symmetricKeystreamBytes,
    );
    // One flipped bit of the Poseidon shared secret has to reach the whole
    // keystream; a schedule that dropped a hash would leak the structure here.
    const flipped = fromHex(recorded.flippedSharedSecretBytes) as Bytes32;
    expect(toHex(symmetricApply(flipped, MERGE_INFO, zeros()))).toBe(
      recorded.flippedSharedKeystreamBytes,
    );
    expect(recorded.symmetricKeystreamBytes).not.toBe(recorded.flippedSharedKeystreamBytes);
  });

  it("packs the key-schedule label at Rust's split, position, and length prefix", () => {
    const shared = fromHex(recorded.symmetricSharedSecretBytes) as Bytes32;
    const streams = new Set<string>();
    for (const row of recorded.infoPacking) {
      const stream = toHex(symmetricApply(shared, fromHex(row.infoBytes), zeros()));
      expect(stream, `label ${row.infoBytes || "(empty)"}`).toBe(row.keystreamBytes);
      streams.add(stream);
    }
    // The rows differ only in label length, in the byte at the 31/32 limb
    // split, and in the leading byte. A packing that lost any of the three
    // would collapse two rows onto one keystream.
    expect(streams.size).toBe(recorded.infoPacking.length);
  });

  it("chunks the ciphertext hash the way Rust right-aligns its trailing block", () => {
    for (const row of recorded.ciphertextHashChunking) {
      const ciphertext = fromHex(row.ciphertextBytes);
      expect(ciphertext).toHaveLength(row.length);
      expect(toHex(mergeCiphertextHash(ciphertext)), `length ${String(row.length)}`).toBe(
        row.hashBytes,
      );
    }
    // The exact multiples of 16 are where a left-aligning port still agrees,
    // so the lengths either side of them carry the evidence.
    expect(recorded.ciphertextHashChunking.map((row) => row.length)).toEqual([
      1, 15, 16, 17, 31, 32, 33, 47, 71,
    ]);
  });

  it("packs the transaction viewing key into field limbs on both parity branches", () => {
    for (const row of recorded.publicContributions) {
      const key = publicKey(row.publicKeyBytes);
      expect(key.yIsOdd()).toBe(row.yIsOdd);
      const contribution = mergePublicContribution(key, new Uint8Array(32).fill(7));
      expect(toHex(contribution.txViewingPublicKeyLow)).toBe(row.lowBytes);
      expect(toHex(contribution.txViewingPublicKeyHigh)).toBe(row.highBytes);
      expect(toHex(contribution.ciphertextHash)).toBe(row.ciphertextHashBytes);
    }
    expect(recorded.publicContributions.map((row) => row.yIsOdd)).toEqual([false, true]);
  });

  it("matches the ciphertext, recovery, and hash of the recorded bundle", () => {
    const encrypted = tx().encryptVerifiable(user().publicKey(), fromHex(recorded.plaintextBytes));
    expect(toHex(encrypted.ciphertext)).toBe(recorded.ciphertextBytes);
    expect(
      toHex(user().decryptVerifiable(encrypted.txViewingPublicKey, encrypted.ciphertext)),
    ).toBe(recorded.recoveredBytes);
    expect(recorded.recoveredBytes).toBe(recorded.plaintextBytes);
  });

  it("returns Rust's exact garbage for a wrong user key, wrong tx key, or tampered ciphertext", () => {
    const ciphertext = fromHex(recorded.ciphertextBytes);
    const txPublic = publicKey(recorded.txViewingPublicKeyBytes);
    expect(toHex(stranger().decryptVerifiable(txPublic, ciphertext))).toBe(
      recorded.wrongUserRecoveredBytes,
    );
    expect(toHex(user().decryptVerifiable(stranger().publicKey(), ciphertext))).toBe(
      recorded.wrongTxKeyRecoveredBytes,
    );

    const tampered = fromHex(recorded.tamperedCiphertextBytes);
    expect(toHex(user().decryptVerifiable(txPublic, tampered))).toBe(
      recorded.tamperedRecoveredBytes,
    );
    // The proof binds the ciphertext through this hash, which is the only
    // integrity the scheme has: a flipped byte has to move it.
    expect(toHex(mergeCiphertextHash(tampered))).toBe(recorded.tamperedHashBytes);
    expect(recorded.tamperedHashBytes).not.toBe(
      toHex(mergeCiphertextHash(fromHex(recorded.ciphertextBytes))),
    );
  });
});
