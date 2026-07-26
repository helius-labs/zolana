import { describe, expect, it } from "vitest";

import type { Bytes31, Bytes32 } from "../../src/bytes.js";
import { BLINDING_LENGTH } from "../../src/constants.js";
import { NullifierKey, SigningKey, ownerHash } from "../../src/index.js";
import { certification, expectDisposition, expectHex, fromHex, toHex } from "./certification.js";

const recorded = certification.k4Nullifiers;
const signingSecret = () => fromHex(recorded.signingSecretBytes) as Bytes32;
const key = () => NullifierKey.fromSigningKey(SigningKey.fromBytes(signingSecret()));
const otherKey = () =>
  NullifierKey.fromSecret(fromHex(recorded.otherNullifierSecretBytes) as Bytes31);

describe("K4 nullifier derivation and binding", () => {
  it("derives the same 31-byte secret and public key from the signing key", () => {
    expect(BLINDING_LENGTH).toBe(recorded.secretLength);
    const nullifier = key();
    expectHex(nullifier.secretBytes(), recorded.nullifierSecretBytes);
    expect(nullifier.secretBytes()).toHaveLength(recorded.secretLength);
    expectHex(nullifier.publicKey(), recorded.nullifierPublicKeyBytes);
    expectHex(otherKey().publicKey(), recorded.otherNullifierPublicKeyBytes);
  });

  it("reaches the same secret from the raw signing bytes as from the key", () => {
    expectHex(
      NullifierKey.fromSigningSecret(signingSecret()).secretBytes(),
      recorded.nullifierSecretBytes,
    );
  });

  it("produces the Rust nullifier at both ends of the blinding range", () => {
    const nullifier = key();
    for (const entry of recorded.derivations) {
      const produced = nullifier.nullifier(
        fromHex(entry.utxoHashBytes) as Bytes32,
        fromHex(entry.blindingBytes) as Bytes31,
      );
      expectHex(produced, entry.nullifierBytes);
    }
    expect(new Set(recorded.derivations.map((entry) => entry.nullifierBytes)).size).toBe(
      recorded.derivations.length,
    );
  });

  /**
   * The UTXO hash is a BN254 field element, so a 32-byte input at or above the
   * modulus is not a nullifier with a different value: it is refused. Both
   * sides must draw that line at the same place.
   */
  it("takes the same decision on every input across the field modulus", () => {
    const nullifier = key();
    const blinding = fromHex(recorded.derivations[0]?.blindingBytes ?? "") as Bytes31;
    for (const entry of recorded.fieldBoundary) {
      expectDisposition(
        () => nullifier.nullifier(fromHex(entry.utxoHashBytes) as Bytes32, blinding),
        entry.disposition,
        entry.name,
      );
    }
  });

  it("repeats for the same inputs and changes with any of them", () => {
    const nullifier = key();
    const entry = recorded.derivations[0];
    if (!entry) throw new Error("corpus records no derivation");
    const utxoHash = fromHex(entry.utxoHashBytes) as Bytes32;
    const blinding = fromHex(entry.blindingBytes) as Bytes31;
    const baseline = toHex(nullifier.nullifier(utxoHash, blinding));

    expect(toHex(nullifier.nullifier(utxoHash, blinding))).toBe(baseline);
    expect(recorded.repeatsIdentically).toBe(true);

    const movedHash = Uint8Array.from(utxoHash) as Bytes32;
    movedHash[31] ^= 0x01;
    const movedBlinding = Uint8Array.from(blinding) as Bytes31;
    movedBlinding[30] ^= 0x01;
    expect(toHex(nullifier.nullifier(movedHash, blinding))).not.toBe(baseline);
    expect(toHex(nullifier.nullifier(utxoHash, movedBlinding))).not.toBe(baseline);
    expect(toHex(otherKey().nullifier(utxoHash, blinding))).not.toBe(baseline);
  });

  it("refuses every width other than the recorded ones", () => {
    const nullifier = key();
    const utxoHash = fromHex(recorded.derivations[0]?.utxoHashBytes ?? "") as Bytes32;
    const blinding = fromHex(recorded.derivations[0]?.blindingBytes ?? "") as Bytes31;
    for (const width of [0, 30, 31, 33]) {
      expect(() => nullifier.nullifier(new Uint8Array(width) as Bytes32, blinding)).toThrow();
    }
    for (const width of [0, 30, 32, 33]) {
      expect(() => nullifier.nullifier(utxoHash, new Uint8Array(width) as Bytes31)).toThrow();
    }
  });

  /**
   * The nullifier public key is bound into the owner hash, which is what makes
   * a UTXO spendable only by the holder of the nullifier secret. Swapping the
   * nullifier key alone must move the owner hash.
   */
  it("binds the nullifier public key into the owner hash", () => {
    const signing = SigningKey.fromBytes(signingSecret());
    const ownerField = signing.publicKey().ownerPublicKeyField();
    expectHex(ownerField, recorded.ownerPkFieldBytes);
    expectHex(ownerHash(ownerField, key().publicKey()), recorded.ownerHashBytes);
    expectHex(
      ownerHash(ownerField, otherKey().publicKey()),
      recorded.ownerHashWithOtherNullifierBytes,
    );
    expect(recorded.ownerHashBytes).not.toBe(recorded.ownerHashWithOtherNullifierBytes);
  });

  it("returns owned copies and refuses use after destroy", () => {
    const nullifier = key();
    const secret = nullifier.secretBytes();
    secret.fill(0xff);
    expectHex(nullifier.secretBytes(), recorded.nullifierSecretBytes);

    nullifier.destroy();
    expect(() => nullifier.secretBytes()).toThrow();
    expect(() => nullifier.publicKey()).toThrow();
  });
});
