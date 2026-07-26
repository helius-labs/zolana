import { describe, expect, it } from "vitest";

import certification from "../../../vectors/keypair-crypto-cert-v1.json" with { type: "json" };
import type { Bytes16, Bytes32 } from "../../src/bytes.js";
import { P256PublicKey, ViewingKey } from "../../src/index.js";

/**
 * K6, transfer encryption, against
 * `sdk-libs/keypair/tests/crypto_certification.rs`.
 *
 * The suite asks for the AES key, the nonce and the initial CTR counter as
 * named values. Rust keeps `derive_key_nonce` private and the fixture contract
 * forbids re-deriving it in the generator, so the three are certified jointly
 * through a keystream: AES-CTR over an all-zero plaintext is the keystream
 * itself, and five blocks of it are wrong in every byte if the key, the nonce
 * or the starting counter differs. What a keystream does not distinguish is a
 * pair of compensating errors across the three, which no implementation
 * produces by accident.
 */

const recorded = certification.transferEncryption;

function fromHex(value: string): Uint8Array {
  return Uint8Array.from((value.match(/../g) ?? []).map((byte) => Number.parseInt(byte, 16)));
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const viewing = (hex: string) => ViewingKey.fromBytes(fromHex(hex) as Bytes32);
const salt = (hex: string) => fromHex(hex) as Bytes16;

const sender = () => viewing(recorded.senderSecretBytes);
const recipient = () => viewing(recorded.recipientSecretBytes);
const stranger = () => viewing(recorded.strangerSecretBytes);

function keystream(from: ViewingKey, to: P256PublicKey, saltBytes: Bytes16, slot: number): string {
  return toHex(from.encryptSlot(to, new Uint8Array(recorded.keystreamLength), saltBytes, slot));
}

describe("K6 transfer encryption against current Rust", () => {
  it("derives the shared x-coordinate Rust derives, in both directions", () => {
    expect(toHex(sender().ecdh(recipient().publicKey()))).toBe(recorded.ecdhBytes);
    expect(toHex(recipient().ecdh(sender().publicKey()))).toBe(recorded.ecdhReverseBytes);
    expect(recorded.ecdhBytes).toBe(recorded.ecdhReverseBytes);
  });

  it("produces Rust's keystream, so the AES key, nonce, and initial counter agree", () => {
    const base = recorded.boundaries[0];
    expect(base?.case).toBe("base");
    expect(
      keystream(sender(), recipient().publicKey(), salt(recorded.baseSaltBytes), recorded.baseSlot),
    ).toBe(base?.keystreamBytes);
  });

  it("binds every input of the key schedule, one perturbation at a time", () => {
    const keys = new Map([
      [recorded.senderPublicKeyBytes, sender()],
      [recorded.strangerPublicKeyBytes, stranger()],
    ]);
    const publicKeys = new Map([
      [recorded.recipientPublicKeyBytes, recipient().publicKey()],
      [recorded.strangerPublicKeyBytes, stranger().publicKey()],
    ]);

    const base = recorded.boundaries[0]?.keystreamBytes;
    for (const row of recorded.boundaries) {
      const from = keys.get(row.senderPublicKeyBytes);
      const to = publicKeys.get(row.recipientPublicKeyBytes);
      expect(from, `unmapped sender in row ${row.case}`).toBeDefined();
      expect(to, `unmapped recipient in row ${row.case}`).toBeDefined();
      expect(
        keystream(from as ViewingKey, to as P256PublicKey, salt(row.saltBytes), row.slot),
      ).toBe(row.keystreamBytes);
      // A row that matched the base would mean the perturbed input never
      // reached the derivation, which is the divergence the row exists to find.
      if (row.case !== "base") expect(row.keystreamBytes).not.toBe(base);
    }
    expect(recorded.boundaries.map((row) => row.case)).toEqual([
      "base",
      "slot",
      "salt",
      "recipient",
      "ephemeral",
    ]);
  });

  it("encodes the slot index big-endian across all four bytes", () => {
    for (const row of recorded.slotEncoding) {
      expect(
        keystream(sender(), recipient().publicKey(), salt(recorded.baseSaltBytes), row.slot),
      ).toBe(row.keystreamBytes);
    }
    // A little-endian slot would map 1 to the keystream recorded for
    // 0x01000000 and back, so the two rows must not be interchangeable.
    const [one, , , high] = recorded.slotEncoding;
    expect(one?.slot).toBe(1);
    expect(high?.slot).toBe(16_777_216);
    expect(one?.keystreamBytes).not.toBe(high?.keystreamBytes);
  });

  it("consumes the salt in Rust's byte order", () => {
    for (const row of recorded.saltPositions) {
      expect(
        keystream(sender(), recipient().publicKey(), salt(row.saltBytes), recorded.baseSlot),
      ).toBe(row.keystreamBytes);
    }
    const [leading, trailing] = recorded.saltPositions;
    expect(leading?.keystreamBytes).not.toBe(trailing?.keystreamBytes);
  });

  it("matches the ciphertext and both decryption directions", () => {
    const plaintext = fromHex(recorded.plaintextBytes);
    const ciphertext = sender().encryptSlot(
      recipient().publicKey(),
      plaintext,
      salt(recorded.baseSaltBytes),
      recorded.baseSlot,
    );
    expect(toHex(ciphertext)).toBe(recorded.ciphertextBytes);
    expect(
      toHex(
        recipient().decryptUtxo(
          ciphertext,
          sender().publicKey(),
          salt(recorded.baseSaltBytes),
          recorded.baseSlot,
        ),
      ),
    ).toBe(recorded.recoveredBytes);
    expect(
      toHex(
        sender().decryptSlotEphemeral(
          recipient().publicKey(),
          ciphertext,
          salt(recorded.baseSaltBytes),
          recorded.baseSlot,
        ),
      ),
    ).toBe(recorded.ephemeralRecoveredBytes);
    expect(recorded.recoveredBytes).toBe(recorded.plaintextBytes);

    // The ciphertext is the keystream XOR the plaintext, which is what makes
    // the keystream rows above evidence about this path rather than a separate
    // one.
    const stream = fromHex(recorded.boundaries[0]?.keystreamBytes ?? "");
    expect(toHex(plaintext.map((byte, index) => byte ^ (stream[index] ?? 0)))).toBe(
      recorded.ciphertextBytes,
    );
  });

  it("returns Rust's exact garbage for a wrong recipient or wrong ephemeral key", () => {
    const ciphertext = fromHex(recorded.ciphertextBytes);
    // AES-CTR carries no tag, so these succeed. Asserting the exact output
    // rather than "not the plaintext" is what catches a port that derives a
    // different wrong key and would therefore decrypt some other ciphertext
    // correctly.
    expect(
      toHex(
        stranger().decryptUtxo(
          ciphertext,
          sender().publicKey(),
          salt(recorded.baseSaltBytes),
          recorded.baseSlot,
        ),
      ),
    ).toBe(recorded.wrongRecipientRecoveredBytes);
    expect(
      toHex(
        recipient().decryptUtxo(
          ciphertext,
          stranger().publicKey(),
          salt(recorded.baseSaltBytes),
          recorded.baseSlot,
        ),
      ),
    ).toBe(recorded.wrongEphemeralRecoveredBytes);
    expect(recorded.wrongRecipientRecoveredBytes).not.toBe(recorded.plaintextBytes);
    expect(recorded.wrongEphemeralRecoveredBytes).not.toBe(recorded.plaintextBytes);
  });

  it("encrypts under the per-transaction viewing key the production flow uses", () => {
    const flow = recorded.transactionViewingKey;
    const txViewing = sender().transactionViewingKey(fromHex(flow.firstNullifierBytes) as Bytes32);
    expect(toHex(txViewing.publicKey().toBytes())).toBe(flow.publicKeyBytes);
    const ciphertext = txViewing.encryptSlot(
      recipient().publicKey(),
      fromHex(recorded.plaintextBytes),
      salt(recorded.baseSaltBytes),
      recorded.baseSlot,
    );
    expect(toHex(ciphertext)).toBe(flow.ciphertextBytes);
    expect(
      toHex(
        recipient().decryptUtxo(
          ciphertext,
          txViewing.publicKey(),
          salt(recorded.baseSaltBytes),
          recorded.baseSlot,
        ),
      ),
    ).toBe(flow.recoveredBytes);
    // The long-term key must not open a transaction-keyed ciphertext.
    expect(flow.ciphertextBytes).not.toBe(recorded.ciphertextBytes);
  });
});
