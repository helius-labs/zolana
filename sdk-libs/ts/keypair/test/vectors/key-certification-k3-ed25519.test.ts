import { describe, expect, it } from "vitest";

import type { Bytes32, Bytes64 } from "../../src/bytes.js";
import { SigningKey } from "../../src/index.js";
import { certification, expectHex, fromHex, toHex } from "./certification.js";

const recorded = certification.k3Ed25519Signatures;
const key = () => SigningKey.fromEd25519Bytes(fromHex(recorded.secretBytes) as Bytes32);
const otherKey = () => SigningKey.fromEd25519Bytes(fromHex(recorded.otherSecretBytes) as Bytes32);

describe("K3 Ed25519 signing and verification", () => {
  it("derives the same public key on both encodings", () => {
    const signer = key();
    expect(signer.isEd25519()).toBe(true);
    expect(signer.signatureType()).toBe("ed25519");
    expectHex(signer.publicKey().toBytes(), recorded.taggedPublicKeyBytes);
    expectHex(signer.publicKey().ed25519(), recorded.rawPublicKeyBytes);
    expectHex(otherKey().publicKey().toBytes(), recorded.otherTaggedPublicKeyBytes);
  });

  it("produces the Rust signature byte for byte at every message width", () => {
    const signer = key();
    for (const entry of recorded.messages) {
      const message = fromHex(entry.messageBytes);
      expectHex(signer.sign(message), entry.signatureBytes);
      expect(signer.verify(message, fromHex(entry.signatureBytes) as Bytes64)).toBe(entry.verified);
    }
  });

  /**
   * G2-2 rules that acceptance mirrors the Solana runtime, so this replays the
   * cases `verify_strict` separates from the permissive check: a small-order R
   * that the cofactored equation would accept, an R whose `y` exceeds `p`, and
   * an S at or above the group order.
   */
  it("takes the same acceptance decision on every malleated signature", () => {
    const signer = key();
    for (const entry of recorded.signatureCases) {
      const message = fromHex(entry.messageBytes);
      const signature = fromHex(entry.signatureBytes) as Bytes64;
      expect(signer.verify(message, signature), entry.name).toBe(entry.verified);
    }
  });

  it("covers the cases the strict policy exists to reject", () => {
    const named = new Map(recorded.signatureCases.map((entry) => [entry.name, entry]));
    for (const name of ["smallOrderR", "nonCanonicalR", "sAtOrder", "sPlusOrder"]) {
      expect(named.get(name)?.verified, name).toBe(false);
    }
    expect(named.get("canonical")?.verified).toBe(true);
    expect(recorded.acceptancePolicy).toBe("ed25519_dalek::VerifyingKey::verify_strict");
  });

  it("refuses a signature from another key and from the other rail", () => {
    const signer = key();
    const canonical = fromHex(
      recorded.signatureCases.find((entry) => entry.name === "canonical")?.signatureBytes ?? "",
    ) as Bytes64;
    expect(otherKey().verify(new Uint8Array(), canonical)).toBe(recorded.otherKeyVerifiesCanonical);
    expect(
      signer.verify(new Uint8Array(), fromHex(recorded.wrongRailSignatureBytes) as Bytes64),
    ).toBe(recorded.wrongRailVerified);
  });

  it("refuses every signature width other than 64 bytes", () => {
    const signer = key();
    const canonical = signer.sign(new Uint8Array());
    for (const width of [0, 1, 32, 63, 65, 128]) {
      const candidate = new Uint8Array(width);
      candidate.set(canonical.subarray(0, Math.min(width, 64)));
      expect(signer.verify(new Uint8Array(), candidate as Bytes64), `width ${String(width)}`).toBe(false);
    }
  });

  it("rejects its own signature after any single-bit change", () => {
    const signer = key();
    const message = fromHex("2a");
    const signature = signer.sign(message);
    expect(signer.verify(message, signature)).toBe(true);
    for (const index of [0, 31, 32, 62]) {
      const mutated = Uint8Array.from(signature) as Bytes64;
      mutated[index] ^= 0x01;
      expect(signer.verify(message, mutated), `byte ${String(index)}`).toBe(false);
    }
    const otherMessage = Uint8Array.from([0x2b]);
    expect(signer.verify(otherMessage, signature)).toBe(false);
  });

  /**
   * Rust derives the verifying key from the secret inside `SigningKey::verify`,
   * so a caller cannot present a small-order or non-canonically encoded public
   * key. TypeScript must not widen that surface, or the two would disagree on
   * inputs Rust cannot express.
   */
  it("exposes no verification path that accepts a caller-supplied public key", () => {
    expect(recorded.publicKeyIsDerivedFromSecret).toBe(true);
    const publicKey = key().publicKey() as unknown as Record<string, unknown>;
    expect(typeof publicKey.verify).toBe("undefined");
    expect(toHex(key().publicKey().ed25519())).toBe(recorded.rawPublicKeyBytes);
  });
});
