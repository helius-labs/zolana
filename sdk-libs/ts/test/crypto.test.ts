import { describe, expect, it } from "vitest";

import fixture from "../vectors/poseidon-parity-v1.json" with { type: "json" };
import { HasherWasmError, MAX_POSEIDON_INPUTS, poseidon } from "../src/hasher/index.js";
import {
  P256PublicKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  type Bytes16,
  type Bytes32,
} from "../src/keypair/index.js";

function bytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("Poseidon parity with Rust", () => {
  for (const vector of fixture.vectors) {
    it(vector.id, () => {
      expect(hex(poseidon(vector.inputsBytes.map(bytes)))).toBe(vector.expectedBytes);
    });
  }

  it("covers every verifier-supported arity", () => {
    const arities = new Set(fixture.vectors.map((vector) => vector.inputsBytes.length));
    expect(MAX_POSEIDON_INPUTS).toBe(fixture.parameters.maxInputs);
    for (let arity = 1; arity <= MAX_POSEIDON_INPUTS; arity += 1) {
      expect(arities).toContain(arity);
    }
  });

  it("rejects empty, over-wide, and over-arity inputs", () => {
    expect(() => poseidon([])).toThrow(HasherWasmError);
    expect(() => poseidon([new Uint8Array(33)])).toThrow(HasherWasmError);
    expect(() =>
      poseidon(Array.from({ length: MAX_POSEIDON_INPUTS + 1 }, () => new Uint8Array(32))),
    ).toThrow(HasherWasmError);
  });
});

describe("shielded key material", () => {
  it.each(["p256", "ed25519"] as const)("signs and verifies on the %s rail", (rail) => {
    const key = SigningKey.generate(rail);
    const message = new Uint8Array(32).fill(7);
    const signature = key.sign(message);
    expect(key.verify(message, signature)).toBe(true);
    const changed = message.slice();
    changed[0] = 8;
    expect(key.verify(changed, signature)).toBe(false);
  });

  it("defaults generated identities to the supported Ed25519 signing rail", () => {
    const keypair = ShieldedKeypair.generate();
    expect(keypair.curve()).toBe("ed25519");
    expect(keypair.signingPublicKey().curve()).toBe("ed25519");
    expect(keypair.viewingPublicKey()).toBeInstanceOf(P256PublicKey);
    expect(ShieldedKeypair.generate("p256").curve()).toBe("p256");
  });

  it("derives symmetric ECDH secrets and authenticated viewing encryption", () => {
    const alice = ViewingKey.fromSeed(new Uint8Array(32).fill(1) as Bytes32, 0);
    const bob = ViewingKey.fromSeed(new Uint8Array(32).fill(2) as Bytes32, 0);
    expect(alice.ecdh(bob.publicKey())).toEqual(bob.ecdh(alice.publicKey()));

    const plaintext = new TextEncoder().encode("private note");
    const encrypted = alice.encryptVerifiable(bob.publicKey(), plaintext);
    expect(bob.decryptVerifiable(encrypted.txViewingPublicKey, encrypted.ciphertext)).toEqual(
      plaintext,
    );
  });

  it("encrypts transfer slots for the intended viewing key", () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const salt = new Uint8Array(16).fill(9) as Bytes16;
    const plaintext = new TextEncoder().encode("slot payload");
    const ciphertext = sender
      .viewingKey()
      .encryptSlot(recipient.viewingPublicKey(), plaintext, salt, 2);
    expect(
      recipient.viewingKey().decryptUtxo(ciphertext, sender.viewingPublicKey(), salt, 2),
    ).toEqual(plaintext);
  });
});
