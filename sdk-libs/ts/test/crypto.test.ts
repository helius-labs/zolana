import { describe, expect, it } from "vitest";

import fixture from "../vectors/poseidon-parity-v1.json" with { type: "json" };
import { HasherWasmError, MAX_POSEIDON_INPUTS, poseidon } from "../src/hasher/index.js";
import {
  KeypairError,
  P256PublicKey,
  P_CONST_SEC1,
  P_DERIVE_SEC1,
  P_PDA_SEC1,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  ed25519DerivationMessage,
  symmetricApply,
  type Bytes16,
  type Bytes32,
  type Bytes33,
} from "../src/keypair/index.js";
import { MERGE_INFO } from "../src/keypair/merge/index.js";

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
    expect(keypair.signingPublicKey().signatureType()).toBe("ed25519");
    expect(keypair.viewingPublicKey()).toBeInstanceOf(P256PublicKey);
    expect(ShieldedKeypair.generate("p256").curve()).toBe("p256");
  });

  it("derives symmetric ECDH secrets", () => {
    const alice = ViewingKey.fromSeed(new Uint8Array(32).fill(1) as Bytes32, 0);
    const bob = ViewingKey.fromSeed(new Uint8Array(32).fill(2) as Bytes32, 0);
    expect(alice.ecdh(bob.publicKey())).toEqual(bob.ecdh(alice.publicKey()));
  });

  it("applies the symmetric key schedule as an involution", () => {
    const sharedSecret = new Uint8Array(32);
    sharedSecret.set(new Uint8Array(31).fill(0x11), 1);
    const plaintext = new TextEncoder().encode("private note");
    const ciphertext = symmetricApply(sharedSecret, MERGE_INFO, plaintext);
    expect(ciphertext).not.toEqual(plaintext);
    expect(symmetricApply(sharedSecret, MERGE_INFO, ciphertext)).toEqual(plaintext);
  });

  it("refuses to sign derivation inputs on both rails", () => {
    for (const rail of ["p256", "ed25519"] as const) {
      const key = SigningKey.generate(rail);
      const payload = new TextEncoder().encode("TSPP/derive/v1".padEnd(32, "\0")).subarray(0, 32);
      expect(() => key.sign(payload)).toThrow(KeypairError);
    }
    const ed25519Key = SigningKey.generate("ed25519");
    const message = ed25519DerivationMessage(ed25519Key.publicKey().ed25519());
    expect(() => ed25519Key.sign(message)).toThrow(KeypairError);
  });

  it("refuses ECDH against the committed derivation points", () => {
    const viewing = ViewingKey.generate();
    expect(() => viewing.ecdh(P256PublicKey.fromBytes(P_CONST_SEC1 as Bytes33))).toThrow(
      KeypairError,
    );
    expect(() => viewing.ecdh(P256PublicKey.fromBytes(P_DERIVE_SEC1 as Bytes33))).toThrow(
      KeypairError,
    );
    expect(() => viewing.ecdh(P256PublicKey.fromBytes(P_PDA_SEC1 as Bytes33))).toThrow(
      KeypairError,
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
