import { describe, expect, it } from "vitest";
import { extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import fixture from "../vectors/poseidon-parity-v1.json" with { type: "json" };
import {
  HasherFailure,
  MAX_POSEIDON_INPUTS,
  initializePoseidon,
  poseidon,
  resetPoseidonForTests,
} from "../src/hasher/index.js";
import { SOL_MINT } from "../src/transaction/index.js";
import { createDeposit } from "../src/wallet/deposit.js";
import {
  KeypairError,
  X25519PublicKey,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
  ed25519DerivationMessage,
  symmetricApply,
  type Bytes16,
  type Bytes32,
  type Bytes34,
} from "../src/keypair/index.js";
import {
  DST_X25519_VIEW_ROOT,
  roleExpansion,
  viewRoot,
  type RoleSecrets,
} from "../src/keypair/derivation.js";
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

  it("loads the hasher itself at an async build entry", async () => {
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    resetPoseidonForTests();
    try {
      const deposit = await createDeposit({ recipient, asset: SOL_MINT, amount: 1n });
      expect(deposit.data.recipientOwnerHash).toHaveLength(32);
    } finally {
      await initializePoseidon();
    }
  });

  it("rejects empty, over-wide, and over-arity inputs", () => {
    expect(() => poseidon([])).toThrow(HasherFailure);
    expect(() => poseidon([new Uint8Array(33)])).toThrow(HasherFailure);
    expect(() =>
      poseidon(Array.from({ length: MAX_POSEIDON_INPUTS + 1 }, () => new Uint8Array(32))),
    ).toThrow(HasherFailure);
  });
});

describe("shielded key material", () => {
  it.each(["ed25519"] as const)("signs and verifies on the %s rail", (rail) => {
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
    expect(keypair.viewingPublicKey()).toBeInstanceOf(X25519PublicKey);
    expect(() => ShieldedKeypair.generate("p256")).toThrow("KEYPAIR_INVALID_SIGNATURE_TYPE");
    expect(() => SigningKey.generate("p256")).toThrow("KEYPAIR_INVALID_SIGNATURE_TYPE");
  });

  it("rejects the reserved owner tag without changing Ed25519 or PDA encodings", () => {
    const ed = SigningKey.generate().publicKey();
    const encoded = ed.toBytes();
    const reserved = encoded.slice() as Bytes34;
    reserved[0] = 0;
    expect(() => ShieldedPublicKey.fromBytes(reserved)).toThrow("KEYPAIR_INVALID_SIGNATURE_TYPE");
    expect(ShieldedPublicKey.fromBytes(encoded).ed25519()).toEqual(ed.ed25519());
    const pda = ShieldedPublicKey.fromPda(ed.ed25519());
    expect(pda.toBytes()[0]).toBe(2);
    expect(ShieldedPublicKey.fromBytes(pda.toBytes()).pda()).toEqual(ed.ed25519());
  });

  it("wipes role secrets when the expansion callback settles or throws", () => {
    const seed = new Uint8Array(64).fill(7);
    const zero31 = new Uint8Array(31);
    const zero32 = new Uint8Array(32);
    const kept: RoleSecrets[] = [];
    roleExpansion(seed, "ed25519", (roles) => {
      kept.push(roles);
      expect(roles.nullifierSecret).not.toEqual(zero31);
      expect(roles.viewingSecret).not.toEqual(zero32);
    });
    expect(() =>
      roleExpansion(seed, "ed25519", (roles) => {
        kept.push(roles);
        throw new Error("interrupted");
      }),
    ).toThrow("interrupted");
    for (const roles of kept) {
      expect(roles.nullifierSecret).toEqual(zero31);
      expect(roles.viewingSecret).toEqual(zero32);
    }
    expect(kept).toHaveLength(2);
  });

  it("derives symmetric ECDH secrets", () => {
    const alice = ViewingKey.fromBytes(new Uint8Array(32).fill(1) as Bytes32);
    const bob = ViewingKey.fromBytes(new Uint8Array(32).fill(2) as Bytes32);
    expect(alice.ecdh(bob.publicKey())).toEqual(bob.ecdh(alice.publicKey()));
  });

  it("applies the symmetric key schedule as an involution", () => {
    const sharedSecret = new Uint8Array(32);
    sharedSecret.set(new Uint8Array(31).fill(0x11), 1);
    const plaintext = new TextEncoder().encode("private UTXO");
    const ciphertext = symmetricApply(sharedSecret, MERGE_INFO, plaintext);
    expect(ciphertext).not.toEqual(plaintext);
    expect(symmetricApply(sharedSecret, MERGE_INFO, ciphertext)).toEqual(plaintext);
  });

  it("refuses to sign derivation inputs", () => {
    for (const rail of ["ed25519"] as const) {
      const key = SigningKey.generate(rail);
      const payload = new TextEncoder().encode("TSPP/derive/v1".padEnd(32, "\0")).subarray(0, 32);
      expect(() => key.sign(payload)).toThrow(KeypairError);
    }
    const ed25519Key = SigningKey.generate("ed25519");
    const message = ed25519DerivationMessage(ed25519Key.publicKey().ed25519());
    expect(() => ed25519Key.sign(message)).toThrow(KeypairError);
  });

  it("keeps role roots private when ECDH is queried at a related fixed peer", () => {
    const secret = new Uint8Array(32).fill(7) as Bytes32;
    const viewing = ViewingKey.fromBytes(secret);
    const root = viewRoot(secret);
    try {
      expect(hex(root)).toBe("f8f47fe6e0dee526f6e95d87ba0d52687c8729581443c14d0c928c69769cff2a");
      // Translating the former fixed peer by order-two torsion preserves DH.
      const peer = X25519PublicKey.fromBytes(
        Uint8Array.of(
          4,
          ...bytes("178bfe424f295736d60f0b9c30ec17044f7fba8cf9e30dcd6bb0e5ecafa7f71a"),
        ),
      );
      const leaked = viewing.ecdh(peer);
      const candidate = extract(sha256, leaked, new TextEncoder().encode(DST_X25519_VIEW_ROOT));
      try {
        expect(candidate).not.toEqual(root);
      } finally {
        leaked.fill(0);
        candidate.fill(0);
      }
    } finally {
      root.fill(0);
      secret.fill(0);
      viewing.destroy();
    }
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
