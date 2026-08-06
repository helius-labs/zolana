import { getAddressDecoder, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  NullifierKey,
  ShieldedAddress,
  ShieldedKeypair,
  ShieldedPda,
  ShieldedPublicKey,
  ViewingKey,
  randomSalt,
  type Bytes31,
  type Bytes32,
} from "../src/keypair/index.js";

const addressDecoder = getAddressDecoder();

function bytes(fill: number): Bytes32 {
  return new Uint8Array(32).fill(fill) as Bytes32;
}

function pda(fill: number): Address {
  return addressDecoder.decode(bytes(fill));
}

function viewing(fill: number): ViewingKey {
  const secret = new Uint8Array(32) as Bytes32;
  secret[31] = fill;
  return ViewingKey.fromBytes(secret);
}

describe("ShieldedPda", () => {
  it("derives the same identity for both key-exchange participants", () => {
    const alice = viewing(2);
    const bob = viewing(3);
    const fromAlice = ShieldedPda.fromKeyExchange(pda(7), alice, bob.publicKey());
    const fromBob = ShieldedPda.fromKeyExchange(pda(7), bob, alice.publicKey());

    expect(fromAlice.shieldedAddress().nullifierPublicKey).toEqual(
      fromBob.shieldedAddress().nullifierPublicKey,
    );
    expect(fromAlice.viewingPublicKey().toBytes()).toEqual(fromBob.viewingPublicKey().toBytes());
    expect(fromAlice.ownerHash()).toEqual(fromBob.ownerHash());
    expect(fromAlice.nullifier(bytes(1), bytes(2))).toEqual(fromBob.nullifier(bytes(1), bytes(2)));
  });

  it("binds derived roles to the PDA address", () => {
    const alice = viewing(2);
    const bob = viewing(3);
    const first = ShieldedPda.fromKeyExchange(pda(7), alice, bob.publicKey());
    const second = ShieldedPda.fromKeyExchange(pda(8), alice, bob.publicKey());

    expect(first.viewingPublicKey().toBytes()).not.toEqual(second.viewingPublicKey().toBytes());
    expect(first.nullifierPublicKey()).not.toEqual(second.nullifierPublicKey());
  });

  it("derives a deterministic sole-holder identity distinct from exchanges", () => {
    const alice = viewing(2);
    const bob = viewing(3);
    const first = ShieldedPda.fromViewingKey(pda(7), alice);
    const second = ShieldedPda.fromViewingKey(pda(7), alice);
    const otherPda = ShieldedPda.fromViewingKey(pda(8), alice);
    const soleExchange = ShieldedPda.fromKeyExchange(pda(7), alice, alice.publicKey());
    const pairedExchange = ShieldedPda.fromKeyExchange(pda(7), alice, bob.publicKey());

    expect(first.shieldedAddress().nullifierPublicKey).toEqual(
      second.shieldedAddress().nullifierPublicKey,
    );
    expect(first.viewingPublicKey().toBytes()).toEqual(second.viewingPublicKey().toBytes());
    expect(first.viewingKey().publicKey().toBytes()).toEqual(first.viewingPublicKey().toBytes());
    expect(first.viewingPublicKey().toBytes()).not.toEqual(otherPda.viewingPublicKey().toBytes());
    for (const exchange of [soleExchange, pairedExchange]) {
      expect(first.viewingPublicKey().toBytes()).not.toEqual(exchange.viewingPublicKey().toBytes());
      expect(first.nullifierPublicKey()).not.toEqual(exchange.nullifierPublicKey());
    }
  });

  it("holds explicitly supplied roles", () => {
    const viewingKey = viewing(4);
    const nullifier = NullifierKey.fromSecret(new Uint8Array(31).fill(3) as Bytes31);
    const expectedNullifier = nullifier.publicKey();
    const identity = ShieldedPda.fromParts(pda(7), nullifier, viewingKey);

    expect(identity.viewingPublicKey().toBytes()).toEqual(viewingKey.publicKey().toBytes());
    expect(identity.nullifierPublicKey()).toEqual(expectedNullifier);
    expect(identity.shieldedAddress().nullifierPublicKey).toEqual(expectedNullifier);
  });

  it("cannot sign", () => {
    const alice = viewing(2);
    const identity = ShieldedPda.fromKeyExchange(pda(7), alice, alice.publicKey());

    expect(identity.curve()).toBe("pda");
    expect(() => identity.sign(new TextEncoder().encode("private_tx_hash"))).toThrow(
      expect.objectContaining({ code: "KEYPAIR_PDA_CANNOT_SIGN" }),
    );
  });

  it("round-trips an encrypted slot to the PDA identity", () => {
    const alice = viewing(2);
    const bob = viewing(3);
    const identity = ShieldedPda.fromKeyExchange(pda(7), alice, bob.publicKey());
    const salt = randomSalt();
    const plaintext = new TextEncoder().encode("pda utxo");
    const ciphertext = alice.encryptSlot(identity.viewingPublicKey(), plaintext, salt, 0);

    expect(identity.decryptUtxo(ciphertext, alice.publicKey(), salt, 0)).toEqual(plaintext);
  });

  it("encodes PDA owners without changing their proof-input field", () => {
    const ownerBytes = bytes(7);
    const asPda = ShieldedPublicKey.fromPda(ownerBytes);
    const asEd25519 = ShieldedPublicKey.fromEd25519(ownerBytes);

    expect(asPda.toBytes()).not.toEqual(asEd25519.toBytes());
    expect(asPda.confidentialViewTag()).toEqual(asEd25519.confidentialViewTag());
    expect(asPda.ownerPublicKeyField()).toEqual(asEd25519.ownerPublicKeyField());
    expect(asPda.curve()).toBe("pda");
    expect(asPda.pda()).toEqual(ownerBytes);
    expect(() => asPda.ed25519()).toThrow(
      expect.objectContaining({ code: "KEYPAIR_INVALID_SIGNATURE_TYPE" }),
    );
    expect(ShieldedPublicKey.fromBytes(asPda.toBytes()).toBytes()).toEqual(asPda.toBytes());

    const invalid = asPda.toBytes();
    invalid[33] = 1;
    expect(() => ShieldedPublicKey.fromBytes(invalid)).toThrow(
      expect.objectContaining({ code: "KEYPAIR_INVALID_PUBLIC_KEY" }),
    );
  });

  it("returns the PDA as its Solana address", () => {
    const address = pda(7);
    const alice = viewing(2);
    const identity = ShieldedPda.fromKeyExchange(address, alice, alice.publicKey());

    expect(identity.shieldedAddress().solanaAddress()).toBe(address);
    expect(identity.pda()).toBe(address);
    expect(() => ShieldedKeypair.generate("p256").shieldedAddress().solanaAddress()).toThrow(
      expect.objectContaining({ code: "KEYPAIR_NO_SOLANA_ADDRESS" }),
    );
  });

  it("constructs a public PDA address directly", () => {
    const pdaAddress = pda(9);
    const address = ShieldedAddress.forPda(
      pdaAddress,
      new Uint8Array(32) as Bytes32,
      viewing(5).publicKey(),
    );
    expect(address.signingPublicKey.curve()).toBe("pda");
    expect(address.solanaAddress()).toBe(pdaAddress);
  });
});
