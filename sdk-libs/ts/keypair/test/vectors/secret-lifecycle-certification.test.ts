import { describe, expect, it } from "vitest";

import certification from "../../../vectors/keypair-crypto-cert-v1.json" with { type: "json" };
import type { Bytes31, Bytes32 } from "../../src/bytes.js";
import {
  KeypairError,
  NullifierKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
} from "../../src/index.js";

/**
 * K8, secret ownership and lifecycle, against
 * `sdk-libs/keypair/tests/crypto_certification.rs`.
 *
 * Rust and TypeScript do not have the same lifecycle to certify. Rust wipes on
 * `Drop` through `Zeroizing` and offers the caller no destruction; TypeScript
 * has no drop, so it exposes `destroy()`. The Rust rows here are the ones a
 * fixture can carry -- who owns an exported secret, and what a clone duplicates
 * -- and each is asserted as a shared property. The `destroy()` half is
 * measured against the threat model it exists for, and the row-update records
 * it as a deliberate divergence rather than a parity claim.
 */

const recorded = certification.secretLifecycle;
const traitMethods = certification.capabilityBoundary.viewingKeyTrait;

function fromHex(value: string): Uint8Array {
  return Uint8Array.from((value.match(/../g) ?? []).map((byte) => Number.parseInt(byte, 16)));
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const viewingSecret = () => fromHex(certification.transferEncryption.senderSecretBytes) as Bytes32;
const signingSecret = () => fromHex(certification.mergeEncryption.txSecretBytes) as Bytes32;

function expectDestroyed(operation: () => unknown): void {
  let caught: unknown;
  try {
    operation();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(KeypairError);
  expect((caught as KeypairError).code).toBe("KEYPAIR_INVALID_SECRET_KEY");
  expect((caught as KeypairError).details?.reason).toBe("destroyed");
}

/** Every {@link ViewingKeyLike} capability, invoked with arguments it accepts. */
function callViewingCapability(key: ViewingKey, method: string): unknown {
  const counterparty = ViewingKey.fromBytes(signingSecret()).publicKey();
  const salt = new Uint8Array(16) as import("../../src/bytes.js").Bytes16;
  switch (method) {
    case "publicKey":
      return key.publicKey();
    case "ecdh":
      return key.ecdh(counterparty);
    case "senderViewTag":
      return key.senderViewTag(0n);
    case "recipientRequestViewTag":
      return key.recipientRequestViewTag(0n);
    case "mergeViewTag":
      return key.mergeViewTag(0n);
    case "sendSharedViewTag":
      return key.sendSharedViewTag(counterparty, 0n);
    case "recipientSharedViewTag":
      return key.recipientSharedViewTag(counterparty, 0n);
    case "recipientBootstrapViewTag":
      return key.recipientBootstrapViewTag();
    case "transactionViewingKey":
      return key.transactionViewingKey(new Uint8Array(32).fill(1) as Bytes32);
    case "encryptSlot":
      return key.encryptSlot(counterparty, new Uint8Array(8), salt, 0);
    case "decryptUtxo":
      return key.decryptUtxo(new Uint8Array(8), counterparty, salt, 0);
    case "decryptSlotEphemeral":
      return key.decryptSlotEphemeral(counterparty, new Uint8Array(8), salt, 0);
    case "encryptVerifiable":
      return key.encryptVerifiable(counterparty, new Uint8Array(8));
    case "decryptVerifiable":
      return key.decryptVerifiable(counterparty, new Uint8Array(8));
    default:
      throw new Error(`unmapped viewing capability ${method}`);
  }
}

describe("K8 secret ownership and lifecycle against current Rust", () => {
  it("hands out exported secrets that Rust also owns independently", () => {
    expect(recorded.viewingSecretExportIsIndependent).toBe(true);
    const key = ViewingKey.fromBytes(viewingSecret());
    const exported = key.secretBytes();
    exported.fill(0);
    expect(toHex(key.secretBytes())).toBe(certification.transferEncryption.senderSecretBytes);

    expect(recorded.signingSecretExportIsIndependent).toBe(true);
    const signing = SigningKey.fromBytes(signingSecret());
    signing.secretBytes().fill(0);
    expect(toHex(signing.secretBytes())).toBe(certification.mergeEncryption.txSecretBytes);
  });

  it("copies the constructor's input rather than aliasing it", () => {
    const input = viewingSecret();
    const key = ViewingKey.fromBytes(input);
    input.fill(0);
    // A key that aliased its input would now be the zero scalar and could not
    // reproduce the recorded public key.
    expect(toHex(key.publicKey().toBytes())).toBe(
      certification.transferEncryption.senderPublicKeyBytes,
    );
  });

  it("owns the nullifier secret Rust lends out", () => {
    // Rust's `NullifierKey::secret()` returns `&[u8; 31]`, a borrow of live key
    // material. TypeScript returns a copy, so it is strictly the safer side and
    // the divergence is recorded rather than reconciled.
    expect(recorded.nullifierSecretAccessor).toBe("borrow");
    const key = NullifierKey.fromSecret(new Uint8Array(31).fill(5) as Bytes31);
    expect(toHex(key.secretBytes())).toBe(recorded.nullifierSecretBytes);
    key.secretBytes().fill(0);
    expect(toHex(key.secretBytes())).toBe(recorded.nullifierSecretBytes);
  });

  it("duplicates key material the way Rust's Clone does, without sharing it", () => {
    expect(recorded.viewingKeyCloneCarriesSecret).toBe(true);
    const keypair = ShieldedKeypair.fromSigningAndViewingKeys(
      SigningKey.fromBytes(signingSecret()),
      ViewingKey.fromBytes(viewingSecret()),
    );
    const first = keypair.viewingKey();
    const second = keypair.viewingKey();
    expect(toHex(first.secretBytes())).toBe(certification.transferEncryption.senderSecretBytes);
    // Destroying one duplicate must not reach the other or the source, which is
    // the property Rust gets for free from owning separate buffers.
    first.destroy();
    expect(toHex(second.secretBytes())).toBe(certification.transferEncryption.senderSecretBytes);
    expect(toHex(keypair.viewingPublicKey().toBytes())).toBe(
      certification.transferEncryption.senderPublicKeyBytes,
    );
  });

  it("refuses every viewing capability once the key is destroyed", () => {
    // Rust has no caller-invoked destruction, so this is the TypeScript-only
    // half of the lifecycle. Walking the trait's own capability list is what
    // keeps a newly added method from escaping the check.
    expect(recorded.rustHasExplicitDestroy).toBe(false);
    const names = traitMethods.map((row) => row.typescript);
    expect(names).toHaveLength(14);
    for (const method of names) {
      const key = ViewingKey.fromBytes(viewingSecret());
      expect(() => callViewingCapability(key, method)).not.toThrow();
      key.destroy();
      expectDestroyed(() => callViewingCapability(key, method));
    }
  });

  it("refuses signing and nullifier capabilities once destroyed, idempotently", () => {
    const signing = SigningKey.fromBytes(signingSecret());
    const nullifier = NullifierKey.fromSigningKey(signing);
    const digest = new Uint8Array(32).fill(9) as Bytes32;
    const signature = signing.sign(digest);
    signing.destroy();
    signing.destroy();
    expectDestroyed(() => signing.publicKey());
    expectDestroyed(() => signing.secretBytes());
    expectDestroyed(() => signing.sign(digest));
    expectDestroyed(() => signing.verify(digest, signature));
    // The rail is not key material, so it survives: a caller can still tell
    // which circuit the destroyed key belonged to.
    expect(signing.signatureType()).toBe("p256");

    nullifier.destroy();
    nullifier.destroy();
    expectDestroyed(() => nullifier.publicKey());
    expectDestroyed(() => nullifier.secretBytes());
    expectDestroyed(() => nullifier.nullifier(digest, new Uint8Array(31) as Bytes31));
  });

  it("destroys all three components through the keypair facade", () => {
    const signing = SigningKey.fromBytes(signingSecret());
    const viewing = ViewingKey.fromBytes(viewingSecret());
    const keypair = ShieldedKeypair.fromSigningAndViewingKeys(signing, viewing);
    const nullifierPublicKey = keypair.nullifierPublicKey();
    keypair.destroy();
    expectDestroyed(() => signing.secretBytes());
    expectDestroyed(() => viewing.secretBytes());
    expectDestroyed(() => keypair.nullifierPublicKey());
    expectDestroyed(() => keypair.shieldedAddress());
    expectDestroyed(() => keypair.ownerHash());
    // The address taken before destruction stays usable: it holds public
    // material only, so nothing about it needs wiping.
    expect(nullifierPublicKey).toHaveLength(32);
  });

  it("keeps key material out of the error a destroyed key raises", () => {
    const key = ViewingKey.fromBytes(viewingSecret());
    key.destroy();
    let caught: KeypairError | undefined;
    try {
      key.publicKey();
    } catch (error) {
      caught = error as KeypairError;
    }
    const serialized = JSON.stringify(caught);
    for (const secret of [
      certification.transferEncryption.senderSecretBytes,
      certification.transferEncryption.senderPublicKeyBytes,
    ]) {
      expect(serialized).not.toContain(secret);
      expect(caught?.message).not.toContain(secret);
    }
  });
});
