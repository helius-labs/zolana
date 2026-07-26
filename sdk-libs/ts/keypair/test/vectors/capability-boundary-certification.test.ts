import { describe, expect, it } from "vitest";

import certification from "../../../vectors/keypair-crypto-cert-v1.json" with { type: "json" };
import type { Bytes16, Bytes31, Bytes32 } from "../../src/bytes.js";
import {
  type P256PublicKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  type ViewTag,
} from "../../src/index.js";
import type { ShieldedKeypairLike, ViewingKeyLike } from "../../src/traits/index.js";

/**
 * K9, capability and HSM boundaries, against
 * `sdk-libs/keypair/tests/crypto_certification.rs`.
 *
 * `trait-surface.test.ts` already certifies the method lists against the Rust
 * trait declarations. This suite covers the rest of the boundary: that the
 * interfaces are implementable by a backend which is not a concrete key and
 * produce the same bytes when they are, that neither interface offers secret
 * export or construction, and that every capability returns without a
 * `Promise`, which is the shape the owner's 2026-07-26 ruling requires.
 */

const recorded = certification.capabilityBoundary;

function fromHex(value: string): Uint8Array {
  return Uint8Array.from((value.match(/../g) ?? []).map((byte) => Number.parseInt(byte, 16)));
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const senderSecret = () => fromHex(certification.transferEncryption.senderSecretBytes) as Bytes32;
const recipientSecret = () =>
  fromHex(certification.transferEncryption.recipientSecretBytes) as Bytes32;
const salt = () => fromHex(certification.transferEncryption.baseSaltBytes) as Bytes16;
const slot = certification.transferEncryption.baseSlot;

/**
 * The TypeScript counterpart of the Rust fixture's `BackendViewingKey`: a
 * viewing-key backend that is not a {@link ViewingKey}. Custody sits behind the
 * adapter, so what the interface can ask for is exactly what a remote or
 * hardware-held key would have to answer.
 */
class BackendViewingKey implements ViewingKeyLike {
  readonly #inner: ViewingKey;
  readonly calls: string[] = [];

  constructor(secret: Bytes32) {
    this.#inner = ViewingKey.fromBytes(secret);
  }

  #record<T>(name: string, value: T): T {
    this.calls.push(name);
    return value;
  }

  publicKey(): P256PublicKey {
    return this.#record("publicKey", this.#inner.publicKey());
  }

  ecdh(counterparty: P256PublicKey): Bytes32 {
    return this.#record("ecdh", this.#inner.ecdh(counterparty));
  }

  senderViewTag(txCount: bigint): ViewTag {
    return this.#record("senderViewTag", this.#inner.senderViewTag(txCount));
  }

  recipientRequestViewTag(requestCount: bigint): ViewTag {
    return this.#record(
      "recipientRequestViewTag",
      this.#inner.recipientRequestViewTag(requestCount),
    );
  }

  mergeViewTag(mergeCount: bigint): ViewTag {
    return this.#record("mergeViewTag", this.#inner.mergeViewTag(mergeCount));
  }

  sendSharedViewTag(counterparty: P256PublicKey, index: bigint): ViewTag {
    return this.#record("sendSharedViewTag", this.#inner.sendSharedViewTag(counterparty, index));
  }

  recipientSharedViewTag(counterparty: P256PublicKey, index: bigint): ViewTag {
    return this.#record(
      "recipientSharedViewTag",
      this.#inner.recipientSharedViewTag(counterparty, index),
    );
  }

  recipientBootstrapViewTag(): ViewTag {
    return this.#record("recipientBootstrapViewTag", this.#inner.recipientBootstrapViewTag());
  }

  transactionViewingKey(firstNullifier: Bytes32): ViewingKey {
    return this.#record("transactionViewingKey", this.#inner.transactionViewingKey(firstNullifier));
  }

  encryptSlot(
    recipientPublicKey: P256PublicKey,
    plaintext: Uint8Array,
    saltBytes: Bytes16,
    slotIndex: number,
  ): Uint8Array {
    return this.#record(
      "encryptSlot",
      this.#inner.encryptSlot(recipientPublicKey, plaintext, saltBytes, slotIndex),
    );
  }

  decryptUtxo(
    ciphertext: Uint8Array,
    txViewingPublicKey: P256PublicKey,
    saltBytes: Bytes16,
    slotIndex: number,
  ): Uint8Array {
    return this.#record(
      "decryptUtxo",
      this.#inner.decryptUtxo(ciphertext, txViewingPublicKey, saltBytes, slotIndex),
    );
  }

  decryptSlotEphemeral(
    recipientPublicKey: P256PublicKey,
    ciphertext: Uint8Array,
    saltBytes: Bytes16,
    slotIndex: number,
  ): Uint8Array {
    return this.#record(
      "decryptSlotEphemeral",
      this.#inner.decryptSlotEphemeral(recipientPublicKey, ciphertext, saltBytes, slotIndex),
    );
  }

  encryptVerifiable(
    userViewingPublicKey: P256PublicKey,
    plaintext: Uint8Array,
  ): Readonly<{ ciphertext: Uint8Array; txViewingPublicKey: P256PublicKey }> {
    return this.#record(
      "encryptVerifiable",
      this.#inner.encryptVerifiable(userViewingPublicKey, plaintext),
    );
  }

  decryptVerifiable(txViewingPublicKey: P256PublicKey, ciphertext: Uint8Array): Uint8Array {
    return this.#record(
      "decryptVerifiable",
      this.#inner.decryptVerifiable(txViewingPublicKey, ciphertext),
    );
  }
}

/**
 * Compile-time half of the boundary: neither interface names a constructor or a
 * secret export, so a holder of one cannot ask for key material. If any of
 * these became a member, the `never` check below stops compiling.
 */
type ViewingExports = Extract<
  keyof ViewingKeyLike,
  "secretBytes" | "fromBytes" | "fromSeed" | "generate" | "destroy"
>;
type KeypairExports = Extract<
  keyof ShieldedKeypairLike,
  "secretBytes" | "viewingKey" | "nullifierKey" | "signingKey" | "destroy"
>;
const viewingOffersNoExport: [ViewingExports] extends [never] ? true : false = true;
const keypairOffersNoExport: [KeypairExports] extends [never] ? true : false = true;

function callViewingCapability(backend: ViewingKeyLike, method: string): unknown {
  const counterparty = ViewingKey.fromBytes(recipientSecret()).publicKey();
  switch (method) {
    case "publicKey":
      return backend.publicKey();
    case "ecdh":
      return backend.ecdh(counterparty);
    case "senderViewTag":
      return backend.senderViewTag(1n);
    case "recipientRequestViewTag":
      return backend.recipientRequestViewTag(1n);
    case "mergeViewTag":
      return backend.mergeViewTag(1n);
    case "sendSharedViewTag":
      return backend.sendSharedViewTag(counterparty, 1n);
    case "recipientSharedViewTag":
      return backend.recipientSharedViewTag(counterparty, 1n);
    case "recipientBootstrapViewTag":
      return backend.recipientBootstrapViewTag();
    case "transactionViewingKey":
      return backend.transactionViewingKey(new Uint8Array(32).fill(1) as Bytes32);
    case "encryptSlot":
      return backend.encryptSlot(counterparty, new Uint8Array(8), salt(), slot);
    case "decryptUtxo":
      return backend.decryptUtxo(new Uint8Array(8), counterparty, salt(), slot);
    case "decryptSlotEphemeral":
      return backend.decryptSlotEphemeral(counterparty, new Uint8Array(8), salt(), slot);
    case "encryptVerifiable":
      return backend.encryptVerifiable(counterparty, new Uint8Array(8));
    case "decryptVerifiable":
      return backend.decryptVerifiable(counterparty, new Uint8Array(8));
    default:
      throw new Error(`unmapped viewing capability ${method}`);
  }
}

function callKeypairCapability(keypair: ShieldedKeypairLike, method: string): unknown {
  switch (method) {
    case "signingPublicKey":
      return keypair.signingPublicKey();
    case "viewingPublicKey":
      return keypair.viewingPublicKey();
    case "curve":
      return keypair.curve();
    case "shieldedAddress":
      return keypair.shieldedAddress();
    case "ownerHash":
      return keypair.ownerHash();
    case "compressedAddress":
      return keypair.compressedAddress();
    case "sign":
      return keypair.sign(new Uint8Array(32).fill(9));
    case "nullifier":
      return keypair.nullifier(
        new Uint8Array(32).fill(1) as Bytes32,
        new Uint8Array(31).fill(2) as Bytes31,
      );
    case "nullifierPublicKey":
      return keypair.nullifierPublicKey();
    default:
      throw new Error(`unmapped keypair capability ${method}`);
  }
}

function isThenable(value: unknown): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { then?: unknown }).then === "function"
  );
}

const viewingCapabilities = certification.capabilityBoundary.viewingKeyTrait.map(
  (row) => row.typescript,
);
const keypairCapabilities = certification.capabilityBoundary.shieldedKeypairTrait
  .map((row) => row.typescript)
  .filter((name): name is string => name !== null);

describe("K9 capability and HSM boundary against current Rust", () => {
  it("offers neither construction nor secret export through either interface", () => {
    expect(viewingOffersNoExport).toBe(true);
    expect(keypairOffersNoExport).toBe(true);
    // The Rust trait's exclusions are read out of its source by the generator,
    // so this pins the two languages to the same omissions.
    expect(recorded.excludedFromViewingKeyTrait).toEqual([
      "from_bytes",
      "from_seed",
      "generate",
      "secret_bytes",
    ]);
  });

  it("lets a backend that is not a viewing key satisfy the interface", () => {
    expect(recorded.backendMatchesDirectKey).toBe(true);
    const backend = new BackendViewingKey(senderSecret());
    const recipient = ViewingKey.fromBytes(recipientSecret()).publicKey();
    const plaintext = fromHex(certification.transferEncryption.plaintextBytes);
    // Against Rust's ciphertext rather than against the concrete TypeScript
    // key, so the row detects a derivation change as well as a lossy adapter.
    expect(toHex(backend.encryptSlot(recipient, plaintext, salt(), slot))).toBe(
      certification.transferEncryption.ciphertextBytes,
    );
    expect(
      toHex(ViewingKey.fromBytes(senderSecret()).encryptSlot(recipient, plaintext, salt(), slot)),
    ).toBe(certification.transferEncryption.ciphertextBytes);
    expect(backend.calls).toEqual(["encryptSlot"]);
  });

  it("accepts a full keypair wherever a viewing backend is required", () => {
    expect(recorded.shieldedKeypairIsViewingBackend).toBe(true);
    const keypair = ShieldedKeypair.fromSigningAndViewingKeys(
      SigningKey.fromBytes(recipientSecret()),
      ViewingKey.fromBytes(senderSecret()),
    );
    const asViewing: ViewingKeyLike = keypair;
    const asKeypair: ShieldedKeypairLike = keypair;
    // No cast: the K11 narrowing removed the promise arm, so this reads as a
    // `P256PublicKey` outright. Restoring the union would make the cast
    // necessary again and fail the lint gate, which is the point.
    expect(toHex(asViewing.publicKey().toBytes())).toBe(
      certification.transferEncryption.senderPublicKeyBytes,
    );
    expect(asKeypair.nullifierPublicKey()).toHaveLength(32);
  });

  it("answers every viewing capability without a promise", () => {
    expect(recorded.synchronous).toBe(true);
    const backends: ViewingKeyLike[] = [
      ViewingKey.fromBytes(senderSecret()),
      ShieldedKeypair.fromSigningAndViewingKeys(
        SigningKey.fromBytes(recipientSecret()),
        ViewingKey.fromBytes(senderSecret()),
      ),
      new BackendViewingKey(senderSecret()),
    ];
    expect(viewingCapabilities).toHaveLength(14);
    for (const backend of backends) {
      for (const method of viewingCapabilities) {
        expect(isThenable(callViewingCapability(backend, method)), method).toBe(false);
      }
    }
  });

  it("answers every keypair capability without a promise", () => {
    const keypair: ShieldedKeypairLike = ShieldedKeypair.fromSigningAndViewingKeys(
      SigningKey.fromBytes(recipientSecret()),
      ViewingKey.fromBytes(senderSecret()),
    );
    expect(keypairCapabilities).toHaveLength(9);
    for (const method of keypairCapabilities) {
      expect(isThenable(callKeypairCapability(keypair, method)), method).toBe(false);
    }
  });
});
