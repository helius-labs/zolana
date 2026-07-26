import { describe, expect, it } from "vitest";

import certification from "../../../vectors/keypair-crypto-cert-v1.json" with { type: "json" };
import type { Bytes31, Bytes32 } from "../../src/bytes.js";
import {
  CompressedShieldedAddress,
  NullifierKey,
  P256PublicKey,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
} from "../../src/index.js";

/**
 * G6-2: every public accessor that returns secret-adjacent bytes hands out an
 * independent buffer. Mutating the return must leave the object's next read
 * unchanged. The list below is the census; a new accessor that returns key
 * material or a stored public-key encoding must appear here.
 */

const viewingSecret = () =>
  Uint8Array.from(
    (certification.transferEncryption.senderSecretBytes.match(/../g) ?? []).map((byte) =>
      Number.parseInt(byte, 16),
    ),
  ) as Bytes32;

const signingSecret = () =>
  Uint8Array.from(
    (certification.mergeEncryption.txSecretBytes.match(/../g) ?? []).map((byte) =>
      Number.parseInt(byte, 16),
    ),
  ) as Bytes32;

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function expectIndependent(label: string, read: () => Uint8Array): void {
  const first = read();
  const before = toHex(first);
  first.fill(0xff);
  expect(toHex(read()), label).toBe(before);
  expect(toHex(first), `${label} mutated`).not.toBe(before);
}

describe("G6-2 aliasing census for secret-adjacent accessors", () => {
  it("copies every secret and public-key byte accessor", () => {
    const viewing = ViewingKey.fromBytes(viewingSecret());
    const signing = SigningKey.fromBytes(signingSecret());
    const nullifier = NullifierKey.fromSigningKey(signing);
    const keypair = ShieldedKeypair.fromSigningAndViewingKeys(signing, viewing);
    const address = keypair.shieldedAddress();
    const compressed = CompressedShieldedAddress.fromAddress(address);
    const p256 = viewing.publicKey();
    const shielded = signing.publicKey();

    const ed25519PublicKey = SigningKey.generate("ed25519").publicKey();
    const accessors: ReadonlyArray<readonly [string, () => Uint8Array]> = [
      ["ViewingKey.secretBytes", () => viewing.secretBytes()],
      ["ViewingKey.ecdh", () => viewing.ecdh(p256)],
      ["SigningKey.secretBytes", () => signing.secretBytes()],
      ["NullifierKey.secretBytes", () => nullifier.secretBytes()],
      ["NullifierKey.publicKey", () => nullifier.publicKey()],
      ["P256PublicKey.toBytes", () => p256.toBytes()],
      ["P256PublicKey.x", () => p256.x()],
      ["ShieldedPublicKey.toBytes", () => shielded.toBytes()],
      ["ShieldedPublicKey.confidentialViewTag", () => shielded.confidentialViewTag()],
      ["ShieldedPublicKey.ed25519", () => ed25519PublicKey.ed25519()],
      ["ShieldedAddress.nullifierPublicKey", () => address.nullifierPublicKey],
      ["CompressedShieldedAddress.ownerHash", () => compressed.ownerHash],
      ["CompressedShieldedAddress.bytes", () => compressed.bytes],
      ["ShieldedKeypair.nullifierPublicKey", () => keypair.nullifierPublicKey()],
      ["ShieldedKeypair.ownerHash", () => keypair.ownerHash()],
    ];

    // Sorted name list is the census. Adding an accessor without a row here fails.
    expect(accessors.map(([name]) => name).sort()).toEqual(
      [
        "CompressedShieldedAddress.bytes",
        "CompressedShieldedAddress.ownerHash",
        "NullifierKey.publicKey",
        "NullifierKey.secretBytes",
        "P256PublicKey.toBytes",
        "P256PublicKey.x",
        "ShieldedAddress.nullifierPublicKey",
        "ShieldedKeypair.nullifierPublicKey",
        "ShieldedKeypair.ownerHash",
        "ShieldedPublicKey.confidentialViewTag",
        "ShieldedPublicKey.ed25519",
        "ShieldedPublicKey.toBytes",
        "SigningKey.secretBytes",
        "ViewingKey.ecdh",
        "ViewingKey.secretBytes",
      ].sort(),
    );

    for (const [label, read] of accessors) {
      expectIndependent(label, read);
    }
  });

  it("copies constructor inputs rather than aliasing them", () => {
    const viewingInput = viewingSecret();
    const signingInput = signingSecret();
    const nullifierInput = new Uint8Array(31).fill(7) as Bytes31;
    const p256Bytes = ViewingKey.fromBytes(viewingSecret()).publicKey().toBytes();
    const shieldedBytes = SigningKey.fromBytes(signingSecret()).publicKey().toBytes();

    const viewing = ViewingKey.fromBytes(viewingInput);
    const signing = SigningKey.fromBytes(signingInput);
    const nullifier = NullifierKey.fromSecret(nullifierInput);
    const p256 = P256PublicKey.fromBytes(p256Bytes);
    const shielded = ShieldedPublicKey.fromBytes(shieldedBytes);

    viewingInput.fill(0);
    signingInput.fill(0);
    nullifierInput.fill(0);
    p256Bytes.fill(0);
    shieldedBytes.fill(0);

    expect(toHex(viewing.secretBytes())).toBe(certification.transferEncryption.senderSecretBytes);
    expect(toHex(signing.secretBytes())).toBe(certification.mergeEncryption.txSecretBytes);
    expect(toHex(nullifier.secretBytes())).toBe("07".repeat(31));
    expect(toHex(p256.toBytes())).toBe(certification.transferEncryption.senderPublicKeyBytes);
    expect(shielded.toBytes()).toHaveLength(34);
  });
});
