import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it, vi } from "vitest";

import constantsFixture from "../../../fixtures/keypair/constants.json" with { type: "json" };
import encryptionFixture from "../../../fixtures/keypair/encryption.json" with { type: "json" };
import errorFixture from "../../../fixtures/keypair/error.json" with { type: "json" };
import hashFixture from "../../../fixtures/keypair/hash.json" with { type: "json" };
import libFixture from "../../../fixtures/keypair/lib.json" with { type: "json" };
import mergeFixture from "../../../fixtures/keypair/merge.json" with { type: "json" };
import nullifierFixture from "../../../fixtures/keypair/nullifier_key.json" with { type: "json" };
import pubkeyFixture from "../../../fixtures/keypair/pubkey.json" with { type: "json" };
import shieldedFixture from "../../../fixtures/keypair/shielded.json" with { type: "json" };
import signingFixture from "../../../fixtures/keypair/signing_key.json" with { type: "json" };
import testsFixture from "../../../fixtures/keypair/tests.json" with { type: "json" };
import viewingFixture from "../../../fixtures/keypair/viewing_key.json" with { type: "json" };
import type { Bytes16, Bytes31, Bytes32, Bytes33, Bytes64 } from "../../src/bytes.js";
import {
  BLINDING_LENGTH,
  DST_VIEW_ROOT,
  INFO_MERGE_VIEW_TAG_SECRET,
  INFO_RECIPIENT_VIEW_TAG_SECRET,
  INFO_SENDER_VIEW_TAG_SECRET,
  INFO_TX_VIEWING,
  P256_PUBLIC_KEY_LENGTH,
  P_CONST_SEC1,
  SALT_LENGTH,
  SHIELDED_PUBLIC_KEY_LENGTH,
} from "../../src/constants.js";
import { KeypairError } from "../../src/error.js";
import { hashField, pack33, sha256Be, sha256Bytes, splitBigEndian128 } from "../../src/hash.js";
import {
  NullifierKey,
  P256PublicKey,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
  randomBlinding,
  randomSalt,
} from "../../src/index.js";
import {
  MERGE_INFO,
  decryptVerifiable,
  encryptVerifiable,
  mergeCiphertextHash,
  mergePublicContribution,
} from "../../src/merge/index.js";
import { poseidon } from "../../src/poseidon.js";

const fixtures = [
  constantsFixture,
  encryptionFixture,
  errorFixture,
  hashFixture,
  libFixture,
  mergeFixture,
  nullifierFixture,
  pubkeyFixture,
  shieldedFixture,
  signingFixture,
  testsFixture,
  viewingFixture,
] as const;

function fromHex(value: string): Uint8Array {
  return Uint8Array.from((value.match(/../g) ?? []).map((byte) => Number.parseInt(byte, 16)));
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function expectHex(actual: Uint8Array, expected: string): void {
  expect(toHex(actual)).toBe(expected);
}

function asBytes32(value: string): Bytes32 {
  return fromHex(value) as Bytes32;
}

function asBytes31(value: string): Bytes31 {
  return fromHex(value) as Bytes31;
}

function asP256(value: string): P256PublicKey {
  return P256PublicKey.fromBytes(fromHex(value) as Bytes33);
}

function mappedCode(rustCode: string): KeypairError["code"] {
  switch (rustCode) {
    case "InvalidPublicKey":
      return "KEYPAIR_INVALID_PUBLIC_KEY";
    case "InvalidSecretKey":
      return "KEYPAIR_INVALID_SECRET_KEY";
    case "InvalidSignatureType":
    case "NotEd25519":
      return "KEYPAIR_INVALID_SIGNATURE_TYPE";
    default:
      throw new Error(`unmapped Rust error code: ${rustCode}`);
  }
}

function expectMappedError(
  operation: () => unknown,
  expected: Readonly<{ code: string; details: string }>,
): void {
  expect(operation).toThrow(
    expect.objectContaining<KeypairError>({ code: mappedCode(expected.code) }),
  );
  expect(expected.details).toContain(expected.code);
}

function compressedAddressHash(bytes: Uint8Array): Bytes32 {
  const ownerHash = bytes.subarray(0, 32);
  const [viewingLow, viewingHigh] = pack33(bytes.subarray(32));
  return poseidon([ownerHash, viewingLow, viewingHigh]) as Bytes32;
}

describe("frozen Rust keypair fixtures", () => {
  it("uses all fixed-secret fixtures without exposing secret diagnostics", () => {
    expect(fixtures).toHaveLength(12);
    expect(fixtures.map((fixture) => fixture.id).sort()).toEqual([
      "fx-p00-keypair-constants-v1",
      "fx-p00-keypair-encryption-v1",
      "fx-p00-keypair-error-v1",
      "fx-p00-keypair-hash-v1",
      "fx-p00-keypair-lib-v1",
      "fx-p00-keypair-merge-v1",
      "fx-p00-keypair-nullifier-key-v1",
      "fx-p00-keypair-pubkey-v1",
      "fx-p00-keypair-shielded-v1",
      "fx-p00-keypair-signing-key-v1",
      "fx-p00-keypair-tests-v1",
      "fx-p00-keypair-viewing-key-v1",
    ]);
    for (const fixture of fixtures) expect(fixture.inputs.testOnlySecret).toBe(true);
    expect(testsFixture.inputs.fixedRandomnessOnly).toBe(true);
  });

  it("matches constants and recorded random boundaries", () => {
    const expected = constantsFixture.expected;
    expect(BLINDING_LENGTH).toBe(Number(expected.blindingLength));
    expect(P256_PUBLIC_KEY_LENGTH).toBe(Number(expected.p256PublicKeyLength));
    expect(SHIELDED_PUBLIC_KEY_LENGTH).toBe(Number(expected.publicKeyLength));
    expect(SALT_LENGTH).toBe(Number(expected.saltLength));
    expect(Number(expected.viewTagLength)).toBe(32);
    expectHex(P_CONST_SEC1, expected.pConstBytes);
    expectHex(new TextEncoder().encode(DST_VIEW_ROOT), expected.dstViewRootBytes);
    expectHex(MERGE_INFO, expected.mergeInfoBytes);

    let call = 0;
    const random = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((array) => {
      const bytes = fromHex(
        call++ === 0
          ? constantsFixture.inputs.recordedBlindingBytes
          : constantsFixture.inputs.recordedSaltBytes,
      );
      (array as Uint8Array).set(bytes);
      return array;
    });
    try {
      expectHex(randomBlinding(), libFixture.inputs.recordedRandomBlindingBytes);
      expectHex(randomSalt(), libFixture.inputs.recordedRandomSaltBytes);
    } finally {
      random.mockRestore();
    }
    expect(libFixture.inputs.recordedRandomBlindingBytes).toBe(
      constantsFixture.inputs.recordedBlindingBytes,
    );
    expect(libFixture.inputs.recordedRandomSaltBytes).toBe(
      constantsFixture.inputs.recordedSaltBytes,
    );
    expect(libFixture.expected.randomBlindingLength).toBe(expected.blindingLength);
    expect(libFixture.expected.randomSaltLength).toBe(expected.saltLength);
    expect(libFixture.expected.signatureTypes).toEqual(["p256", "ed25519"]);
  });

  it("matches P256 and Ed25519 parsing, hashes, fields, and signatures", () => {
    const parsedP256 = SigningKey.fromBytes(
      asBytes32(pubkeyFixture.inputs.p256SecretBytes),
    ).publicKey();
    expectHex(parsedP256.toBytes(), pubkeyFixture.expected.p256Bytes);
    expectHex(
      parsedP256.confidentialViewTag(),
      pubkeyFixture.expected.p256ConfidentialViewTagBytes,
    );
    expectHex(parsedP256.p256().x(), pubkeyFixture.expected.p256XBytes);
    expect(parsedP256.p256().yIsOdd()).toBe(pubkeyFixture.expected.p256YIsOdd);
    expectHex(
      ShieldedPublicKey.fromBytes(fromHex(pubkeyFixture.expected.p256Bytes) as Bytes33).toBytes(),
      pubkeyFixture.expected.p256RoundTripBytes,
    );

    const parsedEd25519 = SigningKey.fromEd25519Bytes(
      asBytes32(pubkeyFixture.inputs.ed25519SecretBytes),
    ).publicKey();
    expectHex(parsedEd25519.toBytes(), pubkeyFixture.expected.ed25519Bytes);
    expectHex(
      parsedEd25519.confidentialViewTag(),
      pubkeyFixture.expected.ed25519ConfidentialViewTagBytes,
    );
    expectHex(
      ShieldedPublicKey.fromBytes(
        fromHex(pubkeyFixture.expected.ed25519Bytes) as Bytes33,
      ).toBytes(),
      pubkeyFixture.expected.ed25519RoundTripBytes,
    );

    const p256 = SigningKey.fromBytes(asBytes32(signingFixture.inputs.p256SecretBytes));
    const p256Public = p256.publicKey();
    expectHex(p256Public.toBytes(), signingFixture.expected.p256.publicKeyBytes);
    expect(p256Public.signatureType()).toBe(signingFixture.expected.p256.signatureType);
    expectHex(p256Public.hash(), hashFixture.expected.p256PublicHashBytes);
    expectHex(p256Public.ownerPublicKeyField(), hashFixture.expected.p256OwnerFieldBytes);
    const p256Message = fromHex(signingFixture.inputs.p256MessageDigestBytes);
    const p256Signature = p256.sign(p256Message);
    expectHex(p256Signature, signingFixture.expected.p256.signatureBytes);
    expect(p256Signature).toHaveLength(Number(libFixture.expected.p256SignatureLength));
    expect(p256.verify(p256Message, p256Signature)).toBe(signingFixture.expected.p256.verified);

    const ed25519 = SigningKey.fromEd25519Bytes(
      asBytes32(signingFixture.inputs.ed25519SecretBytes),
    );
    const ed25519Public = ed25519.publicKey();
    expectHex(ed25519Public.toBytes(), signingFixture.expected.ed25519.publicKeyBytes);
    expect(ed25519Public.signatureType()).toBe(signingFixture.expected.ed25519.signatureType);
    expectHex(
      ed25519Public.confidentialViewTag(),
      signingFixture.expected.ed25519.confidentialViewTagBytes,
    );
    expectHex(ed25519Public.hash(), hashFixture.expected.ed25519PublicHashBytes);
    expectHex(ed25519Public.ownerPublicKeyField(), hashFixture.expected.ed25519OwnerFieldBytes);
    const ed25519Message = fromHex(signingFixture.inputs.ed25519MessageBytes);
    const ed25519Signature = ed25519.sign(ed25519Message);
    expectHex(ed25519Signature, signingFixture.expected.ed25519.signatureBytes);
    expect(ed25519Signature).toHaveLength(Number(libFixture.expected.ed25519SignatureLength));
    expect(ed25519.verify(ed25519Message, ed25519Signature)).toBe(
      signingFixture.expected.ed25519.verified,
    );
  });

  it("matches hash and field encoding operations", () => {
    const preimage = fromHex(hashFixture.inputs.preimageBytes);
    const digest = sha256Bytes(preimage);
    expectHex(digest, hashFixture.expected.sha256Bytes);
    expectHex(sha256Be(preimage), hashFixture.expected.sha256BeBytes);
    const [low, high] = splitBigEndian128(digest);
    expectHex(low, hashFixture.expected.splitLowBytes);
    expectHex(high, hashFixture.expected.splitHighBytes);
    expectHex(
      hashField(asBytes32(pubkeyFixture.expected.p256ConfidentialViewTagBytes)),
      hashFixture.expected.p256OwnerFieldBytes,
    );
  });

  it("matches nullifier derivation and binding", () => {
    const direct = NullifierKey.fromSecret(asBytes31(nullifierFixture.inputs.secretBytes));
    expectHex(direct.publicKey(), nullifierFixture.expected.publicKeyBytes);
    expectHex(
      direct.nullifier(
        asBytes32(nullifierFixture.inputs.utxoHashBytes),
        asBytes31(nullifierFixture.inputs.blindingBytes),
      ),
      nullifierFixture.expected.nullifierBytes,
    );
    const signing = SigningKey.fromBytes(asBytes32(nullifierFixture.inputs.signingSecretBytes));
    expectHex(
      NullifierKey.fromSigningKey(signing).publicKey(),
      nullifierFixture.expected.derivedFromSigningPublicKeyBytes,
    );
  });

  it("matches ECDH, HKDF, AES slot bytes, decrypt paths, and slot separation", () => {
    const ephemeral = ViewingKey.fromBytes(
      asBytes32(encryptionFixture.inputs.ephemeralSecretBytes),
    );
    const recipient = ViewingKey.fromBytes(
      asBytes32(encryptionFixture.inputs.recipientSecretBytes),
    );
    const recipientPublic = asP256(encryptionFixture.inputs.recipientPublicKeyBytes);
    const plaintext = fromHex(encryptionFixture.inputs.plaintextBytes);
    const salt = fromHex(encryptionFixture.inputs.saltBytes) as Bytes16;
    const slot = Number(encryptionFixture.inputs.slotIndex);
    const ciphertext = ephemeral.encryptSlot(recipientPublic, plaintext, salt, slot);
    expectHex(ciphertext, encryptionFixture.expected.ciphertextBytes);
    expectHex(
      recipient.decryptUtxo(ciphertext, ephemeral.publicKey(), salt, slot),
      encryptionFixture.expected.recipientRecoveredBytes,
    );
    expectHex(
      ephemeral.decryptSlotEphemeral(recipientPublic, ciphertext, salt, slot),
      encryptionFixture.expected.ephemeralRecoveredBytes,
    );
    expectHex(
      recipient.decryptUtxo(ciphertext, ephemeral.publicKey(), salt, slot + 1),
      encryptionFixture.expected.wrongSlotRecoveredBytes,
    );
  });

  it("matches every viewing derivation and direction", () => {
    const input = viewingFixture.inputs;
    const expected = viewingFixture.expected;
    const viewing = ViewingKey.fromBytes(asBytes32(input.viewingSecretBytes));
    const counterparty = ViewingKey.fromBytes(asBytes32(input.counterpartySecretBytes));
    const index = BigInt(input.tagIndex);
    expectHex(viewing.publicKey().toBytes(), expected.publicKeyBytes);
    expectHex(viewing.ecdh(counterparty.publicKey()), expected.ecdhSharedBytes);
    expectHex(viewing.recipientBootstrapViewTag(), expected.bootstrapTagBytes);
    expectHex(viewing.senderViewTag(index), expected.senderTagBytes);
    expectHex(viewing.recipientRequestViewTag(index), expected.recipientRequestTagBytes);
    expectHex(viewing.mergeViewTag(index), expected.mergeTagBytes);
    expectHex(
      viewing.sendSharedViewTag(counterparty.publicKey(), index),
      expected.sendSharedTagBytes,
    );
    expect(viewing.sendSharedViewTag(counterparty.publicKey(), index)).toEqual(
      counterparty.recipientSharedViewTag(viewing.publicKey(), index),
    );

    const shared = viewing.ecdh(asP256(constantsFixture.expected.pConstBytes));
    const root = extract(sha256, shared);
    expectHex(
      expand(sha256, root, new TextEncoder().encode(INFO_SENDER_VIEW_TAG_SECRET), 32),
      expected.senderTagRootBytes,
    );
    expectHex(
      expand(sha256, root, new TextEncoder().encode(INFO_RECIPIENT_VIEW_TAG_SECRET), 32),
      expected.recipientTagRootBytes,
    );
    expectHex(
      expand(sha256, root, new TextEncoder().encode(INFO_MERGE_VIEW_TAG_SECRET), 32),
      expected.mergeTagRootBytes,
    );
    expectHex(
      expand(sha256, root, new TextEncoder().encode(INFO_TX_VIEWING), 32),
      expected.txViewingTagRootBytes,
    );

    const seeded = ViewingKey.fromSeed(asBytes32(input.seedBytes), Number(input.seedAccount));
    expectHex(seeded.secretBytes(), expected.seededSecretBytes);
    expectHex(seeded.publicKey().toBytes(), expected.seededPublicKeyBytes);
    const transaction = viewing.transactionViewingKey(asBytes32(input.firstNullifierBytes));
    expectHex(transaction.secretBytes(), expected.transactionViewingSecretBytes);
    expectHex(transaction.publicKey().toBytes(), expected.transactionViewingPublicKeyBytes);
  });

  it("matches both shielded address rails and compressed address hashes", () => {
    const input = shieldedFixture.inputs;
    const signing = SigningKey.fromBytes(asBytes32(input.p256SigningSecretBytes));
    const p256 = ShieldedKeypair.fromKeys(
      signing,
      NullifierKey.fromSigningKey(signing),
      ViewingKey.fromBytes(asBytes32(input.p256ViewingSecretBytes)),
    );
    const ed25519 = ShieldedKeypair.fromEd25519(
      asBytes32(input.ed25519SecretBytes),
      Number(input.ed25519ViewingAccount),
    );

    for (const [keypair, expected] of [
      [p256, shieldedFixture.expected.p256],
      [ed25519, shieldedFixture.expected.ed25519],
    ] as const) {
      const address = keypair.shieldedAddress();
      expectHex(address.signingPublicKey.toBytes(), expected.signingPublicKeyBytes);
      expectHex(address.nullifierPublicKey, expected.nullifierPublicKeyBytes);
      expectHex(address.viewingPublicKey.toBytes(), expected.viewingPublicKeyBytes);
      expectHex(address.ownerHash(), expected.ownerHashBytes);
      expectHex(address.confidentialViewTag(), expected.confidentialViewTagBytes);
      const compressed = keypair.compressedAddress().bytes;
      expectHex(compressed.subarray(0, 32), expected.compressedOwnerHashBytes);
      expectHex(compressed.subarray(32), expected.compressedViewingPublicKeyBytes);
      expectHex(compressedAddressHash(compressed), expected.compressedAddressHashBytes);
      if (expected.solanaAddress === null) {
        expectMappedError(() => address.solanaAddress(), errorFixture.expected.notEd25519);
      } else {
        expect(address.solanaAddress()).toBe(expected.solanaAddress);
      }
    }
  });

  it("matches merge ciphertext, recovery, contribution, hash, and tamper evidence", () => {
    const input = mergeFixture.inputs;
    const expected = mergeFixture.expected;
    const plaintext = fromHex(input.plaintextBytes);
    const encrypted = encryptVerifiable(
      asBytes32(input.txViewingSecretBytes),
      asP256(input.userViewingPublicKeyBytes),
      plaintext,
    );
    expectHex(encrypted.ciphertext, expected.ciphertextBytes);
    expectHex(encrypted.txViewingPublicKey.toBytes(), expected.txViewingPublicKeyBytes);
    expectHex(
      decryptVerifiable(
        asBytes32(input.userViewingSecretBytes),
        encrypted.txViewingPublicKey,
        encrypted.ciphertext,
      ),
      expected.recoveredBytes,
    );
    expectHex(mergeCiphertextHash(encrypted.ciphertext), expected.ciphertextHashBytes);
    const contribution = mergePublicContribution(
      encrypted.txViewingPublicKey,
      encrypted.ciphertext,
    );
    expectHex(contribution.txViewingPublicKeyLow, expected.txViewingPublicKeyLowBytes);
    expectHex(contribution.txViewingPublicKeyHigh, expected.txViewingPublicKeyHighBytes);
    expectHex(contribution.ciphertextHash, expected.ciphertextHashBytes);
    const tampered = new Uint8Array(encrypted.ciphertext);
    tampered[0] ^= 1;
    expectHex(mergeCiphertextHash(tampered), expected.tamperedCiphertextHashBytes);
  });

  it("matches malformed key, rail, padding, and tampered-signature evidence", () => {
    const input = errorFixture.inputs;
    const expected = errorFixture.expected;
    expectMappedError(
      () => P256PublicKey.fromBytes(fromHex(input.invalidP256Bytes) as Bytes33),
      expected.invalidP256Point,
    );
    expectMappedError(
      () => SigningKey.fromBytes(asBytes32(input.invalidSecretBytes)),
      expected.invalidSecretScalar,
    );
    const invalidPrefix = new Uint8Array(SHIELDED_PUBLIC_KEY_LENGTH);
    invalidPrefix[0] = Number(input.invalidSignaturePrefix);
    expectMappedError(
      () => ShieldedPublicKey.fromBytes(invalidPrefix as Bytes33),
      expected.invalidSignaturePrefix,
    );
    const invalidPadding = fromHex(pubkeyFixture.expected.ed25519Bytes);
    invalidPadding[invalidPadding.length - 1] = 1;
    expectMappedError(
      () => ShieldedPublicKey.fromBytes(invalidPadding as Bytes33),
      expected.invalidEd25519Padding,
    );
    expectMappedError(
      () =>
        ShieldedPublicKey.fromBytes(fromHex(pubkeyFixture.expected.p256Bytes) as Bytes33).ed25519(),
      expected.wrongRail,
    );

    const p256 = SigningKey.fromBytes(asBytes32(signingFixture.inputs.p256SecretBytes));
    const p256Signature = fromHex(signingFixture.expected.p256.signatureBytes) as Bytes64;
    p256Signature[0] ^= 1;
    expect(p256.verify(fromHex(signingFixture.inputs.p256MessageDigestBytes), p256Signature)).toBe(
      expected.tamperedP256SignatureValid,
    );
    const ed25519 = SigningKey.fromEd25519Bytes(
      asBytes32(signingFixture.inputs.ed25519SecretBytes),
    );
    const ed25519Signature = fromHex(signingFixture.expected.ed25519.signatureBytes) as Bytes64;
    ed25519Signature[0] ^= 1;
    expect(ed25519.verify(new Uint8Array(), ed25519Signature)).toBe(
      expected.tamperedEd25519SignatureValid,
    );
  });

  it("reproduces the self-verified production behavior fixture", () => {
    const expected = testsFixture.expected;
    const p256 = SigningKey.fromBytes(asBytes32(signingFixture.inputs.p256SecretBytes));
    const p256Message = fromHex(signingFixture.inputs.p256MessageDigestBytes);
    expect(p256.verify(p256Message, p256.sign(p256Message))).toBe(expected.p256RoundTripVerified);
    const ed25519 = SigningKey.fromEd25519Bytes(
      asBytes32(signingFixture.inputs.ed25519SecretBytes),
    );
    expect(ed25519.verify(new Uint8Array(), ed25519.sign(new Uint8Array()))).toBe(
      expected.ed25519RoundTripVerified,
    );
    const sender = ViewingKey.fromBytes(asBytes32(viewingFixture.inputs.viewingSecretBytes));
    const recipient = ViewingKey.fromBytes(
      asBytes32(viewingFixture.inputs.counterpartySecretBytes),
    );
    const index = BigInt(viewingFixture.inputs.tagIndex);
    const tagsAgree =
      toHex(sender.sendSharedViewTag(recipient.publicKey(), index)) ===
        toHex(recipient.recipientSharedViewTag(sender.publicKey(), index)) &&
      toHex(sender.senderViewTag(index)) === viewingFixture.expected.senderTagBytes &&
      toHex(sender.recipientRequestViewTag(index)) ===
        viewingFixture.expected.recipientRequestTagBytes &&
      toHex(sender.mergeViewTag(index)) === viewingFixture.expected.mergeTagBytes;
    expect(tagsAgree).toBe(expected.allTagDirectionsAgree);

    const slotSalt = fromHex(encryptionFixture.inputs.saltBytes) as Bytes16;
    const slotPlaintext = fromHex(encryptionFixture.inputs.plaintextBytes);
    const slotCiphertext = sender.encryptSlot(
      recipient.publicKey(),
      slotPlaintext,
      slotSalt,
      Number(encryptionFixture.inputs.slotIndex),
    );
    expect(
      recipient.decryptUtxo(
        slotCiphertext,
        sender.publicKey(),
        slotSalt,
        Number(encryptionFixture.inputs.slotIndex),
      ),
    ).toEqual(expected.slotRoundTripVerified ? slotPlaintext : new Uint8Array());

    const merge = encryptVerifiable(
      asBytes32(mergeFixture.inputs.txViewingSecretBytes),
      asP256(mergeFixture.inputs.userViewingPublicKeyBytes),
      fromHex(mergeFixture.inputs.plaintextBytes),
    );
    const mergeRecovered = decryptVerifiable(
      asBytes32(mergeFixture.inputs.userViewingSecretBytes),
      merge.txViewingPublicKey,
      merge.ciphertext,
    );
    expect(toHex(mergeRecovered) === mergeFixture.inputs.plaintextBytes).toBe(
      expected.mergeRoundTripVerified,
    );
  });
});
