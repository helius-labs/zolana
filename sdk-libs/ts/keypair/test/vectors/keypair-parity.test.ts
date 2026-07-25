import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/keypair-parity-v1.json" with { type: "json" };
import type { Bytes16, Bytes31, Bytes32, Bytes33, Bytes34, Bytes64 } from "../../src/bytes.js";
import {
  BLINDING_LENGTH,
  DST_VIEW_ROOT,
  P256_PUBLIC_KEY_LENGTH,
  P_CONST_SEC1,
  SALT_LENGTH,
  SHIELDED_PUBLIC_KEY_LENGTH,
  VIEW_TAG_LENGTH,
} from "../../src/constants.js";
import { KEYPAIR_ERROR_RUST_VARIANT, KeypairError } from "../../src/error.js";
import { hashField, ownerHash, sha256Be, sha256Bytes, splitBigEndian128 } from "../../src/hash.js";
import {
  CompressedShieldedAddress,
  NullifierKey,
  P256PublicKey,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
} from "../../src/index.js";
import {
  MAX_INFO_LENGTH,
  MERGE_INFO,
  mergeCiphertextHash,
  mergePublicContribution,
  symmetricApply,
} from "../../src/merge/index.js";
import { poseidon } from "../../src/poseidon.js";

function fromHex(value: string): Uint8Array {
  return Uint8Array.from((value.match(/../g) ?? []).map((byte) => Number.parseInt(byte, 16)));
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function expectHex(actual: Uint8Array, expected: string): void {
  expect(toHex(actual)).toBe(expected);
}

const bytes32 = (value: string) => fromHex(value) as Bytes32;
const bytes31 = (value: string) => fromHex(value) as Bytes31;
const p256Key = (value: string) => P256PublicKey.fromBytes(fromHex(value) as Bytes33);

/**
 * The code each Rust variant must surface as. A Rust variant with no entry here
 * would mean the port dropped a distinction, which is what `KEYPAIR_ERROR_RUST_VARIANT`
 * is checked against below.
 */
const RUST_VARIANT_TO_CODE: Readonly<Record<string, KeypairError["code"]>> = {
  InvalidPublicKey: "KEYPAIR_INVALID_PUBLIC_KEY",
  InvalidSecretKey: "KEYPAIR_INVALID_SECRET_KEY",
  ZeroScalar: "KEYPAIR_ZERO_SCALAR",
  InvalidSignatureType: "KEYPAIR_INVALID_SIGNATURE_TYPE",
  NotEd25519: "KEYPAIR_NOT_ED25519",
  Hkdf: "KEYPAIR_HKDF",
  Poseidon: "KEYPAIR_POSEIDON",
  FieldElementTooLong: "KEYPAIR_FIELD_ELEMENT_TOO_LONG",
  InvalidPrehashLength: "KEYPAIR_INVALID_PREHASH_LENGTH",
  InfoTooLong: "KEYPAIR_INFO_TOO_LONG",
};

function expectRustError(operation: () => unknown, recorded: { variant: string }): void {
  const expected = RUST_VARIANT_TO_CODE[recorded.variant];
  expect(expected, `no TypeScript code mirrors Rust ${recorded.variant}`).toBeDefined();
  expect(operation).toThrow(expect.objectContaining({ code: expected }));
}

describe("keypair constants against current Rust", () => {
  it("carries every Rust-public constant with the Rust value", () => {
    const expected = fixture.constants;
    expect(SHIELDED_PUBLIC_KEY_LENGTH).toBe(expected.publicKeyLen);
    expect(P256_PUBLIC_KEY_LENGTH).toBe(expected.p256PubkeyLen);
    expect(BLINDING_LENGTH).toBe(expected.blindingLen);
    expect(SALT_LENGTH).toBe(expected.saltLen);
    expect(VIEW_TAG_LENGTH).toBe(expected.viewTagLen);
    expect(DST_VIEW_ROOT).toBe(expected.dstViewRootPConst);
    expectHex(new TextEncoder().encode(DST_VIEW_ROOT), expected.dstViewRootPConstBytes);
    expectHex(P_CONST_SEC1, expected.pConstSec1Bytes);
    expectHex(MERGE_INFO, expected.mergeInfoBytes);
    expect(MAX_INFO_LENGTH).toBe(expected.maxInfoLen);
  });
});

describe("keypair errors against current Rust", () => {
  it("maps one code per Rust variant", () => {
    for (const recorded of fixture.errors.variants) {
      expect(RUST_VARIANT_TO_CODE[recorded.variant]).toBeDefined();
    }
    const mapped = new Set(Object.values(KEYPAIR_ERROR_RUST_VARIANT).filter(Boolean));
    for (const recorded of fixture.errors.variants) {
      expect(mapped).toContain(recorded.variant);
    }
    // The only codes without a Rust variant are the two shape guards Rust
    // enforces in its type system instead.
    const typeScriptOnly = Object.entries(KEYPAIR_ERROR_RUST_VARIANT)
      .filter(([, variant]) => variant === null)
      .map(([code]) => code);
    expect(typeScriptOnly.sort()).toEqual(["KEYPAIR_HASH", "KEYPAIR_INVALID_LENGTH"]);
  });

  it("refuses the malformed public keys Rust refuses, with the same distinction", () => {
    expectRustError(
      () => ShieldedPublicKey.fromBytes(fromHex(fixture.errors.badPrefixBytes) as Bytes34),
      fixture.errors.badPrefixError,
    );
    expectRustError(
      () => ShieldedPublicKey.fromBytes(fromHex(fixture.errors.badPaddingBytes) as Bytes34),
      fixture.errors.badPaddingError,
    );
    expectRustError(
      () => ShieldedPublicKey.fromBytes(fromHex(fixture.errors.badPointBytes) as Bytes34),
      fixture.errors.badPointError,
    );
    expectRustError(
      () =>
        ShieldedPublicKey.fromBytes(
          fromHex(fixture.pubkeys.p256.taggedBytes) as Bytes34,
        ).ed25519(),
      fixture.errors.wrongRailError,
    );
  });

  it("keeps secret material out of a serialized error", () => {
    const error = new KeypairError("KEYPAIR_INVALID_SECRET_KEY", {
      reason: "destroyed",
      // A caller cannot attach anything outside the closed detail set.
      secret: new Uint8Array([1, 2, 3]),
    } as never);
    expect(error.details).toEqual({ reason: "destroyed" });
    expect(JSON.parse(JSON.stringify(error))).toEqual({
      name: "KeypairError",
      code: "KEYPAIR_INVALID_SECRET_KEY",
      details: { reason: "destroyed" },
    });
    const withCause = new KeypairError("KEYPAIR_HKDF", undefined, "secret leaked in a cause");
    expect(Object.keys(withCause)).not.toContain("cause");
    expect(JSON.stringify(withCause)).not.toContain("secret leaked");
    expect(withCause.cause).toBe("secret leaked in a cause");
    expect(withCause.rustVariant).toBe("Hkdf");
  });
});

describe("signing keys against current Rust", () => {
  const p256 = fixture.signing.p256;
  const ed = fixture.signing.ed25519;

  it("derives the Rust P256 public key, signature, and rail", () => {
    const key = SigningKey.fromBytes(bytes32(p256.secretBytes));
    expect(key.isEd25519()).toBe(p256.isEd25519);
    expectHex(key.secretBytes(), p256.secretRoundTripBytes);
    expectHex(key.publicKey().toBytes(), p256.publicKeyBytes);
    expect(key.publicKey().toBytes()).toHaveLength(SHIELDED_PUBLIC_KEY_LENGTH);
    const message = fromHex(p256.messageBytes);
    expectHex(key.sign(message), p256.signatureBytes);
    expect(key.verify(message, fromHex(p256.signatureBytes) as Bytes64)).toBe(p256.verified);
    expect(key.verify(fromHex(ed.messageBytes), fromHex(p256.signatureBytes) as Bytes64)).toBe(
      p256.wrongMessageVerified,
    );
  });

  // G2-1: the circuit range-checks `s` against the curve order alone, so the
  // high-`s` twin of a valid signature is valid. Rust accepts it; a `lowS: true`
  // TypeScript verifier would reject a signature the protocol accepts.
  it("accepts the high-s twin exactly as Rust does", () => {
    const key = SigningKey.fromBytes(bytes32(p256.secretBytes));
    const message = fromHex(p256.messageBytes);
    const signature = fromHex(p256.signatureBytes) as Bytes64;
    const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    let s = 0n;
    for (const byte of signature.subarray(32)) s = (s << 8n) | BigInt(byte);
    const twin = new Uint8Array(signature);
    let negated = order - s;
    for (let index = 63; index >= 32; index -= 1) {
      twin[index] = Number(negated & 0xffn);
      negated >>= 8n;
    }
    expect(key.verify(message, twin as Bytes64)).toBe(p256.negatedSVerified);
  });

  it("refuses every P256 prehash length Rust refuses", () => {
    const key = SigningKey.fromBytes(bytes32(p256.secretBytes));
    expectRustError(() => key.sign(new Uint8Array(31)), p256.shortPrehashError);
    expectRustError(() => key.sign(new Uint8Array(33)), p256.longPrehashError);
    expectRustError(() => key.sign(new Uint8Array()), p256.emptyPrehashError);
  });

  it("derives the Rust Ed25519 public key and signature", () => {
    const key = SigningKey.fromEd25519Bytes(bytes32(ed.secretBytes));
    expect(key.isEd25519()).toBe(ed.isEd25519);
    expectHex(key.secretBytes(), ed.secretRoundTripBytes);
    expectHex(key.publicKey().toBytes(), ed.publicKeyBytes);
    const message = fromHex(ed.messageBytes);
    expectHex(key.sign(message), ed.signatureBytes);
    expect(key.verify(message, fromHex(ed.signatureBytes) as Bytes64)).toBe(ed.verified);
    expectHex(key.sign(new Uint8Array()), ed.emptyMessageSignatureBytes);
    expect(key.verify(new Uint8Array(), fromHex(ed.emptyMessageSignatureBytes) as Bytes64)).toBe(
      ed.emptyMessageVerified,
    );
    expect(key.verify(fromHex(p256.messageBytes), fromHex(ed.signatureBytes) as Bytes64)).toBe(
      ed.wrongMessageVerified,
    );
  });

  it("refuses the out-of-range secret Rust refuses", () => {
    expectRustError(
      () => SigningKey.fromBytes(bytes32(fixture.signing.invalidSecretBytes)),
      fixture.signing.invalidSecretError,
    );
  });
});

describe("public keys against current Rust", () => {
  it("matches the tagged encoding, hashes, and owner field on both rails", () => {
    for (const [name, recorded] of [
      ["p256", fixture.pubkeys.p256],
      ["ed25519", fixture.pubkeys.ed25519],
    ] as const) {
      const key = ShieldedPublicKey.fromBytes(fromHex(recorded.taggedBytes) as Bytes34);
      expectHex(key.toBytes(), recorded.taggedBytes);
      expect(key.toBytes()).toHaveLength(SHIELDED_PUBLIC_KEY_LENGTH);
      expect(key.signatureType()).toBe(recorded.signatureType);
      expect(key.isZero()).toBe(recorded.isZero);
      expectHex(key.confidentialViewTag(), recorded.confidentialViewTagBytes);
      expectHex(key.hash(), recorded.hashBytes);
      expectHex(key.ownerPublicKeyField(), recorded.ownerPkFieldBytes);
      if (name === "p256") {
        const inner = key.p256();
        expectHex(inner.toBytes(), fixture.pubkeys.p256.compressedBytes);
        expectHex(inner.x(), fixture.pubkeys.p256.xBytes);
        expect(inner.yIsOdd()).toBe(fixture.pubkeys.p256.yIsOdd);
      } else {
        expectHex(key.ed25519(), fixture.pubkeys.ed25519.rawBytes);
      }
    }
  });

  it("matches the zeroed dummy owner and canonical equality", () => {
    expectHex(ShieldedPublicKey.zeroed().toBytes(), fixture.pubkeys.zeroed.taggedBytes);
    expect(ShieldedPublicKey.zeroed().isZero()).toBe(fixture.pubkeys.zeroed.isZero);

    const p256 = ShieldedPublicKey.fromBytes(fromHex(fixture.pubkeys.p256.taggedBytes) as Bytes34);
    const same = ShieldedPublicKey.fromBytes(fromHex(fixture.pubkeys.p256.taggedBytes) as Bytes34);
    const ed = ShieldedPublicKey.fromBytes(
      fromHex(fixture.pubkeys.ed25519.taggedBytes) as Bytes34,
    );
    expect(p256.equals(same)).toBe(fixture.pubkeys.equality.sameKeyEqual);
    expect(p256.equals(ed)).toBe(fixture.pubkeys.equality.crossRailEqual);
    expect(p256.p256().equals(same.p256())).toBe(true);
  });
});

describe("nullifier keys against current Rust", () => {
  const recorded = fixture.nullifierKeys;

  it("matches derivation, binding, and the blinding boundaries", () => {
    const key = NullifierKey.fromSecret(bytes31(recorded.direct.secretBytes));
    expectHex(key.publicKey(), recorded.direct.publicKeyBytes);
    const utxo = bytes32(fixture.shielded.p256.derived.nullifierBytes);
    expect(utxo).toBeDefined();
  });

  it("matches every recorded nullifier boundary", () => {
    const key = NullifierKey.fromSecret(bytes31(recorded.direct.secretBytes));
    const utxoHash = sha256Be(new TextEncoder().encode("parity/utxo"));
    expectHex(key.nullifier(utxoHash, bytes31("03".repeat(31))), recorded.direct.nullifierBytes);
    expectHex(
      key.nullifier(utxoHash, bytes31("00".repeat(31))),
      recorded.direct.zeroBlindingNullifierBytes,
    );
    expectHex(
      key.nullifier(utxoHash, bytes31("ff".repeat(31))),
      recorded.direct.maxBlindingNullifierBytes,
    );
    expectHex(
      key.nullifier(bytes32("00".repeat(32)), bytes31("03".repeat(31))),
      recorded.direct.zeroUtxoNullifierBytes,
    );
  });

  it("matches the zero and maximal secrets", () => {
    expectHex(
      NullifierKey.fromSecret(bytes31("00".repeat(31))).publicKey(),
      recorded.zeroSecret.publicKeyBytes,
    );
    expectHex(
      NullifierKey.fromSecret(bytes31("ff".repeat(31))).publicKey(),
      recorded.maxSecret.publicKeyBytes,
    );
  });

  it("accepts every input-keying-material width Rust accepts", () => {
    for (const entry of recorded.ikmLengths) {
      const key = NullifierKey.fromSigningSecret(fromHex(entry.ikmBytes));
      expectHex(key.secretBytes(), entry.secretBytes);
      expectHex(key.publicKey(), entry.publicKeyBytes);
    }
  });

  it("derives repeatably from the signing key and separates the capability", () => {
    const signing = SigningKey.fromBytes(bytes32(recorded.fromSigningKey.signingSecretBytes));
    const first = NullifierKey.fromSigningKey(signing);
    const second = NullifierKey.fromSigningKey(signing);
    expectHex(first.secretBytes(), recorded.fromSigningKey.secretBytes);
    expect(toHex(second.secretBytes())).toBe(toHex(first.secretBytes()));
    expect(recorded.fromSigningKey.repeatsIdentically).toBe(true);
    expectHex(first.publicKey(), recorded.fromSigningKey.publicKeyBytes);
    // The nullifier key never yields the signing secret it came from.
    expect(toHex(first.secretBytes())).not.toBe(recorded.fromSigningKey.signingSecretBytes);
    expect(first.secretBytes()).toHaveLength(BLINDING_LENGTH);
  });

  it("refuses a destroyed key rather than deriving from zeroed material", () => {
    const key = NullifierKey.fromSecret(bytes31(recorded.direct.secretBytes));
    key.destroy();
    expect(() => key.publicKey()).toThrow(KeypairError);
    expect(() => key.secretBytes()).toThrow(KeypairError);
  });
});

describe("hashing against current Rust", () => {
  const recorded = fixture.hashes;

  it("matches sha256, the big-endian split, and the field hash", () => {
    const preimage = fromHex(recorded.preimageBytes);
    expectHex(sha256Bytes(preimage), recorded.sha256Bytes);
    expectHex(sha256Be(preimage), recorded.sha256BeBytes);
    const [low, high] = splitBigEndian128(fromHex(recorded.sha256Bytes));
    expectHex(low, recorded.splitLowBytes);
    expectHex(high, recorded.splitHighBytes);
    expectHex(hashField(fromHex(recorded.sha256Bytes)), recorded.hashFieldBytes);
    expectHex(hashField(new Uint8Array(32)), recorded.hashFieldZeroBytes);
  });

  it("matches the owner hash", () => {
    const signing = ShieldedPublicKey.fromBytes(
      fromHex(fixture.pubkeys.p256.taggedBytes) as Bytes34,
    );
    const nullifier = NullifierKey.fromSecret(
      bytes31(fixture.nullifierKeys.direct.secretBytes),
    ).publicKey();
    expectHex(ownerHash(signing.ownerPublicKeyField(), nullifier), recorded.ownerHashBytes);
  });

  it("matches Poseidon at every arity Rust supports", () => {
    expect(recorded.poseidonArities).toHaveLength(12);
    for (const arity of recorded.poseidonArities) {
      expectHex(poseidon(arity.inputsBytes.map(fromHex)), arity.digestBytes);
    }
  });

  it("refuses the arities and non-canonical inputs Rust refuses", () => {
    expect(recorded.zeroInputsRejected).toBe(true);
    expect(recorded.tooManyInputsRejected).toBe(true);
    expect(recorded.nonCanonicalInputRejected).toBe(true);
    expect(() => poseidon([])).toThrow(expect.objectContaining({ code: "KEYPAIR_POSEIDON" }));
    expect(() => poseidon(Array.from({ length: 13 }, () => new Uint8Array(32)))).toThrow(
      expect.objectContaining({ code: "KEYPAIR_POSEIDON" }),
    );
    expect(() => poseidon([fromHex(recorded.nonCanonicalInputBytes)])).toThrow(
      expect.objectContaining({ code: "KEYPAIR_POSEIDON" }),
    );
    expect(() => poseidon([new Uint8Array(33)])).toThrow(
      expect.objectContaining({ code: "KEYPAIR_FIELD_ELEMENT_TOO_LONG" }),
    );
    const key = NullifierKey.fromSecret(bytes31(fixture.nullifierKeys.direct.secretBytes));
    expect(recorded.nonCanonicalNullifierRejected).toBe(true);
    expect(() => key.nullifier(bytes32("ff".repeat(32)), bytes31("03".repeat(31)))).toThrow(
      KeypairError,
    );
  });
});

describe("viewing keys against current Rust", () => {
  const recorded = fixture.viewingKeys;
  const key = () => ViewingKey.fromBytes(bytes32(recorded.secretBytes));
  const counterparty = () => ViewingKey.fromBytes(bytes32(recorded.counterpartySecretBytes));

  it("matches the public key, ECDH, and bootstrap tag", () => {
    expectHex(key().publicKey().toBytes(), recorded.publicKeyBytes);
    expectHex(counterparty().publicKey().toBytes(), recorded.counterpartyPublicKeyBytes);
    expectHex(key().ecdh(counterparty().publicKey()), recorded.ecdhBytes);
    expectHex(key().ecdh(p256Key(fixture.constants.pConstSec1Bytes)), recorded.ecdhWithPConstBytes);
    expectHex(key().recipientBootstrapViewTag(), recorded.bootstrapTagBytes);
  });

  it("matches every view tag at every recorded counter, including u64::MAX", () => {
    const viewing = key();
    const other = counterparty();
    for (const tags of recorded.tags) {
      const counter = BigInt(tags.counter);
      expectHex(viewing.senderViewTag(counter), tags.senderBytes);
      expectHex(viewing.recipientRequestViewTag(counter), tags.recipientRequestBytes);
      expectHex(viewing.mergeViewTag(counter), tags.mergeBytes);
      expectHex(viewing.sendSharedViewTag(other.publicKey(), counter), tags.sendSharedBytes);
      expectHex(
        viewing.recipientSharedViewTag(other.publicKey(), counter),
        tags.recipientSharedBytes,
      );
      expect(viewing.senderViewTag(counter)[0]).toBe(0);
    }
    expect(recorded.sharedTagsAgree).toBe(true);
  });

  it("refuses a counter outside the Rust u64 domain", () => {
    expect(() => key().senderViewTag(-1n)).toThrow(KeypairError);
    expect(() => key().senderViewTag(2n ** 64n)).toThrow(KeypairError);
    expect(() => key().senderViewTag(2n ** 64n - 1n)).not.toThrow();
  });

  it("matches every seeded account, including u32::MAX", () => {
    for (const entry of recorded.seeded) {
      const derived = ViewingKey.fromSeed(bytes32(recorded.seedBytes), entry.account);
      expectHex(derived.secretBytes(), entry.secretBytes);
      expectHex(derived.publicKey().toBytes(), entry.publicKeyBytes);
    }
    expect(() => ViewingKey.fromSeed(bytes32(recorded.seedBytes), 2 ** 32)).toThrow(KeypairError);
  });

  it("matches the transaction viewing key", () => {
    const derived = key().transactionViewingKey(bytes32(recorded.firstNullifierBytes));
    expectHex(derived.secretBytes(), recorded.transactionSecretBytes);
    expectHex(derived.publicKey().toBytes(), recorded.transactionPublicKeyBytes);
  });

  it("refuses the out-of-range secret Rust refuses", () => {
    expectRustError(
      () => ViewingKey.fromBytes(bytes32("00".repeat(32))),
      recorded.invalidSecretError,
    );
  });

  it("wipes its material on destroy", () => {
    const viewing = key();
    viewing.destroy();
    expect(() => viewing.secretBytes()).toThrow(KeypairError);
    expect(() => viewing.senderViewTag(0n)).toThrow(KeypairError);
  });
});

describe("slot encryption against current Rust", () => {
  const recorded = fixture.encryption;
  const sender = () => ViewingKey.fromBytes(bytes32(recorded.senderSecretBytes));
  const recipient = () => ViewingKey.fromBytes(bytes32(recorded.recipientSecretBytes));
  const salt = fromHex("5a".repeat(16)) as Bytes16;

  it("matches every plaintext length across the AES-CTR block boundary", () => {
    for (const entry of recorded.lengths) {
      const plaintext = fromHex(entry.plaintextBytes);
      const ciphertext = sender().encryptSlot(recipient().publicKey(), plaintext, salt, 3);
      expectHex(ciphertext, entry.ciphertextBytes);
      expect(ciphertext).toHaveLength(entry.length);
      expectHex(
        recipient().decryptUtxo(ciphertext, sender().publicKey(), salt, 3),
        entry.recoveredBytes,
      );
    }
  });

  it("matches every slot index, including u32::MAX", () => {
    const plaintext = fromHex(recorded.plaintextBytes);
    for (const entry of recorded.slots) {
      expectHex(
        sender().encryptSlot(recipient().publicKey(), plaintext, salt, entry.slot),
        entry.ciphertextBytes,
      );
    }
    expect(() =>
      sender().encryptSlot(recipient().publicKey(), plaintext, salt, 2 ** 32),
    ).toThrow(KeypairError);
  });

  it("matches every salt boundary", () => {
    const plaintext = fromHex(recorded.plaintextBytes);
    for (const entry of recorded.salts) {
      expectHex(
        sender().encryptSlot(
          recipient().publicKey(),
          plaintext,
          fromHex(entry.saltBytes) as Bytes16,
          3,
        ),
        entry.ciphertextBytes,
      );
    }
    expect(() =>
      sender().encryptSlot(recipient().publicKey(), plaintext, new Uint8Array(15) as Bytes16, 3),
    ).toThrow(expect.objectContaining({ code: "KEYPAIR_INVALID_LENGTH" }));
  });

  it("matches the ephemeral, wrong-slot, wrong-salt, truncation, extension, and tamper paths", () => {
    const plaintext = fromHex(recorded.plaintextBytes);
    const ciphertext = sender().encryptSlot(recipient().publicKey(), plaintext, salt, 3);
    expectHex(
      sender().decryptSlotEphemeral(recipient().publicKey(), ciphertext, salt, 3),
      recorded.ephemeralRecoveredBytes,
    );
    expectHex(
      recipient().decryptUtxo(ciphertext, sender().publicKey(), salt, 4),
      recorded.wrongSlotRecoveredBytes,
    );
    expectHex(
      recipient().decryptUtxo(ciphertext, sender().publicKey(), fromHex("5b".repeat(16)) as Bytes16, 3),
      recorded.wrongSaltRecoveredBytes,
    );
    expectHex(
      recipient().decryptUtxo(ciphertext.subarray(0, 8), sender().publicKey(), salt, 3),
      recorded.truncatedRecoveredBytes,
    );
    const extended = new Uint8Array(ciphertext.length + 16);
    extended.set(ciphertext);
    expectHex(
      recipient().decryptUtxo(extended, sender().publicKey(), salt, 3),
      recorded.extendedRecoveredBytes,
    );
    const tampered = new Uint8Array(ciphertext);
    tampered[0] ^= 0xff;
    expectHex(
      recipient().decryptUtxo(tampered, sender().publicKey(), salt, 3),
      recorded.tamperedRecoveredBytes,
    );
  });

  it("does not mutate the caller's plaintext buffer", () => {
    const plaintext = fromHex(recorded.plaintextBytes);
    const copy = new Uint8Array(plaintext);
    sender().encryptSlot(recipient().publicKey(), plaintext, salt, 3);
    expect(plaintext).toEqual(copy);
  });
});

describe("merge encryption against current Rust", () => {
  const recorded = fixture.merge;

  it("matches the ciphertext, recovery, hash, and public contribution", () => {
    const tx = ViewingKey.fromBytes(bytes32(recorded.txSecretBytes));
    const user = ViewingKey.fromBytes(bytes32(recorded.userSecretBytes));
    expectHex(user.publicKey().toBytes(), recorded.userPublicKeyBytes);
    const encrypted = tx.encryptVerifiable(user.publicKey(), fromHex(recorded.plaintextBytes));
    expectHex(encrypted.ciphertext, recorded.ciphertextBytes);
    expectHex(encrypted.txViewingPublicKey.toBytes(), recorded.txViewingPublicKeyBytes);
    expectHex(
      user.decryptVerifiable(encrypted.txViewingPublicKey, encrypted.ciphertext),
      recorded.recoveredBytes,
    );
    expectHex(mergeCiphertextHash(encrypted.ciphertext), recorded.ciphertextHashBytes);
    const contribution = mergePublicContribution(
      encrypted.txViewingPublicKey,
      encrypted.ciphertext,
    );
    expectHex(contribution.txViewingPublicKeyLow, recorded.txViewingPublicKeyLowBytes);
    expectHex(contribution.txViewingPublicKeyHigh, recorded.txViewingPublicKeyHighBytes);
    expectHex(contribution.ciphertextHash, recorded.ciphertextHashBytes);
  });

  it("matches symmetricApply at every info length Rust accepts", () => {
    const shared = bytes32(recorded.symmetricSharedSecretBytes);
    for (const entry of recorded.symmetric) {
      const info = fromHex(entry.infoBytes);
      const ciphertext = symmetricApply(shared, info, fromHex(recorded.plaintextBytes));
      expectHex(ciphertext, entry.ciphertextBytes);
      expectHex(symmetricApply(shared, info, ciphertext), entry.roundTripBytes);
      expect(toHex(symmetricApply(shared, info, ciphertext))).toBe(recorded.plaintextBytes);
    }
  });

  it("refuses the info lengths Rust refuses, with the same distinction", () => {
    const shared = bytes32(recorded.symmetricSharedSecretBytes);
    const plaintext = fromHex(recorded.plaintextBytes);
    expectRustError(
      () => symmetricApply(shared, fromHex(recorded.overlongInfoBytes), plaintext),
      recorded.overlongInfoError,
    );
    // A 48-byte label fits the packing but puts the length byte above the BN254
    // modulus, so the key schedule refuses it as a Poseidon input, exactly as
    // Rust does -- a different refusal from the 63-byte length bound.
    expectRustError(
      () => symmetricApply(shared, fromHex(recorded.fieldLimitedInfoBytes), plaintext),
      recorded.fieldLimitedInfoError,
    );
  });

  it("refuses an empty ciphertext hash the way Rust does", () => {
    expect(recorded.emptyCiphertextHashRejected).toBe(true);
    expect(() => mergeCiphertextHash(new Uint8Array())).toThrow(KeypairError);
  });
});

describe("shielded keypairs against current Rust", () => {
  it("matches the P256 rail address, owner hash, and compressed address", () => {
    const recorded = fixture.shielded.p256;
    const keypair = ShieldedKeypair.fromSigningAndViewingKeys(
      SigningKey.fromBytes(bytes32(recorded.signingSecretBytes)),
      ViewingKey.fromBytes(bytes32(recorded.viewingSecretBytes)),
    );
    const address = keypair.shieldedAddress();
    expectHex(address.signingPublicKey.toBytes(), recorded.derived.signingPublicKeyBytes);
    expectHex(address.nullifierPublicKey, recorded.derived.nullifierPublicKeyBytes);
    expectHex(address.viewingPublicKey.toBytes(), recorded.derived.viewingPublicKeyBytes);
    expectHex(keypair.ownerHash(), recorded.derived.ownerHashBytes);
    expectHex(address.ownerHash(), recorded.derived.addressOwnerHashBytes);
    expectHex(address.confidentialViewTag(), recorded.derived.confidentialViewTagBytes);

    const compressed = keypair.compressedAddress();
    expectHex(compressed.ownerHash, recorded.derived.compressedOwnerHashBytes);
    expectHex(
      compressed.viewingPublicKey.toBytes(),
      recorded.derived.compressedViewingPublicKeyBytes,
    );
    expectHex(compressed.hash(), recorded.derived.compressedHashBytes);
    expectHex(compressed.bytes.subarray(0, 32), recorded.derived.compressedOwnerHashBytes);
    expectHex(
      CompressedShieldedAddress.fromAddress(address).hash(),
      recorded.derived.compressedHashBytes,
    );
    expect(recorded.derived.solanaAddress).toBeNull();
    expect(() => address.solanaAddress()).toThrow(KeypairError);
    expect(fixture.shielded.fromKeysDerivesNullifierFromSigningSecret).toBe(true);
  });

  it("matches the Ed25519 rail address and Solana identity", () => {
    const recorded = fixture.shielded.ed25519;
    const keypair = ShieldedKeypair.fromEd25519(
      bytes32(recorded.signingSecretBytes),
      recorded.viewingAccount,
    );
    const address = keypair.shieldedAddress();
    expectHex(address.signingPublicKey.toBytes(), recorded.derived.signingPublicKeyBytes);
    expectHex(address.nullifierPublicKey, recorded.derived.nullifierPublicKeyBytes);
    expectHex(address.viewingPublicKey.toBytes(), recorded.derived.viewingPublicKeyBytes);
    expectHex(keypair.ownerHash(), recorded.derived.ownerHashBytes);
    expectHex(keypair.compressedAddress().hash(), recorded.derived.compressedHashBytes);
    expect(address.solanaAddress()).toBe(recorded.derived.solanaAddress);
    expectHex(
      keypair.nullifier(
        sha256Be(new TextEncoder().encode("parity/utxo")),
        bytes31("03".repeat(31)),
      ),
      recorded.derived.nullifierBytes,
    );
  });

  it("stands in for a viewing-key backend the way Rust's trait impl does", () => {
    const recorded = fixture.shielded.p256;
    const keypair = ShieldedKeypair.fromSigningAndViewingKeys(
      SigningKey.fromBytes(bytes32(recorded.signingSecretBytes)),
      ViewingKey.fromBytes(bytes32(recorded.viewingSecretBytes)),
    );
    const viewing = ViewingKey.fromBytes(bytes32(recorded.viewingSecretBytes));
    expect(toHex(keypair.publicKey().toBytes())).toBe(toHex(viewing.publicKey().toBytes()));
    expect(toHex(keypair.senderViewTag(7n))).toBe(toHex(viewing.senderViewTag(7n)));
    expect(toHex(keypair.mergeViewTag(7n))).toBe(toHex(viewing.mergeViewTag(7n)));
    expect(toHex(keypair.recipientBootstrapViewTag())).toBe(
      toHex(viewing.recipientBootstrapViewTag()),
    );
    expect(keypair.curve()).toBe("p256");
    expect(toHex(keypair.nullifierPublicKey())).toBe(
      toHex(keypair.shieldedAddress().nullifierPublicKey),
    );
  });
});
