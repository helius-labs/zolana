import { ed25519 } from "@noble/curves/ed25519.js";
import { p256, p256_hasher } from "@noble/curves/nist.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import {
  DERIVATION_PAYLOAD_PREFIX,
  DST_DERIVE_P_DERIVE,
  DST_PDA_ROOT_P_PDA,
  DST_VIEW_ROOT_P_CONST,
  ED25519_DERIVATION_MSG,
  INFO_NF_KEY_ECDH,
  INFO_NF_KEY_ED25519,
  INFO_PDA_NF_KEY,
  INFO_PDA_VIEW_KEY,
  INFO_VIEW_KEY_ECDH,
  INFO_VIEW_KEY_ED25519,
  OFFCHAIN_MESSAGE_MAGIC,
  P_CONST_SEC1,
  P_DERIVE_SEC1,
  P_PDA_SEC1,
  P256PublicKey,
  ShieldedKeypair,
  SigningKey,
  TSPP_APPLICATION_DOMAIN,
  ViewingKey,
  ed25519DerivationMessage,
  isDerivationInput,
  type Bytes32,
} from "../src/keypair/index.js";

const encoder = new TextEncoder();
const P256_ORDER =
  115_792_089_210_356_248_762_697_446_949_407_573_529_996_955_224_135_760_342_422_259_061_068_512_044_369n;

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function scalarFromOkm(okm: Uint8Array): Bytes32 {
  let scalar = 0n;
  for (const byte of okm) scalar = (scalar << 8n) | BigInt(byte);
  scalar %= P256_ORDER;
  const bytes = new Uint8Array(32);
  for (let index = 31; index >= 0; index--) {
    bytes[index] = Number(scalar & 0xffn);
    scalar >>= 8n;
  }
  return bytes as Bytes32;
}

function expandRoles(
  seed: Uint8Array,
  nullifierInfo: string,
  viewingInfo: string,
): Readonly<{ nullifier: Uint8Array; viewing: Bytes32 }> {
  const prk = extract(sha256, seed);
  return {
    nullifier: expand(sha256, prk, encoder.encode(nullifierInfo), 31),
    viewing: scalarFromOkm(expand(sha256, prk, encoder.encode(viewingInfo), 48)),
  };
}

function offchainV0(payload: Uint8Array): Uint8Array {
  return Uint8Array.of(
    ...OFFCHAIN_MESSAGE_MAGIC,
    0,
    ...TSPP_APPLICATION_DOMAIN,
    0,
    1,
    ...new Uint8Array(32).fill(7),
    payload.length & 0xff,
    payload.length >> 8,
    ...payload,
  );
}

describe("key derivation registry", () => {
  it("keeps HKDF tags pairwise distinct", () => {
    const tags = [
      DST_VIEW_ROOT_P_CONST,
      DST_DERIVE_P_DERIVE,
      DST_PDA_ROOT_P_PDA,
      ED25519_DERIVATION_MSG,
      DERIVATION_PAYLOAD_PREFIX,
      INFO_NF_KEY_ED25519,
      INFO_NF_KEY_ECDH,
      INFO_VIEW_KEY_ED25519,
      INFO_VIEW_KEY_ECDH,
      INFO_PDA_NF_KEY,
      INFO_PDA_VIEW_KEY,
    ];
    expect(new Set(tags).size).toBe(tags.length);
  });

  it("pins the application domain to the derivation payload hash", () => {
    expect(TSPP_APPLICATION_DOMAIN).toEqual(sha256(encoder.encode(ED25519_DERIVATION_MSG)));
  });

  it("matches the Rust off-chain message golden vector", () => {
    const message = ed25519DerivationMessage(new Uint8Array(32).fill(7) as Bytes32);
    expect(message).toHaveLength(99);
    expect(hex(message)).toBe(
      "ff736f6c616e61206f6666636861696e" +
        "00" +
        "1d32a88533af12d35e5ac6fce817a4cb810bcc4115386b14a78e8b2ef09d864c" +
        "00" +
        "01" +
        "0707070707070707070707070707070707070707070707070707070707070707" +
        "0e00" +
        "545350502f6465726976652f7631",
    );
  });

  it("detects bare and wrapped derivation payloads", () => {
    expect(isDerivationInput(encoder.encode(ED25519_DERIVATION_MSG))).toBe(true);
    expect(isDerivationInput(encoder.encode(DERIVATION_PAYLOAD_PREFIX))).toBe(true);
    expect(
      isDerivationInput(
        encoder.encode("TSPP/derive/pda/v1/9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"),
      ),
    ).toBe(true);
    expect(isDerivationInput(ed25519DerivationMessage(new Uint8Array(32).fill(7) as Bytes32))).toBe(
      true,
    );
    expect(isDerivationInput(offchainV0(encoder.encode("TSPP/derive/pda/v1/x")))).toBe(true);

    expect(isDerivationInput(encoder.encode("TSPP/derive"))).toBe(false);
    expect(isDerivationInput(encoder.encode("private_tx_hash"))).toBe(false);
    expect(isDerivationInput(encoder.encode(INFO_NF_KEY_ED25519))).toBe(false);
    expect(isDerivationInput(offchainV0(encoder.encode("hello")))).toBe(false);

    const truncated = ed25519DerivationMessage(new Uint8Array(32).fill(7) as Bytes32).slice(0, -1);
    expect(isDerivationInput(truncated)).toBe(false);
  });

  it("pins both committed derivation points", () => {
    const derive = p256_hasher.hashToCurve(new Uint8Array(), {
      DST: encoder.encode(DST_DERIVE_P_DERIVE),
    });
    const pda = p256_hasher.hashToCurve(new Uint8Array(), {
      DST: encoder.encode(DST_PDA_ROOT_P_PDA),
    });
    expect(derive.toBytes(true)).toEqual(P_DERIVE_SEC1);
    expect(pda.toBytes(true)).toEqual(P_PDA_SEC1);
    expect(P_DERIVE_SEC1).not.toEqual(P_CONST_SEC1);
    expect(P_PDA_SEC1).not.toEqual(P_CONST_SEC1);
    expect(P_PDA_SEC1).not.toEqual(P_DERIVE_SEC1);
  });
});

describe("role expansion", () => {
  it("matches an independent Ed25519 derivation", () => {
    const secret = new Uint8Array(32).fill(11) as Bytes32;
    const publicKey = ed25519.getPublicKey(secret) as Bytes32;
    const seed = ed25519.sign(ed25519DerivationMessage(publicKey), secret);
    const expected = expandRoles(seed, INFO_NF_KEY_ED25519, INFO_VIEW_KEY_ED25519);
    const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(secret));

    expect(keypair.nullifierKey().secretBytes()).toEqual(expected.nullifier);
    expect(keypair.viewingKey().secretBytes()).toEqual(expected.viewing);
  });

  it("matches an independent P256 ECDH derivation", () => {
    const secret = new Uint8Array(32) as Bytes32;
    secret[31] = 9;
    const seed = p256.getSharedSecret(secret, P_DERIVE_SEC1, true).subarray(1, 33);
    const expected = expandRoles(seed, INFO_NF_KEY_ECDH, INFO_VIEW_KEY_ECDH);
    const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromP256Bytes(secret));

    expect(keypair.nullifierKey().secretBytes()).toEqual(expected.nullifier);
    expect(keypair.viewingKey().secretBytes()).toEqual(expected.viewing);
  });

  it("is deterministic and separates the signing rails", () => {
    const secret = new Uint8Array(32) as Bytes32;
    secret[31] = 3;
    const first = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(secret));
    const second = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(secret));
    const p256Keypair = ShieldedKeypair.fromKeypair(SigningKey.fromP256Bytes(secret));

    expect(first.signingPublicKey().toBytes()).toEqual(second.signingPublicKey().toBytes());
    expect(first.nullifierPublicKey()).toEqual(second.nullifierPublicKey());
    expect(first.viewingPublicKey().toBytes()).toEqual(second.viewingPublicKey().toBytes());
    expect(first.nullifierPublicKey()).not.toEqual(p256Keypair.nullifierPublicKey());
    expect(first.viewingPublicKey().toBytes()).not.toEqual(
      p256Keypair.viewingPublicKey().toBytes(),
    );
  });

  it("keeps a supplied viewing key while deriving the nullifier key", () => {
    const secret = new Uint8Array(32).fill(5) as Bytes32;
    const signing = SigningKey.fromEd25519Bytes(secret);
    const viewing = ViewingKey.fromSeed(new Uint8Array(32).fill(6) as Bytes32, 4);
    const detached = ShieldedKeypair.fromParts(signing, viewing);
    const rooted = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(secret));

    expect(detached.viewingPublicKey().toBytes()).toEqual(viewing.publicKey().toBytes());
    expect(detached.nullifierPublicKey()).toEqual(rooted.nullifierPublicKey());
    expect(detached.viewingPublicKey().toBytes()).not.toEqual(rooted.viewingPublicKey().toBytes());
  });
});

describe("derivation input guards", () => {
  const payload = encoder.encode(ED25519_DERIVATION_MSG);

  it("refuses derivation payloads through signing APIs", () => {
    const signing = SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(8) as Bytes32);
    expect(() => signing.sign(payload)).toThrow(
      expect.objectContaining({ code: "KEYPAIR_DERIVATION_INPUT" }),
    );

    const keypair = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(8) as Bytes32),
    );
    expect(() => keypair.sign(payload)).toThrow(
      expect.objectContaining({ code: "KEYPAIR_DERIVATION_INPUT" }),
    );
    expect(() =>
      keypair
        .toSolanaSigner()
        .signTransactions([{ messageBytes: payload, signatures: {} } as never]),
    ).toThrow(expect.objectContaining({ code: "KEYPAIR_DERIVATION_INPUT" }));
  });

  it("refuses committed derivation points through generic ECDH", () => {
    const secret = new Uint8Array(32) as Bytes32;
    secret[31] = 2;
    const signing = SigningKey.fromP256Bytes(secret);
    const viewing = ViewingKey.fromBytes(secret);
    for (const bytes of [P_DERIVE_SEC1, P_PDA_SEC1]) {
      const point = P256PublicKey.fromBytes(bytes as import("../src/keypair/bytes.js").Bytes33);
      expect(() => signing.ecdh(point)).toThrow(
        expect.objectContaining({ code: "KEYPAIR_DERIVATION_INPUT" }),
      );
      expect(() => viewing.ecdh(point)).toThrow(
        expect.objectContaining({ code: "KEYPAIR_DERIVATION_INPUT" }),
      );
    }
  });
});
