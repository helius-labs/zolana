/**
 * Domain-separation registry and key-derivation primitives, mirroring
 * `sdk-libs/keypair/src/derivation.rs`: every domain-separation tag lives here
 * and every HKDF/ECDH invocation funnels through the functions below, so the
 * full derivation tree is auditable in one file. The values are pinned by
 * `test-vectors/key_derivation.json`.
 */
import { p256 } from "@noble/curves/nist.js";
import { expand, extract, hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { type Bytes31, type Bytes32, type Bytes33, bytesToBigInt } from "./bytes.js";
import { KeypairError, wrapKeypairError } from "./error.js";
import { P256PublicKey } from "./public-key.js";

const encoder = new TextEncoder();

export const DST_VIEW_ROOT_P_CONST = "TSPP/view_root/P_const/v1";

export const P_CONST_SEC1 = Uint8Array.from([
  0x03, 0x0e, 0x4d, 0xf9, 0x46, 0xbc, 0xe1, 0x4b, 0x95, 0x29, 0x2f, 0x13, 0xe1, 0x33, 0xd2, 0xb0,
  0xc6, 0x4e, 0x89, 0x8b, 0x56, 0x44, 0xf6, 0x20, 0xa5, 0xbe, 0xd2, 0x5a, 0x06, 0x1a, 0x42, 0xfc,
  0xdb,
]);

export const DST_DERIVE_P_DERIVE = "TSPP/nullifier/P_nullifier/v1";

export const P_DERIVE_SEC1 = Uint8Array.from([
  0x03, 0x9e, 0xf1, 0x65, 0x92, 0x42, 0x9d, 0xa1, 0x40, 0x3e, 0xaa, 0x29, 0x05, 0x8e, 0xb7, 0xd9,
  0xd5, 0xad, 0x15, 0xa2, 0xea, 0x55, 0x71, 0x74, 0xf7, 0xb0, 0x1f, 0xf7, 0xfe, 0x48, 0x4e, 0xee,
  0xaf,
]);

export const DST_PDA_ROOT_P_PDA = "TSPP/pda_root/P_pda/v1";

export const P_PDA_SEC1 = Uint8Array.from([
  0x03, 0x8a, 0x31, 0xd5, 0x3c, 0x5a, 0xd2, 0x0d, 0x1c, 0xd7, 0xee, 0x1f, 0xbb, 0x99, 0x27, 0xbd,
  0x0c, 0xdf, 0xb6, 0x1b, 0x1b, 0x89, 0xf6, 0xb2, 0xc5, 0xa9, 0x4a, 0x5f, 0x08, 0x1f, 0xe1, 0x6b,
  0x5b,
]);

export const INFO_NF_KEY_ED25519 = "TSPP/nf_key/ed25519/v1";

export const INFO_NF_KEY_ECDH = "TSPP/nf_key/ecdh/v1";

export const INFO_VIEW_KEY_ED25519 = "TSPP/view_key/ed25519/v1";

export const INFO_VIEW_KEY_ECDH = "TSPP/view_key/ecdh/v1";

export const INFO_SEED_P256_VIEWING = "TSPP/seed/p256_viewing";

export const INFO_TX_VIEWING = "TSPP/tx_viewing";

export const ED25519_DERIVATION_MSG = "TSPP/derive/v1";

export const DERIVATION_PAYLOAD_PREFIX = "TSPP/derive/";

export const OFFCHAIN_MESSAGE_MAGIC = Uint8Array.from([
  0xff, 0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x20, 0x6f, 0x66, 0x66, 0x63, 0x68, 0x61, 0x69, 0x6e,
]);

/** `sha256(ED25519_DERIVATION_MSG)`; pinned by a test. */
export const TSPP_APPLICATION_DOMAIN = Uint8Array.from([
  0x1d, 0x32, 0xa8, 0x85, 0x33, 0xaf, 0x12, 0xd3, 0x5e, 0x5a, 0xc6, 0xfc, 0xe8, 0x17, 0xa4, 0xcb,
  0x81, 0x0b, 0xcc, 0x41, 0x15, 0x38, 0x6b, 0x14, 0xa7, 0x8e, 0x8b, 0x2e, 0xf0, 0x9d, 0x86, 0x4c,
]);

export const HPKE_PREFIX = "TSPP/hpke/";

export const ENC_INFO_TRANSFER = "TSPP/tx";

export const MERGE_INFO = encoder.encode("TSPP/merge");

export const DOM_SEP_SILO = 0x544d_5349;
export const DOM_SEP_KEY = 0x544d_534b;
export const DOM_SEP_NONCE = 0x544d_534e;

export const DOMAIN_MERGE_OUTPUT_BLINDING_V1 = 0x544d_4f42;
export const DOMAIN_MERGE_DUMMY_NULLIFIER = 0x544d_444e;

const P256_ORDER =
  115_792_089_210_356_248_762_697_446_949_407_573_529_996_955_224_135_760_342_422_259_061_068_512_044_369n;

const DERIVATION_PAYLOAD_PREFIX_BYTES = encoder.encode(DERIVATION_PAYLOAD_PREFIX);

/**
 * Solana off-chain message v0: magic || version=0 || application_domain ||
 * format=0 (restricted ASCII) || signer_count=1 || signer || len u16 LE ||
 * payload. This is the exact byte string the ed25519 rail signs.
 */
export function ed25519DerivationMessage(signerPublicKey: Bytes32): Uint8Array {
  const payload = encoder.encode(ED25519_DERIVATION_MSG);
  const message = new Uint8Array(85 + payload.length);
  message.set(OFFCHAIN_MESSAGE_MAGIC, 0);
  message[16] = 0;
  message.set(TSPP_APPLICATION_DOMAIN, 17);
  message[49] = 0;
  message[50] = 1;
  message.set(signerPublicKey, 51);
  message[83] = payload.length & 0xff;
  message[84] = payload.length >> 8;
  message.set(payload, 85);
  return message;
}

function startsWith(message: Uint8Array, prefix: Uint8Array): boolean {
  if (message.length < prefix.length) return false;
  return prefix.every((byte, index) => message[index] === byte);
}

function offchainV0Payload(message: Uint8Array): Uint8Array | undefined {
  if (!startsWith(message, OFFCHAIN_MESSAGE_MAGIC)) return undefined;
  const rest = message.subarray(OFFCHAIN_MESSAGE_MAGIC.length);
  if (rest[0] !== 0) return undefined;
  const afterDomain = rest.subarray(1 + 32);
  const signerCount = afterDomain[1];
  if (signerCount === undefined) return undefined;
  const afterSigners = afterDomain.subarray(2 + 32 * signerCount);
  const lengthLow = afterSigners[0];
  const lengthHigh = afterSigners[1];
  if (lengthLow === undefined || lengthHigh === undefined) return undefined;
  const declared = lengthLow | (lengthHigh << 8);
  const payload = afterSigners.subarray(2);
  return payload.length === declared ? payload : undefined;
}

/**
 * True when signing `message` would produce a derivation seed: the payload,
 * bare or off-chain encoded, begins with `DERIVATION_PAYLOAD_PREFIX`.
 */
export function isDerivationInput(message: Uint8Array): boolean {
  if (startsWith(message, DERIVATION_PAYLOAD_PREFIX_BYTES)) return true;
  const payload = offchainV0Payload(message);
  return payload !== undefined && startsWith(payload, DERIVATION_PAYLOAD_PREFIX_BYTES);
}

/**
 * Committed points whose shared secret is a derivation root; the guarded ecdh
 * entry points refuse all three, because `ECDH(viewing_sk, P_const)` is the
 * IKM `viewRoot` extracts from.
 */
export function isDerivationPoint(publicKey: P256PublicKey): boolean {
  const bytes = publicKey.toBytes();
  return (
    startsWith(bytes, P_CONST_SEC1) ||
    startsWith(bytes, P_DERIVE_SEC1) ||
    startsWith(bytes, P_PDA_SEC1)
  );
}

export function ecdhX(secret: Uint8Array, counterparty: P256PublicKey): Uint8Array {
  try {
    return p256.getSharedSecret(secret, counterparty.toBytes(), true).subarray(1, 33);
  } catch (error) {
    throw wrapKeypairError("KEYPAIR_INVALID_PUBLIC_KEY", error);
  }
}

export function pDerive(): P256PublicKey {
  return P256PublicKey.fromBytes(P_DERIVE_SEC1 as Bytes33);
}

export function hkdfExtract(ikm: Uint8Array): Uint8Array {
  return extract(sha256, ikm);
}

export function hkdfExpandPrk(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  try {
    return expand(sha256, prk, info, length);
  } catch (error) {
    throw new KeypairError("KEYPAIR_HKDF", { actual: length }, error);
  }
}

export function hkdfExpand(
  salt: Uint8Array | undefined,
  ikm: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  try {
    return hkdf(sha256, ikm, salt, info, length);
  } catch (error) {
    throw new KeypairError("KEYPAIR_HKDF", { actual: length }, error);
  }
}

/**
 * `view_root = HKDF-Extract(salt=empty, IKM=ECDH(viewing_sk, P_const))`: the PRK
 * all per-purpose viewing secrets expand from. Bypasses the derivation-point
 * guard on purpose; only the `ViewingKey` constructor calls it.
 */
export function viewRoot(secret: Uint8Array): Uint8Array {
  const shared = ecdhX(secret, P256PublicKey.fromBytes(P_CONST_SEC1 as Bytes33));
  try {
    return hkdfExtract(shared);
  } finally {
    shared.fill(0);
  }
}

/**
 * Reduces 48 uniform bytes to a P-256 scalar, numerically equal to Rust's RFC
 * 9380 `Scalar::from_okm`. Rust separates `ZeroScalar` from `InvalidSecretKey`,
 * so the zero case keeps its own code.
 */
export function scalarFromOkm(okm: Uint8Array): Bytes32 {
  const scalar = bytesToBigInt(okm) % P256_ORDER;
  if (scalar === 0n) {
    throw new KeypairError("KEYPAIR_ZERO_SCALAR");
  }
  const bytes = new Uint8Array(32);
  let value = scalar;
  for (let index = 31; index >= 0; index--) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes as Bytes32;
}

export type Rail = "ed25519" | "ecdh";

function railNullifierInfo(rail: Rail): Uint8Array {
  return encoder.encode(rail === "ed25519" ? INFO_NF_KEY_ED25519 : INFO_NF_KEY_ECDH);
}

function railViewingInfo(rail: Rail): Uint8Array {
  return encoder.encode(rail === "ed25519" ? INFO_VIEW_KEY_ED25519 : INFO_VIEW_KEY_ECDH);
}

/**
 * One HKDF-Extract over the derivation seed, then one Expand per role with the
 * rail's tag; mirrors Rust's `RoleExpansion`. Every keypair constructor funnels
 * through this.
 */
export function roleExpansion(
  seed: Uint8Array,
  rail: Rail,
): Readonly<{ nullifierSecret(): Bytes31; viewingSecret(): Bytes32 }> {
  const prk = hkdfExtract(seed);
  return Object.freeze({
    nullifierSecret(): Bytes31 {
      return hkdfExpandPrk(prk, railNullifierInfo(rail), 31) as Bytes31;
    },
    viewingSecret(): Bytes32 {
      const okm = hkdfExpandPrk(prk, railViewingInfo(rail), 48);
      try {
        return scalarFromOkm(okm);
      } finally {
        okm.fill(0);
      }
    },
  });
}
