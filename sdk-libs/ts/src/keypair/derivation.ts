/**
 * Domain-separation registry and key-derivation primitives, mirroring
 * `sdk-libs/keypair/src/derivation.rs`: every domain-separation tag lives here
 * and every HKDF/ECDH invocation funnels through the functions below, so the
 * full derivation tree is auditable in one file. The values are pinned by
 * `test-vectors/key_derivation.json`.
 */
import { expand, extract, hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import type { Bytes31, Bytes32 } from "./bytes.js";
import { KeypairError } from "./error.js";
import { X25519PublicKey, X25519Secret } from "./x25519.js";

const encoder = new TextEncoder();

export const DST_X25519_VIEW_ROOT = "TSPP/view_root/x25519/v1";

export const INFO_NF_KEY_ED25519 = "TSPP/nf_key/ed25519/v1";

export const INFO_VIEW_KEY_ED25519_X25519 = "TSPP/view_key/ed25519/x25519/v1";

export const INFO_TX_VIEWING_X25519 = "TSPP/tx_viewing/x25519/v1";

export const ED25519_DERIVATION_MSG = "TSPP/derive/v1";

export const DERIVATION_PAYLOAD_PREFIX = "TSPP/derive/";

export const OFFCHAIN_MESSAGE_MAGIC = Uint8Array.from([
  0xff, 0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x20, 0x6f, 0x66, 0x66, 0x63, 0x68, 0x61, 0x69, 0x6e,
]);

/** `sha256(ED25519_DERIVATION_MSG)`, pinned by a test. */
export const TSPP_APPLICATION_DOMAIN = Uint8Array.from([
  0x1d, 0x32, 0xa8, 0x85, 0x33, 0xaf, 0x12, 0xd3, 0x5e, 0x5a, 0xc6, 0xfc, 0xe8, 0x17, 0xa4, 0xcb,
  0x81, 0x0b, 0xcc, 0x41, 0x15, 0x38, 0x6b, 0x14, 0xa7, 0x8e, 0x8b, 0x2e, 0xf0, 0x9d, 0x86, 0x4c,
]);

export const HPKE_PREFIX = "TSPP/hpke/";

export const ENC_INFO_TRANSFER = "TSPP/tx";

export const ENC_INFO_RING_DEPOSIT = "TSPP/ring_deposit";

export const MERGE_INFO = encoder.encode("TSPP/merge");

export const DOM_SEP_SILO = 0x544d_5349;
export const DOM_SEP_KEY = 0x544d_534b;
export const DOM_SEP_NONCE = 0x544d_534e;

export const DOMAIN_MERGE_OUTPUT_BLINDING_V1 = 0x544d_4f42;
export const DOMAIN_MERGE_DUMMY_NULLIFIER = 0x544d_444e;
export const DOMAIN_MERGE_OUTPUT_KEY = 0x544d_4f4b;
export const DOMAIN_MERGE_OUTPUT_CIPHERTEXT = 0x544d_4f43;

/** `"TXOS"`: the seed every transact output blinding derives from. */
export const DOMAIN_TRANSACT_OUTPUT_BLINDING_SEED_V1 = 0x5458_4f53;
/** `"TXOB"`: one transact output blinding per output slot. */
export const DOMAIN_TRANSACT_OUTPUT_BLINDING_V1 = 0x5458_4f42;
/** `"TXPB"`: the blinding that keeps the private transaction hash unguessable. */
export const DOMAIN_PRIVATE_TX_BLINDING_V1 = 0x5458_5042;

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

/**
 * The bare payload, what a browser wallet signs. Phantom refuses the off-chain
 * envelope because its first byte, `0xff`, reads as a transaction header to
 * it, so wallets sign `"TSPP/derive/v1"` as text. The guard treats both as
 * derivation inputs. The seed, and so the keys, differ from the envelope's:
 * a wallet key gives one shielded address through a browser wallet and
 * another through a software signer.
 */
export function ed25519DerivationPayload(): Uint8Array {
  return encoder.encode(ED25519_DERIVATION_MSG);
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

/** Normalizes a viewing secret to the one byte string encrypted by the circuit. */
export function clampViewingSecret(secret: Uint8Array): Bytes32 {
  const normalized = checkedViewingSecret(secret);
  normalized[0] = (normalized[0] ?? 0) & 248;
  normalized[31] = ((normalized[31] ?? 0) & 127) | 64;
  return normalized;
}

function checkedViewingSecret(secret: Uint8Array): Bytes32 {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) {
    throw new KeypairError("KEYPAIR_INVALID_SECRET_KEY", { type: "x25519" });
  }
  return new Uint8Array(secret) as Bytes32;
}

/** ECDH rejects low-order peers through Noble's all-zero check. */
export function x25519Ecdh(secret: Uint8Array, peer: X25519PublicKey): Uint8Array {
  const key = X25519Secret.fromBytes(secret);
  try {
    return key.ecdh(peer);
  } finally {
    key.destroy();
  }
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
 * Derives viewing roles directly from the canonical secret with a domain salt.
 * Raw ECDH cannot expose this input. A fixed-peer agreement would be recoverable
 * by querying a multiple of that peer and inverting the multiplication.
 */
export function viewRoot(secret: Uint8Array): Uint8Array {
  const canonical = clampViewingSecret(secret);
  try {
    return extract(sha256, canonical, encoder.encode(DST_X25519_VIEW_ROOT));
  } finally {
    canonical.fill(0);
  }
}

export type Rail = "ed25519";

/** An ed25519 `derivationSeed` is the RFC 8032 signature over the derivation message. */
export const ED25519_SEED_LEN = 64;

/**
 * The seed width is fixed per rail, and every path into `roleExpansion` is
 * checked against it. HKDF-Extract accepts any input length, so a backend that
 * returned a truncated seed would otherwise expand cleanly into a well-formed
 * but *different* identity: every signature still verifies and every address
 * still looks correct, so nothing downstream catches it.
 */
function assertSeedWidth(seed: Uint8Array, rail: Rail): void {
  if (rail !== "ed25519") throw new KeypairError("KEYPAIR_INVALID_SIGNATURE_TYPE", { type: rail });
  const expected = ED25519_SEED_LEN;
  if (!(seed instanceof Uint8Array) || seed.length !== expected) {
    throw new KeypairError("KEYPAIR_INVALID_DERIVATION_SEED", {
      name: "derivation seed",
      expected,
      actual: seed instanceof Uint8Array ? seed.length : -1,
    });
  }
}

/**
 * Checks a `derivationSeed` against its rail's width and returns a copy, so the
 * caller can clear the returned buffer without touching its own.
 *
 * Use this at any boundary that accepts a seed produced elsewhere -- a hardware
 * signer, a remote custodian -- rather than a bare length check, so the failure
 * mirrors Rust's `InvalidDerivationSeed`.
 */
export function checkedDerivationSeed<T extends Uint8Array>(seed: Uint8Array | T, rail: Rail): T {
  assertSeedWidth(seed, rail);
  return new Uint8Array(seed) as T;
}

export interface RoleSecrets {
  readonly nullifierSecret: Bytes31;
  readonly viewingSecret: Bytes32;
}

/**
 * One HKDF-Extract over the derivation seed, then one Expand per role with the
 * role's tag, mirroring Rust's `RoleExpansion`. Every keypair constructor funnels
 * through this. The PRK and both role secrets live only for the synchronous
 * `use` callback and are wiped when it settles, copy what outlives it.
 */
export function roleExpansion<T>(seed: Uint8Array, rail: Rail, use: (roles: RoleSecrets) => T): T {
  assertSeedWidth(seed, rail);
  const prk = hkdfExtract(seed);
  let nullifierSecret: Uint8Array | undefined;
  let viewingSecret: Uint8Array | undefined;
  try {
    nullifierSecret = hkdfExpandPrk(prk, encoder.encode(INFO_NF_KEY_ED25519), 31);
    const okm = hkdfExpandPrk(prk, encoder.encode(INFO_VIEW_KEY_ED25519_X25519), 32);
    try {
      viewingSecret = clampViewingSecret(okm);
    } finally {
      okm.fill(0);
    }
    return use({
      nullifierSecret: nullifierSecret as Bytes31,
      viewingSecret: viewingSecret as Bytes32,
    });
  } finally {
    prk.fill(0);
    nullifierSecret?.fill(0);
    viewingSecret?.fill(0);
  }
}
