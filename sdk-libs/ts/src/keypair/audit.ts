import { hashBytes } from "../hasher/index.js";
import { pack33 } from "../interface/merge-utils.js";
import type { MessageData } from "../interface/types.js";

import { type Bytes32, checkedBytes, concatBytes, u32be } from "./bytes.js";
import { symmetricApply } from "./merge/index.js";
import { poseidon } from "./poseidon.js";
import { P256PublicKey } from "./public-key.js";
import { ViewingKey } from "./viewing-key.js";

/** Rust `AUDIT_ENC_INFO`. */
export const AUDIT_ENC_INFO = new TextEncoder().encode("CRING/adt1");
/** `"CR_S"`, Rust `DOM_SEP_CR_SHARED`. */
const DOM_SEP_CR_SHARED = 0x4352_5f53;
/** `eph_pk(33) || ciphertext(32)`. */
export const AUDITOR_MESSAGE_LENGTH = 65;

export interface AuditorMessage {
  readonly ephemeralPublicKey: P256PublicKey;
  readonly ciphertext: Bytes32;
}

export interface AuditorEncryption {
  readonly ephemeralSecret: Bytes32;
  readonly message: AuditorMessage;
}

function rightAlign(bytes: Uint8Array): Bytes32 {
  const output = new Uint8Array(32);
  output.set(bytes, 32 - bytes.length);
  return output as Bytes32;
}

function hashChain(values: readonly Bytes32[]): Bytes32 {
  const [first, ...remaining] = values;
  let hash = new Uint8Array(first ?? new Uint8Array(32)) as Bytes32;
  for (const value of remaining) hash = poseidon([hash, value]) as Bytes32;
  return hash;
}

/** `lo = 0x00 || bytes[0..31]`, `hi = bytes[31]`, Rust `pack32_to_2fe`. */
function pack32(bytes: Bytes32): readonly [Bytes32, Bytes32] {
  const low = new Uint8Array(32);
  low.set(bytes.subarray(0, 31), 1);
  return [low as Bytes32, rightAlign(bytes.subarray(31))];
}

/**
 * Mirrors Rust `derive_audit_shared_secret` and the circuit's `DeriveAuditSharedSecret`.
 * Binds the ECDH x-coordinate to both public keys, so one shared point serves one key pair.
 */
export function auditSharedSecret(
  dh: Bytes32,
  ephemeralPublicKey: P256PublicKey,
  auditorPublicKey: P256PublicKey,
): Bytes32 {
  const [dhLow, dhHigh] = pack32(dh);
  try {
    const [ephLow, ephHigh] = pack33(ephemeralPublicKey.toBytes());
    const [auditorLow, auditorHigh] = pack33(auditorPublicKey.toBytes());
    return poseidon([
      rightAlign(u32be(DOM_SEP_CR_SHARED)),
      dhLow,
      dhHigh,
      ephLow,
      ephHigh,
      auditorLow,
      auditorHigh,
    ]) as Bytes32;
  } finally {
    dhLow.fill(0);
    dhHigh.fill(0);
  }
}

/** `(ephemeral, auditor)` fixes the keystream, so the ephemeral scalar is never taken from a caller. */
export function encryptTransactionViewingSecret(
  txViewingSecret: Bytes32,
  auditorPublicKey: P256PublicKey,
): AuditorEncryption {
  const ephemeral = ViewingKey.generate();
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  try {
    const ephemeralPublicKey = ephemeral.publicKey();
    dh = ephemeral.ecdh(auditorPublicKey);
    shared = auditSharedSecret(dh, ephemeralPublicKey, auditorPublicKey);
    const ciphertext = symmetricApply(shared, AUDIT_ENC_INFO, txViewingSecret) as Bytes32;
    return Object.freeze({
      ephemeralSecret: ephemeral.secretBytes(),
      message: Object.freeze({ ephemeralPublicKey, ciphertext }),
    });
  } finally {
    ephemeral.destroy();
    dh?.fill(0);
    shared?.fill(0);
  }
}

/** Mirrors Rust `decrypt_tx_viewing_sk`. */
export function decryptTransactionViewingSecret(
  auditor: ViewingKey,
  message: AuditorMessage,
): Bytes32 {
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  try {
    dh = auditor.ecdh(message.ephemeralPublicKey);
    shared = auditSharedSecret(dh, message.ephemeralPublicKey, auditor.publicKey());
    return symmetricApply(shared, AUDIT_ENC_INFO, message.ciphertext) as Bytes32;
  } finally {
    dh?.fill(0);
    shared?.fill(0);
  }
}

export function auditorViewTag(auditorPublicKey: P256PublicKey): Bytes32 {
  return auditorPublicKey.x();
}

export function auditorMessageData(
  message: AuditorMessage,
  auditorPublicKey: P256PublicKey,
): MessageData {
  return Object.freeze({
    viewTag: auditorViewTag(auditorPublicKey),
    data: concatBytes(message.ephemeralPublicKey.toBytes(), message.ciphertext),
  });
}

export function parseAuditorMessage(data: Uint8Array): AuditorMessage {
  const bytes = checkedBytes(data, AUDITOR_MESSAGE_LENGTH, "auditor message");
  return Object.freeze({
    ephemeralPublicKey: P256PublicKey.fromBytes(bytes.subarray(0, 33) as never),
    ciphertext: bytes.slice(33) as Bytes32,
  });
}

/** The base circuit's public-input elements, Rust `CustomRingBasePublicInput`. */
interface CustomRingBasePublicInput {
  readonly privateTxHash: Bytes32;
  readonly txViewingPublicKey: P256PublicKey;
  readonly auditorPublicKey: P256PublicKey;
  readonly message: AuditorMessage;
}

/** The eight-element prefix every custom-ring public input starts with. */
function auditChainElements(input: CustomRingBasePublicInput): readonly Bytes32[] {
  const [txLow, txHigh] = pack33(input.txViewingPublicKey.toBytes());
  const [auditorLow, auditorHigh] = pack33(input.auditorPublicKey.toBytes());
  const [ephLow, ephHigh] = pack33(input.message.ephemeralPublicKey.toBytes());
  return [
    input.privateTxHash,
    txLow,
    txHigh,
    auditorLow,
    auditorHigh,
    ephLow,
    ephHigh,
    hashBytes(input.message.ciphertext) as Bytes32,
  ];
}

/** Input order binds the audit statement, Rust `CustomRingBasePublicInput::hash`. */
export function auditPublicInputHash(input: CustomRingBasePublicInput): Bytes32 {
  return hashChain(auditChainElements(input));
}

/** The audit prefix then policy hash and roots, Rust `CustomRingPolicyPublicInput::hash`. */
export function customRingPublicInputHash(
  input: CustomRingBasePublicInput &
    Readonly<{ policyHash: Bytes32; stateRoot: Bytes32; nullifierRoot: Bytes32 }>,
): Bytes32 {
  return hashChain([
    ...auditChainElements(input),
    checkedBytes(input.policyHash, 32, "policy hash"),
    checkedBytes(input.stateRoot, 32, "state root"),
    checkedBytes(input.nullifierRoot, 32, "nullifier root"),
  ]);
}
