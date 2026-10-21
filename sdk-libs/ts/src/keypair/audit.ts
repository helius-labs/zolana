import { ctr } from "@noble/ciphers/aes.js";

import { fieldAdd, fieldSub, packBytesBe } from "../hasher/index.js";
import { isCanonicalField } from "../interface/canonical-field.js";
import type { MessageData } from "../interface/types.js";

import {
  type Bytes16,
  type Bytes32,
  bigIntToBytes,
  bytesToBigInt,
  checkedBytes,
  concatBytes,
  copyBytes,
  u32be,
} from "./bytes.js";
import { KeypairError } from "./error.js";
import { poseidon } from "./poseidon.js";
import { X25519Keypair, X25519PublicKey } from "./x25519.js";

/** Rust `AUDIT_STREAM_INFO`, the envelope and the delivered bodies share its stream schedule. */
export const AUDIT_ENC_INFO = new TextEncoder().encode("CRING/adt1");
/** Rust `AUDITOR_MESSAGE_PREFIX_LEN`, `0x04 ‖ eph_u ‖ sealed` ahead of the disclosure. */
export const AUDITOR_MESSAGE_PREFIX_LENGTH = 65;

/** `"CR_S"`, Rust `DOM_SEP_CR_SHARED`. */
const DOM_SEP_CR_SHARED = 0x4352_5f53;
/** `"CR_MD"`, Go `MergeDisclosureDomain`, a merge pad never repeats an output pad. */
const MERGE_DISCLOSURE_DOMAIN = 0x4352_5f4d44n;
const DISCLOSURE_CHUNK_BYTES = 31;

/** The sealed transaction viewing secret, `ephemeralSecret` the audit proof's witness. */
export interface AuditorEnvelope {
  readonly ephemeralSecret: Bytes32;
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly sealed: Bytes32;
}

/** The one message a ring transfer publishes under the auditor's view tag. */
export interface AuditorMessage {
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly sealed: Bytes32;
  readonly disclosure: readonly Bytes32[];
}

/** `pad_j = Poseidon(Poseidon(domain, pack_be(key), salt), j)` at position `j`, Rust `DisclosurePad`. */
export interface DisclosurePad {
  readonly key: Bytes32;
  readonly salt: Bytes16;
  readonly domain: number;
  readonly fields: readonly Bytes32[];
}

/** Two Poseidon outputs supply 31 key bytes, then one key byte and a 12-byte nonce. */
export function symmetricAuditApply(shared: Bytes32, data: Uint8Array): Uint8Array {
  const tag = new Uint8Array(11);
  tag.set(AUDIT_ENC_INFO);
  const key = new Uint8Array(32);
  const counter = new Uint8Array(16);
  let head: Uint8Array | undefined;
  let tail: Uint8Array | undefined;
  try {
    head = poseidon([rightAlign(tag), shared]);
    key.set(head.subarray(1), 0);
    tag[10] = 1;
    tail = poseidon([rightAlign(tag), shared]);
    key[31] = tail[19] ?? 0;
    counter.set(tail.subarray(20), 0);
    counter[15] = 2;
    return ctr(key, counter).encrypt(copyBytes(data));
  } finally {
    tag.fill(0);
    key.fill(0);
    counter.fill(0);
    head?.fill(0);
    tail?.fill(0);
  }
}

/** Binds the ECDH x-coordinate to both public keys, one shared point serves one key pair. */
export function auditSharedSecret(
  dh: Bytes32,
  ephemeralPublicKey: X25519PublicKey,
  auditorPublicKey: X25519PublicKey,
): Bytes32 {
  const packedDh = packBytesBe(checkedBytes<Bytes32>(dh, 32, "shared secret"));
  try {
    return poseidon([
      rightAlign(u32be(DOM_SEP_CR_SHARED)),
      ...packedDh,
      ...packBytesBe(ephemeralPublicKey.toBytes()),
      ...packBytesBe(auditorPublicKey.toBytes()),
    ]) as Bytes32;
  } finally {
    for (const field of packedDh) field.fill(0);
  }
}

/** A fresh ephemeral key fixes the keystream, the scalar never comes from a caller. */
export function sealTransactionViewingSecret(
  txViewingSecret: Bytes32,
  auditorPublicKey: X25519PublicKey,
): AuditorEnvelope {
  const ephemeral = X25519Keypair.generate();
  let shared: Bytes32 | undefined;
  try {
    const ephemeralPublicKey = ephemeral.publicKey();
    shared = envelopeSecret(ephemeral, auditorPublicKey, ephemeralPublicKey, auditorPublicKey);
    const sealed = symmetricAuditApply(
      shared,
      checkedBytes<Bytes32>(txViewingSecret, 32, "tx viewing secret"),
    ) as Bytes32;
    return Object.freeze({ ephemeralSecret: ephemeral.secretBytes(), ephemeralPublicKey, sealed });
  } finally {
    ephemeral.destroy();
    shared?.fill(0);
  }
}

/** The auditor's side of `sealTransactionViewingSecret`. */
export function openTransactionViewingSecret(
  auditor: X25519Keypair,
  message: Pick<AuditorMessage, "ephemeralPublicKey" | "sealed">,
): Bytes32 {
  const shared = envelopeSecret(
    auditor,
    message.ephemeralPublicKey,
    message.ephemeralPublicKey,
    auditor.publicKey(),
  );
  try {
    return symmetricAuditApply(
      shared,
      checkedBytes<Bytes32>(message.sealed, 32, "sealed"),
    ) as Bytes32;
  } finally {
    shared.fill(0);
  }
}

export function auditorViewTag(auditorPublicKey: X25519PublicKey): Bytes32 {
  return auditorPublicKey.u();
}

/** `0x04 ‖ eph_u ‖ sealed ‖ disclosure` under the auditor's view tag. */
export function auditorMessageData(
  message: AuditorMessage,
  auditorPublicKey: X25519PublicKey,
): MessageData {
  return Object.freeze({
    viewTag: auditorViewTag(auditorPublicKey),
    data: concatBytes(message.ephemeralPublicKey.toBytes(), message.sealed, ...message.disclosure),
  });
}

/** `fieldCount` comes from the transfer's layout, the program refuses a zero published field. */
export function parseAuditorMessage(data: Uint8Array, fieldCount: number): AuditorMessage {
  if (!Number.isInteger(fieldCount) || fieldCount < 1)
    throw new KeypairError("KEYPAIR_DISCLOSURE_SHAPE", { name: "fieldCount" });
  const bytes = checkedBytes(
    data,
    AUDITOR_MESSAGE_PREFIX_LENGTH + 32 * fieldCount,
    "auditor message",
  );
  const disclosure = Array.from({ length: fieldCount }, (_, index) => {
    const start = AUDITOR_MESSAGE_PREFIX_LENGTH + 32 * index;
    const field = bytes.slice(start, start + 32) as Bytes32;
    if (!isCanonicalField(field) || field.every((byte) => byte === 0))
      throw new KeypairError("KEYPAIR_DISCLOSURE_FIELD", { name: "published", index });
    return field;
  });
  return Object.freeze({
    ephemeralPublicKey: X25519PublicKey.fromBytes(bytes.subarray(0, 33)),
    sealed: bytes.slice(33, AUDITOR_MESSAGE_PREFIX_LENGTH) as Bytes32,
    disclosure: Object.freeze(disclosure),
  });
}

/** Rust `pack_disclosure`, a short last chunk is zero padded at its end. */
export function packDisclosure(plaintext: Uint8Array): readonly Bytes32[] {
  return Array.from(
    { length: Math.ceil(plaintext.length / DISCLOSURE_CHUNK_BYTES) },
    (_, index) => {
      const field = new Uint8Array(32);
      const start = index * DISCLOSURE_CHUNK_BYTES;
      field.set(plaintext.subarray(start, start + DISCLOSURE_CHUNK_BYTES), 1);
      return field as Bytes32;
    },
  );
}

/** Rust `unpack_disclosure`, a field with bytes outside its chunk is refused. */
export function unpackDisclosure(fields: readonly Bytes32[], length: number): Uint8Array {
  if (fields.length !== Math.ceil(length / DISCLOSURE_CHUNK_BYTES))
    throw new KeypairError("KEYPAIR_DISCLOSURE_SHAPE", { expected: length, actual: fields.length });
  const plaintext = new Uint8Array(length);
  fields.forEach((field, index) => {
    const chunk = Math.min(length - index * DISCLOSURE_CHUNK_BYTES, DISCLOSURE_CHUNK_BYTES);
    if (field[0] !== 0 || field.subarray(1 + chunk).some((byte) => byte !== 0))
      throw new KeypairError("KEYPAIR_DISCLOSURE_PADDING", { index });
    plaintext.set(field.subarray(1, 1 + chunk), index * DISCLOSURE_CHUNK_BYTES);
  });
  return plaintext;
}

/** Only the holder of `key` removes the pads. */
export function maskDisclosure(input: DisclosurePad): readonly Bytes32[] {
  return applyDisclosurePad(input.key, input.salt, input.fields, true, BigInt(input.domain));
}

export function unmaskDisclosure(input: DisclosurePad): readonly Bytes32[] {
  return applyDisclosurePad(input.key, input.salt, input.fields, false, BigInt(input.domain));
}

/** Masks a merge disclosure plaintext already zero padded to whole chunks, Rust `MergeDisclosureEncryption::seal`. */
export function sealMergeDisclosureFields(
  key: Bytes32,
  salt: Bytes16,
  plaintext: Uint8Array,
): readonly Bytes32[] {
  if (plaintext.length % DISCLOSURE_CHUNK_BYTES !== 0)
    throw new KeypairError("KEYPAIR_DISCLOSURE_SHAPE", { name: "merge" });
  const chunks = packDisclosure(plaintext);
  try {
    return applyDisclosurePad(key, salt, chunks, true, MERGE_DISCLOSURE_DOMAIN);
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

/** Unmasks an anonymous merge disclosure, the plaintext zero padded to whole chunks, Rust `open_merge_disclosure`. */
export function openMergeDisclosureFields(
  key: Bytes32,
  salt: Bytes16,
  fields: readonly Bytes32[],
): Uint8Array {
  const chunks = applyDisclosurePad(key, salt, fields, false, MERGE_DISCLOSURE_DOMAIN);
  return unpackDisclosure(chunks, chunks.length * DISCLOSURE_CHUNK_BYTES);
}

function envelopeSecret(
  local: X25519Keypair,
  remote: X25519PublicKey,
  ephemeralPublicKey: X25519PublicKey,
  auditorPublicKey: X25519PublicKey,
): Bytes32 {
  const dh = local.ecdh(remote);
  try {
    return auditSharedSecret(dh, ephemeralPublicKey, auditorPublicKey);
  } finally {
    dh.fill(0);
  }
}

/** Masks (`seal`) or unmasks the published values with the keystream at their positions. */
function applyDisclosurePad(
  secret: Bytes32,
  salt: Bytes16,
  values: readonly Bytes32[],
  seal: boolean,
  domain: bigint,
): readonly Bytes32[] {
  const packedKey = packBytesBe(checkedBytes<Bytes32>(secret, 32, "disclosure key"));
  const seed = new Uint8Array(32);
  try {
    seed.set(
      poseidon([
        bigIntToBytes(domain) as Bytes32,
        ...packedKey,
        rightAlign(checkedBytes<Bytes16>(salt, 16, "salt")),
      ]),
    );
    return Object.freeze(
      values.map((value, index) => {
        const mask = bytesToBigInt(poseidon([seed, bigIntToBytes(BigInt(index)) as Bytes32]));
        const masked = seal
          ? fieldAdd(bytesToBigInt(value), mask)
          : fieldSub(bytesToBigInt(value), mask);
        return bigIntToBytes(masked) as Bytes32;
      }),
    );
  } finally {
    for (const field of packedKey) field.fill(0);
    seed.fill(0);
  }
}

function rightAlign(bytes: Uint8Array): Bytes32 {
  const output = new Uint8Array(32);
  output.set(bytes, 32 - bytes.length);
  return output as Bytes32;
}
