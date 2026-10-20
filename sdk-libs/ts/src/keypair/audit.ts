import { ctr } from "@noble/ciphers/aes.js";
import { X25519PublicKey, X25519Keypair } from "./x25519.js";
import {
  inputTreeSlots,
  treeIdField,
  treeSlotsHashChain,
  type TreeSlot,
} from "../interface/tree-slot.js";
import { SOLANA_OWNER_TAG, fieldAdd, fieldSub, hashBytes } from "../hasher/index.js";
import { isCanonicalField } from "../interface/canonical-field.js";
import { pack33 } from "../interface/merge-utils.js";
import type { MessageData } from "../interface/types.js";

import {
  type Bytes16,
  type Bytes32,
  type Bytes33,
  bigIntToBytes,
  bytesToBigInt,
  checkedBytes,
  concatBytes,
  copyBytes,
  u32be,
} from "./bytes.js";
import { poseidon } from "./poseidon.js";

/** Rust `AUDIT_ENC_INFO`. */
export const AUDIT_ENC_INFO = new TextEncoder().encode("CRING/adt1");
/** `"CR_S"`, Rust `DOM_SEP_CR_SHARED`. */
const DOM_SEP_CR_SHARED = 0x4352_5f53;
/** `"CR_R"`, Rust `RECIPIENT_KEY_DOMAIN`, separates a recipient stream from the auditor envelope. */
export const RECIPIENT_KEY_DOMAIN = 0x4352_5f52;
export const AUDIT_OUTPUT_SLOTS = 4;
/** Rust `AUDIT_INPUT_SLOTS`, inputs are disclosed only in an anonymous ring. */
export const AUDIT_INPUT_SLOTS = 12;
/** Rust `BASE_ANONYMOUS_INPUT_SLOTS`, the narrow anonymous base key, the wide one opens `AUDIT_INPUT_SLOTS`. */
export const BASE_ANONYMOUS_INPUT_SLOTS = 4;
/** Rust `SHORT_AUDIT_MIN_INPUTS`, a two-output ring from here on proves the short disclosure. */
export const SHORT_AUDIT_MIN_INPUTS = 17;
/** Rust `IDENTITY_LEN`, an owner tag byte then the 32 key bytes. */
export const ANONYMOUS_IDENTITY_LENGTH = 33;
export const AUDIT_OUTPUT_FIELD_COUNT = 9;
export const AUDIT_DISCLOSURE_FIELD_COUNT = AUDIT_OUTPUT_SLOTS * AUDIT_OUTPUT_FIELD_COUNT;
/** `eph_pk(33) || ciphertext(32) || disclosure(36 * 32)`. */
export const AUDITOR_MESSAGE_LENGTH = 65 + 32 * AUDIT_DISCLOSURE_FIELD_COUNT;
/** `"CR_OD"`, Go `OutputDisclosureDomain`, seeds the output disclosure pad. */
const OUTPUT_DISCLOSURE_DOMAIN = 0x4352_5f4f44n;
/** `"CR_MD"`, Go `MergeDisclosureDomain`, a merge pad never repeats an output pad. */
const MERGE_DISCLOSURE_DOMAIN = 0x4352_5f4d44n;

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
/** The anonymous circuit packs its plaintext into 31-byte big-endian chunks. */
const DISCLOSURE_CHUNK_BYTES = 31;
/** `tag(1) || sender(32)`, zero padded to two chunks. Rust `DISCLOSURE_SENDER_LEN`. */
const DISCLOSURE_SENDER_LEN = 62;
/** `tree_id(2) || amount(8) || asset(32) || blinding(32)`, zero padded to three chunks. */
const DISCLOSURE_INPUT_LEN = 93;
const DISCLOSURE_INPUT_BYTES = 74;
/** `identity(33) || nullifier_pk(32) || viewing_pk(33)`, zero padded to four chunks, Rust `DISCLOSURE_OUTPUT_LEN`. */
const DISCLOSURE_OUTPUT_LEN = 124;
const DISCLOSURE_OUTPUT_BYTES = 98;
/** Position of the output body chain in the thirteen-element base statement, Rust `BODY_CHAIN_INDEX`. */
const BODY_CHAIN_INDEX = 8;
const U16_MAX = 0xffff;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** Rust `DisclosureShape`. Inputs are published only in an anonymous ring. */
export interface AuditDisclosureShape {
  readonly anonymous: boolean;
  readonly inputs: number;
  readonly outputs: number;
}

/** One spent note of an anonymous ring, Rust `AuditInputOpening`. The leaf index is not disclosed. */
export interface AuditInputOpening {
  readonly treeId: number;
  readonly amount: bigint;
  readonly asset: Bytes32;
  readonly blinding: Bytes32;
}

/** The recipient address disclosed for one anonymous output, all zero in a padding slot. */
export interface AnonymousOutputOpening {
  readonly identityTag: number;
  readonly identityKey: Bytes32;
  readonly nullifierPublicKey: Bytes32;
  /** Kept in the auditor capsule so the public output hides the recipient. */
  readonly viewingPublicKey: Bytes33;
}

/** The hidden sender, spent notes and recipients bound by an anonymous proof, Rust `AnonymousDisclosure`. */
export interface AnonymousAuditDisclosure {
  readonly sender: Bytes32;
  readonly inputs: readonly AuditInputOpening[];
  readonly outputs: readonly AnonymousOutputOpening[];
}

export interface AuditOutputOpening {
  readonly domain: Bytes32;
  readonly treeId: Bytes32;
  readonly ownerHash: Bytes32;
  readonly asset: Bytes32;
  readonly amount: Bytes32;
  readonly blinding: Bytes32;
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
  readonly ringProgramId: Bytes32;
}

export interface AuditorMessage {
  readonly ephemeralPublicKey: X25519PublicKey;
  readonly ciphertext: Bytes32;
  readonly disclosure: readonly Bytes32[];
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
  ephemeralPublicKey: X25519PublicKey,
  auditorPublicKey: X25519PublicKey,
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

/** The slot stream of one anonymous output, bound to both keys, the salt and the slot. */
export interface AnonymousOutputStream {
  readonly txViewingPublicKey: X25519PublicKey;
  readonly recipientViewingPublicKey: X25519PublicKey;
  readonly salt: Bytes16;
  readonly slotIndex: number;
}

/** The slot byte a change tag and a recipient key stream index. */
export const ANONYMOUS_SLOT_INDEX_MAX = 0xff;

/** Mirrors Rust `recipient_stream_secret`, the salt and slot index in the key keep two slots sharing `dh` on distinct keystreams. */
export function recipientStreamSecret(dh: Bytes32, stream: AnonymousOutputStream): Bytes32 {
  if (
    !Number.isInteger(stream.slotIndex) ||
    stream.slotIndex < 0 ||
    stream.slotIndex > ANONYMOUS_SLOT_INDEX_MAX
  )
    throw new RangeError("anonymous output slot index is out of range");
  const [dhLow, dhHigh] = pack32(checkedBytes<Bytes32>(dh, 32, "shared secret"));
  try {
    const [txLow, txHigh] = pack33(stream.txViewingPublicKey.toBytes());
    const [recipientLow, recipientHigh] = pack33(stream.recipientViewingPublicKey.toBytes());
    return poseidon([
      rightAlign(u32be(RECIPIENT_KEY_DOMAIN)),
      dhLow,
      dhHigh,
      txLow,
      txHigh,
      recipientLow,
      recipientHigh,
      rightAlign(checkedBytes<Bytes16>(stream.salt, 16, "salt")),
      rightAlign(Uint8Array.of(stream.slotIndex)),
    ]) as Bytes32;
  } finally {
    dhLow.fill(0);
    dhHigh.fill(0);
  }
}

/** Seals or opens one scheme-9 body, AES-256-CTR under the recipient stream secret. */
export function applyAnonymousOutputStream(
  dh: Bytes32,
  stream: AnonymousOutputStream,
  body: Uint8Array,
): Uint8Array {
  const secret = recipientStreamSecret(dh, stream);
  try {
    return symmetricAuditApply(secret, body);
  } finally {
    secret.fill(0);
  }
}

/** `(ephemeral, auditor)` fixes the keystream, so the ephemeral scalar is never taken from a caller. */
export function encryptTransactionViewingSecret(
  txViewingSecret: Bytes32,
  auditorPublicKey: X25519PublicKey,
  outputDisclosure?: AuditDisclosureInput,
): AuditorEncryption {
  const ephemeral = X25519Keypair.generate();
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  try {
    const ephemeralPublicKey = ephemeral.publicKey();
    dh = ephemeral.ecdh(auditorPublicKey);
    shared = auditSharedSecret(dh, ephemeralPublicKey, auditorPublicKey);
    const ciphertext = symmetricAuditApply(shared, txViewingSecret) as Bytes32;
    const disclosure = sealDisclosure(txViewingSecret, outputDisclosure);
    return Object.freeze({
      ephemeralSecret: ephemeral.secretBytes(),
      message: Object.freeze({ ephemeralPublicKey, ciphertext, disclosure }),
    });
  } finally {
    ephemeral.destroy();
    dh?.fill(0);
    shared?.fill(0);
  }
}

/** Mirrors Rust `decrypt_tx_viewing_sk`. */
export function decryptTransactionViewingSecret(
  auditor: X25519Keypair,
  message: AuditorMessage,
): Bytes32 {
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  try {
    dh = auditor.ecdh(message.ephemeralPublicKey);
    shared = auditSharedSecret(dh, message.ephemeralPublicKey, auditor.publicKey());
    return symmetricAuditApply(shared, message.ciphertext) as Bytes32;
  } finally {
    dh?.fill(0);
    shared?.fill(0);
  }
}

export function auditorViewTag(auditorPublicKey: X25519PublicKey): Bytes32 {
  return auditorPublicKey.u();
}

export function auditorMessageData(
  message: AuditorMessage,
  auditorPublicKey: X25519PublicKey,
): MessageData {
  return Object.freeze({
    viewTag: auditorViewTag(auditorPublicKey),
    data: concatBytes(
      message.ephemeralPublicKey.toBytes(),
      message.ciphertext,
      ...message.disclosure,
    ),
  });
}

/** The number of 32-byte disclosure values the circuit publishes for `shape`, Rust `DisclosureShape::field_count`. */
export function auditDisclosureLength(shape: AuditDisclosureShape): number | undefined {
  if (!isSlotCount(shape.outputs)) return undefined;
  if (!shape.anonymous) {
    if (shape.inputs > 24) return undefined;
    return shape.outputs === 2 && shape.inputs > 16 && shape.inputs <= 24
      ? 2 * AUDIT_OUTPUT_FIELD_COUNT
      : AUDIT_DISCLOSURE_FIELD_COUNT;
  }
  const length = anonymousPlaintextLength(shape);
  return length === undefined ? undefined : length / DISCLOSURE_CHUNK_BYTES;
}

/** Without `shape` the message carries the fixed-size disclosure of a non-anonymous ring. */
export function parseAuditorMessage(
  data: Uint8Array,
  shape?: AuditDisclosureShape,
): AuditorMessage {
  const count = shape === undefined ? AUDIT_DISCLOSURE_FIELD_COUNT : auditDisclosureLength(shape);
  if (count === undefined) throw new RangeError("unsupported audit disclosure shape");
  const bytes = checkedBytes(data, 65 + 32 * count, "auditor message");
  const disclosure = Array.from({ length: count }, (_, index) => {
    const field = bytes.slice(65 + 32 * index, 65 + 32 * (index + 1)) as Bytes32;
    if (!isCanonicalField(field)) throw new RangeError("non-canonical audit disclosure field");
    return field;
  });
  return Object.freeze({
    ephemeralPublicKey: X25519PublicKey.fromBytes(bytes.subarray(0, 33)),
    ciphertext: bytes.slice(33, 65) as Bytes32,
    disclosure: Object.freeze(disclosure),
  });
}

/** The base circuit's public-input elements, Rust `CustomRingBasePublicInput`. */
export interface CustomRingBasePublicInput {
  readonly privateTxHash: Bytes32;
  readonly txViewingPublicKey: X25519PublicKey;
  readonly auditorPublicKey: X25519PublicKey;
  readonly message: AuditorMessage;
  readonly outputHashes: readonly Bytes32[];
  /** `hashBytes` of each published scheme-9 body in slot order, absent for a ring that is not anonymous, every slot then chains zero. */
  readonly outputBodyHashes?: readonly Bytes32[];
  readonly salt: Bytes16;
  /** Binds an anonymous statement when true. Ordinary rings are the default. */
  readonly anonymous?: boolean;
}

/** The thirteen elements of the base statement, Rust `CustomRingBasePublicInput::elements`. */
function baseChainElements(input: CustomRingBasePublicInput): readonly Bytes32[] {
  const bodyHashes =
    input.outputBodyHashes ?? input.outputHashes.map(() => new Uint8Array(32) as Bytes32);
  if (bodyHashes.length !== input.outputHashes.length)
    throw new RangeError("one output body hash per output hash");
  const audit = auditChainElements(input);
  return [
    ...audit.slice(0, BODY_CHAIN_INDEX),
    hashChain4(bodyHashes),
    ...audit.slice(BODY_CHAIN_INDEX),
  ];
}

/** The twelve audit elements the body chain is spliced into, Rust `audit_elements`. */
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
    hashChain4(input.outputHashes),
    rightAlign(input.salt),
    hashChain4(input.message.disclosure),
    u64Field(input.anonymous === true ? 1n : 0n),
  ];
}

function hashChain4(values: readonly Bytes32[]): Bytes32 {
  const [first, ...remaining] = values;
  let hash = new Uint8Array(first ?? new Uint8Array(32)) as Bytes32;
  for (let index = 0; index < remaining.length; index += 3) {
    hash = poseidon([
      hash,
      remaining[index] ?? new Uint8Array(32),
      remaining[index + 1] ?? new Uint8Array(32),
      remaining[index + 2] ?? new Uint8Array(32),
    ]) as Bytes32;
  }
  return hash;
}

function outputFields(output: AuditOutputOpening): readonly Bytes32[] {
  return [
    output.domain,
    output.treeId,
    output.ownerHash,
    output.asset,
    output.amount,
    output.blinding,
    output.dataHash,
    output.ringDataHash,
    output.ringProgramId,
  ];
}

/** The circuit's disclosure keystream, `Poseidon(seed, i)` per published value, a known pad reveals no other. */
function disclosurePad(
  domain: bigint,
  secret: Bytes32,
  salt: Bytes16,
  count: number,
): readonly bigint[] {
  const [keyLow, keyHigh] = pack32(secret);
  const seed = new Uint8Array(32);
  try {
    seed.set(poseidon([bigIntToBytes(domain) as Bytes32, keyLow, keyHigh, rightAlign(salt)]));
    return Array.from({ length: count }, (_, index) =>
      bytesToBigInt(poseidon([seed, bigIntToBytes(BigInt(index)) as Bytes32])),
    );
  } finally {
    keyLow.fill(0);
    keyHigh.fill(0);
    seed.fill(0);
  }
}

function maskAt(pad: readonly bigint[], index: number): bigint {
  const mask = pad[index];
  if (mask === undefined) throw new RangeError("audit disclosure index out of range");
  return mask;
}

/** Masks (`seal`) or unmasks the published values with the keystream at their positions. */
function applyDisclosurePad(
  secret: Bytes32,
  salt: Bytes16,
  values: readonly Bytes32[],
  seal: boolean,
  domain = OUTPUT_DISCLOSURE_DOMAIN,
): readonly Bytes32[] {
  const pad = disclosurePad(domain, secret, salt, values.length);
  return Object.freeze(
    values.map((value, index) => {
      const mask = maskAt(pad, index);
      const masked = seal
        ? fieldAdd(bytesToBigInt(value), mask)
        : fieldSub(bytesToBigInt(value), mask);
      return bigIntToBytes(masked) as Bytes32;
    }),
  );
}

export type AuditDisclosureInput =
  | Readonly<{ salt: Bytes16; outputs: readonly AuditOutputOpening[]; inputs?: number }>
  | Readonly<{ salt: Bytes16; anonymous: AnonymousAuditDisclosure }>;

function sealDisclosure(
  secret: Bytes32,
  input: AuditDisclosureInput | undefined,
): readonly Bytes32[] {
  if (input !== undefined && "anonymous" in input) {
    const plaintext = encodeAnonymousAuditDisclosure(input.anonymous);
    try {
      return applyDisclosurePad(secret, input.salt, packDisclosure(plaintext), true);
    } finally {
      plaintext.fill(0);
    }
  }
  return sealOutputDisclosure(secret, input);
}

function sealOutputDisclosure(
  secret: Bytes32,
  input:
    | Readonly<{ salt: Bytes16; outputs: readonly AuditOutputOpening[]; inputs?: number }>
    | undefined,
): readonly Bytes32[] {
  const outputs = input?.outputs ?? [];
  if (outputs.length > AUDIT_OUTPUT_SLOTS) throw new RangeError("audit output count exceeds four");
  const short = outputs.length === 2 && (input?.inputs ?? 0) > 16;
  if (short && (input?.inputs ?? 0) > 24) throw new RangeError("unsupported audit input count");
  const zero = new Uint8Array(32) as Bytes32;
  const plaintext = Array.from({ length: short ? 2 : AUDIT_OUTPUT_SLOTS }, (_, index) =>
    outputs[index] === undefined
      ? Array.from({ length: AUDIT_OUTPUT_FIELD_COUNT }, () => zero)
      : outputFields(outputs[index]),
  ).flat();
  const salt = input?.salt ?? (new Uint8Array(16) as Bytes16);
  return applyDisclosurePad(secret, salt, plaintext, true);
}

export function openAuditOutputDisclosure(
  secret: Bytes32,
  salt: Bytes16,
  disclosure: readonly Bytes32[],
): readonly AuditOutputOpening[] {
  if (
    disclosure.length !== AUDIT_DISCLOSURE_FIELD_COUNT &&
    disclosure.length !== 2 * AUDIT_OUTPUT_FIELD_COUNT
  )
    throw new RangeError("invalid audit disclosure length");
  const fields = applyDisclosurePad(secret, salt, disclosure, false);
  return Object.freeze(
    Array.from({ length: disclosure.length / AUDIT_OUTPUT_FIELD_COUNT }, (_, slot) => {
      const values = fields.slice(
        slot * AUDIT_OUTPUT_FIELD_COUNT,
        (slot + 1) * AUDIT_OUTPUT_FIELD_COUNT,
      ) as Bytes32[];
      return Object.freeze({
        domain: values[0]!,
        treeId: values[1]!,
        ownerHash: values[2]!,
        asset: values[3]!,
        amount: values[4]!,
        blinding: values[5]!,
        dataHash: values[6]!,
        ringDataHash: values[7]!,
        ringProgramId: values[8]!,
      });
    }),
  );
}

/** Mirrors Rust `AuditorMessage::open_anonymous`, the slot-padded chunks the anonymous circuit binds. */
export function openAnonymousAuditDisclosure(
  secret: Bytes32,
  salt: Bytes16,
  disclosure: readonly Bytes32[],
  shape: AuditDisclosureShape,
): AnonymousAuditDisclosure {
  const length = shape.anonymous ? anonymousPlaintextLength(shape) : undefined;
  if (length === undefined || disclosure.length !== length / DISCLOSURE_CHUNK_BYTES)
    throw new RangeError("invalid audit disclosure length");
  const plaintext = unpackDisclosure(applyDisclosurePad(secret, salt, disclosure, false), length);
  try {
    return decodeAnonymousAuditDisclosure(plaintext, shape);
  } finally {
    plaintext.fill(0);
  }
}

export function anonymousAuditDisclosureShape(
  disclosure: AnonymousAuditDisclosure,
): AuditDisclosureShape {
  return { anonymous: true, inputs: disclosure.inputs.length, outputs: disclosure.outputs.length };
}

/** A padding slot discloses all-zero bytes, Rust `AnonymousOutputOpening::default`. */
export function isDummyAnonymousOutput(output: AnonymousOutputOpening): boolean {
  return (
    output.identityTag === 0 &&
    [output.identityKey, output.nullifierPublicKey, output.viewingPublicKey].every(isZero)
  );
}

function isSlotCount(count: number): boolean {
  return Number.isInteger(count) && count >= 1 && count <= AUDIT_OUTPUT_SLOTS;
}

/** Rust `DisclosureShape::plaintext_len` for an anonymous shape. */
function anonymousPlaintextLength(shape: AuditDisclosureShape): number | undefined {
  if (
    !Number.isInteger(shape.inputs) ||
    shape.inputs < 1 ||
    shape.inputs > AUDIT_INPUT_SLOTS ||
    !isSlotCount(shape.outputs)
  )
    return undefined;
  return (
    DISCLOSURE_SENDER_LEN +
    shape.inputs * DISCLOSURE_INPUT_LEN +
    shape.outputs * DISCLOSURE_OUTPUT_LEN
  );
}

function isZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

function checkedUnsigned(value: bigint, max: bigint, name: string): bigint {
  if (value < 0n || value > max) throw new RangeError(`${name} is out of range`);
  return value;
}

/** Slot padding keeps the circuit's chunk boundaries unambiguous, Rust `AnonymousDisclosure::encode`. */
export function encodeAnonymousAuditDisclosure(disclosure: AnonymousAuditDisclosure): Uint8Array {
  const length = anonymousPlaintextLength(anonymousAuditDisclosureShape(disclosure));
  if (length === undefined) throw new RangeError("unsupported audit disclosure shape");
  const bytes = new Uint8Array(length);
  bytes[0] = SOLANA_OWNER_TAG;
  bytes.set(checkedBytes(disclosure.sender, 32, "sender"), 1);
  let offset = DISCLOSURE_SENDER_LEN;
  for (const input of disclosure.inputs) {
    if (!Number.isInteger(input.treeId) || input.treeId < 0 || input.treeId > U16_MAX)
      throw new RangeError("treeId is out of range");
    bytes.set(Uint8Array.of(input.treeId >> 8, input.treeId & 0xff), offset);
    bytes.set(bigIntToBytes(checkedUnsigned(input.amount, U64_MAX, "amount"), 8), offset + 2);
    bytes.set(checkedBytes(input.asset, 32, "asset"), offset + 10);
    bytes.set(checkedBytes(input.blinding, 32, "blinding"), offset + 42);
    offset += DISCLOSURE_INPUT_LEN;
  }
  for (const output of disclosure.outputs) {
    if (
      !Number.isInteger(output.identityTag) ||
      output.identityTag < 0 ||
      output.identityTag > 0xff
    )
      throw new RangeError("identityTag is out of range");
    bytes[offset] = output.identityTag;
    bytes.set(checkedBytes(output.identityKey, 32, "identityKey"), offset + 1);
    bytes.set(checkedBytes(output.nullifierPublicKey, 32, "nullifierPublicKey"), offset + 33);
    bytes.set(checkedBytes(output.viewingPublicKey, 33, "viewingPublicKey"), offset + 65);
    offset += DISCLOSURE_OUTPUT_LEN;
  }
  return bytes;
}

/** Rejects nonzero padding so each accepted disclosure has one byte layout, Rust `AnonymousDisclosure::decode`. */
export function decodeAnonymousAuditDisclosure(
  bytes: Uint8Array,
  shape: AuditDisclosureShape,
): AnonymousAuditDisclosure {
  const length = shape.anonymous ? anonymousPlaintextLength(shape) : undefined;
  if (length === undefined || bytes.length !== length)
    throw new RangeError("invalid audit disclosure length");
  if (bytes[0] !== SOLANA_OWNER_TAG || !isZero(bytes.subarray(33, DISCLOSURE_SENDER_LEN)))
    throw new RangeError("invalid audit disclosure padding");
  const sender = bytes.slice(1, 33) as Bytes32;
  let offset = DISCLOSURE_SENDER_LEN;
  const inputs: AuditInputOpening[] = [];
  for (let index = 0; index < shape.inputs; index += 1) {
    const slot = bytes.subarray(offset, offset + DISCLOSURE_INPUT_LEN);
    if (!isZero(slot.subarray(DISCLOSURE_INPUT_BYTES)))
      throw new RangeError("invalid audit disclosure padding");
    inputs.push(
      Object.freeze({
        treeId: ((slot[0] ?? 0) << 8) | (slot[1] ?? 0),
        amount: bytesToBigInt(slot.subarray(2, 10)),
        asset: slot.slice(10, 42) as Bytes32,
        blinding: slot.slice(42, 74) as Bytes32,
      }),
    );
    offset += DISCLOSURE_INPUT_LEN;
  }
  const outputs: AnonymousOutputOpening[] = [];
  for (let index = 0; index < shape.outputs; index += 1) {
    const slot = bytes.subarray(offset, offset + DISCLOSURE_OUTPUT_LEN);
    if (!isZero(slot.subarray(DISCLOSURE_OUTPUT_BYTES)))
      throw new RangeError("invalid audit disclosure padding");
    outputs.push(
      Object.freeze({
        identityTag: slot[0] ?? 0,
        identityKey: slot.slice(1, 33) as Bytes32,
        nullifierPublicKey: slot.slice(33, 65) as Bytes32,
        viewingPublicKey: slot.slice(65, 98) as Bytes33,
      }),
    );
    offset += DISCLOSURE_OUTPUT_LEN;
  }
  return Object.freeze({ sender, inputs: Object.freeze(inputs), outputs: Object.freeze(outputs) });
}

/** Splits the plaintext into right-aligned 31-byte chunks exactly as the circuit packs it, Rust `pack_disclosure`. */
function packDisclosure(plaintext: Uint8Array): readonly Bytes32[] {
  const chunks: Bytes32[] = [];
  for (let offset = 0; offset < plaintext.length; offset += DISCLOSURE_CHUNK_BYTES) {
    chunks.push(rightAlign(plaintext.subarray(offset, offset + DISCLOSURE_CHUNK_BYTES)));
  }
  return chunks;
}

/** Inverts `packDisclosure`, a value with bytes outside its chunk is rejected, Rust `unpack_disclosure`. */
function unpackDisclosure(values: readonly Bytes32[], length: number): Uint8Array {
  if (values.length !== Math.ceil(length / DISCLOSURE_CHUNK_BYTES))
    throw new RangeError("invalid audit disclosure length");
  const plaintext = new Uint8Array(length);
  values.forEach((value, index) => {
    const chunk = Math.min(length - index * DISCLOSURE_CHUNK_BYTES, DISCLOSURE_CHUNK_BYTES);
    if (!isZero(value.subarray(0, 32 - chunk)))
      throw new RangeError("invalid audit disclosure padding");
    plaintext.set(value.subarray(32 - chunk), index * DISCLOSURE_CHUNK_BYTES);
  });
  return plaintext;
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

/** Input order binds the base statement, Rust `CustomRingBasePublicInput::hash`. */
export function auditPublicInputHash(input: CustomRingBasePublicInput): Bytes32 {
  return hashChain(baseChainElements(input));
}

/** The thirteen-element base statement then the policy tail, Rust `CustomRingPolicyPublicInput::hash`. */
export function policyPublicInputHash(
  input: CustomRingBasePublicInput &
    Readonly<{
      policyHash: Bytes32;
      /** The populated prefix, one to `INPUT_TREES` policy trees. */
      treeSlots: readonly TreeSlot[];
      addressTreeId: number;
      /** `hashBytes` of the ring program id. */
      ringId: Bytes32;
      namespaceOwnerHash: Bytes32;
      /** Set when an outflow passes a limit's cosign threshold, false on the delegate rail. */
      approvalRequired: boolean;
      keyEscrow: boolean;
      memberRegistryRoot: Bytes32;
      foreignRoot: Bytes32;
    }>,
): Bytes32 {
  const indexed = policyIndexedInputs(input);
  return hashChain([
    indexed[0]!,
    treeSlotsHashChain(inputTreeSlots(input.treeSlots)),
    ...indexed.slice(1),
  ]);
}

export function policyIndexedInputs(
  input: Parameters<typeof policyPublicInputHash>[0],
): readonly Bytes32[] {
  return [
    hashChain([...baseChainElements(input), checkedBytes(input.policyHash, 32, "policy hash")]),
    treeIdField(input.addressTreeId),
    checkedBytes(input.ringId, 32, "ring id"),
    checkedBytes(input.namespaceOwnerHash, 32, "namespace owner hash"),
    u64Field(input.approvalRequired ? 1n : 0n),
    u64Field(input.keyEscrow ? 1n : 0n),
    checkedBytes(input.memberRegistryRoot, 32, "member registry root"),
    checkedBytes(input.foreignRoot, 32, "foreign registry root"),
  ];
}

function u64Field(value: bigint): Bytes32 {
  const field = new Uint8Array(32);
  field.set(bigIntToBytes(value, 8), 24);
  return field as Bytes32;
}
