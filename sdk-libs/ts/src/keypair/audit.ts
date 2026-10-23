import { X25519PublicKey, X25519Keypair } from "./x25519.js";
import { bytesToBigInt, concatBytes, isZero, rightAlign } from "../interface/bytes.js";
import {
  inputTreeSlots,
  treeIdField,
  treeSlotsHashChain,
  type TreeSlot,
} from "../interface/tree-slot.js";
import {
  BN254_SCALAR_ORDER,
  SOLANA_OWNER_TAG,
  fieldAdd,
  fieldSub,
  hashBytes,
} from "../hasher/index.js";
import { pack33 } from "../interface/merge-utils.js";
import type { MessageData } from "../interface/types.js";

import {
  type Bytes16,
  type Bytes32,
  type Bytes33,
  bigIntToBytes,
  checkedBytes,
  u32be,
} from "./bytes.js";
import { symmetricApply } from "./merge/index.js";
import { poseidon } from "./poseidon.js";

/** Rust `AUDIT_ENC_INFO`. */
export const AUDIT_ENC_INFO = new TextEncoder().encode("CRING/adt1");
/** `"CR_S"`, Rust `DOM_SEP_CR_SHARED`. */
const DOM_SEP_CR_SHARED = 0x4352_5f53;
export const AUDIT_OUTPUT_SLOTS = 4;
/** Rust `AUDIT_INPUT_SLOTS`, inputs are disclosed only in an anonymous ring. */
export const AUDIT_INPUT_SLOTS = 4;
export const AUDIT_OUTPUT_FIELD_COUNT = 9;
export const AUDIT_DISCLOSURE_FIELD_COUNT = AUDIT_OUTPUT_SLOTS * AUDIT_OUTPUT_FIELD_COUNT;
/** `eph_pk(33) || ciphertext(32) || disclosure(36 * 32)`. */
export const AUDITOR_MESSAGE_LENGTH = 65 + 32 * AUDIT_DISCLOSURE_FIELD_COUNT;
const OUTPUT_DISCLOSURE_DOMAIN = 0x4352_5f4f44n;
/** The anonymous circuit packs its plaintext into 31-byte big-endian chunks. */
const DISCLOSURE_CHUNK_BYTES = 31;
/** `tag(1) || sender(32)`, zero padded to two chunks. Rust `DISCLOSURE_SENDER_LEN`. */
const DISCLOSURE_SENDER_LEN = 62;
/** `tree_id(2) || amount(8) || asset(32) || blinding(32)`, zero padded to three chunks. */
const DISCLOSURE_INPUT_LEN = 93;
const DISCLOSURE_INPUT_BYTES = 74;
/**
 * `identity(33) || viewing_pk(33) || nullifier_pk(32) || amount(8) || asset(32) ||
 * blinding(32) || data_hash(32) || ring_data_hash(32) || ring_note(1)`, zero padded to eight chunks.
 */
const DISCLOSURE_OUTPUT_LEN = 248;
const DISCLOSURE_OUTPUT_BYTES = 235;
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

/** The owner identity and note data disclosed for one anonymous output, Rust `AnonymousOutputOpening`. A dummy slot is all zero. */
export interface AnonymousOutputOpening {
  readonly identityTag: number;
  readonly identityKey: Bytes32;
  /** Kept in the auditor capsule so the public output hides the recipient. */
  readonly viewingPublicKey: Bytes33;
  readonly nullifierPublicKey: Bytes32;
  readonly amount: bigint;
  readonly asset: Bytes32;
  readonly blinding: Bytes32;
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
  /** Set when the note is bound to the ring program. */
  readonly ringNote: boolean;
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
    const ciphertext = symmetricApply(shared, AUDIT_ENC_INFO, txViewingSecret) as Bytes32;
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
    return symmetricApply(shared, AUDIT_ENC_INFO, message.ciphertext) as Bytes32;
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
  if (!shape.anonymous) return AUDIT_DISCLOSURE_FIELD_COUNT;
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
    if (bytesToBigInt(field) >= BN254_SCALAR_ORDER)
      throw new RangeError("non-canonical audit disclosure field");
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
  readonly salt: Bytes16;
}

/** The twelve-element prefix binds the supported non-anonymous ring mode. */
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
    hashChain(input.message.disclosure),
    u64Field(0n),
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

function disclosureStream(secret: Bytes32, salt: Bytes16, index: number): bigint {
  const [keyLow, keyHigh] = pack32(secret);
  try {
    return bytesToBigInt(
      poseidon([
        bigIntToBytes(OUTPUT_DISCLOSURE_DOMAIN) as Bytes32,
        keyLow,
        keyHigh,
        rightAlign(salt),
        bigIntToBytes(BigInt(index)) as Bytes32,
      ]),
    );
  } finally {
    keyLow.fill(0);
    keyHigh.fill(0);
  }
}

/** Masks (`seal`) or unmasks the published values with the per-position stream. */
function applyDisclosureStream(
  secret: Bytes32,
  salt: Bytes16,
  values: readonly Bytes32[],
  seal: boolean,
): readonly Bytes32[] {
  return Object.freeze(
    values.map((value, index) => {
      const pad = disclosureStream(secret, salt, index);
      const masked = seal
        ? fieldAdd(bytesToBigInt(value), pad)
        : fieldSub(bytesToBigInt(value), pad);
      return bigIntToBytes(masked) as Bytes32;
    }),
  );
}

export type AuditDisclosureInput =
  | Readonly<{ salt: Bytes16; outputs: readonly AuditOutputOpening[] }>
  | Readonly<{ salt: Bytes16; anonymous: AnonymousAuditDisclosure }>;

function sealDisclosure(
  secret: Bytes32,
  input: AuditDisclosureInput | undefined,
): readonly Bytes32[] {
  if (input !== undefined && "anonymous" in input) {
    const plaintext = encodeAnonymousAuditDisclosure(input.anonymous);
    try {
      return applyDisclosureStream(secret, input.salt, packDisclosure(plaintext), true);
    } finally {
      plaintext.fill(0);
    }
  }
  return sealOutputDisclosure(secret, input);
}

function sealOutputDisclosure(
  secret: Bytes32,
  input: Readonly<{ salt: Bytes16; outputs: readonly AuditOutputOpening[] }> | undefined,
): readonly Bytes32[] {
  const outputs = input?.outputs ?? [];
  if (outputs.length > AUDIT_OUTPUT_SLOTS) throw new RangeError("audit output count exceeds four");
  const zero = new Uint8Array(32) as Bytes32;
  const plaintext = Array.from({ length: AUDIT_OUTPUT_SLOTS }, (_, index) =>
    outputs[index] === undefined
      ? Array.from({ length: AUDIT_OUTPUT_FIELD_COUNT }, () => zero)
      : outputFields(outputs[index]),
  ).flat();
  const salt = input?.salt ?? (new Uint8Array(16) as Bytes16);
  return applyDisclosureStream(secret, salt, plaintext, true);
}

export function openAuditOutputDisclosure(
  secret: Bytes32,
  salt: Bytes16,
  disclosure: readonly Bytes32[],
): readonly AuditOutputOpening[] {
  if (disclosure.length !== AUDIT_DISCLOSURE_FIELD_COUNT)
    throw new RangeError("invalid audit disclosure length");
  const fields = applyDisclosureStream(secret, salt, disclosure, false);
  return Object.freeze(
    Array.from({ length: AUDIT_OUTPUT_SLOTS }, (_, slot) => {
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
  const plaintext = unpackDisclosure(
    applyDisclosureStream(secret, salt, disclosure, false),
    length,
  );
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

/** A dummy output slot discloses all-zero bytes, Rust `AnonymousOutputOpening::default`. */
export function isDummyAnonymousOutput(output: AnonymousOutputOpening): boolean {
  return (
    output.identityTag === 0 &&
    output.amount === 0n &&
    !output.ringNote &&
    [
      output.identityKey,
      output.viewingPublicKey,
      output.nullifierPublicKey,
      output.asset,
      output.blinding,
      output.dataHash,
      output.ringDataHash,
    ].every(isZero)
  );
}

function isSlotCount(count: number): boolean {
  return Number.isInteger(count) && count >= 1 && count <= AUDIT_OUTPUT_SLOTS;
}

/** Rust `DisclosureShape::plaintext_len` for an anonymous shape. */
function anonymousPlaintextLength(shape: AuditDisclosureShape): number | undefined {
  if (!isSlotCount(shape.inputs) || !isSlotCount(shape.outputs)) return undefined;
  return (
    DISCLOSURE_SENDER_LEN +
    shape.inputs * DISCLOSURE_INPUT_LEN +
    shape.outputs * DISCLOSURE_OUTPUT_LEN
  );
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
    bytes.set(checkedBytes(output.viewingPublicKey, 33, "viewingPublicKey"), offset + 33);
    bytes.set(checkedBytes(output.nullifierPublicKey, 32, "nullifierPublicKey"), offset + 66);
    bytes.set(bigIntToBytes(checkedUnsigned(output.amount, U64_MAX, "amount"), 8), offset + 98);
    bytes.set(checkedBytes(output.asset, 32, "asset"), offset + 106);
    bytes.set(checkedBytes(output.blinding, 32, "blinding"), offset + 138);
    bytes.set(checkedBytes(output.dataHash, 32, "dataHash"), offset + 170);
    bytes.set(checkedBytes(output.ringDataHash, 32, "ringDataHash"), offset + 202);
    bytes[offset + 234] = output.ringNote ? 1 : 0;
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
    const ringNote = slot[234] ?? 0;
    if (ringNote > 1 || !isZero(slot.subarray(DISCLOSURE_OUTPUT_BYTES)))
      throw new RangeError("invalid audit disclosure padding");
    outputs.push(
      Object.freeze({
        identityTag: slot[0] ?? 0,
        identityKey: slot.slice(1, 33) as Bytes32,
        viewingPublicKey: slot.slice(33, 66) as Bytes33,
        nullifierPublicKey: slot.slice(66, 98) as Bytes32,
        amount: bytesToBigInt(slot.subarray(98, 106)),
        asset: slot.slice(106, 138) as Bytes32,
        blinding: slot.slice(138, 170) as Bytes32,
        dataHash: slot.slice(170, 202) as Bytes32,
        ringDataHash: slot.slice(202, 234) as Bytes32,
        ringNote: ringNote === 1,
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

/** Input order binds the audit statement, Rust `CustomRingBasePublicInput::hash`. */
export function auditPublicInputHash(input: CustomRingBasePublicInput): Bytes32 {
  return hashChain(auditChainElements(input));
}

/** The audit prefix then the policy tail, Rust `CustomRingPolicyPublicInput::hash`. */
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
      /** Zero for per-transfer caps and delegate moves. */
      windowIndex: bigint;
      approvalRequired: boolean;
      /** Present exactly when output nullifier keys must be enrolled under it. */
      keyRegistryRoot?: Bytes32;
      revocationTargets?: readonly Bytes32[];
      /** Per fact slot, the index into `treeSlots` its revocation target lives in. */
      revocationTreeIndexes?: readonly number[];
      /** Set exactly for a windowed transfer. */
      countersDisclosureHash?: Bytes32;
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
    hashChain([...auditChainElements(input), checkedBytes(input.policyHash, 32, "policy hash")]),
    treeIdField(input.addressTreeId),
    checkedBytes(input.ringId, 32, "ring id"),
    checkedBytes(input.namespaceOwnerHash, 32, "namespace owner hash"),
    u64Field(input.windowIndex),
    u64Field(input.approvalRequired ? 1n : 0n),
    u64Field(input.keyRegistryRoot === undefined ? 0n : 1n),
    checkedBytes(input.keyRegistryRoot ?? new Uint8Array(32), 32, "key registry root"),
    packRevocationTreeIndexes(input.revocationTreeIndexes),
    ...checkedRevocationTargets(input.revocationTargets),
    ...(input.countersDisclosureHash === undefined
      ? []
      : [checkedBytes(input.countersDisclosureHash, 32, "counters disclosure hash")]),
  ];
}

/** Mirrors Rust `pack_revocation_tree_indexes`, `Σ index_i · 8^i`, an index of 8 or more would alias its neighbour. */
function packRevocationTreeIndexes(indexes: readonly number[] | undefined): Bytes32 {
  const values = indexes ?? Array.from({ length: 10 }, () => 0);
  if (values.length !== 10) throw new RangeError("revocation tree indexes must hold 10 entries");
  const packed = values.reduce((sum, index, slot) => {
    if (!Number.isInteger(index) || index < 0 || index >= 8) {
      throw new RangeError("a revocation tree index must be below 8");
    }
    return sum | (BigInt(index) << BigInt(3 * slot));
  }, 0n);
  return u64Field(packed);
}

function checkedRevocationTargets(targets: readonly Bytes32[] | undefined): readonly Bytes32[] {
  const values = targets ?? Array.from({ length: 10 }, () => new Uint8Array(32) as Bytes32);
  if (values.length !== 10) throw new RangeError("revocation targets must hold 10 entries");
  return values.map((target) => checkedBytes(target, 32, "revocation target"));
}

function u64Field(value: bigint): Bytes32 {
  const field = new Uint8Array(32);
  field.set(bigIntToBytes(value, 8), 24);
  return field as Bytes32;
}
