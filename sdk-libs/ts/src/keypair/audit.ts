import { treeIdField } from "../interface/tree-slot.js";
import { hashBytes } from "../hasher/index.js";
import { pack33 } from "../interface/merge-utils.js";
import type { MessageData } from "../interface/types.js";

import {
  type Bytes16,
  type Bytes32,
  bigIntToBytes,
  bytesToBigInt,
  checkedBytes,
  concatBytes,
  u32be,
} from "./bytes.js";
import { symmetricApply } from "./merge/index.js";
import { poseidon } from "./poseidon.js";
import { P256PublicKey } from "./public-key.js";
import { ViewingKey } from "./viewing-key.js";

/** Rust `AUDIT_ENC_INFO`. */
export const AUDIT_ENC_INFO = new TextEncoder().encode("CRING/adt1");
/** `"CR_S"`, Rust `DOM_SEP_CR_SHARED`. */
const DOM_SEP_CR_SHARED = 0x4352_5f53;
export const AUDIT_OUTPUT_SLOTS = 4;
export const AUDIT_OUTPUT_FIELD_COUNT = 9;
export const AUDIT_DISCLOSURE_FIELD_COUNT = AUDIT_OUTPUT_SLOTS * AUDIT_OUTPUT_FIELD_COUNT;
/** `eph_pk(33) || ciphertext(32) || disclosure(36 * 32)`. */
export const AUDITOR_MESSAGE_LENGTH = 65 + 32 * AUDIT_DISCLOSURE_FIELD_COUNT;
const BN254_MODULUS =
  21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617n;
const OUTPUT_DISCLOSURE_DOMAIN = 0x4352_5f4f44n;

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
  readonly ephemeralPublicKey: P256PublicKey;
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
  outputDisclosure?: Readonly<{
    salt: Bytes16;
    outputs: readonly AuditOutputOpening[];
  }>,
): AuditorEncryption {
  const ephemeral = ViewingKey.generate();
  let dh: Bytes32 | undefined;
  let shared: Bytes32 | undefined;
  try {
    const ephemeralPublicKey = ephemeral.publicKey();
    dh = ephemeral.ecdh(auditorPublicKey);
    shared = auditSharedSecret(dh, ephemeralPublicKey, auditorPublicKey);
    const ciphertext = symmetricApply(shared, AUDIT_ENC_INFO, txViewingSecret) as Bytes32;
    const disclosure = sealOutputDisclosure(txViewingSecret, outputDisclosure);
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
    data: concatBytes(
      message.ephemeralPublicKey.toBytes(),
      message.ciphertext,
      ...message.disclosure,
    ),
  });
}

export function parseAuditorMessage(data: Uint8Array): AuditorMessage {
  const bytes = checkedBytes(data, AUDITOR_MESSAGE_LENGTH, "auditor message");
  const disclosure = Array.from({ length: AUDIT_DISCLOSURE_FIELD_COUNT }, (_, index) => {
    const field = bytes.slice(65 + 32 * index, 65 + 32 * (index + 1)) as Bytes32;
    if (bytesToBigInt(field) >= BN254_MODULUS)
      throw new RangeError("non-canonical audit disclosure field");
    return field;
  });
  return Object.freeze({
    ephemeralPublicKey: P256PublicKey.fromBytes(bytes.subarray(0, 33) as never),
    ciphertext: bytes.slice(33, 65) as Bytes32,
    disclosure: Object.freeze(disclosure),
  });
}

/** The base circuit's public-input elements, Rust `CustomRingBasePublicInput`. */
export interface CustomRingBasePublicInput {
  readonly privateTxHash: Bytes32;
  readonly txViewingPublicKey: P256PublicKey;
  readonly auditorPublicKey: P256PublicKey;
  readonly message: AuditorMessage;
  readonly outputHashes: readonly Bytes32[];
  readonly salt: Bytes16;
}

/** The eleven-element prefix every custom-ring public input starts with. */
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
  return Object.freeze(
    plaintext.map(
      (field, index) =>
        bigIntToBytes(
          (bytesToBigInt(field) + disclosureStream(secret, salt, index)) % BN254_MODULUS,
        ) as Bytes32,
    ),
  );
}

export function openAuditOutputDisclosure(
  secret: Bytes32,
  salt: Bytes16,
  disclosure: readonly Bytes32[],
): readonly AuditOutputOpening[] {
  if (disclosure.length !== AUDIT_DISCLOSURE_FIELD_COUNT)
    throw new RangeError("invalid audit disclosure length");
  const fields = disclosure.map(
    (field, index) =>
      bigIntToBytes(
        (bytesToBigInt(field) + BN254_MODULUS - disclosureStream(secret, salt, index)) %
          BN254_MODULUS,
      ) as Bytes32,
  );
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

/** Input order binds the audit statement, Rust `CustomRingBasePublicInput::hash`. */
export function auditPublicInputHash(input: CustomRingBasePublicInput): Bytes32 {
  return hashChain(auditChainElements(input));
}

/** The audit prefix then policy hash and roots, Rust `CustomRingPolicyPublicInput::hash`. */
export function policyPublicInputHash(
  input: CustomRingBasePublicInput &
    Readonly<{
      policyHash: Bytes32;
      stateRoot: Bytes32;
      nullifierRoot: Bytes32;
      entriesTreeId: number;
      /** `hashBytes` of the ring program id. */
      ringId: Bytes32;
      namespaceOwnerHash: Bytes32;
      /** Zero for per-transfer caps and delegate moves. */
      windowIndex: bigint;
      approvalRequired: boolean;
      revocationTargets?: readonly Bytes32[];
      headTransition?: Readonly<{
        oldRoot: Bytes32;
        newRoot: Bytes32;
        countersDisclosureHash: Bytes32;
      }>;
    }>,
): Bytes32 {
  return hashChain([
    ...auditChainElements(input),
    checkedBytes(input.policyHash, 32, "policy hash"),
    checkedBytes(input.stateRoot, 32, "state root"),
    checkedBytes(input.nullifierRoot, 32, "nullifier root"),
    treeIdField(input.entriesTreeId),
    checkedBytes(input.ringId, 32, "ring id"),
    checkedBytes(input.namespaceOwnerHash, 32, "namespace owner hash"),
    u64Field(input.windowIndex),
    u64Field(input.approvalRequired ? 1n : 0n),
    ...checkedRevocationTargets(input.revocationTargets),
    ...(input.headTransition === undefined
      ? []
      : [
          checkedBytes(input.headTransition.oldRoot, 32, "head old root"),
          checkedBytes(input.headTransition.newRoot, 32, "head new root"),
          checkedBytes(input.headTransition.countersDisclosureHash, 32, "counters disclosure hash"),
        ]),
  ]);
}

export const customRingPublicInputHash = policyPublicInputHash;

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
