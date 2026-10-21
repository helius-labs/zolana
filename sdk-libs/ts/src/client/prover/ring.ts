import { bytesToHex } from "@noble/hashes/utils.js";

import { InterfaceError } from "../../interface/errors.js";
import {
  APPLY_BATCH,
  QUAD_ARITY,
  QUAD_HEIGHT,
  type ApplyProofInputs,
  type QuadPath,
  type QueueEntry,
  type RecordOpening,
  type RecordWriteProofInput,
} from "../../interface/member-registry.js";
import { ringCircuitType, type RingKeyCircuit } from "../../interface/proving-keys.js";
import { RING_DEPOSIT_AUDIT_SLOTS } from "../../interface/ring-deposit-capsule.js";
import { auditLayoutValue, type AuditLayout } from "../../interface/ring-disclosure-layout.js";
import { N_PUBLIC_SLOTS } from "../../interface/shape.js";
import type { Bytes16, Bytes32 } from "../../interface/types.js";
import { BODY_LEN, J_INBOX } from "../../keypair/ring-stream.js";
import { ClientError } from "../error.js";
import { bytesField } from "../internal.js";
import {
  RING_INLINE_ASSET_SLOTS,
  RING_OUTFLOW_LIMIT_SLOTS,
  RING_RULE_SLOTS,
  RING_SOURCE_SLOTS,
  RING_STATE_PATH_LENGTH,
  type PresentRecordOpening,
} from "./types.js";

/** Go `Opening`, one transaction slot as the ring circuits open it. */
export interface RingSlotOpening {
  readonly domain: Bytes32;
  readonly treeId: Bytes32;
  readonly ownerPkHash: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly asset: Bytes32;
  readonly amount: Bytes32;
  readonly blinding: Bytes32;
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
  readonly ringProgramId: Bytes32;
}

/** Go `AuditParams`, the envelope inputs every audit proof opens with. */
export interface AuditEnvelopeProofInputs {
  readonly firstNullifier: Bytes32;
  readonly ringId: Bytes32;
  /** The clamped secret the envelope seals. */
  readonly txViewingSk: Bytes32;
  readonly ephSk: Bytes32;
  /** The auditor's X25519 u without the tag byte. */
  readonly auditorPk: Bytes32;
  readonly salt: Bytes16;
  /** SPP's derived output seed, every exit blinding derives from it. */
  readonly seedOut: Bytes32;
  /** The statement's layout element, its flags fix the published fields. */
  readonly layout: AuditLayout;
}

/** Go `DeliveredOutput`, a delivered slot and the body its recipient decrypts. */
export interface DeliveredSlotProofInputs {
  readonly output: RingSlotOpening;
  /** All zero for SOL. */
  readonly assetAddress: Bytes32;
  readonly recipientKey: Bytes32;
  readonly ownerKey: Bytes32;
  readonly body: Uint8Array;
}

/** Go `Stream`, a ring output takes exactly one of `inbox`, `pair` and `self`. */
export interface AnonymousStreamPosition {
  readonly tag: Bytes32;
  readonly inbox: boolean;
  readonly pair: boolean;
  readonly self: boolean;
  readonly index: number;
}

/** Go `AnonymousOutput`. */
export interface AnonymousSlotProofInputs extends DeliveredSlotProofInputs {
  readonly stream: AnonymousStreamPosition;
}

/** Go `Anchor`, the first contact whose slot secret keys the transfer's one pair stream. */
export interface FirstContactAnchor {
  readonly treeId: Bytes32;
  readonly asset: Bytes32;
  readonly amount: Bytes32;
  readonly slotSecret: Bytes32;
  readonly firstNullifier: Bytes32;
  readonly slotIndex: number;
  /** The epoch and index of the first contact's inbox tag. */
  readonly epoch: bigint;
  readonly index: number;
  readonly pathIndex: bigint;
  /** State tree siblings, leaf level first. */
  readonly path: readonly Bytes32[];
}

/** Go `Source`, a zero `registry` names the ring's own registry. */
export interface PolicySourceProofInput {
  readonly listId: number;
  readonly registry: Bytes32;
}

/** Go `OutflowLimit`. */
export interface OutflowLimitProofInput {
  readonly asset: Bytes32;
  readonly cap: Bytes32;
  readonly cosignAbove: Bytes32;
}

/** Go `PolicyTable`, every row past its count zero. */
export interface PolicyTableProofInputs {
  readonly sources: readonly PolicySourceProofInput[];
  readonly policyLen: number;
  readonly rules: readonly Bytes32[];
  readonly inlineAssets: readonly Bytes32[];
  readonly inlineLimits: readonly Bytes32[];
  readonly inlineCount: number;
  readonly limits: readonly OutflowLimitProofInput[];
  readonly limitCount: number;
}

/** Go `OutputOpening`, `ctHash` absent without key escrow. */
export interface PolicyOutputOpening extends RingSlotOpening {
  readonly ctHash?: Bytes32;
}

/** Go `Entry`, an absent opening assigns zeros. */
export interface PolicySubjectEntry {
  readonly own: RecordOpening | undefined;
  readonly curator: RecordOpening | undefined;
}

/** Go `PolicyParams`, one owner and one asset entry per output. */
export interface PolicyProofInputs extends PolicyTableProofInputs {
  readonly privateTxHash: Bytes32;
  readonly policyHash: Bytes32;
  readonly ringId: Bytes32;
  readonly ownRoot: Bytes32;
  readonly curatorRoot: Bytes32;
  readonly publicAssets: readonly Bytes32[];
  readonly publicAmounts: readonly Bytes32[];
  readonly addressChain: Bytes32;
  readonly privateTxBlinding: Bytes32;
  readonly outputs: readonly PolicyOutputOpening[];
  readonly senderPkHash: Bytes32;
  readonly senderEntry: PolicySubjectEntry;
  readonly ownerEntries: readonly PolicySubjectEntry[];
  readonly assetEntries: readonly PolicySubjectEntry[];
}

/** Go `MergeInput`, one SPP merge slot. */
export interface MergeInputOpening {
  readonly domain: Bytes32;
  readonly treeId: Bytes32;
  readonly amount: Bytes32;
  readonly blinding: Bytes32;
  readonly ringDataHash: Bytes32;
}

/** Go `PackedAuditParams`, `outputs` and `ownerKeys` at the key's capacity. */
export interface PackedAuditProofRequest extends AuditEnvelopeProofInputs {
  readonly kind: "packedAudit";
  readonly publicInputHash: Bytes32;
  /** The published output count. */
  readonly nOut: number;
  readonly outputs: readonly RingSlotOpening[];
  readonly ownerKeys: readonly Bytes32[];
}

/** Go `DeliveredAuditParams`, every slot published. */
export interface DeliveredAuditProofRequest extends AuditEnvelopeProofInputs {
  readonly kind: "deliveredAudit";
  readonly publicInputHash: Bytes32;
  readonly outputs: readonly DeliveredSlotProofInputs[];
}

/** Go `AnonymousAuditParams`, `inputs` fill the input class. */
export interface AnonymousAuditProofRequest extends AuditEnvelopeProofInputs {
  readonly kind: "anonymousAudit";
  readonly publicInputHash: Bytes32;
  readonly outputs: readonly AnonymousSlotProofInputs[];
  readonly privateTxHash: Bytes32;
  readonly privateTxBlinding: Bytes32;
  readonly senderKey: Bytes32;
  /** The published nullifier count, the slots past it carry no UTXO. */
  readonly inputCount: number;
  readonly inputs: readonly RingSlotOpening[];
  readonly senderCommitment: Bytes32;
  readonly epoch: bigint;
  readonly firstContactRoot: Bytes32;
  /** Absent without a pair-tagged slot. */
  readonly anchor?: FirstContactAnchor;
}

/** Go `MemberPolicyParams`. */
export interface MemberPolicyProofRequest extends PolicyProofInputs {
  readonly kind: "memberPolicy";
  readonly publicInputHash: Bytes32;
  readonly anonymous: boolean;
  readonly approvalRequired: boolean;
  readonly keyEscrow: boolean;
  readonly sender: Bytes32;
  readonly inputChain: Bytes32;
}

/** Go `DelegatePolicyParams`. */
export interface DelegatePolicyProofRequest extends PolicyProofInputs {
  readonly kind: "delegatePolicy";
  readonly publicInputHash: Bytes32;
  readonly inputs: readonly RingSlotOpening[];
}

/** Go `ApplyRecordsParams`, one write takes the 1-write key, more the batch key. */
export interface ApplyRecordsProofRequest extends ApplyProofInputs {
  readonly kind: "applyRecords";
  readonly publicInputHash: Bytes32;
}

/** Go `KeyRegisterParams`. */
export interface RegisterKeyProofRequest {
  readonly kind: "registerKey";
  readonly publicInputHash: Bytes32;
  /** The owner identity of the signing member. */
  readonly member: Bytes32;
  /** A zero lead byte then the 31 secret bytes. */
  readonly nullifierSecret: Bytes32;
  readonly ephSk: Bytes32;
  readonly auditorPk: Bytes32;
}

/** Go `DepositParams`, every slot list at the deposit capacity. */
export interface DepositProofRequest {
  readonly kind: "deposit";
  readonly publicInputHash: Bytes32;
  readonly contextHash: Bytes32;
  readonly count: number;
  readonly anonymous: boolean;
  readonly ownerPkHashes: readonly Bytes32[];
  /** Absent keys assign zeros, only an anonymous deposit names them. */
  readonly ownerKeys?: readonly Bytes32[];
  readonly nullifierPks: readonly Bytes32[];
  readonly blindingSecrets: readonly Bytes32[];
  readonly ctHashes: readonly Bytes32[];
  readonly members: readonly (PresentRecordOpening | undefined)[];
  readonly ephSk: Bytes32;
  readonly auditorPk: Bytes32;
  readonly keyEscrow: boolean;
  readonly memberRegistryRoot: Bytes32;
}

/** Go `MergeAnonymousParams`. */
export interface AnonymousMergeProofRequest {
  readonly kind: "anonymousMerge";
  readonly publicInputHash: Bytes32;
  readonly privateTxHash: Bytes32;
  readonly outputUtxoHash: Bytes32;
  readonly firstNullifier: Bytes32;
  readonly ringProgramId: Bytes32;
  readonly auditorPk: Bytes32;
  /** The SPP output ciphertext salt as one field. */
  readonly salt: Bytes32;
  readonly ephSk: Bytes32;
  readonly disclosureKey: Bytes32;
  readonly ownerKey: Bytes32;
  readonly nullifierSecret: Bytes32;
  readonly mintChunks: readonly Bytes32[];
  readonly inputs: readonly MergeInputOpening[];
  readonly outputTreeId: Bytes32;
  readonly outputRingDataHash: Bytes32;
}

export type RingProofRequest =
  | PackedAuditProofRequest
  | DeliveredAuditProofRequest
  | AnonymousAuditProofRequest
  | MemberPolicyProofRequest
  | DelegatePolicyProofRequest
  | ApplyRecordsProofRequest
  | RegisterKeyProofRequest
  | DepositProofRequest
  | AnonymousMergeProofRequest;

/** The key a request proves under, its list widths pick the shape. */
export function ringProofCircuit(request: RingProofRequest): RingKeyCircuit {
  switch (request.kind) {
    case "packedAudit":
      return { family: "packedAudit", outputs: request.outputs.length };
    case "deliveredAudit":
      return { family: "deliveredAudit", outputs: request.outputs.length };
    case "anonymousAudit":
      return {
        family: request.layout.fullOpenings ? "anonymousEntryAudit" : "anonymousAudit",
        inputClass: request.inputs.length,
        outputs: request.outputs.length,
      };
    case "memberPolicy":
      return { family: "memberPolicy", outputs: request.outputs.length };
    case "delegatePolicy":
      return {
        family: "delegatePolicy",
        inputs: request.inputs.length,
        outputs: request.outputs.length,
      };
    case "applyRecords":
      return { family: "applyRecords", writes: applyCapacity(request.writes.length) };
    case "registerKey":
      return { family: "registerKey" };
    case "deposit":
      return { family: "deposit" };
    case "anonymousMerge":
      return { family: "anonymousMerge", width: request.inputs.length };
  }
}

/** The body the prover's strict decoder accepts, keys in Go declaration order. */
export function ringProofRequestBody(request: RingProofRequest): Readonly<Record<string, unknown>> {
  const head = {
    circuitType: keyedCircuitType(request),
    publicInputHash: field(request.publicInputHash, "publicInputHash"),
  };
  switch (request.kind) {
    case "packedAudit": {
      const capacity = request.outputs.length;
      return {
        ...head,
        ...envelopeJson(request),
        nOut: integer(request.nOut, "nOut", 1, capacity),
        outputs: request.outputs.map((output, i) => openingJson(output, `outputs[${i}]`)),
        ownerKeys: sized(request.ownerKeys, capacity, "ownerKeys").map((key, i) =>
          hexBytes(key, 32, `ownerKeys[${i}]`),
        ),
      };
    }
    case "deliveredAudit":
      return {
        ...head,
        ...envelopeJson(request),
        outputs: request.outputs.map((output, i) => deliveredJson(output, `outputs[${i}]`)),
      };
    case "anonymousAudit":
      return {
        ...head,
        ...envelopeJson(request),
        outputs: request.outputs.map((output, i) => anonymousSlotJson(output, `outputs[${i}]`)),
        privateTxHash: field(request.privateTxHash, "privateTxHash"),
        privateTxBlinding: field(request.privateTxBlinding, "privateTxBlinding"),
        senderKey: hexBytes(request.senderKey, 32, "senderKey"),
        inputCount: integer(request.inputCount, "inputCount", 1, request.inputs.length),
        inputs: request.inputs.map((input, i) => openingJson(input, `inputs[${i}]`)),
        senderCommitment: field(request.senderCommitment, "senderCommitment"),
        epoch: u64(request.epoch, "epoch"),
        firstContactRoot: field(request.firstContactRoot, "firstContactRoot"),
        ...(request.anchor === undefined ? {} : { anchor: anchorJson(request.anchor) }),
      };
    case "memberPolicy":
      return {
        ...head,
        anonymous: flag(request.anonymous),
        approvalRequired: flag(request.approvalRequired),
        keyEscrow: flag(request.keyEscrow),
        sender: field(request.sender, "sender"),
        inputChain: field(request.inputChain, "inputChain"),
        ...policyJson(request),
      };
    case "delegatePolicy":
      return {
        ...head,
        inputs: request.inputs.map((input, i) => openingJson(input, `inputs[${i}]`)),
        ...policyJson(request),
      };
    case "applyRecords": {
      const capacity = applyCapacity(request.writes.length);
      return {
        ...head,
        oldRoot: field(request.oldRoot, "oldRoot"),
        newRoot: field(request.newRoot, "newRoot"),
        oldNextIndex: integer(request.oldNextIndex, "oldNextIndex", 0, U32_MAX),
        newNextIndex: integer(request.newNextIndex, "newNextIndex", 0, U32_MAX),
        chainStart: field(request.chainStart, "chainStart"),
        chainEnd: field(request.chainEnd, "chainEnd"),
        count: request.writes.length,
        // A slot past the count assigns zeros.
        writes: Array.from({ length: capacity }, (_, i) => {
          const write = request.writes[i];
          return write === undefined ? null : writeJson(write, `writes[${i}]`);
        }),
      };
    }
    case "registerKey":
      return {
        ...head,
        member: field(request.member, "member"),
        nullifierSecret: hexBytes(request.nullifierSecret, 32, "nullifierSecret"),
        ephSk: hexBytes(request.ephSk, 32, "ephSk"),
        auditorPk: hexBytes(request.auditorPk, 32, "auditorPk"),
      };
    case "deposit":
      return {
        ...head,
        contextHash: field(request.contextHash, "contextHash"),
        count: integer(request.count, "count", 1, RING_DEPOSIT_AUDIT_SLOTS),
        ...(flag(request.anonymous) ? { anonymous: true } : {}),
        ownerPkHashes: fields(request.ownerPkHashes, RING_DEPOSIT_AUDIT_SLOTS, "ownerPkHashes"),
        ...(request.ownerKeys === undefined
          ? {}
          : {
              ownerKeys: sized(request.ownerKeys, RING_DEPOSIT_AUDIT_SLOTS, "ownerKeys").map(
                (key, i) => hexBytes(key, 32, `ownerKeys[${i}]`),
              ),
            }),
        nullifierPks: fields(request.nullifierPks, RING_DEPOSIT_AUDIT_SLOTS, "nullifierPks"),
        blindingSecrets: fields(
          request.blindingSecrets,
          RING_DEPOSIT_AUDIT_SLOTS,
          "blindingSecrets",
        ),
        ctHashes: fields(request.ctHashes, RING_DEPOSIT_AUDIT_SLOTS, "ctHashes"),
        members: sized(request.members, RING_DEPOSIT_AUDIT_SLOTS, "members").map((member, i) =>
          member === undefined ? null : recordJson(member, `members[${i}]`),
        ),
        ephSk: hexBytes(request.ephSk, 32, "ephSk"),
        auditorPk: hexBytes(request.auditorPk, 32, "auditorPk"),
        keyEscrow: flag(request.keyEscrow),
        memberRegistryRoot: field(request.memberRegistryRoot, "memberRegistryRoot"),
      };
    case "anonymousMerge":
      return {
        ...head,
        privateTxHash: field(request.privateTxHash, "privateTxHash"),
        outputUtxoHash: field(request.outputUtxoHash, "outputUtxoHash"),
        firstNullifier: field(request.firstNullifier, "firstNullifier"),
        ringProgramId: field(request.ringProgramId, "ringProgramId"),
        auditorPk: hexBytes(request.auditorPk, 32, "auditorPk"),
        salt: field(request.salt, "salt"),
        ephSk: hexBytes(request.ephSk, 32, "ephSk"),
        disclosureKey: hexBytes(request.disclosureKey, 32, "disclosureKey"),
        ownerKey: hexBytes(request.ownerKey, 32, "ownerKey"),
        nullifierSecret: field(request.nullifierSecret, "nullifierSecret"),
        mintChunks: fields(request.mintChunks, MINT_CHUNKS, "mintChunks"),
        inputs: request.inputs.map((input, i) => mergeInputJson(input, `inputs[${i}]`)),
        outputTreeId: field(request.outputTreeId, "outputTreeId"),
        outputRingDataHash: field(request.outputRingDataHash, "outputRingDataHash"),
      };
  }
}

type Json = Readonly<Record<string, unknown>>;

const U8_MAX = 0xff;
const U32_MAX = 0xffff_ffff;
/** Go `[2]Field`, the two `hash_bytes_32` halves of the merged mint. */
const MINT_CHUNKS = 2;
const ZERO = new Uint8Array(32) as Bytes32;

/** One write takes the 1-write key, 2 to `APPLY_BATCH` the batch key, any other count none. */
function applyCapacity(count: number): number {
  return count >= 2 && count <= APPLY_BATCH ? APPLY_BATCH : count;
}

/** A list width no key serves fails here, before any encoding. */
function keyedCircuitType(request: RingProofRequest): string {
  return proofInput(() => ringCircuitType(ringProofCircuit(request)));
}

/** An interface refusal of a request value is an invalid proof input. */
function proofInput<T>(read: () => T): T {
  try {
    return read();
  } catch (cause) {
    if (cause instanceof InterfaceError) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    throw cause;
  }
}

function envelopeJson(envelope: AuditEnvelopeProofInputs): Json {
  return {
    firstNullifier: field(envelope.firstNullifier, "firstNullifier"),
    ringId: field(envelope.ringId, "ringId"),
    txViewingSk: hexBytes(envelope.txViewingSk, 32, "txViewingSk"),
    ephSk: hexBytes(envelope.ephSk, 32, "ephSk"),
    auditorPk: hexBytes(envelope.auditorPk, 32, "auditorPk"),
    salt: hexBytes(envelope.salt, 16, "salt"),
    seedOut: field(envelope.seedOut, "seedOut"),
    layout: proofInput(() => auditLayoutValue(envelope.layout)),
  };
}

function openingJson(opening: RingSlotOpening, name: string): Json {
  return {
    domain: field(opening.domain, `${name}.domain`),
    treeId: field(opening.treeId, `${name}.treeId`),
    ownerPkHash: field(opening.ownerPkHash, `${name}.ownerPkHash`),
    nullifierPk: field(opening.nullifierPk, `${name}.nullifierPk`),
    asset: field(opening.asset, `${name}.asset`),
    amount: field(opening.amount, `${name}.amount`),
    blinding: field(opening.blinding, `${name}.blinding`),
    dataHash: field(opening.dataHash, `${name}.dataHash`),
    ringDataHash: field(opening.ringDataHash, `${name}.ringDataHash`),
    ringProgramId: field(opening.ringProgramId, `${name}.ringProgramId`),
  };
}

function deliveredJson(slot: DeliveredSlotProofInputs, name: string): Json {
  return {
    output: openingJson(slot.output, `${name}.output`),
    assetAddress: hexBytes(slot.assetAddress, 32, `${name}.assetAddress`),
    recipientKey: hexBytes(slot.recipientKey, 32, `${name}.recipientKey`),
    ownerKey: hexBytes(slot.ownerKey, 32, `${name}.ownerKey`),
    body: hexBytes(slot.body, BODY_LEN, `${name}.body`),
  };
}

function anonymousSlotJson(slot: AnonymousSlotProofInputs, name: string): Json {
  const stream = slot.stream;
  return {
    ...deliveredJson(slot, name),
    stream: {
      tag: field(stream.tag, `${name}.stream.tag`),
      inbox: flag(stream.inbox),
      pair: flag(stream.pair),
      self: flag(stream.self),
      index: integer(stream.index, `${name}.stream.index`, 0, J_INBOX - 1),
    },
  };
}

function anchorJson(anchor: FirstContactAnchor): Json {
  return {
    treeId: field(anchor.treeId, "anchor.treeId"),
    asset: field(anchor.asset, "anchor.asset"),
    amount: field(anchor.amount, "anchor.amount"),
    slotSecret: field(anchor.slotSecret, "anchor.slotSecret"),
    firstNullifier: field(anchor.firstNullifier, "anchor.firstNullifier"),
    slotIndex: integer(anchor.slotIndex, "anchor.slotIndex", 0, U8_MAX),
    epoch: u64(anchor.epoch, "anchor.epoch"),
    index: integer(anchor.index, "anchor.index", 0, J_INBOX - 1),
    pathIndex: u64(anchor.pathIndex, "anchor.pathIndex"),
    path: fields(anchor.path, RING_STATE_PATH_LENGTH, "anchor.path"),
  };
}

function policyJson(policy: PolicyProofInputs): Json {
  const outputs = policy.outputs.length;
  return {
    privateTxHash: field(policy.privateTxHash, "privateTxHash"),
    policyHash: field(policy.policyHash, "policyHash"),
    ringId: field(policy.ringId, "ringId"),
    ownRoot: field(policy.ownRoot, "ownRoot"),
    curatorRoot: field(policy.curatorRoot, "curatorRoot"),
    publicAssets: fields(policy.publicAssets, N_PUBLIC_SLOTS, "publicAssets"),
    publicAmounts: fields(policy.publicAmounts, N_PUBLIC_SLOTS, "publicAmounts"),
    sources: sized(policy.sources, RING_SOURCE_SLOTS, "sources").map((source, i) => ({
      listId: integer(source.listId, `sources[${i}].listId`, 0, U8_MAX),
      registry: field(source.registry, `sources[${i}].registry`),
    })),
    policyLen: integer(policy.policyLen, "policyLen", 0, RING_RULE_SLOTS),
    rules: fields(policy.rules, RING_RULE_SLOTS, "rules"),
    inlineAssets: fields(policy.inlineAssets, RING_INLINE_ASSET_SLOTS, "inlineAssets"),
    inlineLimits: fields(policy.inlineLimits, RING_INLINE_ASSET_SLOTS, "inlineLimits"),
    inlineCount: integer(policy.inlineCount, "inlineCount", 0, RING_INLINE_ASSET_SLOTS),
    limits: sized(policy.limits, RING_OUTFLOW_LIMIT_SLOTS, "limits").map((limit, i) => ({
      asset: field(limit.asset, `limits[${i}].asset`),
      cap: field(limit.cap, `limits[${i}].cap`),
      cosignAbove: field(limit.cosignAbove, `limits[${i}].cosignAbove`),
    })),
    limitCount: integer(policy.limitCount, "limitCount", 0, RING_OUTFLOW_LIMIT_SLOTS),
    addressChain: field(policy.addressChain, "addressChain"),
    privateTxBlinding: field(policy.privateTxBlinding, "privateTxBlinding"),
    outputs: policy.outputs.map((output, i) => ({
      ...openingJson(output, `outputs[${i}]`),
      ...(output.ctHash === undefined
        ? {}
        : { ctHash: field(output.ctHash, `outputs[${i}].ctHash`) }),
    })),
    senderPkHash: field(policy.senderPkHash, "senderPkHash"),
    senderEntry: entryJson(policy.senderEntry, "senderEntry"),
    ownerEntries: sized(policy.ownerEntries, outputs, "ownerEntries").map((entry, i) =>
      entryJson(entry, `ownerEntries[${i}]`),
    ),
    assetEntries: sized(policy.assetEntries, outputs, "assetEntries").map((entry, i) =>
      entryJson(entry, `assetEntries[${i}]`),
    ),
  };
}

function entryJson(entry: PolicySubjectEntry, name: string): Json {
  return {
    own: memberOpeningJson(entry.own, `${name}.own`),
    curator: memberOpeningJson(entry.curator, `${name}.curator`),
  };
}

/** Go `MemberOpening`, the side the opening does not use is zero. */
function memberOpeningJson(opening: RecordOpening | undefined, name: string): Json | null {
  if (opening === undefined) return null;
  if (opening.kind !== "present" && opening.kind !== "absent")
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  const present = opening.kind === "present";
  const record = present ? opening.record : undefined;
  const low = present ? undefined : opening.low;
  return {
    present,
    next: field(record?.next ?? ZERO, `${name}.next`),
    lists: u64(record?.lists ?? 0n, `${name}.lists`),
    escrowKey: field(record?.escrowKey ?? ZERO, `${name}.escrowKey`),
    ...quadPathJson(opening.path, name, "index", "path"),
    lowMember: field(low?.member ?? ZERO, `${name}.lowMember`),
    lowNext: field(low?.next ?? ZERO, `${name}.lowNext`),
    lowLists: u64(low?.lists ?? 0n, `${name}.lowLists`),
    lowEscrow: field(low?.escrowKey ?? ZERO, `${name}.lowEscrow`),
  };
}

/** Go `RecordOpening`, the present record a deposit and a ring merge prove. */
export function recordJson(opening: PresentRecordOpening, name: string): Json {
  if (opening.kind !== "present") throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  return {
    next: field(opening.record.next, `${name}.next`),
    lists: u64(opening.record.lists, `${name}.lists`),
    escrowKey: field(opening.record.escrowKey, `${name}.escrowKey`),
    ...quadPathJson(opening.path, name, "index", "path"),
  };
}

function writeJson(write: RecordWriteProofInput, name: string): Json {
  return {
    entry: queueEntryJson(write.entry, `${name}.entry`),
    exists: flag(write.exists),
    oldNext: field(write.oldNext, `${name}.oldNext`),
    oldLists: u64(write.oldLists, `${name}.oldLists`),
    oldEscrow: field(write.oldEscrow, `${name}.oldEscrow`),
    ...quadPathJson(write.slot, name, "index", "path"),
    lowMember: field(write.low.member, `${name}.lowMember`),
    lowNext: field(write.low.next, `${name}.lowNext`),
    lowLists: u64(write.low.lists, `${name}.lowLists`),
    lowEscrow: field(write.low.escrowKey, `${name}.lowEscrow`),
    ...quadPathJson(write.lowPath, name, "lowIndex", "lowPath"),
  };
}

function queueEntryJson(entry: QueueEntry, name: string): Json {
  return {
    member: field(entry.member, `${name}.member`),
    mask: u64(entry.mask, `${name}.mask`),
    value: u64(entry.value, `${name}.value`),
    escrowKey: field(entry.escrowKey, `${name}.escrowKey`),
  };
}

function mergeInputJson(input: MergeInputOpening, name: string): Json {
  return {
    domain: field(input.domain, `${name}.domain`),
    treeId: field(input.treeId, `${name}.treeId`),
    amount: field(input.amount, `${name}.amount`),
    blinding: field(input.blinding, `${name}.blinding`),
    ringDataHash: field(input.ringDataHash, `${name}.ringDataHash`),
  };
}

/** Go keeps the index and the flat siblings, leaf level first, three per level in child order. */
function quadPathJson(path: QuadPath, name: string, index: string, siblings: string): Json {
  const levels = sized(path.siblings, QUAD_HEIGHT, `${name}.${siblings}`);
  return {
    [index]: integer(path.index, `${name}.${index}`, 0, Number.MAX_SAFE_INTEGER),
    [siblings]: levels.flatMap((level, l) =>
      fields(level, QUAD_ARITY - 1, `${name}.${siblings}[${l}]`),
    ),
  };
}

/** Go `Field`, `0x` and 64 lowercase hex digits below the modulus. */
function field(value: Bytes32, name: string): string {
  const bytes = checkedLength(value, 32, name);
  bytesField(bytes, name);
  return `0x${bytesToHex(bytes)}`;
}

function fields(values: readonly Bytes32[], length: number, name: string): readonly string[] {
  return sized(values, length, name).map((value, i) => field(value, `${name}[${i}]`));
}

/** Go `Bytes`, the circuit array it fills fixes its length. */
function hexBytes(value: Uint8Array, length: number, name: string): string {
  return `0x${bytesToHex(checkedLength(value, length, name))}`;
}

function checkedLength(value: Uint8Array, length: number, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length)
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: {
        field: name,
        expected: length,
        actual: value instanceof Uint8Array ? value.length : -1,
      },
    });
  return value;
}

function sized<T>(values: readonly T[], length: number, name: string): readonly T[] {
  if (!Array.isArray(values) || values.length !== length)
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: {
        field: name,
        expected: length,
        actual: Array.isArray(values) ? values.length : -1,
      },
    });
  return values;
}

function integer(value: number, name: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum)
    throw new ClientError("CLIENT_INVALID_INTEGER", {
      details: { field: name, length: byteWidth(maximum) },
    });
  return value;
}

/** Go `uint64`, sent as a JSON number, so above the safe range no JSON number is exact. */
function u64(value: bigint, name: string): number {
  if (typeof value !== "bigint" || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER))
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field: name, length: 8 } });
  return Number(value);
}

function flag(value: boolean): boolean {
  if (typeof value !== "boolean") throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  return value;
}

function byteWidth(maximum: number): number {
  return maximum <= U8_MAX ? 1 : maximum <= U32_MAX ? 4 : 8;
}
