import { hashBytes, hashChain4, packBytesBe } from "../hasher/index.js";
import { auditLayoutValue, type AuditLayout } from "../interface/ring-disclosure-layout.js";
import { N_PUBLIC_SLOTS } from "../interface/shape.js";
import type { Bytes16, Bytes32, Bytes33 } from "../interface/types.js";
import { checkedBytes } from "../keypair/bytes.js";
import { bigIntBytes, rightAlign } from "../transaction/internal.js";

import { RingDomain, domainField } from "../keypair/ring-domain.js";
import { RingError } from "./error.js";
import {
  RingTransactData,
  outputBodyHash,
  outputRecipientKeyFields,
  outputTagField,
  taggedX25519,
  type RingOutput,
} from "./transact.js";

/** The values every audit statement opens with, Rust `AuditHead`. */
export interface AuditHead {
  readonly firstNullifier: Bytes32;
  /** `hash_bytes` of the ring program id. */
  readonly ringId: Bytes32;
  readonly txViewingU: Bytes32;
  /** `0x04 ‖ u` as the ring config stores it. */
  readonly auditorPubkey: Bytes33;
  readonly ephU: Bytes32;
  readonly sealed: Bytes32;
  readonly salt: Bytes16;
  readonly layout: AuditLayout;
}

export type AuditKind =
  | Readonly<{ kind: "packed" }>
  | Readonly<{ kind: "delivered" }>
  | Readonly<{
      kind: "anonymous";
      privateTxHash: Bytes32;
      epoch: bigint;
      /** Zero without a pair-anchored slot. */
      firstContactRoot: Bytes32;
      /** Zero outside a policy ring. */
      senderCommitment: Bytes32;
    }>;

/** Every ring transfer's audit proof, Rust `AuditStatement`. */
export interface AuditStatement {
  readonly head: AuditHead;
  /** Published output order. */
  readonly outputs: readonly RingOutput[];
  /** Exactly the published disclosure fields. */
  readonly disclosure: readonly Bytes32[];
  readonly kind: AuditKind;
}

export type PolicyKey =
  | Readonly<{ kind: "member"; anonymous: boolean }>
  | Readonly<{ kind: "delegate" }>;

/** A policy ring transfer's policy proof, Rust `PolicyStatement`. */
export interface PolicyStatement {
  readonly key: PolicyKey;
  readonly privateTxHash: Bytes32;
  readonly policyHash: Bytes32;
  readonly ringId: Bytes32;
  readonly approvalRequired: boolean;
  readonly keyEscrow: boolean;
  readonly ownRoot: Bytes32;
  /** Zero without a curator source. */
  readonly curatorRoot: Bytes32;
  /** The owner signer's identity, the sender commitment on an anonymous ring, zero on the delegate rail. */
  readonly sender: Bytes32;
  /** SPP's public asset fields, zero past the used slots. */
  readonly publicAssets: readonly Bytes32[];
  /** SPP's public amount fields, a withdrawal is `q - |amount|`. */
  readonly publicAmounts: readonly Bytes32[];
}

/** An application of `count` queued writes, Rust `ApplyRecordsStatement`. */
export interface ApplyRecordsStatement {
  readonly oldRoot: Bytes32;
  readonly newRoot: Bytes32;
  readonly oldNextIndex: number;
  readonly newNextIndex: number;
  /** `chain(head - 1)`. */
  readonly chainStart: Bytes32;
  /** `chain(tail - 1)`. */
  readonly chainEnd: Bytes32;
  readonly count: bigint;
}

/** The auditor envelope of a registered nullifier key, Rust `RegisterKeyStatement`. */
export interface RegisterKeyStatement {
  /** The owner identity of the signing member. */
  readonly member: Bytes32;
  readonly nullifierPk: Bytes32;
  readonly auditorPubkey: Bytes33;
  readonly ephU: Bytes32;
  readonly ciphertext: Bytes32;
}

/**
 * `head ‖ [output_chain, disclosure_chain]` packed,
 * `head ‖ [output_chain, body_chain, disclosure_chain, recipient_key_chain]` delivered,
 * `head ‖ [output_chain, body_chain, disclosure_chain, private_tx_hash, tag_chain,
 * epoch, first_contact_root, sender_commitment]` anonymous.
 */
export function auditStatementElements(statement: AuditStatement): readonly Bytes32[] {
  const { outputs, kind } = statement;
  const outputChain = chain(outputs.map((output) => output.hash));
  const disclosureChain = chain(statement.disclosure);
  const head = auditHeadElements(statement.head);
  switch (kind.kind) {
    case "packed":
      return [...head, outputChain, disclosureChain];
    case "delivered":
      return [
        ...head,
        outputChain,
        chain(outputs.map(outputBodyHash)),
        disclosureChain,
        chain(outputs.flatMap(outputRecipientKeyFields)),
      ];
    case "anonymous":
      return [
        ...head,
        outputChain,
        chain(outputs.map(outputBodyHash)),
        disclosureChain,
        checkedBytes<Bytes32>(kind.privateTxHash, 32, "private tx hash"),
        chain(outputs.map(outputTagField)),
        u64Field(kind.epoch, "epoch"),
        checkedBytes<Bytes32>(kind.firstContactRoot, 32, "first contact root"),
        checkedBytes<Bytes32>(kind.senderCommitment, 32, "sender commitment"),
      ];
  }
}

export function auditStatementHash(statement: AuditStatement): Bytes32 {
  return chain(auditStatementElements(statement));
}

/** What the program supplies beside the data for the audit statement, Rust `AuditBinding`. */
export interface AuditBinding {
  /** `hash_bytes` of the ring program id. */
  readonly ringId: Bytes32;
  readonly auditorPubkey: Bytes33;
  /** The anonymous rail's statement epoch. */
  readonly epoch: bigint;
  /** The anonymous rail's first-contact root, zero without an anchor. */
  readonly firstContactRoot: Bytes32;
  /** The ring mode escrows every output nullifier key, the frame flag has to agree. */
  readonly keyEscrow: boolean;
}

/** The statement the audit proof is verified against, a key escrow flag off the ring mode refused. */
export function ringAuditStatement(data: RingTransactData, binding: AuditBinding): AuditStatement {
  if (binding.keyEscrow !== data.keyEscrow)
    throw new RingError("RING_TRANSACT_DATA_INVALID", { details: { reason: "FlagNotAllowed" } });
  const layout = RingTransactData.disclosureLayout(data);
  const kind: AuditKind =
    layout.kind === "anonymous"
      ? {
          kind: "anonymous",
          privateTxHash: data.privateTxHash,
          epoch: binding.epoch,
          firstContactRoot: binding.firstContactRoot,
          senderCommitment: data.policy?.senderCommitment ?? (new Uint8Array(32) as Bytes32),
        }
      : { kind: layout.kind };
  return Object.freeze({
    head: Object.freeze({
      firstNullifier: RingTransactData.firstNullifier(data),
      ringId: binding.ringId,
      txViewingU: data.txViewingU,
      auditorPubkey: binding.auditorPubkey,
      ephU: data.ephU,
      sealed: data.sealed,
      salt: data.salt,
      layout: RingTransactData.auditLayout(data),
    }),
    outputs: data.outputs,
    disclosure: data.disclosure,
    kind,
  });
}

/**
 * `[CRPO, private_tx_hash, policy_hash, ring_id, anonymous, approval_required,
 * key_escrow, own_root, curator_root, sender, (asset_k, amount_k) x 3]`, the
 * delegate key without `anonymous`.
 */
export function policyStatementElements(statement: PolicyStatement): readonly Bytes32[] {
  const { publicAssets, publicAmounts } = statement;
  if (publicAssets.length !== N_PUBLIC_SLOTS || publicAmounts.length !== N_PUBLIC_SLOTS)
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name: "publicSlots", expected: N_PUBLIC_SLOTS },
    });
  return [
    domainField(RingDomain.policyStatement),
    checkedBytes<Bytes32>(statement.privateTxHash, 32, "private tx hash"),
    checkedBytes<Bytes32>(statement.policyHash, 32, "policy hash"),
    checkedBytes<Bytes32>(statement.ringId, 32, "ring id"),
    ...(statement.key.kind === "member" ? [bit(statement.key.anonymous)] : []),
    bit(statement.approvalRequired),
    bit(statement.keyEscrow),
    checkedBytes<Bytes32>(statement.ownRoot, 32, "own root"),
    checkedBytes<Bytes32>(statement.curatorRoot, 32, "curator root"),
    checkedBytes<Bytes32>(statement.sender, 32, "sender"),
    ...publicAssets.flatMap((asset, slot) => [
      checkedBytes<Bytes32>(asset, 32, "public asset"),
      checkedBytes<Bytes32>(publicAmounts[slot] as Bytes32, 32, "public amount"),
    ]),
  ];
}

export function policyStatementHash(statement: PolicyStatement): Bytes32 {
  return chain(policyStatementElements(statement));
}

/** `[CRAP, old_root, new_root, old_next, new_next, chain_start, chain_end, count]`. */
export function applyRecordsStatementElements(
  statement: ApplyRecordsStatement,
): readonly Bytes32[] {
  return [
    domainField(RingDomain.applyRecords),
    checkedBytes<Bytes32>(statement.oldRoot, 32, "old root"),
    checkedBytes<Bytes32>(statement.newRoot, 32, "new root"),
    u64Field(BigInt(statement.oldNextIndex), "old next index", U32_MAX),
    u64Field(BigInt(statement.newNextIndex), "new next index", U32_MAX),
    checkedBytes<Bytes32>(statement.chainStart, 32, "chain start"),
    checkedBytes<Bytes32>(statement.chainEnd, 32, "chain end"),
    u64Field(statement.count, "count"),
  ];
}

export function applyRecordsStatementHash(statement: ApplyRecordsStatement): Bytes32 {
  return chain(applyRecordsStatementElements(statement));
}

/** `[CRRG, member, nullifier_pk, aud0, aud1, eph0, eph1, hash_bytes(ciphertext)]`. */
export function registerKeyStatementElements(statement: RegisterKeyStatement): readonly Bytes32[] {
  return [
    domainField(RingDomain.registerKey),
    checkedBytes<Bytes32>(statement.member, 32, "member"),
    checkedBytes<Bytes32>(statement.nullifierPk, 32, "nullifier pk"),
    ...packedKey(checkedBytes<Bytes33>(statement.auditorPubkey, 33, "auditor pubkey")),
    ...packedKey(taggedX25519(statement.ephU)),
    hashBytes(checkedBytes<Bytes32>(statement.ciphertext, 32, "ciphertext")) as Bytes32,
  ];
}

export function registerKeyStatementHash(statement: RegisterKeyStatement): Bytes32 {
  return chain(registerKeyStatementElements(statement));
}

const U32_MAX = 0xffff_ffffn;
const U64_MAX = 0xffff_ffff_ffff_ffffn;

/** `[CRAU, n0, ring_id, txpk0, txpk1, aud0, aud1, eph0, eph1, sealed_hash, salt, layout]`. */
function auditHeadElements(head: AuditHead): readonly Bytes32[] {
  return [
    domainField(RingDomain.auditStatement),
    checkedBytes<Bytes32>(head.firstNullifier, 32, "first nullifier"),
    checkedBytes<Bytes32>(head.ringId, 32, "ring id"),
    ...packedKey(taggedX25519(head.txViewingU)),
    ...packedKey(checkedBytes<Bytes33>(head.auditorPubkey, 33, "auditor pubkey")),
    ...packedKey(taggedX25519(head.ephU)),
    hashBytes(checkedBytes<Bytes32>(head.sealed, 32, "sealed")) as Bytes32,
    rightAlign(checkedBytes<Bytes16>(head.salt, 16, "salt")),
    rightAlign(Uint8Array.of(auditLayoutValue(head.layout))),
  ];
}

function packedKey(key: Bytes33): readonly Bytes32[] {
  return packBytesBe(key) as Bytes32[];
}

function chain(values: readonly Bytes32[]): Bytes32 {
  return hashChain4(values) as Bytes32;
}

function bit(value: boolean): Bytes32 {
  return rightAlign(Uint8Array.of(value ? 1 : 0));
}

function u64Field(value: bigint, name: string, maximum = U64_MAX): Bytes32 {
  if (typeof value !== "bigint" || value < 0n || value > maximum)
    throw new RingError("RING_INVALID_LENGTH", {
      details: { name, minimum: "0", maximum: maximum.toString() },
    });
  return bigIntBytes(value) as Bytes32;
}
