import { CUSTOM_RING_PROOF_LENGTH } from "../client/prover/proof.js";
import {
  RING_INLINE_ASSET_SLOTS,
  RING_OUTFLOW_LIMIT_SLOTS,
  RING_RULE_SLOTS,
  RING_SOURCE_SLOTS,
} from "../client/prover/types.js";
import { Reader, encodeBase58 } from "../interface/internal.js";
import {
  APPLY_BATCH,
  MEMBER_REGISTRY_CAPACITY,
  MEMBER_REGISTRY_ROOT_HISTORY,
} from "../interface/member-registry.js";
import type { Address, Bytes32, Bytes33 } from "../interface/types.js";
import { tagEpoch } from "../keypair/ring-stream.js";
import { X25519PublicKey } from "../keypair/x25519.js";
import { ZERO_32, bytesToBigInt } from "../transaction/internal.js";
import { equalBytes } from "../wallet/internal.js";

import { RingError } from "./error.js";
import type { OutflowLimit } from "./policy.js";

/** Mirrors Rust `RingMode`, set once at creation and never cleared. */
export type RingMode = "off" | "registry" | "anonymous";

/** Rust `CustomRingConfig`, the ring's governance as its config account holds it. */
export interface RingProgramConfig {
  readonly authority: Address;
  readonly auditorPublicKey: X25519PublicKey;
  readonly bump: number;
  /** A policy ring enforces its table, an audit-only ring proves only the audit statement. */
  readonly hasPolicy: boolean;
  readonly mode: RingMode;
  /** `mode === "registry"`, every output nullifier key is escrowed in the registry. */
  readonly keyEscrow: boolean;
  /** Lamports a record write by a signer other than the authority pays the authority. */
  readonly insertFee: bigint;
  readonly coSigner?: RingCoSigner;
  readonly delegate?: Address;
  /** The slot `CreateConfig` ran in. */
  readonly createdSlot: bigint;
  /** No stream of the ring holds an output before this epoch, a restore scans from it. */
  readonly creationEpoch: bigint;
}

/** Rust `CustomRingCoSigner`, a mint without a threshold row always needs the co-signer. */
export interface RingCoSigner {
  readonly signer: Address;
  /** `RING_COSIGN_*` bits. */
  readonly scope: number;
  readonly thresholds: readonly RingCoSignThreshold[];
}

/** SOL under the zero address. */
export interface RingCoSignThreshold {
  readonly mint: Address;
  readonly amount: bigint;
}

export const RING_COSIGN_TRANSFERS = 1;
export const RING_COSIGN_DEPOSITS = 2;
export const RING_COSIGN_WITHDRAWALS = 4;
export const RING_COSIGN_SCOPE_MASK = 7;
/** Rust `MAX_CO_SIGNER_THRESHOLDS`. */
export const RING_COSIGN_THRESHOLD_SLOTS = 8;

/** Rust `RootEntry`, `applied` the queue position the application reached. */
export interface RingRootEntry {
  readonly root: Bytes32;
  readonly applied: bigint;
  readonly slot: bigint;
}

/** Mirrors Rust `SourceSlot`, slot `i` is empty (`listId === 0`) or serves list `i + 1`. */
export interface RingSourceSlot {
  readonly listId: number;
  /** The curator's member registry account, the zero address for the ring's own. */
  readonly registry: Address;
}

/** Rust `EncodedRuleTable`, counted rows without their zero padding. */
export interface EncodedRuleTable {
  readonly rules: readonly Bytes32[];
  readonly inlineAssets: readonly Bytes32[];
  readonly inlineLimits: readonly bigint[];
  readonly limits: readonly OutflowLimit[];
}

/** Rust `MemberRegistry`, what every policy transfer reads of the ring's lists. */
export interface RingMemberRegistry {
  readonly bump: number;
  /** Slot of the newest root in `history`. */
  readonly historyCursor: number;
  /** The leaf the next insert takes. */
  readonly nextIndex: number;
  /** The applied position every own-ring root must reach. */
  readonly floor: bigint;
  readonly priorFloor: bigint;
  /** The slot of the last floor raise. */
  readonly floorSlot: bigint;
  /** `MEMBER_REGISTRY_ROOT_HISTORY` slots, `undefined` where no root was pushed. */
  readonly history: readonly (RingRootEntry | undefined)[];
  /** Zero before the first policy write. */
  readonly policyHash: Bytes32;
  readonly sources: readonly RingSourceSlot[];
  readonly rules: EncodedRuleTable;
  readonly generation: number;
  readonly generationSlot: bigint;
}

/** Rust `QueueCheckpoint`, `chain(p)` and the slot `p` was queued at. */
export interface RingQueueCheckpoint {
  readonly chain: Bytes32;
  readonly slot: bigint;
}

/** Rust `RecordQueue`, the chain checkpoints of the pending record writes. */
export interface RingRecordQueue {
  readonly bump: number;
  /** The position of the oldest pending write. */
  readonly head: bigint;
  /** The position the next write takes. */
  readonly tail: bigint;
  /** `chain(head - 1)`. */
  readonly chainHead: Bytes32;
  /** Position `p` sits at `p mod APPLY_BATCH`. */
  readonly checkpoints: readonly RingQueueCheckpoint[];
  /** The first slot a permissionless application may land in. */
  readonly nextApplySlot: bigint;
}

/** Rust `MEMBER_QUEUE_LIMIT`, the member share of the queue. */
export const MEMBER_QUEUE_LIMIT = 8n;
/** Rust `AUTHORITY_RESERVED_LEAVES`, the leaves only authority writes take. */
export const AUTHORITY_RESERVED_LEAVES = 1n << 16n;
/** Rust `APPLY_DELAY_SLOTS`, the age a queued write reaches before anyone may apply it. */
export const APPLY_DELAY_SLOTS = 150n;
/** Rust `GRACE_SLOTS`, the slots a curator root stays usable at the prior floor after a raise. */
export const GRACE_SLOTS = 750n;
/** Rust `DEFAULT_INSERT_FEE`, the lamports `CreateConfig` charges a member's record write. */
export const DEFAULT_INSERT_FEE = 1_000_000n;

const RING_MODES: readonly RingMode[] = ["off", "registry", "anonymous"];
const RING_PROGRAM_CONFIG_DISCRIMINATOR = 10;
const RING_PROGRAM_CONFIG_SIZE = 471;
const MEMBER_REGISTRY_DISCRIMINATOR = 11;
const MEMBER_REGISTRY_SIZE = 3094;
const RECORD_QUEUE_DISCRIMINATOR = 12;
const RECORD_QUEUE_SIZE = 698;

/** Mirrors Rust `CustomRingConfig::new` over `RingProgramConfig::valid`. */
export function decodeRingProgramConfig(data: Uint8Array): RingProgramConfig {
  const reader = accountReader(data, {
    discriminator: RING_PROGRAM_CONFIG_DISCRIMINATOR,
    size: RING_PROGRAM_CONFIG_SIZE,
    code: "RING_CONFIG_INVALID",
  });
  const authority = encodeBase58(reader.bytes(32, "authority"));
  const auditorPublicKey = auditorKey(reader.bytes(33, "auditorPubkey") as Bytes33);
  const bump = reader.u8("bump");
  const hasPolicy = reader.u8("hasPolicy");
  const modeByte = reader.u8("mode");
  const mode = RING_MODES[modeByte];
  const insertFee = reader.u64("insertFee");
  const coSigner = reader.bytes(32, "coSigner");
  const scope = reader.u8("coSignScope");
  const thresholdCount = reader.u8("thresholdCount");
  const rows = Array.from({ length: RING_COSIGN_THRESHOLD_SLOTS }, () =>
    Object.freeze({
      mint: encodeBase58(reader.bytes(32, "threshold.mint")),
      amount: reader.u64("threshold.amount"),
    }),
  );
  const delegate = reader.bytes(32, "delegate");
  const createdSlot = reader.u64("createdSlot");
  reader.done();
  if (mode === undefined || hasPolicy > 1 || thresholdCount > RING_COSIGN_THRESHOLD_SLOTS)
    throw new RingError("RING_CONFIG_INVALID", {
      details: { mode: modeByte, hasPolicy, thresholdCount },
    });
  const signer = equalBytes(coSigner, ZERO_32) ? undefined : encodeBase58(coSigner);
  if (signer !== undefined && !validScope(scope))
    throw new RingError("RING_CONFIG_INVALID", {
      details: { coSignScope: scope },
    });
  return Object.freeze({
    authority,
    auditorPublicKey,
    bump,
    hasPolicy: hasPolicy === 1,
    mode,
    keyEscrow: mode === "registry",
    insertFee,
    ...(signer === undefined
      ? {}
      : {
          coSigner: Object.freeze({
            signer,
            scope,
            thresholds: Object.freeze(rows.slice(0, thresholdCount)),
          }),
        }),
    ...(equalBytes(delegate, ZERO_32) ? {} : { delegate: encodeBase58(delegate) }),
    createdSlot,
    creationEpoch: tagEpoch(createdSlot),
  });
}

/** Mirrors Rust `MemberRegistry::valid`, every rule row past its count zero. */
export function decodeRingMemberRegistry(data: Uint8Array): RingMemberRegistry {
  const reader = accountReader(data, {
    discriminator: MEMBER_REGISTRY_DISCRIMINATOR,
    size: MEMBER_REGISTRY_SIZE,
    code: "RING_MEMBER_REGISTRY_INVALID",
  });
  const bump = reader.u8("bump");
  const historyCursor = reader.u8("historyCursor");
  const nextIndex = reader.u32("nextIndex");
  const floor = reader.u64("floor");
  const priorFloor = reader.u64("priorFloor");
  const floorSlot = reader.u64("floorSlot");
  const history = Array.from({ length: MEMBER_REGISTRY_ROOT_HISTORY }, () => {
    const root = reader.bytes(32, "history.root") as Bytes32;
    const applied = reader.u64("history.applied");
    const slot = reader.u64("history.slot");
    return equalBytes(root, ZERO_32) ? undefined : Object.freeze({ root, applied, slot });
  });
  const policyHash = reader.bytes(32, "policyHash") as Bytes32;
  const sources = Array.from({ length: RING_SOURCE_SLOTS }, () =>
    Object.freeze({
      listId: reader.u8("source.listId"),
      registry: encodeBase58(reader.bytes(32, "source.registry")),
    }),
  );
  const rules = readEncodedRuleTable(reader);
  const generation = reader.u32("generation");
  const generationSlot = reader.u64("generationSlot");
  reader.done();
  if (historyCursor >= MEMBER_REGISTRY_ROOT_HISTORY || BigInt(nextIndex) > MEMBER_REGISTRY_CAPACITY)
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", {
      details: { historyCursor, nextIndex },
    });
  return Object.freeze({
    bump,
    historyCursor,
    nextIndex,
    floor,
    priorFloor,
    floorSlot,
    history: Object.freeze(history),
    policyHash,
    sources: Object.freeze(sources),
    rules,
    generation,
    generationSlot,
  });
}

/** Mirrors Rust `RecordQueue::valid`. */
export function decodeRingRecordQueue(data: Uint8Array): RingRecordQueue {
  const reader = accountReader(data, {
    discriminator: RECORD_QUEUE_DISCRIMINATOR,
    size: RECORD_QUEUE_SIZE,
    code: "RING_RECORD_QUEUE_INVALID",
  });
  const bump = reader.u8("bump");
  const head = reader.u64("head");
  const tail = reader.u64("tail");
  const chainHead = reader.bytes(32, "chainHead") as Bytes32;
  const checkpoints = Array.from({ length: APPLY_BATCH }, () =>
    Object.freeze({
      chain: reader.bytes(32, "checkpoint.chain") as Bytes32,
      slot: reader.u64("checkpoint.slot"),
    }),
  );
  const nextApplySlot = reader.u64("nextApplySlot");
  reader.done();
  if (head > tail || tail - head > BigInt(APPLY_BATCH))
    throw new RingError("RING_RECORD_QUEUE_INVALID", {
      details: { head, tail },
    });
  return Object.freeze({
    bump,
    head,
    tail,
    chainHead,
    checkpoints: Object.freeze(checkpoints),
    nextApplySlot,
  });
}

/** Rust `MemberRegistry::own_root`, the entry must reach the floor. */
export function registryOwnRoot(registry: RingMemberRegistry, index: number): RingRootEntry {
  const entry = registryEntry(registry, index);
  if (entry.applied < registry.floor)
    throw new RingError("RING_MEMBER_REGISTRY_STALE", {
      details: { reason: "RootBelowFloor", index },
    });
  return entry;
}

/** Rust `MemberRegistry::curator_root`, at the floor or inside the grace window at the prior floor. */
export function registryCuratorRoot(
  registry: RingMemberRegistry,
  index: number,
  slot: bigint,
): RingRootEntry {
  const entry = registryEntry(registry, index);
  const inGrace = slot < registry.floorSlot + GRACE_SLOTS;
  if (entry.applied >= registry.floor || (inGrace && entry.applied >= registry.priorFloor))
    return entry;
  throw new RingError("RING_MEMBER_REGISTRY_STALE", {
    details: { reason: "CuratorRootStale", index },
  });
}

/** Rust `MemberRegistry::current_root`, the root the next application starts from. */
export function registryCurrentRoot(registry: RingMemberRegistry): RingRootEntry {
  return registryEntry(registry, registry.historyCursor);
}

/** Rust `MemberRegistry::curator`, the one curator registry the sources name. */
export function registryCurator(registry: RingMemberRegistry): Address | undefined {
  return registry.sources.find((source) => !isZeroAddress(source.registry))?.registry;
}

/** Rust `RecordQueue::pending`. */
export function queuePending(queue: RingRecordQueue): bigint {
  return queue.tail - queue.head;
}

/** Rust `RecordQueue::chain_tail`, the chain an application of every pending write ends at. */
export function queueChainTail(queue: RingRecordQueue): Bytes32 {
  if (queuePending(queue) === 0n) return queue.chainHead;
  return queueCheckpoint(queue, queue.tail - 1n).chain;
}

/** Rust `RecordQueue::apply_due`, a permissionless application needs a full or aged queue. */
export function queueApplyDue(queue: RingRecordQueue, slot: bigint): boolean {
  const pending = queuePending(queue);
  if (pending === 0n) return false;
  const aged = slot >= queueCheckpoint(queue, queue.head).slot + APPLY_DELAY_SLOTS;
  return (pending >= MEMBER_QUEUE_LIMIT || aged) && slot >= queue.nextApplySlot;
}

/** Rust `RecordQueue::admit_member_write`, the member share of the queue and of the leaves. */
export function queueAdmitsMemberWrite(
  queue: RingRecordQueue,
  registry: RingMemberRegistry,
): "admitted" | "queueFull" | "authorityLeafReserve" {
  if (queuePending(queue) >= MEMBER_QUEUE_LIMIT) return "queueFull";
  const reserved = BigInt(registry.nextIndex) + queuePending(queue) + 1n;
  return reserved > MEMBER_REGISTRY_CAPACITY - AUTHORITY_RESERVED_LEAVES
    ? "authorityLeafReserve"
    : "admitted";
}

export { CUSTOM_RING_PROOF_LENGTH };

export function checkedCustomRingProof(proof: Uint8Array): Uint8Array {
  if (proof.length !== CUSTOM_RING_PROOF_LENGTH) {
    throw new RingError("RING_PROOF_LENGTH", {
      details: { expected: CUSTOM_RING_PROOF_LENGTH, actual: proof.length },
    });
  }
  return new Uint8Array(proof);
}

function accountReader(
  data: Uint8Array,
  account: Readonly<{
    discriminator: number;
    size: number;
    code: "RING_CONFIG_INVALID" | "RING_MEMBER_REGISTRY_INVALID" | "RING_RECORD_QUEUE_INVALID";
  }>,
): Reader {
  if (data.length !== account.size || data[0] !== account.discriminator)
    throw new RingError(account.code, {
      details: { length: data.length, discriminator: data[0] },
    });
  const reader = new Reader(data);
  reader.u8("discriminator");
  return reader;
}

/** A key the program would refuse to encrypt to reads as an invalid config. */
function auditorKey(bytes: Bytes33): X25519PublicKey {
  try {
    return X25519PublicKey.fromBytes(bytes);
  } catch (cause) {
    throw new RingError("RING_CONFIG_INVALID", {
      details: { field: "auditorPubkey" },
      cause,
    });
  }
}

function validScope(scope: number): boolean {
  return scope !== 0 && (scope & ~RING_COSIGN_SCOPE_MASK) === 0;
}

/** Mirrors Rust `EncodedRuleTable::decode`, every slot past a count zero. */
function readEncodedRuleTable(reader: Reader): EncodedRuleTable {
  const rules = countedRows(reader, RING_RULE_SLOTS, "rules");
  const inlineAssets = countedRows(reader, RING_INLINE_ASSET_SLOTS, "inlineAssets");
  const inlineLimits = countedLimits(
    reader,
    inlineAssets.length,
    RING_INLINE_ASSET_SLOTS,
    "inlineLimits",
  );
  const limitAssets = countedRows(reader, RING_OUTFLOW_LIMIT_SLOTS, "limitAssets");
  const limitCaps = countedLimits(
    reader,
    limitAssets.length,
    RING_OUTFLOW_LIMIT_SLOTS,
    "limitCaps",
  );
  const limitCosign = countedLimits(
    reader,
    limitAssets.length,
    RING_OUTFLOW_LIMIT_SLOTS,
    "limitCosign",
  );
  return Object.freeze({
    rules,
    inlineAssets,
    inlineLimits,
    limits: Object.freeze(
      limitAssets.map((asset, index) =>
        Object.freeze({
          asset,
          cap: limitCaps[index] ?? 0n,
          cosignAbove: limitCosign[index] ?? 0n,
        }),
      ),
    ),
  });
}

function countedRows(reader: Reader, slots: number, field: string): readonly Bytes32[] {
  const count = reader.u8(`${field}.count`);
  if (count > slots)
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", {
      details: { field, count },
    });
  const rows = Array.from({ length: slots }, () => reader.bytes(32, field) as Bytes32);
  if (rows.slice(count).some((row) => !equalBytes(row, ZERO_32)))
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", {
      details: { field, padding: true },
    });
  return Object.freeze(rows.slice(0, count));
}

/** Big endian, Rust `u64::from_be_bytes`. */
function countedLimits(
  reader: Reader,
  count: number,
  slots: number,
  field: string,
): readonly bigint[] {
  const limits = Array.from({ length: slots }, () => bytesToBigInt(reader.bytes(8, field)));
  if (limits.slice(count).some((limit) => limit !== 0n))
    throw new RingError("RING_MEMBER_REGISTRY_INVALID", {
      details: { field, padding: true },
    });
  return Object.freeze(limits.slice(0, count));
}

function registryEntry(registry: RingMemberRegistry, index: number): RingRootEntry {
  const entry = Number.isInteger(index) ? registry.history[index] : undefined;
  if (entry === undefined)
    throw new RingError("RING_MEMBER_REGISTRY_STALE", {
      details: { reason: "RootIndexEmpty", index },
    });
  return entry;
}

function queueCheckpoint(queue: RingRecordQueue, position: bigint): RingQueueCheckpoint {
  const checkpoint = queue.checkpoints[Number(position % BigInt(APPLY_BATCH))];
  if (checkpoint === undefined) throw new RingError("RING_RECORD_QUEUE_INVALID");
  return checkpoint;
}

function isZeroAddress(address: Address): boolean {
  return address === ZERO_ADDRESS;
}

const ZERO_ADDRESS = encodeBase58(ZERO_32);
