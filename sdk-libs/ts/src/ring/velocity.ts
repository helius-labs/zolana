import type { Address } from "@solana/kit";
import { NullifierKey } from "../keypair/nullifier-key.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { ShieldedPublicKey } from "../keypair/public-key.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import { randomBlinding } from "../keypair/bytes.js";
import { transactOutputBlinding } from "../keypair/transact/index.js";
import { hashBytes } from "../hasher/index.js";
import type { Shape } from "../interface/shape.js";
import { SPP_SUPPORTED_SHAPES } from "../interface/shape.js";
import type { Bytes31, Bytes32, MessageData, RequestContext } from "../interface/types.js";
import { Utxo, ProofInputUtxo, createProofOutput } from "../transaction/utxo.js";
import type { ProofOutputUtxo, TreeId } from "../transaction/utxo.js";
import { SOL_MINT } from "../transaction/asset.js";
import { U64_MAX, decodeAddress } from "../transaction/internal.js";
import { equalBytes } from "../wallet/internal.js";
import type { SealedMessageInput, SpendSession } from "../transaction/wallet/authority.js";
import type {
  SlotReader,
  ChainReader,
  RingHeadReader,
  RingHeadTransferProof,
} from "../client/ports.js";
import {
  RING_INPUT_SLOTS,
  RING_OUTPUT_SLOTS,
  velocityProofInputOff,
} from "../client/prover/types.js";
import type {
  CustomRingVelocityRow,
  CustomRingVelocityProofInput,
} from "../client/prover/types.js";
import { RingError } from "./error.js";
import {
  RingListNamespace,
  memberOfAsset,
  memberOfIdentity,
  ringNamespaceOwnerHash,
  spendCountersCommitment,
  spendCountersSpent,
  zeroSpendCounters,
  encodeSpendRecord,
  spendRecordMessageTag,
  type LiveSpendRecord,
  type Member,
  type SpendCounters,
  type SpendRecord,
} from "./policy.js";
import { findSpendCountersMessage, openSpendCounters, sealedSpendCounters } from "./counters.js";
import { readCurrentSpendRecord } from "./head-reader.js";

const ZERO_NULLIFIER_SECRET = new Uint8Array(31) as Bytes31;

/** Excludes the record slot from money openings for outflow accounting. */
export interface RingMovement {
  readonly sender: Member;
  readonly ringProgramId: Address;
  readonly inputs: readonly ProofInputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
}

/** Opens authenticated counters only within their record's window. */
export interface VelocityFacts {
  readonly namespace: Address;
  readonly owner: RingListNamespace;
  readonly entriesTreeId: TreeId;
  readonly windowSlots: bigint;
  readonly rows: readonly CustomRingVelocityRow[];
  readonly windowIndex: bigint;
  readonly live: LiveSpendRecord;
  /** `undefined` for an expired record, the circuit opens only its commitment. */
  readonly counters: SpendCounters | undefined;
  readonly head: RingHeadTransferProof;
}

/** Locates the sender's compressed record under the configured entries tree. */
export interface ReadVelocityFactsInput {
  readonly client: Pick<RingHeadReader, "getRingHeadTransferProof"> &
    SlotReader &
    Pick<ChainReader, "getAccount">;
  readonly ringProgramId: Address;
  readonly session: Pick<SpendSession, "openSealedMessage">;
  readonly namespace: Address;
  readonly entriesTree: Address;
  readonly entriesTreeId: TreeId;
  readonly windowSlots: bigint;
  readonly rows: readonly CustomRingVelocityRow[];
  readonly sender: Member;
}

/** Couples the successor counters to the record spend and head transition. */
export interface VelocityPlan {
  readonly nextNullifier: Bytes32;
  readonly shape: Shape;
  readonly recordInput: ProofInputUtxo;
  readonly recordOutput: ProofOutputUtxo;
  readonly recordMessage: MessageData;
  readonly countersSeal: Omit<SealedMessageInput, "slotIndex">;
  readonly proofInput: CustomRingVelocityProofInput;
  readonly approvalRequired: boolean;
}

/** Binds record accounting to the money transfer and its output blindings. */
export interface PlanVelocityInput {
  readonly facts: VelocityFacts;
  readonly movement: RingMovement;
  readonly firstNullifier: Bytes32;
  readonly outputBlindingSeed: Bytes32;
  readonly moneyShape: Shape;
}

/** The smallest supported shape with one slot beyond the money on each side. */
export function recordShape(money: Shape): Shape {
  const shape = SPP_SUPPORTED_SHAPES.find(
    (candidate) =>
      candidate.inputs <= RING_INPUT_SLOTS &&
      candidate.outputs <= RING_OUTPUT_SLOTS &&
      candidate.inputs >= money.inputs + 1 &&
      candidate.outputs >= money.outputs + 1,
  );
  if (shape === undefined) {
    throw new RingError("RING_BUILD_TRANSFER", {
      details: { reason: "recordShape" },
    });
  }
  return shape;
}

/** The sender's outflow of one mint, inputs less the change kept inside the ring. */
export function senderOutflow(movement: RingMovement, asset: Bytes32): bigint {
  let inflow = 0n;
  for (const input of movement.inputs) {
    if (input.isDummy()) continue;
    if (equalBytes(memberOfAsset(input.utxo.asset), asset)) inflow += input.utxo.amount;
  }
  let change = 0n;
  for (const output of movement.outputs) {
    const owner = output.ownerAddress;
    if (owner === undefined) continue;
    const sameAsset = equalBytes(memberOfAsset(output.asset), asset);
    const sameOwner = equalBytes(
      memberOfIdentity(owner.signingPublicKey.ownerProofInputHash()),
      movement.sender,
    );
    const inRing =
      output.ringProgramId !== undefined && output.ringProgramId === movement.ringProgramId;
    if (sameAsset && sameOwner && inRing) change += output.amount;
  }
  if (change > inflow) throw new RingError("RING_VELOCITY_OVERFLOW", { details: { asset } });
  const outflow = inflow - change;
  if (outflow > U64_MAX) throw new RingError("RING_VELOCITY_OVERFLOW", { details: { asset } });
  return outflow;
}

export async function readVelocityFacts(
  input: ReadVelocityFactsInput,
  context?: RequestContext,
): Promise<VelocityFacts> {
  const owner = RingListNamespace.of(input.namespace, input.entriesTreeId);
  if (input.windowSlots <= 0n) throw new RingError("RING_VELOCITY_DISABLED");
  const { head, live } = await readCurrentSpendRecord(input, context);
  const slot = await input.client.getSlot(context);
  const windowIndex = slot / input.windowSlots;
  const counters = await recoverCounters(input, live, windowIndex);
  return Object.freeze({
    namespace: input.namespace,
    owner,
    entriesTreeId: input.entriesTreeId,
    windowSlots: input.windowSlots,
    rows: input.rows,
    windowIndex,
    live,
    counters,
    head,
  });
}

async function recoverCounters(
  input: ReadVelocityFactsInput,
  live: LiveSpendRecord,
  windowIndex: bigint,
): Promise<SpendCounters | undefined> {
  if (live.record.window > windowIndex) throw new RingError("RING_SPEND_RECORD_INVALID");
  if (live.record.window < windowIndex) return undefined;
  if (live.record.version === 0n) return zeroSpendCounters();
  const message = findSpendCountersMessage(live.origin.messages, decodeAddress(input.namespace));
  if (message === undefined || live.origin.salt === undefined) {
    throw new RingError("RING_SPEND_COUNTERS_UNKNOWN", {
      details: { reason: message === undefined ? "missingMessage" : "missingSalt" },
    });
  }
  return openSpendCounters(input.session, {
    firstNullifier: live.origin.firstNullifier,
    salt: live.origin.salt,
    data: message.data,
    commitment: live.record.countersCommitment,
  });
}

export function planVelocity(input: PlanVelocityInput): VelocityPlan {
  // 1. Charge outflow against counters from the current window only.
  const { facts, movement } = input;
  const shape = recordShape(input.moneyShape);
  const sameWindow = facts.live.record.window === facts.windowIndex;
  const previous = sameWindow ? facts.counters : undefined;

  const rows: CustomRingVelocityRow[] = [];
  const spent: bigint[] = [];
  let approvalRequired = false;
  for (const row of facts.rows) {
    const outflow = senderOutflow(movement, row.asset);
    const before = previous === undefined ? 0n : spendCountersSpent(previous, row.asset);
    const charged = before + outflow;
    if (charged > U64_MAX) {
      throw new RingError("RING_VELOCITY_OVERFLOW", { details: { asset: row.asset } });
    }
    if (row.cap !== 0n && charged > row.cap) {
      throw new RingError("RING_VELOCITY_CAP_EXCEEDED", {
        details: { asset: row.asset, cap: row.cap, spent: charged },
      });
    }
    if (row.cosignAbove !== 0n && outflow > row.cosignAbove) approvalRequired = true;
    rows.push(row);
    spent.push(charged);
  }

  // 2. Bind successor counters to fresh salt and the SPP output blinding.
  const nextSalt = randomBlinding();
  const nextCounters: SpendCounters = Object.freeze({
    salt: nextSalt,
    assets: Object.freeze(rows.map((row) => row.asset)),
    spent: Object.freeze([...spent]),
  });
  const commitment = spendCountersCommitment(nextCounters);

  const spentRecord = facts.live.record;
  const successor: SpendRecord = Object.freeze({
    member: spentRecord.member,
    version: spentRecord.version + 1n,
    window: facts.windowIndex,
    countersCommitment: commitment,
    blinding: transactOutputBlinding(
      input.firstNullifier,
      input.outputBlindingSeed,
      shape.outputs - 1,
    ),
  });

  // 3. Keep the namespace-owned record outside money subjects.
  const namespace = decodeAddress(facts.namespace);
  const spentHashes = facts.owner.spendRecordHashes(spentRecord);
  const nextHashes = facts.owner.spendRecordHashes(successor);
  const zeroNullifier = NullifierKey.fromSecret(ZERO_NULLIFIER_SECRET);
  const viewing = ViewingKey.generate();
  let recordInput: ProofInputUtxo;
  let recordOutput: ProofOutputUtxo;
  try {
    recordInput = new ProofInputUtxo({
      utxo: new Utxo({
        owner: ShieldedPublicKey.fromPda(namespace),
        asset: SOL_MINT,
        amount: 0n,
        blinding: spentRecord.blinding,
      }),
      nullifierKey: zeroNullifier,
      treeId: facts.entriesTreeId,
      dataHash: spentHashes.dataHash,
    });
    recordOutput = createProofOutput({
      asset: SOL_MINT,
      amount: 0n,
      blinding: successor.blinding,
      dataHash: nextHashes.dataHash,
      ownerAddress: ShieldedAddress.forPda({
        pda: namespace,
        nullifierPublicKey: zeroNullifier.publicKey(),
        viewingPublicKey: viewing.publicKey(),
      }),
      ownerTag: namespace,
    });
  } finally {
    zeroNullifier.destroy();
    viewing.destroy();
  }

  const opened = facts.counters ?? zeroSpendCounters();
  const proofInput: CustomRingVelocityProofInput = Object.freeze({
    windowSlots: facts.windowSlots,
    rows: Object.freeze(rows.map((row) => Object.freeze({ ...row }))),
    ringId: hashBytes(decodeAddress(movement.ringProgramId)) as Bytes32,
    namespaceOwnerHash: ringNamespaceOwnerHash(facts.namespace),
    windowIndex: facts.windowIndex,
    approvalRequired,
    record: Object.freeze({
      version: spentRecord.version,
      window: spentRecord.window,
      commitment: spentRecord.countersCommitment,
      salt: opened.salt,
      assets: Object.freeze([...opened.assets]),
      spent: Object.freeze([...opened.spent]),
      nextSalt,
    }),
  });

  return Object.freeze({
    shape,
    nextNullifier: nextHashes.nullifier,
    recordInput,
    recordOutput,
    recordMessage: {
      viewTag: spendRecordMessageTag(namespace),
      data: encodeSpendRecord(successor),
    },
    countersSeal: sealedSpendCounters(nextCounters, namespace),
    proofInput,
    approvalRequired,
  });
}

/** Charges one transfer without a persistent spend record. */
export function chargeRows(
  input: Readonly<{
    movement: RingMovement;
    rows: readonly CustomRingVelocityRow[];
    namespaceOwnerHash: Bytes32;
  }>,
): CustomRingVelocityProofInput {
  let approvalRequired = false;
  const kept: CustomRingVelocityRow[] = [];
  for (const row of input.rows) {
    const outflow = senderOutflow(input.movement, row.asset);
    if (row.cap !== 0n && outflow > row.cap) {
      throw new RingError("RING_VELOCITY_CAP_EXCEEDED", {
        details: { asset: row.asset, cap: row.cap, spent: outflow },
      });
    }
    if (row.cosignAbove !== 0n && outflow > row.cosignAbove) approvalRequired = true;
    kept.push(Object.freeze({ ...row }));
  }
  return Object.freeze({
    ...velocityProofInputOff({
      ringId: hashBytes(decodeAddress(input.movement.ringProgramId)) as Bytes32,
      namespaceOwnerHash: input.namespaceOwnerHash,
    }),
    rows: Object.freeze(kept),
    approvalRequired,
  });
}
