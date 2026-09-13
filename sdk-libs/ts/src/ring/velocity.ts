/** The record slots and witness a velocity transfer adds, mirrors Rust `custom-rings/sdk/src/velocity.rs`. */
import type { Address } from "@solana/kit";
import { NullifierKey } from "../keypair/nullifier-key.js";
import { ShieldedAddress } from "../keypair/shielded.js";
import { ShieldedPublicKey } from "../keypair/public-key.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import { transactOutputBlinding } from "../keypair/transact/index.js";
import { hashBytes } from "../hasher/index.js";
import { addressBytes } from "../client/internal.js";
import type { Shape } from "../interface/shape.js";
import { SPP_SUPPORTED_SHAPES } from "../interface/shape.js";
import type { Bytes16, Bytes31, Bytes32, MessageData, RequestContext } from "../interface/types.js";
import { Utxo, ProofInputUtxo, createProofOutput } from "../transaction/utxo.js";
import type { ProofOutputUtxo, TreeId } from "../transaction/utxo.js";
import { SOL_MINT } from "../transaction/asset.js";
import { equalBytes } from "../wallet/internal.js";
import type { SpendSession } from "../transaction/wallet/authority.js";
import type {
  SlotReader,
  ChainReader,
  RingHeadReader,
  RingHeadTransferProof,
} from "../client/ports.js";
import { RING_VELOCITY_SLOTS } from "../client/prover/types.js";
import type { CustomRingVelocityRow, CustomRingVelocityWitness } from "../client/prover/types.js";
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
  type VelocityRow,
} from "./policy.js";
import { findSpendCountersMessage, openSpendCounters, sealedSpendCounters } from "./counters.js";
import { readCurrentSpendRecord } from "./head-reader.js";

const ZERO_NULLIFIER_SECRET = new Uint8Array(31) as Bytes31;
const RING_INPUT_SLOTS = 5;
const RING_OUTPUT_SLOTS = 4;

/** A field element below the modulus, the Poseidon commitment rejects the rest. */
function canonicalSalt(): Bytes32 {
  const salt = new Uint8Array(32);
  globalThis.crypto.getRandomValues(salt);
  salt[0] = 0;
  return salt as Bytes32;
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
export function senderOutflow(
  sender: Member,
  ringProgramId: Address,
  inputs: readonly ProofInputUtxo[],
  outputs: readonly ProofOutputUtxo[],
  asset: Bytes32,
): bigint {
  let inflow = 0n;
  for (const input of inputs) {
    if (input.isDummy()) continue;
    if (equalBytes(memberOfAsset(input.utxo.asset), asset)) inflow += input.utxo.amount;
  }
  let change = 0n;
  for (const output of outputs) {
    const owner = output.ownerAddress;
    if (owner === undefined) continue;
    const sameAsset = equalBytes(memberOfAsset(output.asset), asset);
    const sameOwner = equalBytes(
      memberOfIdentity(owner.signingPublicKey.ownerProofInputHash()),
      sender,
    );
    const inRing = output.ringProgramId !== undefined && output.ringProgramId === ringProgramId;
    if (sameAsset && sameOwner && inRing) change += output.amount;
  }
  if (change > inflow) throw new RingError("RING_VELOCITY_OVERFLOW", { details: { asset } });
  return inflow - change;
}

export interface VelocityFacts {
  readonly namespace: Address;
  readonly owner: RingListNamespace;
  readonly entriesTreeId: TreeId;
  readonly windowSlots: bigint;
  readonly rows: readonly VelocityRow[];
  readonly windowIndex: bigint;
  readonly live: LiveSpendRecord;
  /** `undefined` for an expired record, the circuit opens only its commitment. */
  readonly counters: SpendCounters | undefined;
  readonly head?: RingHeadTransferProof;
}

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
  readonly rows: readonly VelocityRow[];
  readonly sender: Member;
}

/** Mirrors Rust `VelocityLookup::read` and `recover_counters`. */
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
  const message = findSpendCountersMessage(live.origin.messages, addressBytes(input.namespace));
  if (message === undefined || live.origin.salt === undefined) {
    throw new RingError("RING_SPEND_COUNTERS_UNKNOWN", { details: {} });
  }
  return openSpendCounters(input.session, {
    firstNullifier: live.origin.firstNullifier,
    salt: live.origin.salt as Bytes16,
    data: message.data,
    commitment: live.record.countersCommitment,
  });
}

export interface VelocityPlan {
  readonly nextNullifier: Bytes32;
  readonly shape: Shape;
  readonly recordInput: ProofInputUtxo;
  readonly recordOutput: ProofOutputUtxo;
  readonly recordMessage: MessageData;
  readonly countersSeal: Readonly<{
    viewTag: Bytes32;
    plaintext: Uint8Array;
    slotIndex: number;
  }>;
  readonly witness: CustomRingVelocityWitness;
  readonly approvalRequired: boolean;
}

export interface PlanVelocityInput {
  readonly facts: VelocityFacts;
  readonly sender: Member;
  readonly ringProgramId: Address;
  readonly inputs: readonly ProofInputUtxo[];
  readonly outputs: readonly ProofOutputUtxo[];
  readonly firstNullifier: Bytes32;
  readonly outputBlindingSeed: Bytes32;
  readonly moneyShape: Shape;
}

/** Mirrors Rust `VelocityPlanInput::plan`, the sender spends its record into the successor. */
export function planVelocity(input: PlanVelocityInput): VelocityPlan {
  const { facts } = input;
  const shape = recordShape(input.moneyShape);
  const sameWindow = facts.live.record.window === facts.windowIndex;
  const previous = sameWindow ? facts.counters : undefined;

  const rows: VelocityRow[] = [];
  const spent: bigint[] = [];
  let approvalRequired = false;
  for (const row of facts.rows) {
    const outflow = senderOutflow(
      input.sender,
      input.ringProgramId,
      input.inputs,
      input.outputs,
      row.asset,
    );
    const before = previous === undefined ? 0n : spendCountersSpent(previous, row.asset);
    const charged = before + outflow;
    if (row.cap !== 0n && charged > row.cap) {
      throw new RingError("RING_VELOCITY_CAP_EXCEEDED", {
        details: { asset: row.asset, cap: row.cap, spent: charged },
      });
    }
    if (row.cosignAbove !== 0n && outflow > row.cosignAbove) approvalRequired = true;
    rows.push(row);
    spent.push(charged);
  }

  const nextSalt = canonicalSalt();
  const nextCounters: SpendCounters = Object.freeze({
    salt: nextSalt,
    assets: Object.freeze(rows.map((row) => row.asset)),
    spent: Object.freeze([...spent]),
  });
  const commitment = spendCountersCommitment(nextCounters);

  const spentRecord = facts.live.record;
  const successorBlinding = transactOutputBlinding(
    input.firstNullifier,
    input.outputBlindingSeed,
    shape.outputs - 1,
  );
  const successor: SpendRecord = Object.freeze({
    member: spentRecord.member,
    version: spentRecord.version + 1n,
    window: facts.windowIndex,
    countersCommitment: commitment,
    blinding: successorBlinding,
  });

  const spentHashes = facts.owner.spendRecordHashes(spentRecord);
  const nextHashes = facts.owner.spendRecordHashes(successor);
  const zeroNullifier = NullifierKey.fromSecret(ZERO_NULLIFIER_SECRET);
  let recordInput: ProofInputUtxo;
  try {
    recordInput = new ProofInputUtxo({
      utxo: new Utxo({
        owner: ShieldedPublicKey.fromPda(addressBytes(facts.namespace)),
        asset: SOL_MINT,
        amount: 0n,
        blinding: spentRecord.blinding,
      }),
      nullifierKey: zeroNullifier,
      treeId: facts.entriesTreeId,
      dataHash: spentHashes.dataHash,
    });
  } finally {
    zeroNullifier.destroy();
  }

  const viewing = ViewingKey.generate();
  let recordOutput: ProofOutputUtxo;
  try {
    const nullifier = NullifierKey.fromSecret(ZERO_NULLIFIER_SECRET);
    try {
      recordOutput = createProofOutput({
        asset: SOL_MINT,
        amount: 0n,
        blinding: successor.blinding,
        dataHash: nextHashes.dataHash,
        ownerAddress: ShieldedAddress.forPda(
          addressBytes(facts.namespace),
          nullifier.publicKey(),
          viewing.publicKey(),
        ),
        ownerTag: addressBytes(facts.namespace),
      });
    } finally {
      nullifier.destroy();
    }
  } finally {
    viewing.destroy();
  }

  const opened = facts.counters ?? zeroSpendCounters();
  const witness: CustomRingVelocityWitness = Object.freeze({
    windowSlots: facts.windowSlots,
    rows: Object.freeze(rows.map((row) => Object.freeze({ ...row }))),
    ringId: hashBytes(addressBytes(input.ringProgramId)) as Bytes32,
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
      viewTag: spendRecordMessageTag(addressBytes(facts.namespace)),
      data: encodeSpendRecord(successor),
    },
    countersSeal: sealedSpendCounters(nextCounters, addressBytes(facts.namespace)),
    witness,
    approvalRequired,
  });
}

function emptyRecord(): CustomRingVelocityWitness["record"] {
  const zero = (): Bytes32 => new Uint8Array(32) as Bytes32;
  return Object.freeze({
    version: 0n,
    window: 0n,
    commitment: zero(),
    salt: zero(),
    assets: Object.freeze(Array.from({ length: RING_VELOCITY_SLOTS }, () => zero())),
    spent: Object.freeze(Array.from({ length: RING_VELOCITY_SLOTS }, () => 0n)),
    nextSalt: zero(),
  });
}

/** Mirrors Rust `ChargeRows` into a per-transfer witness, no record accompanies it. */
export function chargeRows(
  sender: Member,
  ringProgramId: Address,
  inputs: readonly ProofInputUtxo[],
  outputs: readonly ProofOutputUtxo[],
  rows: readonly VelocityRow[],
  namespaceOwnerHash: Bytes32,
): CustomRingVelocityWitness {
  let approvalRequired = false;
  const kept: CustomRingVelocityRow[] = [];
  for (const row of rows) {
    const outflow = senderOutflow(sender, ringProgramId, inputs, outputs, row.asset);
    if (row.cap !== 0n && outflow > row.cap) {
      throw new RingError("RING_VELOCITY_CAP_EXCEEDED", {
        details: { asset: row.asset, cap: row.cap, spent: outflow },
      });
    }
    if (row.cosignAbove !== 0n && outflow > row.cosignAbove) approvalRequired = true;
    kept.push(Object.freeze({ ...row }));
  }
  return Object.freeze({
    windowSlots: 0n,
    rows: Object.freeze(kept),
    ringId: hashBytes(addressBytes(ringProgramId)) as Bytes32,
    namespaceOwnerHash,
    windowIndex: 0n,
    approvalRequired,
    record: emptyRecord(),
  });
}
