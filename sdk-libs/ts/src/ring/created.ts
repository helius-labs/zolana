/** Ring notes of deposits and anonymous merges, a commitment layout spends them by hash alone, Rust `created`. */
import { hashBytes, initializePoseidon } from "../hasher/index.js";
import { addressBytes } from "../interface/internal.js";
import type { Address, Bytes32, RequestContext } from "../interface/types.js";
import type { X25519Keypair } from "../keypair/x25519.js";
import type { OutputSlot } from "../transaction/instructions/transact.js";
import { equal } from "../transaction/internal.js";
import type { RingDepositOutput } from "../transaction/serialization/ring-deposit.js";
import { ownerUtxoHash } from "../transaction/utxo.js";

import type { KnownNote, RingAuditReader } from "./audit.js";
import { confirmedMerge, disclosedMergeOpening } from "./audit-merge.js";
import {
  openRingDepositOpening,
  ringDepositOutput,
  type RingDepositOpening,
} from "./deposit-audit.js";
import { readRingDepositCapsule } from "./deposit-capsule.js";
import { RingError } from "./error.js";
import { readRingHistory, scanLimits } from "./history.js";
import {
  RpcTransactionOrigin,
  type ConfirmedRingTransaction,
  type TransactionOrigin,
} from "./origin.js";

/** Rust `CreatedNote`. */
export interface CreatedRingNote {
  readonly commitment: Bytes32;
  readonly slotIndex: number;
  readonly note: KnownNote;
}

/** Rust `CreatedNotePage`. */
export interface CreatedRingNotesPage {
  readonly notes: readonly CreatedRingNote[];
  /** Set only when the page cap stopped the read. */
  readonly nextCursor?: Uint8Array;
}

/** Rust `CreatedNoteScan::run`. */
export async function scanCreatedRingNotes(
  input: Readonly<{
    client: RingAuditReader;
    ringProgramId: Address;
    auditor: X25519Keypair;
    origin?: TransactionOrigin;
    cursor?: Uint8Array;
    pageSize?: number;
    maxPages?: number;
  }>,
  context?: RequestContext,
): Promise<CreatedRingNotesPage> {
  await initializePoseidon();
  const notes: CreatedRingNote[] = [];
  const nextCursor = await readRingHistory(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      origin: input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc),
      ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
      limits: scanLimits(input),
    },
    (confirmed) => {
      notes.push(
        ...createdRingNotes({
          confirmed,
          ringProgramId: input.ringProgramId,
          auditor: input.auditor,
        }),
      );
    },
    context,
  );
  return Object.freeze({
    notes: Object.freeze(notes),
    ...(nextCursor === undefined ? {} : { nextCursor }),
  });
}

/** Rust `CreatedNotes::open`, none for a transfer and for a confidential ring's deposit or merge. */
export function createdRingNotes(
  input: Readonly<{
    confirmed: ConfirmedRingTransaction;
    ringProgramId: Address;
    auditor: X25519Keypair;
  }>,
): readonly CreatedRingNote[] {
  const { confirmed } = input;
  switch (confirmed.kind) {
    case "transfer":
      return Object.freeze([]);
    case "deposit":
      return depositNotes(input, confirmed);
    case "merge": {
      const { disclosure, transaction } = confirmed;
      if (disclosure === undefined) return Object.freeze([]);
      if (transaction.eventIndex === undefined)
        throw new RingError("RING_RPC", { details: { reason: "missing event index" } });
      const merge = confirmedMerge(transaction, transaction.eventIndex, disclosure);
      const opening = disclosedMergeOpening(input, merge, disclosure);
      return Object.freeze([
        Object.freeze({
          commitment: merge.outputCommitment,
          slotIndex: 0,
          note: Object.freeze({
            ownerKey: addressBytes(opening.ownerKey) as Bytes32,
            nullifierPk: opening.nullifierPublicKey,
            asset: hashBytes(addressBytes(opening.mint)) as Bytes32,
            mint: opening.mint,
            amount: opening.amount,
            blinding: opening.outputBlinding,
            dataHash: new Uint8Array(32) as Bytes32,
            ringDataHash: merge.ringDataHash,
          }),
        }),
      ]);
    }
  }
}

function depositNotes(
  input: Readonly<{ ringProgramId: Address; auditor: X25519Keypair }>,
  confirmed: Extract<ConfirmedRingTransaction, { kind: "deposit" }>,
): readonly CreatedRingNote[] {
  const notes: CreatedRingNote[] = [];
  for (const [slotIndex, slot] of confirmed.transaction.outputSlots.entries()) {
    const output = ringDepositOutput(slot.payload, input.ringProgramId);
    const binding = confirmed.deposits.find((deposit) => deposit.slotIndex === slotIndex);
    if (output === undefined || binding === undefined) continue;
    const capsule = readRingDepositCapsule(output.encrypted.ciphertext);
    if (capsule === undefined)
      throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "deposit opening" } });
    const opening = openRingDepositOpening(capsule, input.auditor, output.ownerUtxoHash, binding);
    try {
      const note = createdDepositNote({
        ringProgramId: input.ringProgramId,
        slotIndex,
        slot,
        output,
        opening,
      });
      if (note !== undefined) notes.push(note);
    } finally {
      opening.ownerHash.fill(0);
      opening.blinding.fill(0);
    }
  }
  return Object.freeze(notes);
}

/** @internal The note an opened deposit slot creates, `undefined` unless its capsule names the owner key. */
export function createdDepositNote(
  input: Readonly<{
    ringProgramId: Address;
    slotIndex: number;
    slot: OutputSlot;
    output: RingDepositOutput;
    opening: Omit<RingDepositOpening, "recipientCiphertext">;
  }>,
): CreatedRingNote | undefined {
  const { output, opening, slot } = input;
  // Only an anonymous ring's capsule names the owner key.
  if (opening.ownerKey === undefined) return undefined;
  const dataHash = output.dataHash ?? (new Uint8Array(32) as Bytes32);
  const commitment = ownerUtxoHash({
    owner: opening.ownerHash,
    asset: output.asset,
    amount: output.amount,
    blinding: opening.blinding,
    treeId: slot.outputContext.treeId,
    dataHash,
    ringDataHash: output.ringDataHash,
    ringProgramId: input.ringProgramId,
  });
  if (!equal(commitment, slot.outputContext.hash))
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "deposit opening" } });
  return Object.freeze({
    commitment,
    slotIndex: input.slotIndex,
    note: Object.freeze({
      ownerKey: opening.ownerKey,
      asset: hashBytes(addressBytes(output.asset)) as Bytes32,
      mint: output.asset,
      amount: output.amount,
      blinding: opening.blinding.slice() as Bytes32,
      dataHash,
      ringDataHash: output.ringDataHash,
    }),
  });
}
