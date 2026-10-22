/** UTXOs of deposits and anonymous merges, a commitment layout names them by hash or prefix, Rust `created`. */
import { hashBytes, initializePoseidon } from "../hasher/index.js";
import { addressBytes } from "../interface/internal.js";
import type { Address, Bytes32, RequestContext } from "../interface/types.js";
import { ringIdField } from "../keypair/ring-stream.js";
import type { X25519Keypair } from "../keypair/x25519.js";
import type { OutputSlot } from "../transaction/instructions/transact.js";
import { equal } from "../transaction/internal.js";
import type { RingDepositOutput } from "../transaction/serialization/ring-deposit.js";

import {
  knownUtxoHash,
  type CreatedRingUtxo,
  type KnownUtxo,
  type RingAuditReader,
} from "./audit.js";
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

/** Rust `CreatedUtxoPage`. */
export interface CreatedRingUtxosPage {
  readonly utxos: readonly CreatedRingUtxo[];
  /** Set only when the page cap stopped the read. */
  readonly nextCursor?: Uint8Array;
}

/** Rust `CreatedUtxoScan::run`. */
export async function scanCreatedRingUtxos(
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
): Promise<CreatedRingUtxosPage> {
  await initializePoseidon();
  const utxos: CreatedRingUtxo[] = [];
  const nextCursor = await readRingHistory(
    {
      client: input.client,
      ringProgramId: input.ringProgramId,
      origin: input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc),
      ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
      limits: scanLimits(input),
    },
    (confirmed) => {
      utxos.push(
        ...createdRingUtxos({
          confirmed,
          ringProgramId: input.ringProgramId,
          auditor: input.auditor,
        }),
      );
    },
    context,
  );
  return Object.freeze({
    utxos: Object.freeze(utxos),
    ...(nextCursor === undefined ? {} : { nextCursor }),
  });
}

/** Rust `CreatedUtxos::open`, none for a transfer and for a confidential ring's deposit or merge. */
export function createdRingUtxos(
  input: Readonly<{
    confirmed: ConfirmedRingTransaction;
    ringProgramId: Address;
    auditor: X25519Keypair;
  }>,
): readonly CreatedRingUtxo[] {
  const { confirmed } = input;
  switch (confirmed.kind) {
    case "transfer":
      return Object.freeze([]);
    case "deposit":
      return depositUtxos(input, confirmed);
    case "merge": {
      const { disclosure, transaction } = confirmed;
      if (disclosure === undefined) return Object.freeze([]);
      if (transaction.eventIndex === undefined)
        throw new RingError("RING_RPC", { details: { reason: "missing event index" } });
      const merge = confirmedMerge(transaction, transaction.eventIndex, disclosure);
      const opening = disclosedMergeOpening(input, merge, disclosure);
      const utxo: KnownUtxo = Object.freeze({
        ownerKey: addressBytes(opening.ownerKey) as Bytes32,
        owner: Object.freeze({ kind: "keyed", nullifierPk: opening.nullifierPublicKey }),
        asset: hashBytes(addressBytes(opening.mint)) as Bytes32,
        mint: opening.mint,
        amount: opening.amount,
        blinding: opening.outputBlinding,
        dataHash: new Uint8Array(32) as Bytes32,
        ringDataHash: merge.ringDataHash,
        treeId: merge.transaction.outputSlots[0]!.outputContext.treeId,
      });
      return Object.freeze([
        Object.freeze({ commitment: merge.outputCommitment, slotIndex: 0, utxo }),
      ]);
    }
  }
}

function depositUtxos(
  input: Readonly<{ ringProgramId: Address; auditor: X25519Keypair }>,
  confirmed: Extract<ConfirmedRingTransaction, { kind: "deposit" }>,
): readonly CreatedRingUtxo[] {
  const utxos: CreatedRingUtxo[] = [];
  for (const [slotIndex, slot] of confirmed.transaction.outputSlots.entries()) {
    const output = ringDepositOutput(slot.payload, input.ringProgramId);
    const binding = confirmed.deposits.find((deposit) => deposit.slotIndex === slotIndex);
    if (output === undefined || binding === undefined) continue;
    const capsule = readRingDepositCapsule(output.encrypted.ciphertext);
    if (capsule === undefined)
      throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "deposit opening" } });
    const opening = openRingDepositOpening(capsule, input.auditor, output.ownerUtxoHash, binding);
    try {
      const created = createdDepositUtxo({
        ringProgramId: input.ringProgramId,
        slotIndex,
        slot,
        output,
        opening,
      });
      if (created !== undefined) utxos.push(created);
    } finally {
      opening.ownerHash.fill(0);
      opening.blinding.fill(0);
    }
  }
  return Object.freeze(utxos);
}

/** @internal The UTXO an opened deposit slot creates, `undefined` unless its capsule names the owner key. */
export function createdDepositUtxo(
  input: Readonly<{
    ringProgramId: Address;
    slotIndex: number;
    slot: OutputSlot;
    output: RingDepositOutput;
    opening: Omit<RingDepositOpening, "recipientCiphertext">;
  }>,
): CreatedRingUtxo | undefined {
  const { output, opening, slot } = input;
  // Only an anonymous ring's capsule names the owner key.
  if (opening.ownerKey === undefined) return undefined;
  const utxo: KnownUtxo = Object.freeze({
    ownerKey: opening.ownerKey,
    owner: Object.freeze({ kind: "deposited", ownerHash: opening.ownerHash.slice() as Bytes32 }),
    asset: hashBytes(addressBytes(output.asset)) as Bytes32,
    mint: output.asset,
    amount: output.amount,
    blinding: opening.blinding.slice() as Bytes32,
    dataHash: output.dataHash ?? (new Uint8Array(32) as Bytes32),
    ringDataHash: output.ringDataHash,
    treeId: slot.outputContext.treeId,
  });
  const commitment = knownUtxoHash(utxo, ringIdField(input.ringProgramId));
  if (!equal(commitment, slot.outputContext.hash))
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "deposit opening" } });
  return Object.freeze({ commitment, slotIndex: input.slotIndex, utxo });
}
