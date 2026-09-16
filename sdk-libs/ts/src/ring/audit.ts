import { p256 } from "@noble/curves/nist.js";
import { initializePoseidon } from "../hasher/index.js";

import type { IndexerReader, KitRpcAccess } from "../client/ports.js";
import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
  MessageData,
  RequestContext,
  Signature,
} from "../interface/types.js";
import {
  auditorViewTag,
  decryptTransactionViewingSecret,
  parseAuditorMessage,
  type AuditorMessage,
} from "../keypair/audit.js";
import { bigIntToBytes, bytesToBigInt } from "../keypair/bytes.js";
import { P256PublicKey } from "../keypair/public-key.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import { TransactionError } from "../transaction/error.js";
import { equal } from "../transaction/internal.js";
import type { Data } from "../transaction/data.js";
import type {
  IndexedShieldedTransaction,
  OutputContext,
  OutputSlot,
} from "../transaction/instructions/transact.js";
import {
  EncryptedScheme,
  decryptConfidentialAsSender,
  readOutputData,
} from "../transaction/serialization/codecs.js";
import { SOL_MINT, type AssetRegistry } from "../transaction/asset.js";
import { openSealedMessage } from "../transaction/wallet/encrypt-rails.js";

import { fetchSplAssetRegistrations } from "../wallet/sync.js";

import { RingError } from "./error.js";
import { spendRecordFromSlot, type SpendCounters, type SpendRecord } from "./policy.js";
import {
  checkedSpendCounters,
  findSpendCountersMessage,
  RING_SPEND_COUNTERS_SLOT_INDEX,
} from "./counters.js";
import { CachedTransactionOrigin, RpcTransactionOrigin, type TransactionOrigin } from "./origin.js";

/** Mirrors Rust `AuditedOutput`. */
export interface AuditedRingOutput {
  readonly slotIndex: number;
  readonly outputContext: OutputContext;
  readonly recipientViewingPublicKey: P256PublicKey;
  /** `OutputSlot.viewTag`, which the circuit binds to the output's owner. */
  readonly ownerTag: Bytes32;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly data: Data;
  readonly ringProgramId?: Address;
}

/** Reports a spend record and any counters authenticated by its commitment. */
export interface AuditedRingSpendRecord {
  readonly slotIndex: number;
  readonly record: SpendRecord;
  readonly counters?: SpendCounters;
}

/** Mirrors Rust `AuditedTransaction`. Dummy slots and foreign schemes land in `undecryptableSlots`. */
export interface AuditedRingTransaction {
  readonly signature: Signature;
  readonly slot: bigint;
  readonly txViewingPublicKey: P256PublicKey;
  readonly outputs: readonly AuditedRingOutput[];
  readonly spendRecords: readonly AuditedRingSpendRecord[];
  readonly undecryptableSlots: readonly number[];
  readonly invalidSpendRecordSlots: readonly number[];
}

export interface RingAuditPage {
  readonly transactions: readonly AuditedRingTransaction[];
  readonly nextCursor?: Uint8Array;
}

const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 32;
const P256_ORDER = p256.Point.Fn.ORDER;

/** Mirrors Rust `auditor_message`, the program accepts the tagged message only as the unique last entry. */
export function auditorMessage(
  transaction: IndexedShieldedTransaction,
  auditorPublicKey: P256PublicKey,
): AuditorMessage {
  const viewTag = auditorViewTag(auditorPublicKey);
  const tagged = transaction.messages.flatMap((message, index) =>
    equal(message.viewTag, viewTag) ? [index] : [],
  );
  const index = tagged[0];
  if (index === undefined) {
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "missing" } });
  }
  if (tagged.length > 1) {
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "duplicate" } });
  }
  const count = transaction.messages.length;
  if (index + 1 !== count) {
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "not last", index, count } });
  }
  const message = transaction.messages[index];
  if (message === undefined) {
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "missing" } });
  }
  return parseAuditorMessage(message.data);
}

/**
 * Mirrors Rust `recover_tx_viewing_key`. The circuit binds the secret modulo the
 * P-256 group order, so any representative of the scalar class decrypts to the
 * canonical key.
 */
export function recoverTransactionViewingKey(
  auditor: ViewingKey,
  message: AuditorMessage,
): ViewingKey {
  const recovered = decryptTransactionViewingSecret(auditor, message);
  try {
    return ViewingKey.fromBytes(bigIntToBytes(bytesToBigInt(recovered) % P256_ORDER) as Bytes32);
  } finally {
    recovered.fill(0);
  }
}

/** Mirrors Rust `TransactionAudit::run`. */
export function auditRingTransaction(
  input: Readonly<{
    auditor: ViewingKey;
    transaction: IndexedShieldedTransaction;
    assets: AssetRegistry;
  }>,
): AuditedRingTransaction {
  const { transaction } = input;
  const message = auditorMessage(transaction, input.auditor.publicKey());
  const txViewingPublicKey = transaction.txViewingPublicKey;
  const salt = transaction.salt;
  if (txViewingPublicKey === undefined || salt === undefined) {
    throw new RingError("RING_AUDIT_UNSEALED", { details: { signature: transaction.txSignature } });
  }
  const txKey = recoverTransactionViewingKey(input.auditor, message);
  try {
    if (!txKey.publicKey().equals(txViewingPublicKey)) {
      throw new RingError("RING_AUDIT_KEY_MISMATCH", {
        details: { signature: transaction.txSignature },
      });
    }
    const outputs: AuditedRingOutput[] = [];
    const spendRecords: AuditedRingSpendRecord[] = [];
    const undecryptableSlots: number[] = [];
    const invalidSpendRecordSlots: number[] = [];
    transaction.outputSlots.forEach((slot, slotIndex) => {
      const output = auditOutput(txKey, slot, salt, slotIndex, input.assets);
      const carried = carriedRecord({
        slot,
        messages: transaction.messages,
        last: slotIndex === transaction.outputSlots.length - 1,
        output,
        txViewingPublicKey,
      });
      if (carried.kind === "record") {
        const counters = openRecordCounters(txKey, {
          messages: transaction.messages,
          viewTag: slot.viewTag,
          salt,
          record: carried.record,
        });
        spendRecords.push({
          slotIndex,
          record: carried.record,
          ...(counters === undefined ? {} : { counters }),
        });
        return;
      }
      if (carried.kind === "invalid") invalidSpendRecordSlots.push(slotIndex);
      if (output !== undefined) {
        outputs.push(output);
        return;
      }
      undecryptableSlots.push(slotIndex);
    });
    return Object.freeze({
      signature: transaction.txSignature,
      slot: transaction.slot,
      txViewingPublicKey,
      outputs: Object.freeze(outputs),
      spendRecords: Object.freeze(spendRecords),
      undecryptableSlots: Object.freeze(undecryptableSlots),
      invalidSpendRecordSlots: Object.freeze(invalidSpendRecordSlots),
    });
  } finally {
    txKey.destroy();
  }
}

export type RingAuditReader = KitRpcAccess & Pick<IndexerReader, "getShieldedTransactionsByTags">;

/**
 * Mirrors Rust `RingAudit`. The indexer knows no rings, each tagged transaction
 * is attributed through its confirmed call stack, and the tag match is
 * re-applied because the indexer matches output tags too. An unknown SPL asset
 * id refreshes `assets` once from the chain registry.
 */
export async function auditRing(
  input: Readonly<{
    client: RingAuditReader;
    auditor: ViewingKey;
    ringProgramId: Address;
    assets: AssetRegistry;
    origin?: TransactionOrigin;
    cursor?: Uint8Array;
    pageSize?: number;
    maxPages?: number;
  }>,
  context?: RequestContext,
): Promise<RingAuditPage> {
  await initializePoseidon();
  const viewTag = auditorViewTag(input.auditor.publicKey());
  const pageSize = input.pageSize ?? DEFAULT_PAGE_SIZE;
  const maxPages = input.maxPages ?? DEFAULT_MAX_PAGES;
  const origin = new CachedTransactionOrigin(
    input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc),
  );
  const transactions: AuditedRingTransaction[] = [];
  let assetsRefreshed = false;
  let cursor = input.cursor;
  for (let page = 0; page < maxPages; page++) {
    const response = await input.client.getShieldedTransactionsByTags(
      {
        tags: [viewTag],
        limit: pageSize,
        ...(cursor === undefined ? {} : { cursor }),
      },
      undefined,
      context,
    );
    for (const transaction of response.transactions) {
      if (!transaction.messages.some((message) => equal(message.viewTag, viewTag))) continue;
      if (!(await origin.ringInvoked(transaction.txSignature, input.ringProgramId, context))) {
        continue;
      }
      try {
        transactions.push(
          auditRingTransaction({ auditor: input.auditor, transaction, assets: input.assets }),
        );
      } catch (error) {
        if (assetsRefreshed || !isUnknownAsset(error)) throw error;
        assetsRefreshed = true;
        for (const { assetId, mint } of await fetchSplAssetRegistrations(input.client, context)) {
          input.assets.register(assetId, mint);
        }
        transactions.push(
          auditRingTransaction({ auditor: input.auditor, transaction, assets: input.assets }),
        );
      }
    }
    const next = response.nextCursor;
    if (next === undefined) return Object.freeze({ transactions: Object.freeze(transactions) });
    if (cursor !== undefined && equal(cursor, next)) {
      throw new RingError("RING_RPC", { details: { reason: "ring scan cursor did not advance" } });
    }
    cursor = next;
  }
  return Object.freeze({
    transactions: Object.freeze(transactions),
    ...(cursor === undefined ? {} : { nextCursor: cursor }),
  });
}

function isUnknownAsset(error: unknown): boolean {
  return error instanceof TransactionError && error.code === "TRANSACTION_UNKNOWN_ASSET";
}

type CarriedRecord =
  | Readonly<{ kind: "record"; record: SpendRecord }>
  | Readonly<{ kind: "none" | "invalid" }>;

const NO_RECORD: CarriedRecord = Object.freeze({ kind: "none" });
const INVALID_RECORD: CarriedRecord = Object.freeze({ kind: "invalid" });

/** A crafted message marks its slot invalid, the money the slot carries is still reported. */
function carriedRecord(
  input: Readonly<{
    slot: OutputSlot;
    messages: readonly MessageData[];
    last: boolean;
    output: AuditedRingOutput | undefined;
    txViewingPublicKey: P256PublicKey;
  }>,
): CarriedRecord {
  let record: SpendRecord | undefined;
  try {
    record = spendRecordFromSlot(input.slot, input.messages);
  } catch {
    return INVALID_RECORD;
  }
  if (record === undefined) return NO_RECORD;
  const { output } = input;
  const carrier =
    input.last &&
    output !== undefined &&
    output.asset === SOL_MINT &&
    output.amount === 0n &&
    output.ringProgramId === undefined &&
    equal(output.blinding, record.blinding) &&
    output.recipientViewingPublicKey.equals(input.txViewingPublicKey);
  if (record.version !== 0n && !carrier) return INVALID_RECORD;
  return { kind: "record", record };
}

/** `undefined` when the counters do not reproduce the record's commitment. */
function openRecordCounters(
  txKey: ViewingKey,
  input: Readonly<{
    messages: readonly MessageData[];
    viewTag: Bytes32;
    salt: Bytes16;
    record: SpendRecord;
  }>,
): SpendCounters | undefined {
  const message = findSpendCountersMessage(input.messages, input.viewTag);
  if (message === undefined) return undefined;
  try {
    return checkedSpendCounters(
      openSealedMessage(txKey, {
        salt: input.salt,
        slotIndex: RING_SPEND_COUNTERS_SLOT_INDEX,
        data: message.data,
      }),
      input.record.countersCommitment,
    );
  } catch {
    return undefined;
  }
}

/** `undefined` for a slot this audit cannot open, Rust `OutputAudit::run`. */
function auditOutput(
  txKey: ViewingKey,
  slot: OutputSlot,
  salt: Bytes16,
  slotIndex: number,
  assets: AssetRegistry,
): AuditedRingOutput | undefined {
  let plaintext;
  let recipient: P256PublicKey;
  try {
    const frame = readOutputData(slot.payload);
    if (
      frame.encoding !== "encrypted" ||
      (frame.scheme !== EncryptedScheme.confidential &&
        frame.scheme !== EncryptedScheme.ringConfidential)
    ) {
      return undefined;
    }
    recipient = P256PublicKey.fromBytes(frame.body.slice(0, 33) as Bytes33);
    plaintext = decryptConfidentialAsSender(txKey, frame.body, salt, slotIndex);
  } catch {
    return undefined;
  }
  return Object.freeze({
    slotIndex,
    outputContext: slot.outputContext,
    recipientViewingPublicKey: recipient,
    ownerTag: slot.viewTag,
    asset: assets.resolve(plaintext.assetId),
    amount: plaintext.amount,
    blinding: plaintext.blinding,
    data: plaintext.data,
    ...(plaintext.ringProgramId === undefined ? {} : { ringProgramId: plaintext.ringProgramId }),
  });
}
