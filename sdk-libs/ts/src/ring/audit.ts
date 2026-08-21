import { p256 } from "@noble/curves/nist.js";

import type { ZolanaClient } from "../client/client.js";
import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
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
import { equal } from "../transaction/internal.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";
import {
  EncryptedScheme,
  decryptConfidentialAsSender,
  readOutputData,
} from "../transaction/serialization/codecs.js";
import type { AssetRegistry } from "../transaction/wallet/asset.js";

import { RingError } from "./error.js";
import { CachedTransactionOrigin, RpcTransactionOrigin, type TransactionOrigin } from "./origin.js";

/** Mirrors Rust `AuditedOutput`. */
export interface AuditedRingOutput {
  readonly slotIndex: number;
  readonly recipientViewingPublicKey: P256PublicKey;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly ringProgramId?: Address;
}

/** Mirrors Rust `AuditedTransaction`. Dummy slots and foreign schemes land in `undecryptableSlots`. */
export interface AuditedRingTransaction {
  readonly signature: Signature;
  readonly slot: bigint;
  readonly txViewingPublicKey: P256PublicKey;
  readonly outputs: readonly AuditedRingOutput[];
  readonly undecryptableSlots: readonly number[];
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
    const undecryptableSlots: number[] = [];
    transaction.outputSlots.forEach((slot, slotIndex) => {
      const output = auditOutput(txKey, slot.payload, salt, slotIndex, input.assets);
      if (output === undefined) undecryptableSlots.push(slotIndex);
      else outputs.push(output);
    });
    return Object.freeze({
      signature: transaction.txSignature,
      slot: transaction.slot,
      txViewingPublicKey,
      outputs: Object.freeze(outputs),
      undecryptableSlots: Object.freeze(undecryptableSlots),
    });
  } finally {
    txKey.destroy();
  }
}

/**
 * Mirrors Rust `RingAudit`. The indexer knows no rings, each tagged transaction
 * is attributed through its confirmed call stack, and the tag match is
 * re-applied because the indexer matches output tags too.
 */
export async function auditRing(
  input: Readonly<{
    client: ZolanaClient;
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
  const viewTag = auditorViewTag(input.auditor.publicKey());
  const pageSize = input.pageSize ?? DEFAULT_PAGE_SIZE;
  const maxPages = input.maxPages ?? DEFAULT_MAX_PAGES;
  const origin = new CachedTransactionOrigin(
    input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc),
  );
  const transactions: AuditedRingTransaction[] = [];
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
      transactions.push(
        auditRingTransaction({ auditor: input.auditor, transaction, assets: input.assets }),
      );
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

/** `undefined` for a slot this audit cannot open, Rust `OutputAudit::run`. */
function auditOutput(
  txKey: ViewingKey,
  payload: Uint8Array,
  salt: Bytes16,
  slotIndex: number,
  assets: AssetRegistry,
): AuditedRingOutput | undefined {
  let plaintext;
  let recipient: P256PublicKey;
  try {
    const frame = readOutputData(payload);
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
    recipientViewingPublicKey: recipient,
    asset: assets.resolve(plaintext.assetId),
    amount: plaintext.amount,
    blinding: plaintext.blinding,
    ...(plaintext.zoneProgramId === undefined ? {} : { ringProgramId: plaintext.zoneProgramId }),
  });
}
