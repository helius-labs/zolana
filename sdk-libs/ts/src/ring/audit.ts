import { X25519PublicKey, X25519Keypair } from "../keypair/x25519.js";
import { SOLANA_OWNER_TAG, hashBytes, initializePoseidon } from "../hasher/index.js";

import type { IndexerReader, KitRpcAccess } from "../client/ports.js";
import { concatBytes, equalBytes } from "../interface/bytes.js";
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
  AUDIT_OUTPUT_SLOTS,
  auditorViewTag,
  decryptTransactionViewingSecret,
  isDummyAnonymousOutput,
  openAnonymousAuditDisclosure,
  openAuditOutputDisclosure,
  parseAuditorMessage,
  type AnonymousAuditDisclosure,
  type AnonymousOutputOpening,
  type AuditDisclosureShape,
  type AuditOutputOpening,
  type AuditorMessage,
} from "../keypair/audit.js";
import { bigIntToBytes } from "../keypair/bytes.js";
import { clampViewingSecret } from "../keypair/derivation.js";
import { ownerHash } from "../keypair/hash.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import { TransactionError } from "../transaction/error.js";
import { commitmentPoseidon, rightAlign, ZERO_32 } from "../transaction/internal.js";
import { addressBytes, encodeBase58 } from "../interface/internal.js";
import { UTXO_DOMAIN } from "../interface/program.js";
import { treeIdField } from "../interface/tree-slot.js";
import type { Data } from "../transaction/data.js";
import type {
  IndexedShieldedTransaction,
  OutputContext,
  OutputSlot,
} from "../transaction/instructions/transact.js";
import {
  EncryptedScheme,
  decodeConfidential,
  decryptConfidentialAsSender,
  readOutputData,
  type ConfidentialOutputPlaintext,
} from "../transaction/serialization/codecs.js";
import { SOL_MINT, type AssetRegistry } from "../transaction/asset.js";

import { fetchSplAssetRegistrations } from "../wallet/sync.js";

import type { RingMode } from "./codecs.js";
import { RingError } from "./error.js";
import { spendRecordFromSlot, type SpendCounters, type SpendRecord } from "./policy.js";
import { openSpendCountersWithKey, findSpendCountersMessage } from "./counters.js";
import { CachedTransactionOrigin, RpcTransactionOrigin, type TransactionOrigin } from "./origin.js";

/** Hidden identities and note openings disclosed only to authorized audit readers. */
export interface DecryptedAnonymousRingTrace {
  readonly sender: Address;
  readonly inputs: readonly Readonly<{ treeId: number; amount: bigint; asset: Bytes32 }>[];
  readonly recipients: readonly Readonly<{
    slotIndex: number;
    identityTag: typeof SOLANA_OWNER_TAG;
    identityKey: Bytes32;
    nullifierPk: Bytes32;
    amount: bigint;
    asset: Bytes32;
  }>[];
}

/** Mirrors Rust `AuditedOutput`. */
export interface AuditedRingOutput {
  readonly slotIndex: number;
  readonly outputContext: OutputContext;
  readonly recipientViewingPublicKey: X25519PublicKey;
  /** `OutputSlot.viewTag`, which the circuit binds to the output's owner. In an anonymous ring, the disclosed owner key. */
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
  readonly txViewingPublicKey: X25519PublicKey;
  readonly outputs: readonly AuditedRingOutput[];
  /** One per output slot, a dummy slot of an anonymous ring opens to zero. */
  readonly outputOpenings: readonly AuditOutputOpening[];
  /** Present exactly for a transaction audited as `"anonymous"`. */
  readonly anonymous?: DecryptedAnonymousRingTrace;
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

/**
 * Mirrors Rust `auditor_message`, the program accepts the tagged message only as
 * the unique last entry. `shape` selects the anonymous disclosure length.
 */
export function auditorMessage(
  transaction: IndexedShieldedTransaction,
  auditorPublicKey: X25519PublicKey,
  shape?: AuditDisclosureShape,
): AuditorMessage {
  const viewTag = auditorViewTag(auditorPublicKey);
  const tagged = transaction.messages.flatMap((message, index) =>
    equalBytes(message.viewTag, viewTag) ? [index] : [],
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
  try {
    return parseAuditorMessage(message.data, shape);
  } catch (cause) {
    throw new RingError("RING_AUDIT_MESSAGE", {
      details: { reason: "malformed", length: message.data.length },
      cause,
    });
  }
}

/**
 * Recovers the clamped transaction secret bound byte for byte by the circuit.
 */
export function recoverTransactionViewingKey(
  auditor: X25519Keypair,
  message: AuditorMessage,
): ViewingKey {
  const recovered = decryptTransactionViewingSecret(auditor, message);
  const canonical = clampViewingSecret(recovered);
  try {
    let difference = 0;
    for (let index = 0; index < 32; index++) {
      difference |= (recovered[index] ?? 0) ^ (canonical[index] ?? 0);
    }
    if (difference !== 0) {
      throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "noncanonical key" } });
    }
    return ViewingKey.fromBytes(recovered as Bytes32);
  } finally {
    canonical.fill(0);
    recovered.fill(0);
  }
}

/**
 * Mirrors Rust `TransactionAudit::run_with_mode`. The ring's on-chain `mode`
 * selects the disclosure layout, `"anonymous"` opens the hidden sender, inputs
 * and recipients and reconstructs every real output commitment from them.
 */
export function auditRingTransaction(
  input: Readonly<{
    auditor: X25519Keypair;
    transaction: IndexedShieldedTransaction;
    assets: AssetRegistry;
    mode?: RingMode;
  }>,
): AuditedRingTransaction {
  const { transaction } = input;
  const anonymous = input.mode === "anonymous";
  const shape: AuditDisclosureShape = {
    anonymous,
    inputs: transaction.nullifiers.length,
    outputs: transaction.outputSlots.length,
  };
  const message = auditorMessage(
    transaction,
    input.auditor.publicKey(),
    anonymous ? shape : undefined,
  );
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
    if (transaction.outputSlots.length > AUDIT_OUTPUT_SLOTS) {
      throw new RingError("RING_AUDIT_OUTPUT_MISMATCH", {
        details: { reason: "count", count: transaction.outputSlots.length },
      });
    }
    const txSecret = txKey.secretBytes();
    let outputOpenings: readonly AuditOutputOpening[];
    let disclosure: AnonymousAuditDisclosure | undefined;
    try {
      if (anonymous) {
        disclosure = openAnonymousDisclosure(txSecret, salt, message.disclosure, shape);
        const opened = disclosure;
        outputOpenings = transaction.outputSlots.map((slot, slotIndex) =>
          anonymousOutputOpening(
            opened.outputs[slotIndex],
            slot,
            transaction.ringProgramId,
            slotIndex,
          ),
        );
      } else {
        outputOpenings = openAuditOutputDisclosure(txSecret, salt, message.disclosure).slice(
          0,
          transaction.outputSlots.length,
        );
      }
    } finally {
      txSecret.fill(0);
    }
    const trace = disclosure === undefined ? undefined : anonymousTrace(disclosure);
    const spendRecords: AuditedRingSpendRecord[] = [];
    const undecryptableSlots: number[] = [];
    const invalidSpendRecordSlots: number[] = [];
    transaction.outputSlots.forEach((slot, slotIndex) => {
      const opening = outputOpenings[slotIndex];
      const anonymousOutput = disclosure?.outputs[slotIndex];
      // A dummy slot of an anonymous ring carries no blinding to reconstruct.
      const dummy = anonymousOutput !== undefined && isDummyAnonymousOutput(anonymousOutput);
      if (
        opening === undefined ||
        (!dummy && !equalBytes(auditOpeningHash(opening), slot.outputContext.hash))
      ) {
        throw new RingError("RING_AUDIT_OUTPUT_MISMATCH", {
          details: { reason: "commitment", slotIndex },
        });
      }
      const output = auditOutput(
        txKey,
        slot,
        salt,
        slotIndex,
        input.assets,
        opening,
        anonymousOutput,
      );
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
      outputOpenings: Object.freeze(outputOpenings),
      ...(trace === undefined ? {} : { anonymous: trace }),
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
    auditor: X25519Keypair;
    ringProgramId: Address;
    assets: AssetRegistry;
    /** The ring's on-chain mode, `"off"` when omitted. */
    mode?: RingMode;
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
      if (transaction.eventIndex === undefined) {
        throw new RingError("RING_RPC", { details: { reason: "missing event index" } });
      }
      if (transaction.ringProgramId !== input.ringProgramId) continue;
      if (!transaction.messages.some((message) => equalBytes(message.viewTag, viewTag))) continue;
      if (
        !(await origin.ringInvoked(
          transaction.txSignature,
          transaction.eventIndex,
          input.ringProgramId,
          context,
        ))
      ) {
        continue;
      }
      const audit = {
        auditor: input.auditor,
        transaction,
        assets: input.assets,
        ...(input.mode === undefined ? {} : { mode: input.mode }),
      };
      try {
        transactions.push(auditRingTransaction(audit));
      } catch (error) {
        if (assetsRefreshed || !isUnknownAsset(error)) throw error;
        assetsRefreshed = true;
        for (const { assetId, mint } of await fetchSplAssetRegistrations(input.client, context)) {
          input.assets.register(assetId, mint);
        }
        transactions.push(auditRingTransaction(audit));
      }
    }
    const next = response.nextCursor;
    if (next === undefined) return Object.freeze({ transactions: Object.freeze(transactions) });
    if (cursor !== undefined && equalBytes(cursor, next)) {
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
    txViewingPublicKey: X25519PublicKey;
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
    equalBytes(output.blinding, record.blinding) &&
    output.recipientViewingPublicKey.equals(input.txViewingPublicKey);
  if (record.version !== 0n && !carrier) return INVALID_RECORD;
  return { kind: "record", record };
}

function openRecordCounters(
  txKey: ViewingKey,
  input: Readonly<{
    messages: readonly MessageData[];
    viewTag: Bytes32;
    salt: Bytes16;
    record: SpendRecord;
  }>,
): SpendCounters | undefined {
  if (input.record.version === 0n) return undefined;
  const message = findSpendCountersMessage(input.messages, input.viewTag);
  if (message === undefined) throw new RingError("RING_SPEND_COUNTERS_UNKNOWN");
  return openSpendCountersWithKey(txKey, {
    salt: input.salt,
    data: message.data,
    commitment: input.record.countersCommitment,
  });
}

/**
 * `undefined` for a slot this audit cannot open, Rust `OutputAudit::run`. An
 * anonymous slot omits the recipient key, the proved disclosure supplies it.
 */
function auditOutput(
  txKey: ViewingKey,
  slot: OutputSlot,
  salt: Bytes16,
  slotIndex: number,
  assets: AssetRegistry,
  opening: AuditOutputOpening,
  anonymousOutput: AnonymousOutputOpening | undefined,
): AuditedRingOutput | undefined {
  let plaintext: ConfidentialOutputPlaintext;
  let recipient: X25519PublicKey;
  let ownerTag: Bytes32;
  try {
    const frame = readOutputData(slot.payload);
    if (frame.encoding !== "encrypted") return undefined;
    if (frame.scheme === EncryptedScheme.ringAnonymous) {
      if (anonymousOutput === undefined || isDummyAnonymousOutput(anonymousOutput))
        return undefined;
      recipient = X25519PublicKey.fromBytes(anonymousOutput.viewingPublicKey);
      plaintext = decodeConfidential(
        txKey.decryptSlotEphemeral(recipient, frame.body, salt, slotIndex),
      );
      ownerTag = anonymousOutput.identityKey;
    } else if (
      frame.scheme === EncryptedScheme.confidential ||
      frame.scheme === EncryptedScheme.ringConfidential
    ) {
      recipient = X25519PublicKey.fromBytes(frame.body.slice(0, 33) as Bytes33);
      plaintext = decryptConfidentialAsSender(txKey, frame.body, salt, slotIndex);
      ownerTag = slot.viewTag;
    } else {
      return undefined;
    }
  } catch {
    return undefined;
  }
  const asset = assets.resolve(plaintext.assetId);
  const ringProgramId =
    plaintext.ringProgramId === undefined
      ? ZERO_32
      : (hashBytes(addressBytes(plaintext.ringProgramId, "ringProgramId")) as Bytes32);
  if (
    !equalBytes(hashBytes(addressBytes(asset, "asset")), opening.asset) ||
    !equalBytes(rightAlign(bigIntToBytes(plaintext.amount, 8)), opening.amount) ||
    !equalBytes(plaintext.blinding, opening.blinding) ||
    !equalBytes(ringProgramId, opening.ringProgramId)
  ) {
    throw new RingError("RING_AUDIT_OUTPUT_MISMATCH", {
      details: { reason: "plaintext", slotIndex },
    });
  }
  return Object.freeze({
    slotIndex,
    outputContext: slot.outputContext,
    recipientViewingPublicKey: recipient,
    ownerTag,
    asset,
    amount: plaintext.amount,
    blinding: plaintext.blinding,
    data: plaintext.data,
    ...(plaintext.ringProgramId === undefined ? {} : { ringProgramId: plaintext.ringProgramId }),
  });
}

function openAnonymousDisclosure(
  secret: Bytes32,
  salt: Bytes16,
  disclosure: readonly Bytes32[],
  shape: AuditDisclosureShape,
): AnonymousAuditDisclosure {
  try {
    return openAnonymousAuditDisclosure(secret, salt, disclosure, shape);
  } catch (cause) {
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "disclosure" }, cause });
  }
}

const ZERO_OPENING: AuditOutputOpening = Object.freeze({
  domain: ZERO_32,
  treeId: ZERO_32,
  ownerHash: ZERO_32,
  asset: ZERO_32,
  amount: ZERO_32,
  blinding: ZERO_32,
  dataHash: ZERO_32,
  ringDataHash: ZERO_32,
  ringProgramId: ZERO_32,
});

/**
 * Rebuilds a real output's proof opening from its disclosed identity and ring
 * flag, Rust `anonymous_output_opening`. The tree id is not disclosed, so the
 * indexed context must carry it.
 */
function anonymousOutputOpening(
  output: AnonymousOutputOpening | undefined,
  slot: OutputSlot,
  ring: Address | undefined,
  slotIndex: number,
): AuditOutputOpening {
  const mismatch = (reason: string): RingError =>
    new RingError("RING_AUDIT_OUTPUT_MISMATCH", { details: { reason, slotIndex } });
  if (output === undefined) throw mismatch("count");
  if (isDummyAnonymousOutput(output)) return ZERO_OPENING;
  const treeId = slot.outputContext.treeId;
  if (treeId === undefined) throw mismatch("treeId");
  let ringProgramId: Bytes32 = ZERO_32;
  if (output.ringNote) {
    if (ring === undefined) throw mismatch("ring");
    ringProgramId = hashBytes(addressBytes(ring, "ringProgramId")) as Bytes32;
  }
  const identity = hashBytes(concatBytes(Uint8Array.of(output.identityTag), output.identityKey));
  return Object.freeze({
    domain: rightAlign(Uint8Array.of(UTXO_DOMAIN)),
    treeId: treeIdField(treeId),
    ownerHash: ownerHash(identity, output.nullifierPublicKey) as Bytes32,
    asset: output.asset,
    amount: rightAlign(bigIntToBytes(output.amount, 8)),
    blinding: output.blinding,
    dataHash: output.dataHash,
    ringDataHash: output.ringDataHash,
    ringProgramId,
  });
}

/** The reader-facing trace, the same shape `RingRpc.getDecryptedTransactions` returns. */
function anonymousTrace(disclosure: AnonymousAuditDisclosure): DecryptedAnonymousRingTrace {
  const recipients = disclosure.outputs.flatMap((output, slotIndex) => {
    if (isDummyAnonymousOutput(output)) return [];
    const { identityTag } = output;
    if (identityTag !== SOLANA_OWNER_TAG) {
      throw new RingError("RING_AUDIT_OUTPUT_MISMATCH", {
        details: { reason: "identityTag", slotIndex },
      });
    }
    return [
      Object.freeze({
        slotIndex,
        identityTag,
        identityKey: output.identityKey,
        nullifierPk: output.nullifierPublicKey,
        amount: output.amount,
        asset: output.asset,
      }),
    ];
  });
  return Object.freeze({
    sender: encodeBase58(disclosure.sender),
    inputs: Object.freeze(
      disclosure.inputs
        // Match RingRpc's complete dummy opening before discarding the blinding.
        .filter(
          (input) =>
            input.treeId !== 0 ||
            input.amount !== 0n ||
            !equalBytes(input.asset, ZERO_32) ||
            !equalBytes(input.blinding, ZERO_32),
        )
        .map((input) =>
          Object.freeze({ treeId: input.treeId, amount: input.amount, asset: input.asset }),
        ),
    ),
    recipients: Object.freeze(recipients),
  });
}

/** Reconstructs the exact SPP output commitment the custom-ring proof binds. */
function auditOpeningHash(opening: AuditOutputOpening): Bytes32 {
  return commitmentPoseidon([
    opening.domain,
    opening.treeId,
    opening.asset,
    opening.amount,
    opening.dataHash,
    commitmentPoseidon([opening.ringDataHash, opening.ringProgramId]),
    commitmentPoseidon([opening.ownerHash, opening.blinding]),
  ]);
}
