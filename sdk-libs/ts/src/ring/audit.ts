import { SOLANA_OWNER_TAG, hashBytes, initializePoseidon } from "../hasher/index.js";

import type { IndexerReader, KitRpcAccess } from "../client/ports.js";
import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
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
import { bigIntToBytes, concatBytes } from "../keypair/bytes.js";
import { clampViewingSecret } from "../keypair/derivation.js";
import { ownerHash } from "../keypair/hash.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import { X25519PublicKey, X25519Keypair } from "../keypair/x25519.js";
import {
  bytesToBigInt,
  commitmentPoseidon,
  equal,
  rightAlign,
  ZERO_32,
} from "../transaction/internal.js";
import { addressBytes, encodeBase58 } from "../interface/internal.js";
import { UTXO_DOMAIN } from "../interface/program.js";
import { treeIdField } from "../interface/tree-slot.js";
import { Data } from "../transaction/data.js";
import type {
  IndexedShieldedTransaction,
  OutputContext,
  OutputSlot,
} from "../transaction/instructions/transact.js";
import {
  EncryptedScheme,
  RING_ANONYMOUS_PLAINTEXT_LENGTH,
  decodeRingAnonymous,
  decryptConfidentialAsSender,
  readOutputData,
  type ConfidentialOutputPlaintext,
  type RingAnonymousOutputPlaintext,
} from "../transaction/serialization/codecs.js";
import type { AssetRegistry } from "../transaction/asset.js";

import { fetchSplAssetRegistrations } from "../wallet/sync.js";

import type { RingMode } from "./codecs.js";
import { RingError } from "./error.js";
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

/** Optional recipient delivery metadata, checked against the authoritative output opening. */
export interface AuditedRingOutput {
  readonly slotIndex: number;
  readonly outputContext: OutputContext;
  readonly recipientViewingPublicKey: X25519PublicKey;
  /** Recipient-delivery view tag. In an anonymous ring, the disclosed owner key. */
  readonly ownerTag: Bytes32;
  readonly asset: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly data: Data;
  readonly ringProgramId?: Address;
}

/**
 * Why a slot's recipient payload yields no `AuditedRingOutput`, Rust `OutputPayloadErrorKind`.
 * `unreadable` is a ciphertext this audit cannot open, `openingMismatch` a plaintext that
 * disagrees with the proven opening, `unknownAsset` a proven asset the registry lacks and
 * `pairHint` a pair hint outside the canonical X25519 encoding beside a stored output.
 */
export type OutputPayloadErrorKind = "unreadable" | "openingMismatch" | "unknownAsset" | "pairHint";

export const OUTPUT_PAYLOAD_ERROR_KINDS: readonly OutputPayloadErrorKind[] = Object.freeze([
  "unreadable",
  "openingMismatch",
  "unknownAsset",
  "pairHint",
]);

export interface OutputPayloadError {
  readonly slotIndex: number;
  readonly kind: OutputPayloadErrorKind;
}

/** Verified disclosure survives missing or invalid recipient delivery metadata. */
export interface AuditedRingTransaction {
  readonly signature: Signature;
  readonly slot: bigint;
  readonly txViewingPublicKey: X25519PublicKey;
  /** Recipient delivery metadata only, absent for unreadable or mismatching ciphertext. */
  readonly outputs: readonly AuditedRingOutput[];
  /** One per output slot, a dummy slot of an anonymous ring opens to zero. */
  readonly outputOpenings: readonly AuditOutputOpening[];
  /** Same slot order as `outputOpenings`, including dummy slots. */
  readonly outputContexts: readonly OutputContext[];
  /** Present exactly for a transaction audited as `"anonymous"`. */
  readonly anonymous?: DecryptedAnonymousRingTrace;
  /** Slot order, a padding slot of an anonymous ring is not an error. */
  readonly payloadErrors: readonly OutputPayloadError[];
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
 * Mirrors Rust `recover_tx_viewing_key`. The circuit proves the plaintext is the clamped
 * encoding and keys the disclosure stream with these exact bytes, so an alias is refused.
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
      throw new RingError("RING_AUDIT_NONCANONICAL_KEY");
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
  const message = auditorMessage(transaction, input.auditor.publicKey(), shape);
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
    let bodies: readonly (AnonymousBody | undefined)[] = [];
    try {
      if (anonymous) {
        disclosure = openAnonymousDisclosure(txSecret, salt, message.disclosure, shape);
        const opened = disclosure;
        bodies = transaction.outputSlots.map((slot, slotIndex) =>
          openAnonymousBody(txKey, salt, opened.outputs[slotIndex], slot, transaction, slotIndex),
        );
        outputOpenings = bodies.map((body) => body?.opening ?? ZERO_OPENING);
      } else {
        outputOpenings = openAuditOutputDisclosure(txSecret, salt, message.disclosure).slice(
          0,
          transaction.outputSlots.length,
        );
      }
    } finally {
      txSecret.fill(0);
    }
    const trace = disclosure === undefined ? undefined : anonymousTrace(disclosure, bodies);
    const payloadErrors: OutputPayloadError[] = [];
    transaction.outputSlots.forEach((slot, slotIndex) => {
      const opening = outputOpenings[slotIndex];
      if (opening === undefined) {
        throw new RingError("RING_AUDIT_OUTPUT_MISMATCH", {
          details: { reason: "count", slotIndex },
        });
      }
      // A padding slot of an anonymous ring opens to zero and commits to nothing the auditor rebuilds.
      if (anonymous && bodies[slotIndex] === undefined) return;
      if (!equal(auditOpeningHash(opening), slot.outputContext.hash)) {
        throw new RingError("RING_AUDIT_OUTPUT_MISMATCH", {
          details: { reason: "commitment", slotIndex },
        });
      }
      const body = bodies[slotIndex];
      const output =
        body === undefined
          ? auditOutput(txKey, slot, salt, slotIndex, input.assets, opening)
          : anonymousAuditOutput(body, slot, slotIndex);
      for (const kind of output.errors) payloadErrors.push({ slotIndex, kind });
      if (output.output !== undefined) outputs.push(output.output);
    });
    return Object.freeze({
      signature: transaction.txSignature,
      slot: transaction.slot,
      txViewingPublicKey,
      outputs: Object.freeze(outputs),
      outputOpenings: Object.freeze(outputOpenings),
      outputContexts: Object.freeze(transaction.outputSlots.map((slot) => slot.outputContext)),
      ...(trace === undefined ? {} : { anonymous: trace }),
      payloadErrors: Object.freeze(payloadErrors),
    });
  } finally {
    txKey.destroy();
  }
}

export type RingAuditReader = KitRpcAccess & Pick<IndexerReader, "getShieldedTransactionsByTags">;

/**
 * Mirrors Rust `RingAudit`. The indexer knows no rings, each tagged transaction
 * is attributed through its confirmed call stack. Deposits and merges are excluded
 * by their confirmed instruction kind because the indexer also matches output tags.
 * A confirmed transfer must carry its auditor message. An unresolved proved asset
 * refreshes `assets` once from the chain registry, while the opening remains available.
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
  for (const [name, value] of [
    ["pageSize", pageSize],
    ["maxPages", maxPages],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new RingError("RING_RPC", { details: { reason: "invalid scan limit", name, value } });
    }
  }
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
      const confirmed = await origin.confirmedTransaction(
        transaction,
        input.ringProgramId,
        context,
      );
      if (
        confirmed === undefined ||
        confirmed.proofless ||
        confirmed.txViewingPublicKey === undefined
      )
        continue;
      const audit = {
        auditor: input.auditor,
        transaction: confirmed,
        assets: input.assets,
        ...(input.mode === undefined ? {} : { mode: input.mode }),
      };
      let audited = auditRingTransaction(audit);
      if (
        !assetsRefreshed &&
        audited.outputOpenings.some(
          (opening) =>
            bytesToBigInt(opening.domain) === BigInt(UTXO_DOMAIN) &&
            input.assets.addressForField(opening.asset) === undefined,
        )
      ) {
        assetsRefreshed = true;
        for (const { assetId, mint } of await fetchSplAssetRegistrations(input.client, context)) {
          input.assets.register(assetId, mint);
        }
        audited = auditRingTransaction(audit);
      }
      transactions.push(audited);
    }
    // Photon also returns the last row's cursor on a terminal page. Its
    // scanned-through frontier, not that row cursor, marks a complete scan.
    const next = response.scannedThrough === undefined ? response.nextCursor : undefined;
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

/** A slot's recipient view, or the reasons it has none, Rust `OutputAudit::run`. */
interface AuditedOutput {
  readonly output?: AuditedRingOutput;
  readonly errors: readonly OutputPayloadErrorKind[];
}

function auditOutput(
  txKey: ViewingKey,
  slot: OutputSlot,
  salt: Bytes16,
  slotIndex: number,
  assets: AssetRegistry,
  opening: AuditOutputOpening,
): AuditedOutput {
  let plaintext: ConfidentialOutputPlaintext;
  let recipient: X25519PublicKey;
  try {
    const frame = readOutputData(slot.payload);
    if (
      frame.encoding !== "encrypted" ||
      (frame.scheme !== EncryptedScheme.confidential &&
        frame.scheme !== EncryptedScheme.ringConfidential)
    )
      return { errors: ["unreadable"] };
    recipient = X25519PublicKey.fromBytes(frame.body.slice(0, 33) as Bytes33);
    plaintext = decryptConfidentialAsSender(txKey, frame.body, salt, slotIndex);
  } catch {
    return { errors: ["unreadable"] };
  }
  // The proved asset selects the mint. An unproved asset id cannot make the audit fail.
  const asset = assets.addressForField(opening.asset);
  if (asset === undefined) return { errors: ["unknownAsset"] };
  const ringProgramId =
    plaintext.ringProgramId === undefined
      ? ZERO_32
      : (hashBytes(addressBytes(plaintext.ringProgramId, "ringProgramId")) as Bytes32);
  if (
    assets.assetId(asset) !== plaintext.assetId ||
    !equal(rightAlign(bigIntToBytes(plaintext.amount, 8)), opening.amount) ||
    !equal(plaintext.blinding, opening.blinding) ||
    !equal(ringProgramId, opening.ringProgramId)
  ) {
    return { errors: ["openingMismatch"] };
  }
  return {
    output: Object.freeze({
      slotIndex,
      outputContext: slot.outputContext,
      recipientViewingPublicKey: recipient,
      ownerTag: slot.viewTag,
      asset,
      amount: plaintext.amount,
      blinding: plaintext.blinding,
      data: plaintext.data,
      ...(plaintext.ringProgramId === undefined ? {} : { ringProgramId: plaintext.ringProgramId }),
    }),
    errors: [],
  };
}

/** The note the proven body opens to, its asset is the raw address and needs no registry. */
function anonymousAuditOutput(
  body: AnonymousBody,
  slot: OutputSlot,
  slotIndex: number,
): AuditedOutput {
  const errors: OutputPayloadErrorKind[] = [];
  try {
    X25519PublicKey.fromBytes(concatBytes(Uint8Array.of(4), body.note.pairU));
  } catch {
    errors.push("pairHint");
  }
  return {
    output: Object.freeze({
      slotIndex,
      outputContext: slot.outputContext,
      recipientViewingPublicKey: body.recipient,
      ownerTag: body.identityKey,
      asset: body.note.assetAddress,
      amount: body.note.amount,
      blinding: body.note.blinding,
      data: new Data(),
      ringProgramId: body.ringProgramId,
    }),
    errors,
  };
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

/** A real anonymous output as the auditor reads it, the disclosed address and the opened body. */
interface AnonymousBody {
  readonly opening: AuditOutputOpening;
  readonly note: RingAnonymousOutputPlaintext;
  readonly recipient: X25519PublicKey;
  readonly identityKey: Bytes32;
  readonly ringProgramId: Address;
}

/**
 * Opens the proven scheme-9 body under the recipient stream the transaction key
 * and the disclosed viewing key derive, Rust `anonymous_output_opening`. The
 * proof binds the body to the committed note, so a body that does not open is a
 * mismatch, not a payload error. `undefined` for a padding slot.
 */
function openAnonymousBody(
  txKey: ViewingKey,
  salt: Bytes16,
  output: AnonymousOutputOpening | undefined,
  slot: OutputSlot,
  transaction: IndexedShieldedTransaction,
  slotIndex: number,
): AnonymousBody | undefined {
  const mismatch = (reason: string): RingError =>
    new RingError("RING_AUDIT_OUTPUT_MISMATCH", { details: { reason, slotIndex } });
  if (output === undefined) throw mismatch("count");
  if (isDummyAnonymousOutput(output)) return undefined;
  const treeId = slot.outputContext.treeId;
  if (treeId === undefined) throw mismatch("treeId");
  const ring = transaction.ringProgramId;
  if (ring === undefined) throw mismatch("ring");
  let recipient: X25519PublicKey;
  let note: RingAnonymousOutputPlaintext;
  try {
    const frame = readOutputData(slot.payload);
    if (
      frame.encoding !== "encrypted" ||
      frame.scheme !== EncryptedScheme.ringAnonymous ||
      frame.body.length !== RING_ANONYMOUS_PLAINTEXT_LENGTH
    )
      throw mismatch("body");
    recipient = X25519PublicKey.fromBytes(output.viewingPublicKey);
    note = decodeRingAnonymous(txKey.sealAnonymousOutput(recipient, frame.body, salt, slotIndex));
  } catch (cause) {
    if (cause instanceof RingError) throw cause;
    throw new RingError("RING_AUDIT_OUTPUT_MISMATCH", {
      details: { reason: "body", slotIndex },
      cause,
    });
  }
  const identity = hashBytes(concatBytes(Uint8Array.of(output.identityTag), output.identityKey));
  return {
    opening: Object.freeze({
      domain: rightAlign(Uint8Array.of(UTXO_DOMAIN)),
      treeId: treeIdField(treeId),
      ownerHash: ownerHash(identity, output.nullifierPublicKey) as Bytes32,
      asset: hashBytes(addressBytes(note.assetAddress, "assetAddress")) as Bytes32,
      amount: rightAlign(bigIntToBytes(note.amount, 8)),
      blinding: note.blinding,
      dataHash: ZERO_32,
      ringDataHash: ZERO_32,
      ringProgramId: hashBytes(addressBytes(ring, "ringProgramId")) as Bytes32,
    }),
    note,
    recipient,
    identityKey: output.identityKey,
    ringProgramId: ring,
  };
}

/** The reader-facing trace, the same shape `RingRpc.getDecryptedTransactions` returns. */
function anonymousTrace(
  disclosure: AnonymousAuditDisclosure,
  bodies: readonly (AnonymousBody | undefined)[],
): DecryptedAnonymousRingTrace {
  const recipients = disclosure.outputs.flatMap((output, slotIndex) => {
    const body = bodies[slotIndex];
    if (body === undefined) return [];
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
        amount: body.note.amount,
        asset: body.opening.asset,
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
            !equal(input.asset, ZERO_32) ||
            !equal(input.blinding, ZERO_32),
        )
        .map((input) =>
          Object.freeze({ treeId: input.treeId, amount: input.amount, asset: input.asset }),
        ),
    ),
    recipients: Object.freeze(recipients),
  });
}

/** Reconstructs the exact SPP output commitment the custom-ring proof binds. */
export function auditOpeningHash(opening: AuditOutputOpening): Bytes32 {
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
