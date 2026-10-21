import type { IndexerReader, KitRpcAccess } from "../client/ports.js";
import { hashBytes, initializePoseidon, solanaOwnerIdentity } from "../hasher/index.js";
import { encodeBase58 } from "../interface/internal.js";
import type {
  Address,
  Bytes16,
  Bytes31,
  Bytes32,
  RequestContext,
  Signature,
} from "../interface/types.js";
import {
  disclosureFieldCount,
  type DisclosureLayout,
} from "../interface/ring-disclosure-layout.js";
import {
  auditorViewTag,
  openTransactionViewingSecret,
  parseAuditorMessage,
  type AuditorMessage,
} from "../keypair/audit.js";
import { clampViewingSecret } from "../keypair/derivation.js";
import { KeypairError } from "../keypair/error.js";
import { ownerHash } from "../keypair/hash.js";
import {
  openRingDisclosure,
  type AnonymousOutputOpening,
  type DeliveredOutputOpening,
  type PackedOutputOpening,
  type RingDisclosure,
} from "../keypair/ring-disclosure.js";
import {
  BODY_LEN,
  deliveredSlotSecret,
  openDeliveredBody,
  packedSlotSecret,
  ringIdField,
  ringTagFromOwnerTag,
} from "../keypair/ring-stream.js";
import { transactOutputBlinding } from "../keypair/transact/index.js";
import { ViewingKey } from "../keypair/viewing-key.js";
import { X25519PublicKey, type X25519Keypair } from "../keypair/x25519.js";
import type { AssetRegistry } from "../transaction/asset.js";
import type {
  IndexedShieldedTransaction,
  OutputContext,
  OutputSlot,
} from "../transaction/instructions/transact.js";
import { ZERO_32, equal } from "../transaction/internal.js";
import { EncryptedScheme, decodeOutputData } from "../transaction/serialization/codecs.js";
import { ringDeliveryBlinding } from "../transaction/serialization/ring-delivered.js";
import { dummyUtxoHash, fieldUtxoHash } from "../transaction/utxo.js";
import { bytesKey } from "../wallet/internal.js";
import { fetchSplAssetRegistrations } from "../wallet/sync.js";

import { RingError } from "./error.js";
import { RpcTransactionOrigin, type TransactionOrigin } from "./origin.js";

/** Rust `AuditedNote`, an opening whose commitment the audit rebuilt. */
export interface AuditedNote {
  /** The raw Solana key whose owner identity the commitment binds. */
  readonly ownerKey: Bytes32;
  readonly nullifierPk: Bytes32;
  /** `hashBytes(mint)`. */
  readonly asset: Bytes32;
  /** Absent until the asset registry knows the asset. */
  readonly mint?: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly dataHash: Bytes32;
  readonly ringDataHash: Bytes32;
}

/** Rust `OutputOpening`. */
export type OutputOpening =
  | Readonly<{
      kind: "ring";
      note: AuditedNote;
      recipientU: Bytes32;
      /** The published tag of an anonymous ring output. */
      tag?: Bytes31;
    }>
  /** A default-ring note, its owner the published owner tag. */
  | Readonly<{ kind: "exit"; note: AuditedNote }>
  | Readonly<{ kind: "dummy" }>;

/** Rust `AuditedOutput`, one published slot whose rebuilt commitment is the published one. */
export interface AuditedRingOutput {
  readonly slotIndex: number;
  readonly outputContext: OutputContext;
  readonly opening: OutputOpening;
}

/** Rust `OutputPayloadErrorKind`, why a published slot did not open. */
export type OutputPayloadErrorKind = "frame" | "recipientKey" | "commitment" | "escrowUnknown";

export interface OutputPayloadError {
  readonly slotIndex: number;
  readonly kind: OutputPayloadErrorKind;
}

/** Rust `AuditedSender`, the owner of every UTXO an anonymous transfer spends. */
export interface AuditedSender {
  readonly ownerKey: Bytes32;
  /** Spent UTXO 0's key, absent when that UTXO is a deposit. */
  readonly nullifierPk?: Bytes32;
}

/** Rust `InputRing`, SPP spends a UTXO of the ring or of the default ring and the disclosure names neither. */
export type InputRing =
  | Readonly<{ kind: "ring"; commitment: Bytes32 }>
  | Readonly<{ kind: "default"; commitment: Bytes32 }>
  /** No known commitment told the candidates apart. */
  | Readonly<{ kind: "unresolved"; ring: Bytes32; default: Bytes32 }>;

export interface AuditedInputOpening {
  readonly asset: Bytes32;
  readonly mint?: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  /** Absent without the input's tree id, every commitment binds it. */
  readonly ring?: InputRing;
}

export interface AuditedInput {
  readonly nullifier: Bytes32;
  /** Absent for a dummy input. */
  readonly opening?: AuditedInputOpening;
}

/** Rust `AuditedTransaction`. */
export interface AuditedRingTransaction {
  readonly signature: Signature;
  readonly slot: bigint;
  /** Checked against the key the auditor envelope seals. */
  readonly txViewingPublicKey: X25519PublicKey;
  /** Published order, a slot that did not open sits in `payloadErrors` instead. */
  readonly outputs: readonly AuditedRingOutput[];
  readonly payloadErrors: readonly OutputPayloadError[];
  /** The hidden sender of an anonymous transfer. */
  readonly sender?: AuditedSender;
  /** One per published nullifier of an anonymous transfer. */
  readonly inputs: readonly AuditedInput[];
}

/** Rust `KnownNote`, a ring note an earlier audit opened, a spend names it by its commitment alone. */
export interface KnownNote extends Omit<AuditedNote, "nullifierPk"> {
  /** Absent for a deposit, its capsule discloses only the owner hash. */
  readonly nullifierPk?: Bytes32;
}

/** Rust `KnownNotes`, notes the auditor opened before by their commitment. */
export interface KnownNotes {
  note(commitment: Bytes32): KnownNote | undefined;
}

/** Rust `EscrowedKeys`, the nullifier key each registered owner escrows by its raw Solana key. */
export interface EscrowedKeys {
  nullifierPk(ownerKey: Bytes32): Bytes32 | undefined;
}

export interface RingAuditPage {
  readonly transactions: readonly AuditedRingTransaction[];
  /** Set only when the page cap stopped the scan. */
  readonly nextCursor?: Uint8Array;
}

export type RingAuditReader = KitRpcAccess & Pick<IndexerReader, "getShieldedTransactionsByTags">;

const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 32;

/** Mirrors Rust `PageEnd::next`, `undefined` only past a page that states its scan frontier. */
export function nextScanCursor(
  cursor: Uint8Array | undefined,
  page: Readonly<{ nextCursor?: Uint8Array; scannedThrough?: Uint8Array }>,
): Uint8Array | undefined {
  if (page.scannedThrough !== undefined) return undefined;
  if (page.nextCursor === undefined) throw new RingError("RING_SCAN_FRONTIER_MISSING");
  if (cursor !== undefined && equal(cursor, page.nextCursor))
    throw new RingError("RING_RPC", { details: { reason: "scan cursor did not advance" } });
  return page.nextCursor;
}

/** Mirrors Rust `auditor_message`, the program accepts the tagged message only as the unique last entry. */
export function auditorMessage(
  transaction: IndexedShieldedTransaction,
  auditorPublicKey: X25519PublicKey,
): Uint8Array {
  const viewTag = auditorViewTag(auditorPublicKey);
  const tagged = transaction.messages.flatMap((message, index) =>
    equal(message.viewTag, viewTag) ? [index] : [],
  );
  const index = tagged[0];
  const message = index === undefined ? undefined : transaction.messages[index];
  if (index === undefined || message === undefined)
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "missing" } });
  if (tagged.length > 1)
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "duplicate" } });
  const count = transaction.messages.length;
  if (index + 1 !== count)
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "not last", index, count } });
  return message.data;
}

/** Mirrors Rust `AuditEnvelope::open`, the circuit seals the clamped encoding and an alias is refused. */
export function recoverTransactionViewingKey(
  auditor: X25519Keypair,
  message: AuditorMessage,
): ViewingKey {
  const recovered = openTransactionViewingSecret(auditor, message);
  const canonical = clampViewingSecret(recovered);
  try {
    let difference = 0;
    for (let index = 0; index < 32; index++)
      difference |= (recovered[index] ?? 0) ^ (canonical[index] ?? 0);
    if (difference !== 0) throw new RingError("RING_AUDIT_NONCANONICAL_KEY");
    return ViewingKey.fromBytes(recovered);
  } finally {
    canonical.fill(0);
    recovered.fill(0);
  }
}

/** Mirrors Rust `TransactionAudit::run`, every published commitment rebuilt from the disclosure. */
export function auditRingTransaction(
  input: Readonly<{
    auditor: X25519Keypair;
    transaction: IndexedShieldedTransaction;
    assets: AssetRegistry;
    /** The layout the ring program verified the audit proof under, `ConfirmedRingTransaction` reads it. */
    layout: DisclosureLayout;
    /** One per published nullifier, the tree the input was spent from. */
    inputTreeIds?: readonly (number | undefined)[];
    /** Opens a commitment-layout input, and among two candidates resolves an entry input's ring. */
    knownNotes?: KnownNotes;
    /** The output nullifier keys a key-escrow ring leaves out of its disclosure. */
    escrowedKeys?: EscrowedKeys;
  }>,
): AuditedRingTransaction {
  const { transaction } = input;
  const unsealed = (reason: string): RingError =>
    new RingError("RING_AUDIT_UNSEALED", {
      details: { reason, signature: transaction.txSignature },
    });
  const txViewingPublicKey = transaction.txViewingPublicKey;
  if (txViewingPublicKey === undefined) throw unsealed("txViewingPk");
  const salt = transaction.salt;
  if (salt === undefined) throw unsealed("salt");
  const ring = transaction.ringProgramId;
  if (ring === undefined) throw unsealed("ringProgramId");
  const firstNullifier = transaction.nullifiers[0];
  if (firstNullifier === undefined) throw unsealed("nullifier");
  if (
    input.inputTreeIds !== undefined &&
    input.inputTreeIds.length !== transaction.nullifiers.length
  )
    throw new RingError("RING_INVALID_LENGTH", {
      details: {
        name: "inputTreeIds",
        expected: transaction.nullifiers.length,
        actual: input.inputTreeIds.length,
      },
    });
  const { layout } = input;
  const exits = transaction.outputSlots.map(isExit);
  // The program bound the layout to these counts and exits, the message length checks its field count.
  if (
    layout.outputs !== transaction.outputSlots.length ||
    layout.exits !== exits.includes(true) ||
    (layout.kind === "anonymous" && layout.inputs !== transaction.nullifiers.length)
  )
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "layout" } });
  const message = parsedMessage(auditorMessage(transaction, input.auditor.publicKey()), layout);
  const txKey = recoverTransactionViewingKey(input.auditor, message);
  const txViewingSecret = txKey.secretBytes();
  try {
    // The proof binds the envelope to the published key, a mismatch is a forged message.
    if (!txKey.publicKey().equals(txViewingPublicKey))
      throw new RingError("RING_AUDIT_KEY_MISMATCH", {
        details: { signature: transaction.txSignature },
      });
    const disclosure = openDisclosure(txViewingSecret, salt, {
      layout,
      fields: message.disclosure,
      exits,
    });
    const transfer = new Transfer({
      ring,
      txKey,
      txViewingSecret,
      txViewingPublicKey,
      salt,
      firstNullifier,
      seedOut: disclosure.seedOut,
      assets: input.assets,
      ...(input.escrowedKeys === undefined ? {} : { escrowed: input.escrowedKeys }),
    });
    const audited = new AuditRecord();
    transaction.outputSlots.forEach((output, index) => {
      const slot = { index, output };
      audited.record(slot, transfer.open(slot, disclosure));
    });
    const spent =
      disclosure.kind === "anonymous"
        ? transfer.inputs({
            disclosure,
            nullifiers: transaction.nullifiers,
            ...(input.inputTreeIds === undefined ? {} : { trees: input.inputTreeIds }),
            ...(input.knownNotes === undefined ? {} : { known: input.knownNotes }),
          })
        : undefined;
    return Object.freeze({
      signature: transaction.txSignature,
      slot: transaction.slot,
      txViewingPublicKey,
      outputs: Object.freeze(audited.outputs),
      payloadErrors: Object.freeze(audited.payloadErrors),
      ...(spent === undefined || disclosure.kind !== "anonymous"
        ? {}
        : {
            sender: Object.freeze({
              ownerKey: disclosure.senderKey,
              ...(spent.senderNullifierPk === undefined
                ? {}
                : { nullifierPk: spent.senderNullifierPk }),
            }),
          }),
      inputs: Object.freeze(spent?.inputs ?? []),
    });
  } finally {
    txViewingSecret.fill(0);
    txKey.destroy();
  }
}

/** Every opened note by its commitment, Rust `AuditedTransaction::notes`. */
export function auditedNotes(
  transaction: AuditedRingTransaction,
): readonly Readonly<{ commitment: Bytes32; note: AuditedNote }>[] {
  return transaction.outputs.flatMap((output) =>
    output.opening.kind === "dummy"
      ? []
      : [Object.freeze({ commitment: output.outputContext.hash, note: output.opening.note })],
  );
}

/** Rust `AuditedTransaction::has_unknown_assets`, a registry refresh may name the mint. */
export function hasUnknownAssets(transaction: AuditedRingTransaction): boolean {
  return (
    auditedNotes(transaction).some(({ note }) => note.mint === undefined) ||
    transaction.inputs.some(
      (input) => input.opening !== undefined && input.opening.mint === undefined,
    )
  );
}

/** Mirrors Rust `RingScan::audit`, each tagged event attributed through its confirmed call stack. */
export async function auditRing(
  input: Readonly<{
    client: RingAuditReader;
    auditor: X25519Keypair;
    ringProgramId: Address;
    assets: AssetRegistry;
    /** The output nullifier keys a key-escrow ring leaves out of its disclosure. */
    escrowedKeys?: EscrowedKeys;
    /** Notes opened outside the scan, earlier pages and `createdRingNotes` among them. */
    knownNotes?: KnownNotes;
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
    if (!Number.isSafeInteger(value) || value < 1)
      throw new RingError("RING_RPC", { details: { reason: "invalid scan limit", name, value } });
  }
  const origin = input.origin ?? new RpcTransactionOrigin(input.client.solanaRpc);
  const known = new NoteIndex(input.knownNotes);
  const transactions: AuditedRingTransaction[] = [];
  let assetsRefreshed = false;
  let cursor = input.cursor;
  for (let page = 0; page < maxPages; page++) {
    const response = await input.client.getShieldedTransactionsByTags(
      { tags: [viewTag], limit: pageSize, ...(cursor === undefined ? {} : { cursor }) },
      undefined,
      context,
    );
    for (const indexed of response.transactions) {
      if (indexed.eventIndex === undefined)
        throw new RingError("RING_RPC", { details: { reason: "missing event index" } });
      const confirmed = await origin.confirmedTransaction(indexed, input.ringProgramId, context);
      if (confirmed?.kind !== "transfer") continue;
      // Photon matches output tags too, only the message match marks an auditor's transfer.
      if (!confirmed.transaction.messages.some((message) => equal(message.viewTag, viewTag)))
        throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "missing" } });
      const audit = () =>
        auditRingTransaction({
          auditor: input.auditor,
          transaction: confirmed.transaction,
          assets: input.assets,
          layout: confirmed.layout,
          inputTreeIds: confirmed.inputTreeIds,
          knownNotes: known,
          ...(input.escrowedKeys === undefined ? {} : { escrowedKeys: input.escrowedKeys }),
        });
      let audited = audit();
      if (!assetsRefreshed && hasUnknownAssets(audited)) {
        assetsRefreshed = true;
        for (const { assetId, mint } of await fetchSplAssetRegistrations(input.client, context))
          input.assets.register(assetId, mint);
        audited = audit();
      }
      known.add(audited);
      transactions.push(audited);
    }
    const next = nextScanCursor(cursor, response);
    if (next === undefined) return Object.freeze({ transactions: Object.freeze(transactions) });
    cursor = next;
  }
  return Object.freeze({
    transactions: Object.freeze(transactions),
    ...(cursor === undefined ? {} : { nextCursor: cursor }),
  });
}

/** The ring program encodes every exit under scheme 3, every other slot under its rail's scheme. */
function isExit(slot: OutputSlot): boolean {
  return encryptedBody(slot.payload, EncryptedScheme.confidential) !== undefined;
}

/** The body of an encrypted payload of `scheme`, `undefined` for any other frame. */
function encryptedBody(payload: Uint8Array, scheme: EncryptedScheme): Uint8Array | undefined {
  try {
    const frame = decodeOutputData(payload);
    return frame.encoding === "encrypted" && frame.scheme === scheme ? frame.body : undefined;
  } catch {
    return undefined;
  }
}

function parsedMessage(data: Uint8Array, layout: DisclosureLayout): AuditorMessage {
  try {
    return parseAuditorMessage(data, disclosureFieldCount(layout));
  } catch (cause) {
    throw new RingError("RING_AUDIT_MESSAGE", {
      details: { reason: "malformed", length: data.length },
      cause,
    });
  }
}

function openDisclosure(
  txViewingSecret: Bytes32,
  salt: Bytes16,
  published: Parameters<typeof openRingDisclosure>[1],
): RingDisclosure {
  try {
    return openRingDisclosure({ txViewingSecret, salt }, published);
  } catch (cause) {
    if (!(cause instanceof KeypairError)) throw cause;
    throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "disclosure" }, cause });
  }
}

interface Slot {
  readonly index: number;
  readonly output: OutputSlot;
}

type SlotOpening =
  | Readonly<{ ok: true; opening: OutputOpening }>
  | Readonly<{ ok: false; kind: OutputPayloadErrorKind }>;

/** A ring output whose body opens under its recipient's CRDS slot secret. */
interface Delivery {
  readonly slot: Slot;
  readonly ownerKey: Bytes32;
  /** `undefined` under key escrow. */
  readonly nullifierPk: Bytes32 | undefined;
  readonly recipientU: Bytes32;
  readonly tag?: Bytes31;
}

/** An exit of a delivered rail, its owner key published as its owner tag. */
interface DeliveredExit {
  readonly nullifierPk: Bytes32 | undefined;
  readonly asset: Bytes32;
  readonly amount: bigint;
}

/** The sender's spends and the one nullifier key they share. */
interface Spent {
  /** Absent when spent UTXO 0 is a deposit. */
  readonly senderNullifierPk: Bytes32 | undefined;
  readonly inputs: readonly AuditedInput[];
}

class Transfer {
  constructor(
    private readonly keys: Readonly<{
      ring: Address;
      txKey: ViewingKey;
      txViewingSecret: Bytes32;
      txViewingPublicKey: X25519PublicKey;
      salt: Bytes16;
      firstNullifier: Bytes32;
      /** Published exactly when an output exits. */
      seedOut: Bytes32 | undefined;
      assets: AssetRegistry;
      escrowed?: EscrowedKeys;
    }>,
  ) {}

  open(slot: Slot, disclosure: RingDisclosure): SlotOpening {
    switch (disclosure.kind) {
      case "packed":
        // The decode fixed one entry per published slot, `undefined` is a dummy.
        return this.packed(slot, disclosure.outputs[slot.index]);
      case "delivered":
        return this.delivered(slot, disclosureSlot(disclosure.outputs, slot));
      case "anonymous":
        return this.anonymous(slot, disclosureSlot(disclosure.outputs, slot));
    }
  }

  /**
   * Every input is the sender's with zero data, the commitment key's inputs are notes of the ring
   * the auditor opened before, the entry key's open in full.
   */
  inputs(
    spent: Readonly<{
      disclosure: Extract<RingDisclosure, { kind: "anonymous" }>;
      nullifiers: readonly Bytes32[];
      trees?: readonly (number | undefined)[];
      known?: KnownNotes;
    }>,
  ): Spent {
    const { disclosure, nullifiers } = spent;
    const published = disclosure.inputs;
    if (published.kind === "commitments") {
      const known = (commitment: Bytes32): KnownNote => {
        const note = spent.known?.note(commitment);
        if (note === undefined)
          throw new RingError("RING_AUDIT_UNSEEN_INPUT", {
            details: { commitment: bytesKey(commitment) },
          });
        return note;
      };
      // The circuit proves spent UTXO 0 real.
      const first = published.hashes[0];
      if (first === undefined)
        throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "disclosure" } });
      const senderNullifierPk = known(first).nullifierPk;
      const inputs = nullifiers.map((nullifier, index): AuditedInput => {
        const commitment = published.hashes[index];
        if (commitment === undefined) return Object.freeze({ nullifier });
        const note = known(commitment);
        return Object.freeze({
          nullifier,
          opening: Object.freeze({
            asset: note.asset,
            ...(note.mint === undefined ? {} : { mint: note.mint }),
            amount: note.amount,
            blinding: note.blinding,
            ring: Object.freeze({ kind: "ring", commitment }),
          }),
        });
      });
      return Object.freeze({ senderNullifierPk, inputs: Object.freeze(inputs) });
    }
    const inputs = nullifiers.map((nullifier, index): AuditedInput => {
      const opening = published.inputs[index];
      if (opening === undefined) return Object.freeze({ nullifier });
      const note: AuditedNote = this.note({
        ownerKey: disclosure.senderKey,
        nullifierPk: published.senderNullifierPk,
        asset: opening.asset,
        amount: opening.amount,
        blinding: opening.blinding,
      });
      const tree = spent.trees?.[index];
      const ring = tree === undefined ? undefined : this.inputRing(note, tree, spent.known);
      return Object.freeze({
        nullifier,
        opening: Object.freeze({
          asset: note.asset,
          ...(note.mint === undefined ? {} : { mint: note.mint }),
          amount: note.amount,
          blinding: note.blinding,
          ...(ring === undefined ? {} : { ring }),
        }),
      });
    });
    return Object.freeze({
      senderNullifierPk: published.senderNullifierPk,
      inputs: Object.freeze(inputs),
    });
  }

  private packed(slot: Slot, opening: PackedOutputOpening | undefined): SlotOpening {
    if (opening === undefined) return this.verify(slot, DUMMY);
    const nullifierPk = this.nullifierPk(opening.ownerKey, opening.nullifierPk);
    if (nullifierPk === undefined) return ESCROW_UNKNOWN;
    const exit = isExit(slot.output);
    const note = this.note({
      ownerKey: opening.ownerKey,
      nullifierPk,
      asset: opening.asset,
      amount: opening.amount,
      blinding: exit ? this.exitBlinding(slot) : this.packedBlinding(slot),
      dataHash: opening.dataHash,
      ringDataHash: opening.ringDataHash,
    });
    return this.verify(
      slot,
      exit
        ? Object.freeze({ kind: "exit", note })
        : Object.freeze({ kind: "ring", note, recipientU: slot.output.viewTag }),
    );
  }

  private delivered(slot: Slot, opening: DeliveredOutputOpening): SlotOpening {
    switch (opening.kind) {
      case "ring":
        return this.deliver({
          slot,
          ownerKey: opening.ownerKey,
          nullifierPk: opening.nullifierPk,
          recipientU: slot.output.viewTag,
        });
      case "exit":
        return this.exit(slot, opening);
      case "dummy":
        return this.verify(slot, DUMMY);
    }
  }

  private anonymous(slot: Slot, opening: AnonymousOutputOpening): SlotOpening {
    switch (opening.kind) {
      case "ring": {
        const tag = ringTagFromOwnerTag(slot.output.viewTag);
        if (tag === undefined) return FRAME;
        return this.deliver({
          slot,
          ownerKey: opening.ownerKey,
          nullifierPk: opening.nullifierPk,
          recipientU: opening.recipientU,
          tag,
        });
      }
      case "exit":
        return this.exit(slot, opening);
      case "dummy":
        return this.verify(slot, DUMMY);
    }
  }

  private deliver(delivery: Delivery): SlotOpening {
    const { slot, tag } = delivery;
    const nullifierPk = this.nullifierPk(delivery.ownerKey, delivery.nullifierPk);
    if (nullifierPk === undefined) return ESCROW_UNKNOWN;
    const body = encryptedBody(
      slot.output.payload,
      tag === undefined ? EncryptedScheme.ringConfidentialDelivered : EncryptedScheme.ringAnonymous,
    );
    if (body?.length !== BODY_LEN) return FRAME;
    const secret = this.deliveredSecret(slot, delivery.recipientU);
    if (secret === undefined) return Object.freeze({ ok: false, kind: "recipientKey" });
    try {
      const opened = openDeliveredBody(secret, body);
      const deliverySlot = {
        ring: this.keys.ring,
        firstNullifier: this.keys.firstNullifier,
        outputIndex: slot.index,
        ...(tag === undefined ? {} : { tag }),
      };
      const note: AuditedNote = Object.freeze({
        ownerKey: delivery.ownerKey,
        nullifierPk,
        asset: hashBytes(opened.assetAddress) as Bytes32,
        mint: encodeBase58(opened.assetAddress),
        amount: opened.amount,
        blinding: ringDeliveryBlinding(deliverySlot, secret),
        dataHash: ZERO_32,
        ringDataHash: ZERO_32,
      });
      return this.verify(
        slot,
        Object.freeze({
          kind: "ring",
          note,
          recipientU: delivery.recipientU,
          ...(tag === undefined ? {} : { tag }),
        }),
      );
    } finally {
      secret.fill(0);
    }
  }

  private exit(slot: Slot, exit: DeliveredExit): SlotOpening {
    const nullifierPk = this.nullifierPk(slot.output.viewTag, exit.nullifierPk);
    if (nullifierPk === undefined) return ESCROW_UNKNOWN;
    const note = this.note({
      ownerKey: slot.output.viewTag,
      nullifierPk,
      asset: exit.asset,
      amount: exit.amount,
      blinding: this.exitBlinding(slot),
    });
    return this.verify(slot, Object.freeze({ kind: "exit", note }));
  }

  /** The opening of `slot` when it rebuilds the published commitment. */
  private verify(slot: Slot, opening: OutputOpening): SlotOpening {
    // Without an exit no SeedOut is published, the audit proof alone binds a dummy.
    if (opening.kind === "dummy" && this.keys.seedOut === undefined)
      return Object.freeze({ ok: true, opening });
    const treeId = slot.output.outputContext.treeId;
    const commitment =
      opening.kind === "dummy"
        ? dummyUtxoHash(treeId, this.exitBlinding(slot))
        : noteCommitment(
            opening.note,
            treeId,
            opening.kind === "ring" ? ringIdField(this.keys.ring) : ZERO_32,
          );
    return equal(commitment, slot.output.outputContext.hash)
      ? Object.freeze({ ok: true, opening })
      : Object.freeze({ ok: false, kind: "commitment" });
  }

  /** `undefined` when `recipientU` admits no agreement with the transaction key. */
  private deliveredSecret(slot: Slot, recipientU: Bytes32): Bytes32 | undefined {
    let agreement: Bytes32 | undefined;
    try {
      const recipient = X25519PublicKey.fromU(recipientU);
      agreement = this.keys.txKey.ecdh(recipient);
      return deliveredSlotSecret({
        agreement,
        txViewingKey: this.keys.txViewingPublicKey,
        recipientViewingKey: recipient,
        salt: this.keys.salt,
        outputIndex: slot.index,
        firstNullifier: this.keys.firstNullifier,
      });
    } catch (error) {
      if (error instanceof KeypairError) return undefined;
      throw error;
    } finally {
      agreement?.fill(0);
    }
  }

  /** `Poseidon(TXRB, n0, Poseidon(CRRC, s), i)` over the CRAS slot secret of the packed rail. */
  private packedBlinding(slot: Slot): Bytes32 {
    const secret = packedSlotSecret({
      txViewingSecret: this.keys.txViewingSecret,
      salt: this.keys.salt,
      outputIndex: slot.index,
      firstNullifier: this.keys.firstNullifier,
    });
    try {
      return ringDeliveryBlinding(
        { ring: this.keys.ring, firstNullifier: this.keys.firstNullifier, outputIndex: slot.index },
        secret,
      );
    } finally {
      secret.fill(0);
    }
  }

  /** SPP's TXOB blinding of an exit or a dummy, a layout with an exit publishes SeedOut. */
  private exitBlinding(slot: Slot): Bytes32 {
    const { seedOut } = this.keys;
    if (seedOut === undefined)
      throw new RingError("RING_AUDIT_MESSAGE", {
        details: { reason: "disclosure", slotIndex: slot.index },
      });
    return transactOutputBlinding(this.keys.firstNullifier, seedOut, slot.index);
  }

  /** The disclosed key, else the one the owner's record escrows. */
  private nullifierPk(ownerKey: Bytes32, disclosed: Bytes32 | undefined): Bytes32 | undefined {
    return disclosed ?? this.keys.escrowed?.nullifierPk(ownerKey);
  }

  private note(
    fields: Readonly<{
      ownerKey: Bytes32;
      nullifierPk: Bytes32;
      asset: Bytes32;
      amount: bigint;
      blinding: Bytes32;
      dataHash?: Bytes32;
      ringDataHash?: Bytes32;
    }>,
  ): AuditedNote {
    const mint = this.keys.assets.addressForField(fields.asset);
    return Object.freeze({
      ownerKey: fields.ownerKey,
      nullifierPk: fields.nullifierPk,
      asset: fields.asset,
      ...(mint === undefined ? {} : { mint }),
      amount: fields.amount,
      blinding: fields.blinding,
      dataHash: fields.dataHash ?? ZERO_32,
      ringDataHash: fields.ringDataHash ?? ZERO_32,
    });
  }

  private inputRing(note: AuditedNote, treeId: number, known: KnownNotes | undefined): InputRing {
    const ring = noteCommitment(note, treeId, ringIdField(this.keys.ring));
    const fallback = noteCommitment(note, treeId, ZERO_32);
    const found = (commitment: Bytes32): boolean => known?.note(commitment) !== undefined;
    if (found(ring) && !found(fallback)) return Object.freeze({ kind: "ring", commitment: ring });
    if (found(fallback) && !found(ring))
      return Object.freeze({ kind: "default", commitment: fallback });
    return Object.freeze({ kind: "unresolved", ring, default: fallback });
  }
}

/** Rust `AuditedNote::commitment`, `ringId` zero for a default-ring note. */
function noteCommitment(note: AuditedNote, treeId: number, ringId: Bytes32): Bytes32 {
  return fieldUtxoHash({
    owner: ownerHash(solanaOwnerIdentity(note.ownerKey), note.nullifierPk) as Bytes32,
    assetField: note.asset,
    amount: note.amount,
    blinding: note.blinding,
    treeId,
    dataHash: note.dataHash,
    ringDataHash: note.ringDataHash,
    ringId,
  });
}

/** The layout fixes one disclosed slot per published output. */
function disclosureSlot<T>(outputs: readonly T[], slot: Slot): T {
  const opening = outputs[slot.index];
  if (opening === undefined)
    throw new RingError("RING_AUDIT_MESSAGE", {
      details: { reason: "disclosure", slotIndex: slot.index },
    });
  return opening;
}

const DUMMY: OutputOpening = Object.freeze({ kind: "dummy" });
const FRAME: SlotOpening = Object.freeze({ ok: false, kind: "frame" });
const ESCROW_UNKNOWN: SlotOpening = Object.freeze({ ok: false, kind: "escrowUnknown" });

/** The outputs and payload errors of one audit, in published order. */
class AuditRecord {
  readonly outputs: AuditedRingOutput[] = [];
  readonly payloadErrors: OutputPayloadError[] = [];

  record(slot: Slot, opened: SlotOpening): void {
    if (opened.ok)
      this.outputs.push(
        Object.freeze({
          slotIndex: slot.index,
          outputContext: slot.output.outputContext,
          opening: opened.opening,
        }),
      );
    else this.payloadErrors.push(Object.freeze({ slotIndex: slot.index, kind: opened.kind }));
  }
}

/** Rust's `KnownNotes` map, the notes one scan opened by commitment ahead of the caller's. */
class NoteIndex implements KnownNotes {
  readonly #notes = new Map<string, KnownNote>();
  readonly #known: KnownNotes | undefined;

  constructor(known: KnownNotes | undefined) {
    this.#known = known;
  }

  add(transaction: AuditedRingTransaction): void {
    for (const { commitment, note } of auditedNotes(transaction))
      this.#notes.set(bytesKey(commitment), note);
  }

  note(commitment: Bytes32): KnownNote | undefined {
    return this.#notes.get(bytesKey(commitment)) ?? this.#known?.note(commitment);
  }
}
