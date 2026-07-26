import type { Bytes31, Bytes32, Bytes33, Signature } from "@zolana/interface";
import { P256PublicKey, ShieldedPublicKey, type ViewingKey } from "@zolana/keypair";

import { Data, type DataRecord } from "../data.js";
import { TransactionError } from "../error.js";
import { copy, decodeAddress, encodeAddress, equal, hashField } from "../internal.js";
import type { IndexedShieldedTransaction } from "../instructions/transact.js";
import {
  EncryptedScheme,
  anonymousRecipientUtxo,
  anonymousSenderUtxos,
  confidentialUtxo,
  decodeAnonymousRecipient,
  decodeAnonymousSender,
  decodeContextForSlot,
  decodeOutputData,
  decodePlaintextTransfer,
  decodeProofless,
  decodeSplitBundle,
  type DecodeContext,
  decryptAnonymous,
  decryptConfidential,
  decryptMerge,
  plaintextTransferUtxos,
  prooflessUtxo,
  splitBundleUtxos,
} from "../serialization/codecs.js";
import { Utxo } from "../utxo.js";
import type { SyncWalletAuthority, WalletSyncMaterial } from "./authority.js";
import { SOL_MINT } from "./asset.js";
import {
  newViewingKeyEntry,
  type CounterpartyCounter,
  type PrivateTransaction,
  type SyncReport,
  type ViewingKeyEntry,
  Wallet,
  hex,
} from "./state.js";

/**
 * Tags queried past each family's stored counter. A counterparty that has run
 * ahead by fewer than this many tags stays reachable on the next sync, so
 * lowering it can strand a wallet behind a fast sender.
 */
export const DEFAULT_TAG_WINDOW = 64n;

export interface WalletSyncConfig {
  readonly tagWindow?: bigint;
  /** Recorded as `Wallet.lastSynced` once the sync commits, as `Wallet::sync` records `synced_at`. */
  readonly syncedAt?: bigint;
}

function validateMaterial(wallet: Wallet, material: WalletSyncMaterial): void {
  if (
    !equal(
      material.identity.signingPublicKey.toBytes(),
      wallet.identity.signingPublicKey.toBytes(),
    ) ||
    !equal(material.identity.nullifierPublicKey, wallet.identity.nullifierPublicKey) ||
    !equal(
      material.identity.viewingPublicKey.toBytes(),
      wallet.identity.viewingPublicKey.toBytes(),
    ) ||
    !equal(material.nullifierKey.publicKey(), wallet.identity.nullifierPublicKey)
  ) {
    throw new TransactionError("TRANSACTION_WALLET_AUTHORITY_MISMATCH");
  }
  if (
    !material.viewingKeys.some((key) =>
      equal(key.publicKey().toBytes(), wallet.identity.viewingPublicKey.toBytes()),
    )
  ) {
    throw new TransactionError("TRANSACTION_MISSING_CURRENT_VIEWING_KEY");
  }
}

function transactionRow(
  tx: IndexedShieldedTransaction,
  index: number,
  kind: PrivateTransaction["kind"],
): PrivateTransaction {
  return Object.freeze({
    id: Object.freeze({ signature: tx.txSignature as Signature, index: BigInt(index) }),
    kind,
    direction: "incoming",
    status: "confirmed",
    slot: tx.slot,
  });
}

interface DecodedCandidate {
  readonly utxos: readonly Readonly<{
    utxo: Utxo;
    dataHash?: Bytes32;
    zoneDataHash?: Bytes32;
    outputIndex: number;
  }>[];
  readonly kind: PrivateTransaction["kind"];
  /** Counterparty that sent an anonymous recipient slot. */
  readonly sender?: P256PublicKey;
  /** Counterparties an anonymous sender bundle paid. */
  readonly recipients?: readonly P256PublicKey[];
}

function decodeCandidate(
  cx: DecodeContext,
  material: WalletSyncMaterial,
  wallet: Wallet,
  tx: IndexedShieldedTransaction,
  unknownAssetIds: Set<bigint>,
): DecodedCandidate | undefined {
  const { viewingKey: key, slotIndex } = cx;
  const slot = tx.outputSlots[slotIndex];
  if (!slot) return undefined;
  let decoded: ReturnType<typeof decodeOutputData>;
  try {
    decoded = decodeOutputData(slot.payload);
  } catch {
    return undefined;
  }
  try {
    if (decoded.scheme === EncryptedScheme.proofless && decoded.encoding === "plaintext") {
      const value = decodeProofless(decoded.body);
      return {
        utxos: [
          {
            utxo: prooflessUtxo(value, material.identity.signingPublicKey),
            ...(value.dataHash === undefined ? {} : { dataHash: value.dataHash }),
            ...(value.zoneDataHash === undefined ? {} : { zoneDataHash: value.zoneDataHash }),
            outputIndex: slotIndex,
          },
        ],
        kind: "deposit",
      };
    }
    if (
      (decoded.scheme === EncryptedScheme.anonymousRecipient ||
        decoded.scheme === EncryptedScheme.anonymousSender) &&
      decoded.encoding === "encrypted" &&
      cx.txViewingPublicKey &&
      cx.salt
    ) {
      const plaintext = decryptAnonymous(
        key,
        cx.txViewingPublicKey,
        decoded.body,
        cx.salt,
        slotIndex,
      );
      if (decoded.scheme === EncryptedScheme.anonymousRecipient) {
        const recipient = decodeAnonymousRecipient(plaintext);
        return {
          utxos: [
            {
              utxo: anonymousRecipientUtxo(recipient, wallet.registry),
              outputIndex: slotIndex,
            },
          ],
          kind: "transfer",
          sender: recipient.senderPublicKey,
        };
      }
      const value = decodeAnonymousSender(plaintext);
      const recovered = anonymousSenderUtxos(value, wallet.registry, SOL_MINT);
      let recoveredIndex = 0;
      const utxos: {
        utxo: Utxo;
        outputIndex: number;
      }[] = [];
      if (value.splAmount > 0n) {
        const utxo = recovered[recoveredIndex++];
        if (utxo) utxos.push({ utxo, outputIndex: 0 });
      }
      if (value.solAmount > 0n) {
        const utxo = recovered[recoveredIndex];
        if (utxo) utxos.push({ utxo, outputIndex: 1 });
      }
      return { utxos, kind: "transfer", recipients: value.recipientViewingPublicKeys };
    }
    if (
      decoded.scheme === EncryptedScheme.confidential &&
      decoded.encoding === "encrypted" &&
      cx.txViewingPublicKey &&
      cx.salt
    ) {
      const value = decryptConfidential(
        key,
        cx.txViewingPublicKey,
        decoded.body,
        cx.salt,
        slotIndex,
      );
      return {
        utxos: [
          {
            utxo: confidentialUtxo(value, material.identity.signingPublicKey, wallet.registry),
            outputIndex: slotIndex,
          },
        ],
        kind: "transfer",
      };
    }
    if (decoded.scheme === EncryptedScheme.plaintextTransfer && decoded.encoding === "plaintext") {
      const value = decodePlaintextTransfer(decoded.body);
      // Sender change owns slots 0 and 1 whether or not the payload filled
      // both, so the published slot of each UTXO is its blinding position
      // rather than its offset in the list. Built from the same payload shape
      // `plaintextTransferUtxos` walks, so the two line up entry for entry.
      const positions = [
        ...(value.sender?.spl ? [0] : []),
        ...(value.sender?.solAmount === undefined ? [] : [1]),
        ...value.recipientSlots.map((_, index) => index + 2),
      ];
      return {
        utxos: plaintextTransferUtxos(value, wallet.registry, SOL_MINT).map((utxo, index) => ({
          utxo,
          outputIndex: positions[index] ?? index,
        })),
        kind: "transfer",
      };
    }
    if (
      decoded.scheme === EncryptedScheme.split &&
      decoded.encoding === "encrypted" &&
      cx.txViewingPublicKey &&
      cx.salt
    ) {
      const plaintext = decodeSplitBundle(
        key.decryptUtxo(decoded.body, cx.txViewingPublicKey, cx.salt, slotIndex),
      );
      return {
        utxos: splitBundleUtxos(plaintext, wallet.registry).map((utxo, index) => ({
          utxo,
          outputIndex: index,
        })),
        kind: "split",
      };
    }
    if (decoded.scheme === EncryptedScheme.merge && decoded.encoding === "verifiable") {
      const value = decryptMerge(key, decoded.body);
      const asset = wallet.registry.entries().find(([, mint]) => {
        try {
          return equal(hashField(decodeAddress(mint)), value.assetField);
        } catch {
          return false;
        }
      })?.[1];
      if (!asset) return undefined;
      return {
        utxos: [
          {
            utxo: new Utxo({
              owner: material.identity.signingPublicKey,
              asset,
              amount: value.amount,
              blinding: value.blinding,
            }),
            outputIndex: slotIndex,
          },
        ],
        kind: "merge",
      };
    }
  } catch (error) {
    if (error instanceof TransactionError && error.code === "TRANSACTION_UNKNOWN_ASSET") {
      const assetId = error.details?.["assetId"];
      if (typeof assetId === "string" && /^\d+$/u.test(assetId)) {
        unknownAssetIds.add(BigInt(assetId));
      }
    }
    return undefined;
  }
  return undefined;
}

/**
 * View tags the fetched slots carry, split the way a wallet reads them: a
 * sender bundle covers the whole transaction, every other scheme is one
 * recipient slot. Which set a derived tag lands in decides which counter it
 * advances.
 */
function tagSites(
  transactions: readonly IndexedShieldedTransaction[],
): Readonly<{ sender: ReadonlySet<string>; recipient: ReadonlySet<string> }> {
  const sender = new Set<string>();
  const recipient = new Set<string>();
  for (const tx of transactions) {
    for (const slot of tx.outputSlots) {
      let scheme: EncryptedScheme;
      try {
        scheme = decodeOutputData(slot.payload).scheme;
      } catch {
        continue;
      }
      const isSenderBundle =
        scheme === EncryptedScheme.anonymousSender || scheme === EncryptedScheme.split;
      (isSenderBundle ? sender : recipient).add(hex(slot.viewTag));
    }
  }
  return { sender, recipient };
}

/**
 * Walk one tag family from `start` in `window`-sized steps, extending as long
 * as a step still hits a slot, and return the highest index that did. A gap
 * shorter than the window never ends the scan, which is what lets a wallet
 * catch up with a counterparty that has run ahead.
 */
function scanStream(
  start: bigint,
  window: bigint,
  derive: (index: bigint) => Bytes32,
  present: (tag: string) => boolean,
): bigint | undefined {
  let maxPresent: bigint | undefined;
  for (let base = start; ; base += window) {
    let hit = false;
    for (let n = base; n < base + window; n++) {
      if (!present(hex(derive(n)))) continue;
      hit = true;
      maxPresent = n;
    }
    if (!hit) return maxPresent;
  }
}

function nextCount(current: bigint, maxPresent: bigint | undefined): bigint {
  return maxPresent === undefined ? current : maxPresent + 1n;
}

/** Slots 0 and 1 hold the sender's own change; recipients start after them. */
const SENDER_SLOT_COUNT = 2;

/**
 * Recipient viewing keys of a confidential transfer this wallet sent. Only the
 * sender derives the published transaction viewing key, and each recipient slot
 * stays sealed to its recipient, so the key prefixed to the ciphertext is the
 * one thing the sender reads back out of it.
 */
function confidentialSendRecipients(
  key: ViewingKey,
  tx: IndexedShieldedTransaction,
): readonly P256PublicKey[] {
  const firstNullifier = tx.nullifiers[0];
  if (firstNullifier === undefined || tx.txViewingPublicKey === undefined) return [];
  const published = tx.txViewingPublicKey.toBytes();
  if (!equal(key.transactionViewingKey(firstNullifier).publicKey().toBytes(), published)) return [];
  const recipients: P256PublicKey[] = [];
  for (const slot of tx.outputSlots.slice(SENDER_SLOT_COUNT)) {
    try {
      const decoded = decodeOutputData(slot.payload);
      if (decoded.scheme !== EncryptedScheme.confidential || decoded.encoding !== "encrypted") {
        continue;
      }
      recipients.push(P256PublicKey.fromBytes(decoded.body.slice(0, 33) as Bytes33));
    } catch {
      continue;
    }
  }
  return recipients;
}

/** Adds newly seen counterparties at zero, keeping the counters already held. */
function withDiscovered(
  known: readonly CounterpartyCounter[],
  discovered: ReadonlyMap<string, P256PublicKey>,
): readonly CounterpartyCounter[] {
  const merged = [...known];
  for (const [id, counterparty] of discovered) {
    if (merged.some((entry) => hex(entry.counterparty.toBytes()) === id)) continue;
    merged.push({ counterparty, count: 0n });
  }
  return merged;
}

/** A rotated-in viewing key starts scanning from zero. */
function ensureViewingKeyEntries(
  history: readonly ViewingKeyEntry[],
  viewingKeys: readonly ViewingKey[],
): readonly ViewingKeyEntry[] {
  const known = new Set(history.map((entry) => hex(entry.viewingPublicKey.toBytes())));
  const entries = [...history];
  for (const key of viewingKeys) {
    const id = hex(key.publicKey().toBytes());
    if (known.has(id)) continue;
    known.add(id);
    entries.push(newViewingKeyEntry(key.publicKey(), 0n));
  }
  return entries;
}

function advanceViewingKeyEntry(
  entry: ViewingKeyEntry,
  key: ViewingKey,
  input: Readonly<{
    window: bigint;
    sites: ReturnType<typeof tagSites>;
    senders: ReadonlyMap<string, P256PublicKey>;
    recipients: ReadonlyMap<string, P256PublicKey>;
  }>,
): ViewingKeyEntry {
  const { window, sites } = input;
  const shared = (
    counters: readonly CounterpartyCounter[],
    derive: (counterparty: P256PublicKey, index: bigint) => Bytes32,
  ): readonly CounterpartyCounter[] =>
    counters.map((counter) => ({
      counterparty: counter.counterparty,
      count: nextCount(
        counter.count,
        scanStream(
          counter.count,
          window,
          (n) => derive(counter.counterparty, n),
          (tag) => sites.recipient.has(tag),
        ),
      ),
    }));
  return {
    ...entry,
    txCount: nextCount(
      entry.txCount,
      scanStream(
        entry.txCount,
        window,
        (n) => key.senderViewTag(n),
        (tag) => sites.sender.has(tag),
      ),
    ),
    requestCount: nextCount(
      entry.requestCount,
      scanStream(
        entry.requestCount,
        window,
        (n) => key.recipientRequestViewTag(n),
        (tag) => sites.recipient.has(tag),
      ),
    ),
    knownSenders: shared(withDiscovered(entry.knownSenders, input.senders), (counterparty, n) =>
      key.recipientSharedViewTag(counterparty, n),
    ),
    knownRecipients: shared(
      withDiscovered(entry.knownRecipients, input.recipients),
      (counterparty, n) => key.sendSharedViewTag(counterparty, n),
    ),
  };
}

export async function decryptTransactions(
  input: Readonly<{
    wallet: Wallet;
    authority: SyncWalletAuthority;
    transactions: readonly IndexedShieldedTransaction[];
    config?: WalletSyncConfig;
  }>,
): Promise<SyncReport> {
  const window = input.config?.tagWindow ?? DEFAULT_TAG_WINDOW;
  if (window <= 0n) {
    throw new TransactionError("TRANSACTION_INVALID_TAG_WINDOW");
  }
  const material = await input.authority.syncMaterial();
  validateMaterial(input.wallet, material);
  const current = input.wallet._state();
  const utxos = [...current.utxos];
  const transactions = [...current.transactions];
  const nullifiers = new Set(current.nullifiers);
  const knownOutputs = new Set(utxos.map((entry) => hex(entry.outputContext.hash)));
  const knownRows = new Set(
    transactions.map((entry) => `${entry.id.signature}:${String(entry.id.index)}`),
  );
  let received = 0;
  let transactionCount = 0;
  const unknownAssetIds = new Set<bigint>();
  const senders = new Map<string, Map<string, P256PublicKey>>();
  const recipients = new Map<string, Map<string, P256PublicKey>>();
  const counterparties = (
    into: Map<string, Map<string, P256PublicKey>>,
    key: ViewingKey,
  ): Map<string, P256PublicKey> => {
    const id = hex(key.publicKey().toBytes());
    const existing = into.get(id);
    if (existing) return existing;
    const created = new Map<string, P256PublicKey>();
    into.set(id, created);
    return created;
  };

  const ordered = [...input.transactions].sort((left, right) =>
    left.slot < right.slot
      ? -1
      : left.slot > right.slot
        ? 1
        : left.txSignature.localeCompare(right.txSignature),
  );
  for (const tx of ordered) {
    for (const nullifier of tx.nullifiers) nullifiers.add(hex(nullifier));
    let transactionStored = false;
    for (let slotIndex = 0; slotIndex < tx.outputSlots.length; slotIndex++) {
      for (const key of material.viewingKeys) {
        const candidate = decodeCandidate(
          decodeContextForSlot(key, tx, slotIndex),
          material,
          input.wallet,
          tx,
          unknownAssetIds,
        );
        if (!candidate) continue;
        let matched = false;
        for (const decoded of candidate.utxos) {
          const slot = tx.outputSlots[decoded.outputIndex];
          if (!slot) continue;
          const hash = decoded.utxo.hash(
            material.nullifierKey.publicKey(),
            decoded.dataHash,
            decoded.zoneDataHash,
          );
          if (!equal(hash, slot.outputContext.hash)) continue;
          matched = true;
          const outputId = hex(slot.outputContext.hash);
          if (!knownOutputs.has(outputId)) {
            const nullifier = decoded.utxo.nullifier(hash, material.nullifierKey);
            utxos.push(
              Object.freeze({
                utxo: decoded.utxo,
                outputContext: Object.freeze({
                  hash: copy(slot.outputContext.hash),
                  tree: slot.outputContext.tree,
                  leafIndex: slot.outputContext.leafIndex,
                }),
                nullifier,
                ...(decoded.dataHash === undefined ? {} : { dataHash: decoded.dataHash }),
                ...(decoded.zoneDataHash === undefined
                  ? {}
                  : { zoneDataHash: decoded.zoneDataHash }),
                spent: nullifiers.has(hex(nullifier)),
              }),
            );
            knownOutputs.add(outputId);
            received++;
          }
          const rowIndex = Number(slot.outputContext.leafIndex);
          const rowId = `${tx.txSignature}:${String(rowIndex)}`;
          if (!knownRows.has(rowId)) {
            transactions.push(transactionRow(tx, rowIndex, candidate.kind));
            knownRows.add(rowId);
            transactionStored = true;
          }
        }
        if (candidate.sender && matched) {
          counterparties(senders, key).set(hex(candidate.sender.toBytes()), candidate.sender);
        }
        for (const recipient of candidate.recipients ?? []) {
          counterparties(recipients, key).set(hex(recipient.toBytes()), recipient);
        }
        break;
      }
    }
    if (transactionStored) transactionCount++;
  }
  let spent = 0;
  const finalUtxos = utxos.map((entry) => {
    const isSpent = entry.spent || nullifiers.has(hex(entry.nullifier));
    if (!entry.spent && isSpent) spent++;
    return Object.freeze({ ...entry, spent: isSpent });
  });
  transactions.sort((left, right) =>
    left.slot < right.slot
      ? -1
      : left.slot > right.slot
        ? 1
        : left.id.signature === right.id.signature
          ? Number(left.id.index - right.id.index)
          : left.id.signature.localeCompare(right.id.signature),
  );
  for (const key of material.viewingKeys) {
    for (const tx of ordered) {
      for (const recipient of confidentialSendRecipients(key, tx)) {
        counterparties(recipients, key).set(hex(recipient.toBytes()), recipient);
      }
    }
  }
  const sites = tagSites(ordered);
  const empty = new Map<string, P256PublicKey>();
  const viewingKeyHistory = ensureViewingKeyEntries(
    current.viewingKeyHistory,
    material.viewingKeys,
  ).map((entry) => {
    const id = hex(entry.viewingPublicKey.toBytes());
    const key = material.viewingKeys.find(
      (candidate) => hex(candidate.publicKey().toBytes()) === id,
    );
    if (key === undefined) return entry;
    return advanceViewingKeyEntry(entry, key, {
      window,
      sites,
      senders: senders.get(id) ?? empty,
      recipients: recipients.get(id) ?? empty,
    });
  });
  input.wallet._replace({
    utxos: finalUtxos,
    transactions,
    nullifiers,
    viewingKeyHistory,
    lastSynced: input.config?.syncedAt ?? 0n,
  });
  return Object.freeze({
    received,
    spent,
    transactions: transactionCount,
    unknownAssetIds: [...unknownAssetIds],
  });
}

export async function decryptTransactionsWorkerEquivalent(
  input: Parameters<typeof decryptTransactions>[0],
): Promise<SyncReport> {
  return decryptTransactions(input);
}
