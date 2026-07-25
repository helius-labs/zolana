import type { Bytes31, Bytes32, Signature } from "@zolana/interface";
import { ShieldedPublicKey, type ViewingKey } from "@zolana/keypair";

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
  decodeOutputData,
  decodePlaintextTransfer,
  decodeSplitBundle,
  decryptAnonymous,
  decryptConfidential,
  decryptMerge,
  splitBundleUtxos,
} from "../serialization/codecs.js";
import { Utxo, deriveBlinding } from "../utxo.js";
import type { SyncWalletAuthority, WalletSyncMaterial } from "./authority.js";
import { SOL_MINT } from "./asset.js";
import { type PrivateTransaction, type SyncReport, Wallet, hex } from "./state.js";

export interface WalletSyncConfig {
  readonly tagWindow?: bigint;
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

function readU32(bytes: Uint8Array, offset: number): number {
  if (offset + 4 > bytes.length) throw new TransactionError("TRANSACTION_DESERIALIZE");
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, true);
}

function decodeProofless(
  body: Uint8Array,
  owner: ShieldedPublicKey,
): Readonly<{
  utxo: Utxo;
  dataHash?: Bytes32;
  zoneDataHash?: Bytes32;
}> {
  let offset = 0;
  const take = (length: number): Uint8Array => {
    if (offset + length > body.length) throw new TransactionError("TRANSACTION_DESERIALIZE");
    const value = body.slice(offset, offset + length);
    offset += length;
    return value;
  };
  const option = <T>(read: () => T): T | undefined => {
    const tag = take(1)[0];
    if (tag === 0) return undefined;
    if (tag !== 1) throw new TransactionError("TRANSACTION_DESERIALIZE", { optionTag: tag });
    return read();
  };
  take(32);
  const blinding = take(31) as Bytes31;
  const asset = encodeAddress(take(32));
  const amountBytes = take(8);
  const amount = new DataView(
    amountBytes.buffer,
    amountBytes.byteOffset,
    amountBytes.byteLength,
  ).getBigUint64(0, true);
  const dataHash = option(() => take(32) as Bytes32);
  const vector = (): Uint8Array => {
    const length = readU32(body, offset);
    offset += 4;
    return take(length);
  };
  const utxoData = option(vector);
  const zoneProgramId = option(() => encodeAddress(take(32)));
  const zoneDataHash = option(() => take(32) as Bytes32);
  const zoneData = option(vector);
  const memo = option(vector);
  if (offset !== body.length) throw new TransactionError("TRANSACTION_TRAILING_BYTES");
  const records: DataRecord[] = [];
  if (zoneData) records.push({ kind: "zoneData", bytes: zoneData });
  if (utxoData) records.push({ kind: "utxoData", bytes: utxoData });
  if (memo) records.push({ kind: "memo", bytes: memo });
  return {
    utxo: new Utxo({
      owner,
      asset,
      amount,
      blinding,
      data: new Data(records),
      ...(zoneProgramId === undefined ? {} : { zoneProgramId }),
    }),
    ...(dataHash === undefined ? {} : { dataHash }),
    ...(zoneDataHash === undefined ? {} : { zoneDataHash }),
  };
}

function transactionRow(
  tx: IndexedShieldedTransaction,
  index: number,
  kind: PrivateTransaction["kind"],
): PrivateTransaction {
  return Object.freeze({
    id: Object.freeze({ signature: tx.txSignature as Signature, index }),
    kind,
    direction: "incoming",
    status: "confirmed",
    slot: tx.slot,
  });
}

function decodeCandidate(
  key: ViewingKey,
  material: WalletSyncMaterial,
  wallet: Wallet,
  tx: IndexedShieldedTransaction,
  slotIndex: number,
  unknownAssetIds: Set<bigint>,
):
  | Readonly<{
      utxos: readonly Readonly<{
        utxo: Utxo;
        dataHash?: Bytes32;
        zoneDataHash?: Bytes32;
        outputIndex: number;
      }>[];
      kind: PrivateTransaction["kind"];
    }>
  | undefined {
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
      const value = decodeProofless(decoded.body, material.identity.signingPublicKey);
      return { utxos: [{ ...value, outputIndex: slotIndex }], kind: "deposit" };
    }
    if (
      (decoded.scheme === EncryptedScheme.anonymousRecipient ||
        decoded.scheme === EncryptedScheme.anonymousSender) &&
      decoded.encoding === "encrypted" &&
      tx.txViewingPublicKey &&
      tx.salt
    ) {
      const plaintext = decryptAnonymous(
        key,
        tx.txViewingPublicKey,
        decoded.body,
        tx.salt,
        slotIndex,
      );
      if (decoded.scheme === EncryptedScheme.anonymousRecipient) {
        return {
          utxos: [
            {
              utxo: anonymousRecipientUtxo(decodeAnonymousRecipient(plaintext), wallet.registry),
              outputIndex: slotIndex,
            },
          ],
          kind: "transfer",
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
      return { utxos, kind: "transfer" };
    }
    if (
      decoded.scheme === EncryptedScheme.confidential &&
      decoded.encoding === "encrypted" &&
      tx.txViewingPublicKey &&
      tx.salt
    ) {
      const value = decryptConfidential(
        key,
        tx.txViewingPublicKey,
        decoded.body,
        tx.salt,
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
      const utxos: {
        utxo: Utxo;
        outputIndex: number;
      }[] = [];
      if (value.sender) {
        if (value.sender.spl) {
          utxos.push({
            utxo: new Utxo({
              owner: value.sender.ownerPublicKey,
              asset: wallet.registry.resolve(value.sender.spl.assetId),
              amount: value.sender.spl.amount,
              blinding: deriveBlinding(value.blindingSeed, 0),
              data: value.sender.splData,
            }),
            outputIndex: 0,
          });
        } else if (!value.sender.splData.isEmpty()) {
          throw new TransactionError("TRANSACTION_DATA_WITHOUT_OUTPUT");
        }
        if (value.sender.solAmount !== undefined) {
          utxos.push({
            utxo: new Utxo({
              owner: value.sender.ownerPublicKey,
              asset: SOL_MINT,
              amount: value.sender.solAmount,
              blinding: deriveBlinding(value.blindingSeed, 1),
              data: value.sender.solData,
            }),
            outputIndex: 1,
          });
        } else if (!value.sender.solData.isEmpty()) {
          throw new TransactionError("TRANSACTION_DATA_WITHOUT_OUTPUT");
        }
      }
      value.recipientSlots.forEach((recipient, index) => {
        utxos.push({
          utxo: new Utxo({
            owner: recipient.ownerPublicKey,
            asset: wallet.registry.resolve(recipient.assetId),
            amount: recipient.amount,
            blinding: deriveBlinding(value.blindingSeed, index + 2),
            data: recipient.data,
          }),
          outputIndex: index + 2,
        });
      });
      return { utxos, kind: "transfer" };
    }
    if (
      decoded.scheme === EncryptedScheme.split &&
      decoded.encoding === "encrypted" &&
      tx.txViewingPublicKey &&
      tx.salt
    ) {
      const plaintext = decodeSplitBundle(
        key.decryptUtxo(decoded.body, tx.txViewingPublicKey, tx.salt, slotIndex),
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

export async function decryptTransactions(
  input: Readonly<{
    wallet: Wallet;
    authority: SyncWalletAuthority;
    transactions: readonly IndexedShieldedTransaction[];
    config?: WalletSyncConfig;
  }>,
): Promise<SyncReport> {
  if ((input.config?.tagWindow ?? 64n) <= 0n) {
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
          key,
          material,
          input.wallet,
          tx,
          slotIndex,
          unknownAssetIds,
        );
        if (!candidate) continue;
        for (const decoded of candidate.utxos) {
          const slot = tx.outputSlots[decoded.outputIndex];
          if (!slot) continue;
          const hash = decoded.utxo.hash(
            material.nullifierKey.publicKey(),
            decoded.dataHash,
            decoded.zoneDataHash,
          );
          if (!equal(hash, slot.outputContext.hash)) continue;
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
          ? left.id.index - right.id.index
          : left.id.signature.localeCompare(right.id.signature),
  );
  input.wallet._replace({ utxos: finalUtxos, transactions, nullifiers });
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
