import type { Address, Bytes16, Bytes31, Bytes32, Bytes33 } from "@zolana/interface";
import { P256PublicKey, ShieldedPublicKey, ViewingKey } from "@zolana/keypair";
import { decryptVerifiable, encryptVerifiable } from "@zolana/keypair/merge";

import { Data, type DataRecord } from "../data.js";
import { TransactionError } from "../error.js";
import { checked, concat, copy, decodeAddress, encodeAddress } from "../internal.js";
import type { AssetRegistry } from "../wallet/asset.js";
import { Utxo, deriveBlinding } from "../utxo.js";

export const EncryptedScheme = Object.freeze({
  proofless: 0,
  anonymousRecipient: 1,
  anonymousSender: 2,
  confidential: 3,
  split: 5,
  merge: 6,
  plaintextTransfer: 7,
} as const);
export type EncryptedScheme = (typeof EncryptedScheme)[keyof typeof EncryptedScheme];

export interface ConfidentialOutputPlaintext {
  readonly assetId: bigint;
  readonly amount: bigint;
  readonly blinding: Bytes31;
  readonly zoneProgramId?: Address;
  readonly data: Data;
}

export interface AnonymousRecipientPlaintext {
  readonly ownerPublicKey: ShieldedPublicKey;
  readonly senderPublicKey: P256PublicKey;
  readonly assetId: bigint;
  readonly amount: bigint;
  readonly blinding: Bytes31;
  readonly data: Data;
}

export interface AnonymousSenderPlaintext {
  readonly ownerPublicKey: ShieldedPublicKey;
  readonly splAssetId: bigint;
  readonly splAmount: bigint;
  readonly solAmount: bigint;
  readonly blindingSeed: Bytes31;
  readonly recipientViewingPublicKeys: readonly P256PublicKey[];
  readonly splData: Data;
  readonly solData: Data;
}

export interface SplitBundlePlaintext {
  readonly ownerPublicKey: ShieldedPublicKey;
  readonly numOutputs: number;
  readonly assetId: bigint;
  readonly assetAmount: bigint;
  readonly blindingSeed: Bytes31;
  readonly data: Data;
}

export interface SplitEncryptedUtxos {
  readonly typePrefix: number;
  readonly txViewingPublicKey: P256PublicKey;
  readonly salt: Bytes16;
  readonly ciphertext: Uint8Array;
}

export interface MergePlaintext {
  readonly amount: bigint;
  readonly assetField: Bytes32;
  readonly blinding: Bytes31;
}

export interface TransferPlaintextSplChange {
  readonly amount: bigint;
  readonly assetId: bigint;
}

export interface TransferPlaintextSender {
  readonly ownerPublicKey: ShieldedPublicKey;
  readonly spl?: TransferPlaintextSplChange;
  readonly solAmount?: bigint;
  readonly splData: Data;
  readonly solData: Data;
}

export interface TransferPlaintextRecipient {
  readonly ownerPublicKey: ShieldedPublicKey;
  readonly assetId: bigint;
  readonly amount: bigint;
  readonly data: Data;
}

export interface TransferPlaintextUtxos {
  readonly typePrefix: number;
  readonly blindingSeed: Bytes31;
  readonly sender?: TransferPlaintextSender;
  readonly recipientSlots: readonly TransferPlaintextRecipient[];
}

export interface ProoflessOutput {
  readonly owner: Bytes32;
  readonly blinding: Bytes31;
  readonly asset: Address;
  readonly amount: bigint;
  readonly dataHash?: Bytes32;
  readonly utxoData?: Uint8Array;
  readonly zoneProgramId?: Address;
  readonly zoneDataHash?: Bytes32;
  readonly zoneData?: Uint8Array;
  readonly memo?: Uint8Array;
}

class Writer {
  readonly parts: Uint8Array[] = [];

  u8(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) {
      throw new TransactionError("TRANSACTION_INVALID_INTEGER", { value, bits: 8 });
    }
    this.parts.push(Uint8Array.of(value));
  }

  u16(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
      throw new TransactionError("TRANSACTION_INVALID_INTEGER", { value, bits: 16 });
    }
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    this.parts.push(bytes);
  }

  u32(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
      throw new TransactionError("TRANSACTION_INVALID_INTEGER", { value, bits: 32 });
    }
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    this.parts.push(bytes);
  }

  u64(value: bigint): void {
    if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
      throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
        value: value.toString(),
      });
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    this.parts.push(bytes);
  }

  bytes(value: Uint8Array): void {
    this.parts.push(new Uint8Array(value));
  }

  option<T>(value: T | undefined, write: (value: T) => void): void {
    this.u8(value === undefined ? 0 : 1);
    if (value !== undefined) write(value);
  }

  finish(): Uint8Array {
    return concat(...this.parts);
  }
}

class Reader {
  #offset = 0;

  constructor(readonly bytes: Uint8Array) {}

  take(length: number): Uint8Array {
    if (this.#offset + length > this.bytes.length) {
      throw new TransactionError("TRANSACTION_DESERIALIZE", {
        offset: this.#offset,
        requested: length,
        available: this.bytes.length - this.#offset,
      });
    }
    const result = this.bytes.slice(this.#offset, this.#offset + length);
    this.#offset += length;
    return result;
  }

  u8(): number {
    const value = this.take(1)[0];
    if (value === undefined) throw new TransactionError("TRANSACTION_DESERIALIZE");
    return value;
  }

  u16(): number {
    const bytes = this.take(2);
    return new DataView(bytes.buffer, bytes.byteOffset, 2).getUint16(0, true);
  }

  u32(): number {
    const bytes = this.take(4);
    return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
  }

  u64(): bigint {
    const bytes = this.take(8);
    return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, true);
  }

  option<T>(read: () => T): T | undefined {
    const tag = this.u8();
    if (tag === 0) return undefined;
    if (tag !== 1) throw new TransactionError("TRANSACTION_DESERIALIZE", { optionTag: tag });
    return read();
  }

  exact(): void {
    if (this.#offset !== this.bytes.length) {
      throw new TransactionError("TRANSACTION_TRAILING_BYTES", {
        trailing: this.bytes.length - this.#offset,
      });
    }
  }
}

function writeData(writer: Writer, data: Data): void {
  if (!(data instanceof Data)) {
    throw new TransactionError("TRANSACTION_SERIALIZE", { field: "data" });
  }
  const records = data.records();
  if (records.length > 0xff) {
    throw new TransactionError("TRANSACTION_SERIALIZE", {
      field: "dataRecords",
      maximum: 0xff,
      actual: records.length,
    });
  }
  writer.u8(records.length);
  for (const record of records) {
    if (record.bytes.length > 0xffff) {
      throw new TransactionError("TRANSACTION_SERIALIZE", {
        field: record.kind,
        maximum: 0xffff,
        actual: record.bytes.length,
      });
    }
    writer.u8(dataRecordTag(record.kind));
    writer.u16(record.bytes.length);
    writer.bytes(record.bytes);
  }
}

function dataRecordTag(kind: DataRecord["kind"]): number {
  switch (kind) {
    case "zoneData":
      return 1;
    case "utxoData":
      return 2;
    case "memo":
      return 3;
  }
}

function readData(reader: Reader): Data {
  const count = reader.u8();
  const records: DataRecord[] = [];
  for (let index = 0; index < count; index++) {
    const tag = reader.u8();
    const bytes = reader.take(reader.u16());
    const kind = tag === 1 ? "zoneData" : tag === 2 ? "utxoData" : tag === 3 ? "memo" : undefined;
    if (!kind) throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { tag });
    records.push({ kind, bytes });
  }
  return new Data(records);
}

export function encodeData(data: Data): Uint8Array {
  const writer = new Writer();
  writeData(writer, data);
  return writer.finish();
}

export function decodeData(bytes: Uint8Array): Data {
  const reader = new Reader(bytes);
  const data = readData(reader);
  reader.exact();
  return data;
}

export function encodeConfidential(value: ConfidentialOutputPlaintext): Uint8Array {
  const writer = new Writer();
  writer.u64(value.assetId);
  writer.u64(value.amount);
  writer.bytes(checked<Bytes31>(value.blinding, 31, "blinding"));
  writer.option(value.zoneProgramId, (address) => {
    writer.bytes(decodeAddress(address));
  });
  writeData(writer, value.data);
  return writer.finish();
}

export function decodeConfidential(bytes: Uint8Array): ConfidentialOutputPlaintext {
  const reader = new Reader(bytes);
  const assetId = reader.u64();
  const amount = reader.u64();
  const blinding = reader.take(31) as Bytes31;
  const zoneProgramId = reader.option(() => encodeAddress(reader.take(32)));
  const result: ConfidentialOutputPlaintext = {
    assetId,
    amount,
    blinding,
    ...(zoneProgramId === undefined ? {} : { zoneProgramId }),
    data: readData(reader),
  };
  reader.exact();
  return result;
}

export function confidentialUtxo(
  value: ConfidentialOutputPlaintext,
  owner: ShieldedPublicKey,
  assets: AssetRegistry,
): Utxo {
  return new Utxo({
    owner,
    asset: assets.resolve(value.assetId),
    amount: value.amount,
    blinding: value.blinding,
    data: value.data,
    ...(value.zoneProgramId === undefined ? {} : { zoneProgramId: value.zoneProgramId }),
  });
}

export function encodeAnonymousRecipient(value: AnonymousRecipientPlaintext): Uint8Array {
  const writer = new Writer();
  writer.bytes(value.ownerPublicKey.toBytes());
  writer.bytes(value.senderPublicKey.toBytes());
  writer.u64(value.assetId);
  writer.u64(value.amount);
  writer.bytes(checked<Bytes31>(value.blinding, 31, "blinding"));
  writeData(writer, value.data);
  return writer.finish();
}

export function decodeAnonymousRecipient(bytes: Uint8Array): AnonymousRecipientPlaintext {
  const reader = new Reader(bytes);
  const result: AnonymousRecipientPlaintext = {
    ownerPublicKey: ShieldedPublicKey.fromBytes(reader.take(34) as Bytes33),
    senderPublicKey: P256PublicKey.fromBytes(reader.take(33) as Bytes33),
    assetId: reader.u64(),
    amount: reader.u64(),
    blinding: reader.take(31) as Bytes31,
    data: readData(reader),
  };
  reader.exact();
  return result;
}

export function anonymousRecipientUtxo(
  value: AnonymousRecipientPlaintext,
  assets: AssetRegistry,
  zoneProgramId?: Address,
): Utxo {
  if (value.data.zoneData() || value.data.utxoData()) {
    throw new TransactionError("TRANSACTION_UNSUPPORTED_OUTPUT_DATA");
  }
  return new Utxo({
    owner: value.ownerPublicKey,
    asset: assets.resolve(value.assetId),
    amount: value.amount,
    blinding: value.blinding,
    data: value.data,
    ...(zoneProgramId === undefined ? {} : { zoneProgramId }),
  });
}

export function encodeAnonymousSender(value: AnonymousSenderPlaintext): Uint8Array {
  if (value.recipientViewingPublicKeys.length > 0xff) {
    throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
  }
  const writer = new Writer();
  writer.bytes(value.ownerPublicKey.toBytes());
  writer.u64(value.splAssetId);
  writer.u64(value.splAmount);
  writer.u64(value.solAmount);
  writer.bytes(checked<Bytes31>(value.blindingSeed, 31, "blinding seed"));
  writer.u8(value.recipientViewingPublicKeys.length);
  value.recipientViewingPublicKeys.forEach((key) => {
    writer.bytes(key.toBytes());
  });
  writeData(writer, value.splData);
  writeData(writer, value.solData);
  return writer.finish();
}

export function decodeAnonymousSender(bytes: Uint8Array): AnonymousSenderPlaintext {
  const reader = new Reader(bytes);
  const ownerPublicKey = ShieldedPublicKey.fromBytes(reader.take(34) as Bytes33);
  const splAssetId = reader.u64();
  const splAmount = reader.u64();
  const solAmount = reader.u64();
  const blindingSeed = reader.take(31) as Bytes31;
  const recipientViewingPublicKeys = Array.from({ length: reader.u8() }, () =>
    P256PublicKey.fromBytes(reader.take(33) as Bytes33),
  );
  const result: AnonymousSenderPlaintext = {
    ownerPublicKey,
    splAssetId,
    splAmount,
    solAmount,
    blindingSeed,
    recipientViewingPublicKeys,
    splData: readData(reader),
    solData: readData(reader),
  };
  reader.exact();
  return result;
}

export function anonymousSenderUtxos(
  value: AnonymousSenderPlaintext,
  assets: AssetRegistry,
  solMint: Address,
  zoneProgramId?: Address,
): readonly Utxo[] {
  if (value.splAmount === 0n && !value.splData.isEmpty()) {
    throw new TransactionError("TRANSACTION_DATA_WITHOUT_OUTPUT");
  }
  if (value.solAmount === 0n && !value.solData.isEmpty()) {
    throw new TransactionError("TRANSACTION_DATA_WITHOUT_OUTPUT");
  }
  const values: Utxo[] = [];
  if (value.splAmount > 0n) {
    values.push(
      new Utxo({
        owner: value.ownerPublicKey,
        asset: assets.resolve(value.splAssetId),
        amount: value.splAmount,
        blinding: deriveBlinding(value.blindingSeed, 0),
        data: value.splData,
        ...(zoneProgramId === undefined ? {} : { zoneProgramId }),
      }),
    );
  }
  if (value.solAmount > 0n) {
    values.push(
      new Utxo({
        owner: value.ownerPublicKey,
        asset: solMint,
        amount: value.solAmount,
        blinding: deriveBlinding(value.blindingSeed, 1),
        data: value.solData,
        ...(zoneProgramId === undefined ? {} : { zoneProgramId }),
      }),
    );
  }
  return values;
}

export function encodePlaintextTransfer(value: TransferPlaintextUtxos): Uint8Array {
  if (value.recipientSlots.length > 0xff) {
    throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
  }
  const writer = new Writer();
  writer.u8(value.typePrefix);
  writer.bytes(checked<Bytes31>(value.blindingSeed, 31, "blinding seed"));
  writer.option(value.sender, (sender) => {
    writer.bytes(sender.ownerPublicKey.toBytes());
    writer.option(sender.spl, (spl) => {
      writer.u64(spl.amount);
      writer.u64(spl.assetId);
    });
    writer.option(sender.solAmount, (amount) => {
      writer.u64(amount);
    });
    writeData(writer, sender.splData);
    writeData(writer, sender.solData);
  });
  writer.u8(value.recipientSlots.length);
  value.recipientSlots.forEach((recipient) => {
    writer.bytes(recipient.ownerPublicKey.toBytes());
    writer.u64(recipient.assetId);
    writer.u64(recipient.amount);
    writeData(writer, recipient.data);
  });
  return writer.finish();
}

export function decodePlaintextTransfer(
  bytes: Uint8Array,
  expectedTypePrefix = 4,
): TransferPlaintextUtxos {
  const reader = new Reader(bytes);
  const typePrefix = reader.u8();
  if (typePrefix !== expectedTypePrefix) {
    throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { typePrefix });
  }
  const blindingSeed = reader.take(31) as Bytes31;
  const sender = reader.option<TransferPlaintextSender>(() => {
    const ownerPublicKey = ShieldedPublicKey.fromBytes(reader.take(34) as Bytes33);
    const spl = reader.option<TransferPlaintextSplChange>(() => ({
      amount: reader.u64(),
      assetId: reader.u64(),
    }));
    const solAmount = reader.option(() => reader.u64());
    return {
      ownerPublicKey,
      ...(spl === undefined ? {} : { spl }),
      ...(solAmount === undefined ? {} : { solAmount }),
      splData: readData(reader),
      solData: readData(reader),
    };
  });
  const recipientSlots = Array.from({ length: reader.u8() }, (): TransferPlaintextRecipient => ({
    ownerPublicKey: ShieldedPublicKey.fromBytes(reader.take(34) as Bytes33),
    assetId: reader.u64(),
    amount: reader.u64(),
    data: readData(reader),
  }));
  reader.exact();
  return {
    typePrefix,
    blindingSeed,
    ...(sender === undefined ? {} : { sender }),
    recipientSlots,
  };
}

export function encodeSplitBundle(value: SplitBundlePlaintext): Uint8Array {
  const writer = new Writer();
  writer.bytes(value.ownerPublicKey.toBytes());
  writer.u8(value.numOutputs);
  writer.u64(value.assetId);
  writer.u64(value.assetAmount);
  writer.bytes(checked<Bytes31>(value.blindingSeed, 31, "blinding seed"));
  writeData(writer, value.data);
  return writer.finish();
}

export function decodeSplitBundle(bytes: Uint8Array): SplitBundlePlaintext {
  const reader = new Reader(bytes);
  const result: SplitBundlePlaintext = {
    ownerPublicKey: ShieldedPublicKey.fromBytes(reader.take(34) as Bytes33),
    numOutputs: reader.u8(),
    assetId: reader.u64(),
    assetAmount: reader.u64(),
    blindingSeed: reader.take(31) as Bytes31,
    data: readData(reader),
  };
  reader.exact();
  return result;
}

export function encodeSplitEncrypted(value: SplitEncryptedUtxos): Uint8Array {
  const writer = new Writer();
  writer.u8(value.typePrefix);
  writer.bytes(value.txViewingPublicKey.toBytes());
  writer.bytes(checked<Bytes16>(value.salt, 16, "salt"));
  if (value.ciphertext.length > 0xffff) {
    throw new TransactionError("TRANSACTION_INVALID_DATA_LENGTH", {
      name: "split ciphertext",
      maximum: 0xffff,
      actual: value.ciphertext.length,
    });
  }
  writer.u16(value.ciphertext.length);
  writer.bytes(value.ciphertext);
  return writer.finish();
}

export function decodeSplitEncrypted(bytes: Uint8Array): SplitEncryptedUtxos {
  const reader = new Reader(bytes);
  const typePrefix = reader.u8();
  const txViewingPublicKey = P256PublicKey.fromBytes(reader.take(33) as Bytes33);
  const salt = reader.take(16) as Bytes16;
  const ciphertext = reader.take(reader.u16());
  reader.exact();
  return { typePrefix, txViewingPublicKey, salt, ciphertext };
}

export function splitBundleUtxos(
  value: SplitBundlePlaintext,
  assets: AssetRegistry,
): readonly Utxo[] {
  if (value.numOutputs === 0 && !value.data.isEmpty()) {
    throw new TransactionError("TRANSACTION_DATA_WITHOUT_OUTPUT");
  }
  const asset = assets.resolve(value.assetId);
  return Array.from(
    { length: value.numOutputs },
    (_, position) =>
      new Utxo({
        owner: value.ownerPublicKey,
        asset,
        amount: value.assetAmount,
        blinding: deriveBlinding(value.blindingSeed, position),
        data: value.data,
      }),
  );
}

export function encodeOutputData(
  scheme: EncryptedScheme,
  body: Uint8Array,
  encoding: "plaintext" | "encrypted" | "verifiable",
): Uint8Array {
  const blob = concat(Uint8Array.of(scheme), body);
  const writer = new Writer();
  writer.u8(encoding === "plaintext" ? 0 : encoding === "encrypted" ? 1 : 2);
  writer.u32(blob.length);
  writer.bytes(blob);
  return writer.finish();
}

export function decodeOutputData(bytes: Uint8Array): Readonly<{
  encoding: "plaintext" | "encrypted" | "verifiable";
  scheme: EncryptedScheme;
  body: Uint8Array;
}> {
  const reader = new Reader(bytes);
  const encodingTag = reader.u8();
  const blob = reader.take(reader.u32());
  reader.exact();
  const scheme = blob[0] as EncryptedScheme;
  if (!Object.values(EncryptedScheme).includes(scheme)) {
    throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { scheme });
  }
  const encoding =
    encodingTag === 0
      ? "plaintext"
      : encodingTag === 1
        ? "encrypted"
        : encodingTag === 2
          ? "verifiable"
          : undefined;
  if (!encoding) throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { encodingTag });
  return { encoding, scheme, body: blob.slice(1) };
}

export function encodeProofless(value: ProoflessOutput): Uint8Array {
  const writer = new Writer();
  writer.bytes(checked<Bytes32>(value.owner, 32, "owner hash"));
  writer.bytes(checked<Bytes31>(value.blinding, 31, "blinding"));
  writer.bytes(decodeAddress(value.asset));
  writer.u64(value.amount);
  const optionalBytes = (bytes: Uint8Array | undefined): void => {
    writer.option(bytes, (present) => {
      writer.u32(present.length);
      writer.bytes(present);
    });
  };
  writer.option(value.dataHash, (hash) => {
    writer.bytes(checked<Bytes32>(hash, 32, "data hash"));
  });
  optionalBytes(value.utxoData);
  writer.option(value.zoneProgramId, (address) => {
    writer.bytes(decodeAddress(address));
  });
  writer.option(value.zoneDataHash, (hash) => {
    writer.bytes(checked<Bytes32>(hash, 32, "zone data hash"));
  });
  optionalBytes(value.zoneData);
  optionalBytes(value.memo);
  return writer.finish();
}

export function decodeProofless(bytes: Uint8Array): ProoflessOutput {
  const reader = new Reader(bytes);
  const owner = reader.take(32) as Bytes32;
  const blinding = reader.take(31) as Bytes31;
  const asset = encodeAddress(reader.take(32));
  const amount = reader.u64();
  const dataHash = reader.option(() => reader.take(32) as Bytes32);
  const optionalBytes = (): Uint8Array | undefined =>
    reader.option(() => reader.take(reader.u32()));
  const utxoData = optionalBytes();
  const zoneProgramId = reader.option(() => encodeAddress(reader.take(32)));
  const zoneDataHash = reader.option(() => reader.take(32) as Bytes32);
  const zoneData = optionalBytes();
  const memo = optionalBytes();
  reader.exact();
  return {
    owner,
    blinding,
    asset,
    amount,
    ...(dataHash === undefined ? {} : { dataHash }),
    ...(utxoData === undefined ? {} : { utxoData }),
    ...(zoneProgramId === undefined ? {} : { zoneProgramId }),
    ...(zoneDataHash === undefined ? {} : { zoneDataHash }),
    ...(zoneData === undefined ? {} : { zoneData }),
    ...(memo === undefined ? {} : { memo }),
  };
}

export function encryptConfidential(
  tx: ViewingKey,
  recipient: P256PublicKey,
  value: ConfidentialOutputPlaintext,
  salt: Bytes16,
  slotIndex: number,
): Uint8Array {
  return concat(
    recipient.toBytes(),
    tx.encryptSlot(recipient, encodeConfidential(value), salt, slotIndex),
  );
}

export function encryptAnonymous(
  tx: ViewingKey,
  recipient: P256PublicKey,
  plaintext: Uint8Array,
  salt: Bytes16,
  slotIndex: number,
): Uint8Array {
  return tx.encryptSlot(recipient, plaintext, salt, slotIndex);
}

export function decryptAnonymous(
  key: ViewingKey,
  txViewingPublicKey: P256PublicKey,
  ciphertext: Uint8Array,
  salt: Bytes16,
  slotIndex: number,
): Uint8Array {
  return key.decryptUtxo(ciphertext, txViewingPublicKey, salt, slotIndex);
}

export const encryptSplit = encryptAnonymous;
export const decryptSplit = decryptAnonymous;

export function decryptConfidential(
  key: ViewingKey,
  txViewingPublicKey: P256PublicKey,
  body: Uint8Array,
  salt: Bytes16,
  slotIndex: number,
): ConfidentialOutputPlaintext {
  if (body.length < 33) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      expectedMinimum: 33,
      actual: body.length,
    });
  }
  return decodeConfidential(key.decryptUtxo(body.slice(33), txViewingPublicKey, salt, slotIndex));
}

export function decryptConfidentialAsSender(
  tx: ViewingKey,
  body: Uint8Array,
  salt: Bytes16,
  slotIndex: number,
): ConfidentialOutputPlaintext {
  if (body.length < 33) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      expectedMinimum: 33,
      actual: body.length,
    });
  }
  const recipient = P256PublicKey.fromBytes(body.slice(0, 33) as Bytes33);
  return decodeConfidential(tx.decryptSlotEphemeral(recipient, body.slice(33), salt, slotIndex));
}

export function encodeMerge(value: MergePlaintext): Uint8Array {
  const amount = new Uint8Array(8);
  new DataView(amount.buffer).setBigUint64(0, value.amount, false);
  return concat(amount, checked<Bytes32>(value.assetField, 32, "asset field"), value.blinding);
}

export function decodeMerge(bytes: Uint8Array): MergePlaintext {
  if (bytes.length !== 71) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      expected: 71,
      actual: bytes.length,
    });
  }
  return {
    amount: new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, false),
    assetField: copy(bytes.slice(8, 40)) as Bytes32,
    blinding: copy(bytes.slice(40)) as Bytes31,
  };
}

export function encryptMerge(
  txViewingSecret: Bytes32,
  userViewingPublicKey: P256PublicKey,
  value: MergePlaintext,
): Uint8Array {
  const encrypted = encryptVerifiable(txViewingSecret, userViewingPublicKey, encodeMerge(value));
  return concat(encrypted.txViewingPublicKey.toBytes(), encrypted.ciphertext);
}

export function decryptMerge(userViewingSecret: Bytes32, body: Uint8Array): MergePlaintext {
  if (body.length < 33) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      expectedMinimum: 33,
      actual: body.length,
    });
  }
  const txViewingPublicKey = P256PublicKey.fromBytes(body.slice(0, 33) as Bytes33);
  return decodeMerge(decryptVerifiable(userViewingSecret, txViewingPublicKey, body.slice(33)));
}
