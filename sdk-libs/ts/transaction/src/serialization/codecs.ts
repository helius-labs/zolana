import type { Address, Bytes16, Bytes31, Bytes32, Bytes33 } from "@zolana/interface";
import {
  P256PublicKey,
  ShieldedPublicKey,
  type Bytes34,
  type ViewingKey,
  type ViewingKeyLike,
} from "@zolana/keypair";

import { Data, type DataRecord } from "../data.js";
import { TransactionError } from "../error.js";
import {
  checked,
  concat,
  copy,
  decodeAddress,
  encodeAddress,
  equal,
  hashField,
} from "../internal.js";
import { SOL_MINT, type AssetRegistry } from "../wallet/asset.js";
import { Utxo, deriveBlinding, resolveZoneProgramId } from "../utxo.js";

/**
 * The type prefix each encrypted family writes into its plaintext body. These
 * live beside the reader and the writer that enforce them so a wire-format
 * change has one place to happen; the package root re-exports them, as the Rust
 * crate root does.
 */
export const TRANSFER = 1;
export const SPLIT = 2;
export const MERGE = 3;
export const TRANSFER_PLAINTEXT = 4;

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
export type OutputDataEncoding = "plaintext" | "encrypted" | "verifiable";

export function encryptedSchemeFromByte(byte: number): EncryptedScheme {
  if (!Number.isInteger(byte) || byte < 0 || byte > 0xff) {
    throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { byte });
  }
  switch (byte) {
    case EncryptedScheme.proofless:
    case EncryptedScheme.anonymousRecipient:
    case EncryptedScheme.anonymousSender:
    case EncryptedScheme.confidential:
    case EncryptedScheme.split:
    case EncryptedScheme.merge:
    case EncryptedScheme.plaintextTransfer:
      return byte;
    default:
      throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { byte });
  }
}

/** The wire byte for a scheme, the counterpart of Rust `EncryptedScheme::as_byte`. */
export function encryptedSchemeToByte(scheme: EncryptedScheme): number {
  return encryptedSchemeFromByte(scheme);
}

export function outputDataEncoding(scheme: EncryptedScheme): OutputDataEncoding {
  switch (encryptedSchemeFromByte(scheme)) {
    case EncryptedScheme.proofless:
    case EncryptedScheme.plaintextTransfer:
      return "plaintext";
    case EncryptedScheme.merge:
      return "verifiable";
    default:
      return "encrypted";
  }
}

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
  // The zone id rides in the payload rather than coming from the reader, so
  // the plaintext has to carry one itself before its zone data means anything.
  if (value.data.zoneData() && value.zoneProgramId === undefined) {
    throw new TransactionError("TRANSACTION_MISSING_ZONE_PROGRAM_ID");
  }
  return new Utxo({
    owner,
    asset: assets.resolve(value.assetId),
    amount: value.amount,
    blinding: value.blinding,
    data: value.data,
    ...(value.zoneProgramId === undefined ? {} : { zoneProgramId: value.zoneProgramId }),
  });
}

export function confidentialPlaintextFromUtxo(
  utxo: Utxo,
  owner: ShieldedPublicKey,
  assets: AssetRegistry,
): ConfidentialOutputPlaintext {
  requireOwner(utxo, owner);
  return {
    assetId: assets.assetId(utxo.asset),
    amount: utxo.amount,
    blinding: copy(utxo.blinding),
    ...(utxo.zoneProgramId === undefined ? {} : { zoneProgramId: utxo.zoneProgramId }),
    data: new Data(utxo.data.records()),
  };
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
    ownerPublicKey: ShieldedPublicKey.fromBytes(reader.take(34) as Bytes34),
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
  const zone = resolveZoneProgramId(zoneProgramId, value.data);
  return new Utxo({
    owner: value.ownerPublicKey,
    asset: assets.resolve(value.assetId),
    amount: value.amount,
    blinding: value.blinding,
    data: value.data,
    ...(zone === undefined ? {} : { zoneProgramId: zone }),
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
  const ownerPublicKey = ShieldedPublicKey.fromBytes(reader.take(34) as Bytes34);
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
    const zone = resolveZoneProgramId(zoneProgramId, value.splData);
    values.push(
      new Utxo({
        owner: value.ownerPublicKey,
        asset: assets.resolve(value.splAssetId),
        amount: value.splAmount,
        blinding: deriveBlinding(value.blindingSeed, 0),
        data: value.splData,
        ...(zone === undefined ? {} : { zoneProgramId: zone }),
      }),
    );
  }
  if (value.solAmount > 0n) {
    const zone = resolveZoneProgramId(zoneProgramId, value.solData);
    values.push(
      new Utxo({
        owner: value.ownerPublicKey,
        asset: solMint,
        amount: value.solAmount,
        blinding: deriveBlinding(value.blindingSeed, 1),
        data: value.solData,
        ...(zone === undefined ? {} : { zoneProgramId: zone }),
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
  expectedTypePrefix = TRANSFER_PLAINTEXT,
): TransferPlaintextUtxos {
  const reader = new Reader(bytes);
  const typePrefix = reader.u8();
  if (typePrefix !== expectedTypePrefix) {
    throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { typePrefix });
  }
  const blindingSeed = reader.take(31) as Bytes31;
  const sender = reader.option<TransferPlaintextSender>(() => {
    const ownerPublicKey = ShieldedPublicKey.fromBytes(reader.take(34) as Bytes34);
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
    ownerPublicKey: ShieldedPublicKey.fromBytes(reader.take(34) as Bytes34),
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

/**
 * Rust `TransferPlaintextUtxos::into_utxos`. Slot 0 is the sender's SPL
 * change, slot 1 its SOL change, and recipients follow from slot 2; the
 * position is what derives each blinding, so it is also the position the
 * published output slot must sit at.
 */
export function plaintextTransferUtxos(
  value: TransferPlaintextUtxos,
  assets: AssetRegistry,
  solMint: Address,
  zoneProgramId?: Address,
): readonly Utxo[] {
  const values: Utxo[] = [];
  const { sender } = value;
  if (sender) {
    if (!sender.spl && !sender.splData.isEmpty()) {
      throw new TransactionError("TRANSACTION_DATA_WITHOUT_OUTPUT");
    }
    if (sender.solAmount === undefined && !sender.solData.isEmpty()) {
      throw new TransactionError("TRANSACTION_DATA_WITHOUT_OUTPUT");
    }
    if (sender.spl) {
      const zone = resolveZoneProgramId(zoneProgramId, sender.splData);
      values.push(
        new Utxo({
          owner: sender.ownerPublicKey,
          asset: assets.resolve(sender.spl.assetId),
          amount: sender.spl.amount,
          blinding: deriveBlinding(value.blindingSeed, 0),
          data: sender.splData,
          ...(zone === undefined ? {} : { zoneProgramId: zone }),
        }),
      );
    }
    if (sender.solAmount !== undefined) {
      const zone = resolveZoneProgramId(zoneProgramId, sender.solData);
      values.push(
        new Utxo({
          owner: sender.ownerPublicKey,
          asset: solMint,
          amount: sender.solAmount,
          blinding: deriveBlinding(value.blindingSeed, 1),
          data: sender.solData,
          ...(zone === undefined ? {} : { zoneProgramId: zone }),
        }),
      );
    }
  }
  value.recipientSlots.forEach((recipient, index) => {
    const position = index + 2;
    if (position > 0xff) throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
    const zone = resolveZoneProgramId(zoneProgramId, recipient.data);
    values.push(
      new Utxo({
        owner: recipient.ownerPublicKey,
        asset: assets.resolve(recipient.assetId),
        amount: recipient.amount,
        blinding: deriveBlinding(value.blindingSeed, position),
        data: recipient.data,
        ...(zone === undefined ? {} : { zoneProgramId: zone }),
      }),
    );
  });
  return values;
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
    ownerPublicKey: ShieldedPublicKey.fromBytes(reader.take(34) as Bytes34),
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
  if (value.typePrefix !== SPLIT) {
    throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", {
      typePrefix: value.typePrefix,
    });
  }
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
  if (typePrefix !== SPLIT) {
    throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { typePrefix });
  }
  const txViewingPublicKey = P256PublicKey.fromBytes(reader.take(33) as Bytes33);
  const salt = reader.take(16) as Bytes16;
  const ciphertext = reader.take(reader.u16());
  reader.exact();
  return { typePrefix, txViewingPublicKey, salt, ciphertext };
}

export function splitBundleUtxos(
  value: SplitBundlePlaintext,
  assets: AssetRegistry,
  zoneProgramId?: Address,
): readonly Utxo[] {
  if (value.numOutputs === 0 && !value.data.isEmpty()) {
    throw new TransactionError("TRANSACTION_DATA_WITHOUT_OUTPUT");
  }
  const zone = resolveZoneProgramId(zoneProgramId, value.data);
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
        ...(zone === undefined ? {} : { zoneProgramId: zone }),
      }),
  );
}

export function encodeOutputData(
  scheme: EncryptedScheme,
  body: Uint8Array,
  encoding = outputDataEncoding(scheme),
): Uint8Array {
  const checkedScheme = encryptedSchemeFromByte(scheme);
  const expectedEncoding = outputDataEncoding(checkedScheme);
  if (encoding !== expectedEncoding) {
    throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", {
      scheme: checkedScheme,
      encoding,
      expectedEncoding,
    });
  }
  const blob = concat(Uint8Array.of(checkedScheme), body);
  const writer = new Writer();
  writer.u8(outputDataEncodingTag(encoding));
  writer.u32(blob.length);
  writer.bytes(blob);
  return writer.finish();
}

/**
 * The encoding tag, scheme byte, and remaining body of a slot payload, without
 * requiring the pair to agree. Rust's `OutputDataEncoding::try_from_slice`
 * reads the two independently and every reader dispatches on the pair, so a
 * mismatched payload has to survive parsing in order to be refused where the
 * dispatch happens. Prefer [`decodeOutputData`] unless you are that dispatch.
 */
export function readOutputData(bytes: Uint8Array): Readonly<{
  encoding: OutputDataEncoding;
  scheme: EncryptedScheme;
  body: Uint8Array;
}> {
  const reader = new Reader(bytes);
  const encodingTag = reader.u8();
  const blob = reader.take(reader.u32());
  reader.exact();
  if (blob.length === 0) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      field: "encryptedOutput",
      expectedMinimum: 1,
      actual: 0,
    });
  }
  return {
    encoding: outputDataEncodingFromTag(encodingTag),
    scheme: encryptedSchemeFromByte(blob[0] as number),
    body: blob.slice(1),
  };
}

export function decodeOutputData(bytes: Uint8Array): Readonly<{
  encoding: OutputDataEncoding;
  scheme: EncryptedScheme;
  body: Uint8Array;
}> {
  const frame = readOutputData(bytes);
  const expectedEncoding = outputDataEncoding(frame.scheme);
  if (frame.encoding !== expectedEncoding) {
    throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", {
      scheme: frame.scheme,
      encoding: frame.encoding,
      expectedEncoding,
    });
  }
  return frame;
}

function outputDataEncodingTag(encoding: OutputDataEncoding): number {
  switch (encoding) {
    case "plaintext":
      return 0;
    case "encrypted":
      return 1;
    case "verifiable":
      return 2;
  }
}

function outputDataEncodingFromTag(tag: number): OutputDataEncoding {
  switch (tag) {
    case 0:
      return "plaintext";
    case 1:
      return "encrypted";
    case 2:
      return "verifiable";
    default:
      throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { encodingTag: tag });
  }
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

/**
 * Rust `Proofless::into_utxos`. The deposit rail publishes its zone binding in
 * the payload beside the zone data, so unlike the reader-supplied rails there
 * is nothing to resolve; a zone data hash that contradicts the binding is
 * caught when the commitment is computed.
 */
export function prooflessUtxo(value: ProoflessOutput, owner: ShieldedPublicKey): Utxo {
  const records: DataRecord[] = [];
  if (value.zoneData) records.push({ kind: "zoneData", bytes: value.zoneData });
  if (value.utxoData) records.push({ kind: "utxoData", bytes: value.utxoData });
  if (value.memo) records.push({ kind: "memo", bytes: value.memo });
  return new Utxo({
    owner,
    asset: value.asset,
    amount: value.amount,
    blinding: value.blinding,
    data: new Data(records),
    ...(value.zoneProgramId === undefined ? {} : { zoneProgramId: value.zoneProgramId }),
  });
}

export function encryptConfidential(
  tx: ViewingKeyLike,
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
  tx: ViewingKeyLike,
  recipient: P256PublicKey,
  plaintext: Uint8Array,
  salt: Bytes16,
  slotIndex: number,
): Uint8Array {
  return tx.encryptSlot(recipient, plaintext, salt, slotIndex);
}

export function decryptAnonymous(
  key: ViewingKeyLike,
  txViewingPublicKey: P256PublicKey,
  ciphertext: Uint8Array,
  salt: Bytes16,
  slotIndex: number,
): Uint8Array {
  return key.decryptUtxo(ciphertext, txViewingPublicKey, salt, slotIndex);
}

export const encryptSplit = encryptAnonymous;
export const decryptSplit = decryptAnonymous;

/**
 * The published body carries the counterparty key in front of the ciphertext.
 * Rust reports a body too short to hold one as `InvalidLength { expected: 33 }`
 * even though 33 is a minimum, so the detail keys match across the two.
 */
function splitEmbeddedKey(body: Uint8Array): Readonly<{ key: P256PublicKey; rest: Uint8Array }> {
  if (body.length < 33) {
    throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
      expected: 33,
      actual: body.length,
    });
  }
  return {
    key: P256PublicKey.fromBytes(body.slice(0, 33) as Bytes33),
    rest: body.slice(33),
  };
}

/**
 * Rust converts every `KeypairError` that crosses into a transaction path with
 * `?`, so a caller sees one category for a key or cipher failure. Reproducing
 * that here keeps the reader's rejection categories identical; without it a
 * malformed published slot escapes as a `KeypairError` no transaction caller
 * catches.
 */
function inTransactionCategory<T>(run: () => T): T {
  try {
    return run();
  } catch (error) {
    if (error instanceof TransactionError) throw error;
    const code = (error as { code?: unknown }).code;
    throw new TransactionError("TRANSACTION_KEYPAIR", {
      ...(typeof code === "string" ? { keypair: code } : {}),
    });
  }
}

export function decryptConfidential(
  key: ViewingKeyLike,
  txViewingPublicKey: P256PublicKey,
  body: Uint8Array,
  salt: Bytes16,
  slotIndex: number,
): ConfidentialOutputPlaintext {
  const { rest } = inTransactionCategory(() => splitEmbeddedKey(body));
  return decodeConfidential(
    inTransactionCategory(() => key.decryptUtxo(rest, txViewingPublicKey, salt, slotIndex)),
  );
}

export function decryptConfidentialAsSender(
  tx: ViewingKeyLike,
  body: Uint8Array,
  salt: Bytes16,
  slotIndex: number,
): ConfidentialOutputPlaintext {
  const { key, rest } = inTransactionCategory(() => splitEmbeddedKey(body));
  return decodeConfidential(
    inTransactionCategory(() => tx.decryptSlotEphemeral(key, rest, salt, slotIndex)),
  );
}

export function encodeMerge(value: MergePlaintext): Uint8Array {
  if (
    typeof value.amount !== "bigint" ||
    value.amount < 0n ||
    value.amount > 0xffff_ffff_ffff_ffffn
  ) {
    throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
      value: String(value.amount),
    });
  }
  const amount = new Uint8Array(8);
  new DataView(amount.buffer).setBigUint64(0, value.amount, false);
  return concat(
    amount,
    checked<Bytes32>(value.assetField, 32, "asset field"),
    checked<Bytes31>(value.blinding, 31, "blinding"),
  );
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

export function mergePlaintextFromUtxo(utxo: Utxo, owner: ShieldedPublicKey): MergePlaintext {
  requireOwner(utxo, owner);
  if (!utxo.data.isEmpty()) {
    throw new TransactionError("TRANSACTION_MERGE_INPUT_HAS_DATA", { index: 0 });
  }
  return {
    amount: utxo.amount,
    assetField: hashField(decodeAddress(utxo.asset)),
    blinding: copy(utxo.blinding),
  };
}

export function mergeUtxo(
  value: MergePlaintext,
  owner: ShieldedPublicKey,
  assets: AssetRegistry,
  zoneProgramId?: Address,
): Utxo {
  const asset = assets.addressForField(checked<Bytes32>(value.assetField, 32, "asset field"));
  if (asset === undefined) {
    throw new TransactionError("TRANSACTION_UNKNOWN_ASSET_FIELD", {
      assetField: [...value.assetField],
    });
  }
  return new Utxo({
    owner,
    asset,
    amount: value.amount,
    blinding: value.blinding,
    ...(zoneProgramId === undefined ? {} : { zoneProgramId }),
  });
}

export function encryptMerge(
  txViewingKey: ViewingKeyLike,
  userViewingPublicKey: P256PublicKey,
  value: MergePlaintext,
): Uint8Array {
  const plaintext = encodeMerge(value);
  const encrypted = inTransactionCategory(() =>
    txViewingKey.encryptVerifiable(userViewingPublicKey, plaintext),
  );
  return concat(encrypted.txViewingPublicKey.toBytes(), encrypted.ciphertext);
}

export function decryptMerge(userViewingKey: ViewingKeyLike, body: Uint8Array): MergePlaintext {
  const { key, rest } = inTransactionCategory(() => splitEmbeddedKey(body));
  return decodeMerge(inTransactionCategory(() => userViewingKey.decryptVerifiable(key, rest)));
}

function requireOwner(utxo: Utxo, owner: ShieldedPublicKey): void {
  if (!equal(utxo.owner.toBytes(), owner.toBytes())) {
    throw new TransactionError("TRANSACTION_INPUT_OWNER_MISMATCH", { index: 0 });
  }
}

/**
 * Everything a wallet needs to open one output slot, the counterpart of Rust
 * `DecodeCx`. Each field is per-transaction except `slotIndex`, and the
 * encryption schemes bind the slot index, so a context built for one slot must
 * not be reused to open another.
 */
export interface DecodeContext {
  readonly viewingKey: ViewingKey;
  readonly txViewingPublicKey?: P256PublicKey;
  readonly salt?: Bytes16;
  readonly slotIndex: number;
  readonly firstNullifier?: Bytes32;
}

/**
 * Structural view of an indexed transaction, kept local so the codecs stay
 * independent of the instruction types that own the full shape.
 */
type DecodeSource = Readonly<{
  txViewingPublicKey?: P256PublicKey;
  salt?: Bytes16;
  nullifiers: readonly Bytes32[];
}>;

export function decodeContextForSlot(
  viewingKey: ViewingKey,
  transaction: DecodeSource,
  slotIndex: number,
): DecodeContext {
  const [firstNullifier] = transaction.nullifiers;
  return {
    viewingKey,
    ...(transaction.txViewingPublicKey === undefined
      ? {}
      : { txViewingPublicKey: transaction.txViewingPublicKey }),
    ...(transaction.salt === undefined ? {} : { salt: transaction.salt }),
    slotIndex,
    ...(firstNullifier === undefined ? {} : { firstNullifier }),
  };
}

/**
 * The owner, registry, and zone a set of output UTXOs is converted under, the
 * counterpart of Rust `OwnerCx`. The conversions below are the counterparts of
 * the `UtxoSerialization::from_utxos` implementations, which is where a builder
 * turns the UTXOs it just derived back into the plaintext it will encrypt.
 */
export interface OwnerContext {
  readonly owner: ShieldedPublicKey;
  readonly assets: AssetRegistry;
  readonly zoneProgramId?: Address;
}

function singleUtxo(utxos: readonly Utxo[]): Utxo {
  const first = utxos[0];
  if (utxos.length !== 1 || first === undefined) {
    throw new TransactionError("TRANSACTION_INVALID_OUTPUT_COUNT", {
      expected: 1,
      actual: utxos.length,
    });
  }
  return first;
}

function validateOwner(utxo: Utxo, owner: ShieldedPublicKey, index: number): void {
  if (!equal(utxo.owner.toBytes(), owner.toBytes())) {
    throw new TransactionError("TRANSACTION_OUTPUT_OWNER_MISMATCH", { index });
  }
}

function validateZone(utxo: Utxo, zoneProgramId: Address | undefined, index: number): void {
  if (utxo.zoneProgramId !== zoneProgramId) {
    throw new TransactionError("TRANSACTION_OUTPUT_ZONE_MISMATCH", { index });
  }
}

/** The blinding position a UTXO sits at, or `undefined` if the seed derives none. */
function blindingPosition(seed: Bytes31, blinding: Bytes31): number | undefined {
  for (let position = 0; position <= 0xff; position++) {
    if (equal(deriveBlinding(seed, position), blinding)) return position;
  }
  return undefined;
}

export function plaintextTransferFromUtxos(
  utxos: readonly Utxo[],
  owner: OwnerContext,
  cx: Readonly<{ blindingSeed: Bytes31 }>,
): TransferPlaintextUtxos {
  const blindingSeed = checked<Bytes31>(cx.blindingSeed, 31, "blinding seed");
  let senderOwner: ShieldedPublicKey | undefined;
  let spl: TransferPlaintextSplChange | undefined;
  let solAmount: bigint | undefined;
  let splData = new Data();
  let solData = new Data();
  const recipients: (readonly [number, TransferPlaintextRecipient])[] = [];
  const seen = new Set<number>();
  for (const [index, utxo] of utxos.entries()) {
    validateZone(utxo, owner.zoneProgramId, index);
    const position = blindingPosition(blindingSeed, utxo.blinding);
    if (position === undefined) throw new TransactionError("TRANSACTION_MISSING_OUTPUT", { index });
    if (seen.has(position)) {
      throw new TransactionError("TRANSACTION_INVALID_OUTPUT_POSITION", { position });
    }
    seen.add(position);
    if (position === 0) {
      validateOwner(utxo, owner.owner, index);
      if (utxo.asset === SOL_MINT) {
        throw new TransactionError("TRANSACTION_OUTPUT_ASSET_MISMATCH", { index });
      }
      senderOwner = owner.owner;
      spl = { amount: utxo.amount, assetId: owner.assets.assetId(utxo.asset) };
      splData = new Data(utxo.data.records());
    } else if (position === 1) {
      validateOwner(utxo, owner.owner, index);
      if (utxo.asset !== SOL_MINT) {
        throw new TransactionError("TRANSACTION_OUTPUT_ASSET_MISMATCH", { index });
      }
      senderOwner = owner.owner;
      solAmount = utxo.amount;
      solData = new Data(utxo.data.records());
    } else {
      recipients.push([
        position,
        {
          ownerPublicKey: utxo.owner,
          assetId: owner.assets.assetId(utxo.asset),
          amount: utxo.amount,
          data: new Data(utxo.data.records()),
        },
      ]);
    }
  }
  recipients.sort(([left], [right]) => left - right);
  for (const [offset, [position]] of recipients.entries()) {
    const expected = offset + 2;
    if (expected > 0xff) throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
    if (position !== expected) {
      throw new TransactionError("TRANSACTION_INVALID_OUTPUT_POSITION", { position });
    }
  }
  return {
    typePrefix: TRANSFER_PLAINTEXT,
    blindingSeed,
    ...(senderOwner === undefined
      ? {}
      : {
          sender: {
            ownerPublicKey: senderOwner,
            ...(spl === undefined ? {} : { spl }),
            ...(solAmount === undefined ? {} : { solAmount }),
            splData,
            solData,
          },
        }),
    recipientSlots: recipients.map(([, recipient]) => recipient),
  };
}

export function anonymousRecipientFromUtxos(
  utxos: readonly Utxo[],
  owner: OwnerContext,
  cx: Readonly<{ senderPublicKey: P256PublicKey }>,
): AnonymousRecipientPlaintext {
  const first = singleUtxo(utxos);
  validateOwner(first, owner.owner, 0);
  validateZone(first, owner.zoneProgramId, 0);
  return {
    ownerPublicKey: first.owner,
    senderPublicKey: cx.senderPublicKey,
    assetId: owner.assets.assetId(first.asset),
    amount: first.amount,
    blinding: copy(first.blinding),
    data: new Data(first.data.records()),
  };
}

export function anonymousSenderFromUtxos(
  utxos: readonly Utxo[],
  owner: OwnerContext,
  cx: Readonly<{
    blindingSeed: Bytes31;
    recipientViewingPublicKeys: readonly P256PublicKey[];
  }>,
): AnonymousSenderPlaintext {
  if (utxos.length === 0) throw new TransactionError("TRANSACTION_MISSING_OUTPUT");
  const blindingSeed = checked<Bytes31>(cx.blindingSeed, 31, "blinding seed");
  let splAssetId = 0n;
  let splAmount = 0n;
  let solAmount = 0n;
  let splData = new Data();
  let solData = new Data();
  let splSeen = false;
  let solSeen = false;
  for (const [index, utxo] of utxos.entries()) {
    validateOwner(utxo, owner.owner, index);
    validateZone(utxo, owner.zoneProgramId, index);
    if (utxo.asset === SOL_MINT) {
      if (solSeen || !equal(utxo.blinding, deriveBlinding(blindingSeed, 1))) {
        throw new TransactionError("TRANSACTION_INVALID_OUTPUT_POSITION", { position: 1 });
      }
      solSeen = true;
      solAmount = utxo.amount;
      solData = new Data(utxo.data.records());
    } else {
      if (splSeen || !equal(utxo.blinding, deriveBlinding(blindingSeed, 0))) {
        throw new TransactionError("TRANSACTION_INVALID_OUTPUT_POSITION", { position: 0 });
      }
      splSeen = true;
      splAssetId = owner.assets.assetId(utxo.asset);
      splAmount = utxo.amount;
      splData = new Data(utxo.data.records());
    }
  }
  return {
    ownerPublicKey: owner.owner,
    splAssetId,
    splAmount,
    solAmount,
    blindingSeed,
    recipientViewingPublicKeys: [...cx.recipientViewingPublicKeys],
    splData,
    solData,
  };
}

export function splitBundleFromUtxos(
  utxos: readonly Utxo[],
  owner: OwnerContext,
  cx: Readonly<{ blindingSeed: Bytes31 }>,
): SplitBundlePlaintext {
  const first = utxos[0];
  if (first === undefined) throw new TransactionError("TRANSACTION_MISSING_OUTPUT");
  if (utxos.length > 0xff) throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
  const blindingSeed = checked<Bytes31>(cx.blindingSeed, 31, "blinding seed");
  for (const [index, utxo] of utxos.entries()) {
    validateOwner(utxo, owner.owner, index);
    validateZone(utxo, owner.zoneProgramId, index);
    if (utxo.asset !== first.asset) {
      throw new TransactionError("TRANSACTION_OUTPUT_ASSET_MISMATCH", { index });
    }
    if (utxo.amount !== first.amount) {
      throw new TransactionError("TRANSACTION_OUTPUT_AMOUNT_MISMATCH", { index });
    }
    if (!sameData(utxo.data, first.data)) {
      throw new TransactionError("TRANSACTION_OUTPUT_DATA_MISMATCH", { index });
    }
    if (!equal(utxo.blinding, deriveBlinding(blindingSeed, index))) {
      throw new TransactionError("TRANSACTION_OUTPUT_BLINDING_MISMATCH", { index });
    }
  }
  return {
    ownerPublicKey: owner.owner,
    numOutputs: utxos.length,
    assetId: owner.assets.assetId(first.asset),
    assetAmount: first.amount,
    blindingSeed,
    data: new Data(first.data.records()),
  };
}

export function prooflessFromUtxos(
  utxos: readonly Utxo[],
  owner: OwnerContext,
  cx: Readonly<{ ownerHash: Bytes32; dataHash?: Bytes32; zoneDataHash?: Bytes32 }>,
): ProoflessOutput {
  const utxo = singleUtxo(utxos);
  validateOwner(utxo, owner.owner, 0);
  validateZone(utxo, owner.zoneProgramId, 0);
  const utxoData = utxo.data.utxoData();
  const zoneData = utxo.data.zoneData();
  const memo = utxo.data.memo();
  return {
    owner: checked<Bytes32>(cx.ownerHash, 32, "owner hash"),
    blinding: copy(utxo.blinding),
    asset: utxo.asset,
    amount: utxo.amount,
    ...(cx.dataHash === undefined ? {} : { dataHash: cx.dataHash }),
    ...(utxoData === undefined ? {} : { utxoData }),
    ...(utxo.zoneProgramId === undefined ? {} : { zoneProgramId: utxo.zoneProgramId }),
    ...(cx.zoneDataHash === undefined ? {} : { zoneDataHash: cx.zoneDataHash }),
    ...(zoneData === undefined ? {} : { zoneData }),
    ...(memo === undefined ? {} : { memo }),
  };
}

function sameData(left: Data, right: Data): boolean {
  const leftRecords = left.records();
  const rightRecords = right.records();
  if (leftRecords.length !== rightRecords.length) return false;
  return leftRecords.every((record, index) => {
    const other = rightRecords[index];
    return other !== undefined && record.kind === other.kind && equal(record.bytes, other.bytes);
  });
}
