import { P256PublicKey, ShieldedPublicKey } from "../../keypair/public-key.js";
import { Data } from "../data.js";
import { TransactionError } from "../error.js";
import { checked, concat, copy, decodeAddress, encodeAddress, equal } from "../internal.js";
import { SOL_MINT } from "../wallet/asset.js";
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
});
export function encryptedSchemeFromByte(byte) {
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
export function encryptedSchemeToByte(scheme) {
    return encryptedSchemeFromByte(scheme);
}
export function outputDataEncoding(scheme) {
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
class Writer {
    parts = [];
    u8(value) {
        if (!Number.isInteger(value) || value < 0 || value > 0xff) {
            throw new TransactionError("TRANSACTION_INVALID_INTEGER", { value, bits: 8 });
        }
        this.parts.push(Uint8Array.of(value));
    }
    u16(value) {
        if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
            throw new TransactionError("TRANSACTION_INVALID_INTEGER", { value, bits: 16 });
        }
        const bytes = new Uint8Array(2);
        new DataView(bytes.buffer).setUint16(0, value, true);
        this.parts.push(bytes);
    }
    u32(value) {
        if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
            throw new TransactionError("TRANSACTION_INVALID_INTEGER", { value, bits: 32 });
        }
        const bytes = new Uint8Array(4);
        new DataView(bytes.buffer).setUint32(0, value, true);
        this.parts.push(bytes);
    }
    u64(value) {
        if (value < 0n || value > 0xffffffffffffffffn) {
            throw new TransactionError("TRANSACTION_INVALID_AMOUNT", {
                value: value.toString(),
            });
        }
        const bytes = new Uint8Array(8);
        new DataView(bytes.buffer).setBigUint64(0, value, true);
        this.parts.push(bytes);
    }
    bytes(value) {
        this.parts.push(new Uint8Array(value));
    }
    option(value, write) {
        this.u8(value === undefined ? 0 : 1);
        if (value !== undefined)
            write(value);
    }
    finish() {
        return concat(...this.parts);
    }
}
class Reader {
    bytes;
    #offset = 0;
    constructor(bytes) {
        this.bytes = bytes;
    }
    take(length) {
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
    u8() {
        const value = this.take(1)[0];
        if (value === undefined)
            throw new TransactionError("TRANSACTION_DESERIALIZE");
        return value;
    }
    u16() {
        const bytes = this.take(2);
        return new DataView(bytes.buffer, bytes.byteOffset, 2).getUint16(0, true);
    }
    u32() {
        const bytes = this.take(4);
        return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
    }
    u64() {
        const bytes = this.take(8);
        return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, true);
    }
    option(read) {
        const tag = this.u8();
        if (tag === 0)
            return undefined;
        if (tag !== 1)
            throw new TransactionError("TRANSACTION_DESERIALIZE", { optionTag: tag });
        return read();
    }
    exact() {
        if (this.#offset !== this.bytes.length) {
            throw new TransactionError("TRANSACTION_TRAILING_BYTES", {
                trailing: this.bytes.length - this.#offset,
            });
        }
    }
}
function writeData(writer, data) {
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
function dataRecordTag(kind) {
    switch (kind) {
        case "zoneData":
            return 1;
        case "utxoData":
            return 2;
        case "memo":
            return 3;
    }
}
function readData(reader) {
    const count = reader.u8();
    const records = [];
    for (let index = 0; index < count; index++) {
        const tag = reader.u8();
        const bytes = reader.take(reader.u16());
        const kind = tag === 1 ? "zoneData" : tag === 2 ? "utxoData" : tag === 3 ? "memo" : undefined;
        if (!kind) {
            throw new TransactionError("TRANSACTION_DESERIALIZE", {
                field: "dataRecordTag",
                tag,
            });
        }
        records.push({ kind, bytes });
    }
    return new Data(records);
}
export function encodeData(data) {
    const writer = new Writer();
    writeData(writer, data);
    return writer.finish();
}
export function decodeData(bytes) {
    const reader = new Reader(bytes);
    const data = readData(reader);
    reader.exact();
    return data;
}
export function encodeConfidential(value) {
    const writer = new Writer();
    writer.u64(value.assetId);
    writer.u64(value.amount);
    writer.bytes(checked(value.blinding, 32, "blinding"));
    writer.option(value.zoneProgramId, (address) => {
        writer.bytes(decodeAddress(address));
    });
    writeData(writer, value.data);
    return writer.finish();
}
export function decodeConfidential(bytes) {
    const reader = new Reader(bytes);
    const assetId = reader.u64();
    const amount = reader.u64();
    const blinding = reader.take(32);
    const zoneProgramId = reader.option(() => encodeAddress(reader.take(32)));
    const result = {
        assetId,
        amount,
        blinding,
        ...(zoneProgramId === undefined ? {} : { zoneProgramId }),
        data: readData(reader),
    };
    reader.exact();
    return result;
}
export function confidentialUtxo(value, owner, assets) {
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
export function confidentialPlaintextFromUtxo(utxo, owner, assets) {
    requireOwner(utxo, owner);
    return {
        assetId: assets.assetId(utxo.asset),
        amount: utxo.amount,
        blinding: copy(utxo.blinding),
        ...(utxo.zoneProgramId === undefined ? {} : { zoneProgramId: utxo.zoneProgramId }),
        data: new Data(utxo.data.records()),
    };
}
export function encodeAnonymousRecipient(value) {
    const writer = new Writer();
    writer.bytes(value.ownerPublicKey.toBytes());
    writer.bytes(value.senderPublicKey.toBytes());
    writer.u64(value.assetId);
    writer.u64(value.amount);
    writer.bytes(checked(value.blinding, 32, "blinding"));
    writeData(writer, value.data);
    return writer.finish();
}
export function decodeAnonymousRecipient(bytes) {
    const reader = new Reader(bytes);
    const result = {
        ownerPublicKey: ShieldedPublicKey.fromBytes(reader.take(34)),
        senderPublicKey: P256PublicKey.fromBytes(reader.take(33)),
        assetId: reader.u64(),
        amount: reader.u64(),
        blinding: reader.take(32),
        data: readData(reader),
    };
    reader.exact();
    return result;
}
export function anonymousRecipientUtxo(value, assets, zoneProgramId) {
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
export function encodeAnonymousSender(value) {
    if (value.recipientViewingPublicKeys.length > 0xff) {
        throw new TransactionError("TRANSACTION_SERIALIZE", {
            field: "recipientViewingPublicKeys",
            maximum: 0xff,
            actual: value.recipientViewingPublicKeys.length,
        });
    }
    const writer = new Writer();
    writer.bytes(value.ownerPublicKey.toBytes());
    writer.u64(value.splAssetId);
    writer.u64(value.splAmount);
    writer.u64(value.solAmount);
    writer.bytes(checked(value.blindingSeed, 32, "blinding seed"));
    writer.u8(value.recipientViewingPublicKeys.length);
    value.recipientViewingPublicKeys.forEach((key) => {
        writer.bytes(key.toBytes());
    });
    writeData(writer, value.splData);
    writeData(writer, value.solData);
    return writer.finish();
}
export function decodeAnonymousSender(bytes) {
    const reader = new Reader(bytes);
    const ownerPublicKey = ShieldedPublicKey.fromBytes(reader.take(34));
    const splAssetId = reader.u64();
    const splAmount = reader.u64();
    const solAmount = reader.u64();
    const blindingSeed = reader.take(32);
    const recipientViewingPublicKeys = Array.from({ length: reader.u8() }, () => P256PublicKey.fromBytes(reader.take(33)));
    const result = {
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
export function anonymousSenderUtxos(value, assets, solMint, zoneProgramId) {
    if (value.splAmount === 0n && !value.splData.isEmpty()) {
        throw new TransactionError("TRANSACTION_DATA_WITHOUT_OUTPUT");
    }
    if (value.solAmount === 0n && !value.solData.isEmpty()) {
        throw new TransactionError("TRANSACTION_DATA_WITHOUT_OUTPUT");
    }
    const values = [];
    if (value.splAmount > 0n) {
        const zone = resolveZoneProgramId(zoneProgramId, value.splData);
        values.push(new Utxo({
            owner: value.ownerPublicKey,
            asset: assets.resolve(value.splAssetId),
            amount: value.splAmount,
            blinding: deriveBlinding(value.blindingSeed, 0),
            data: value.splData,
            ...(zone === undefined ? {} : { zoneProgramId: zone }),
        }));
    }
    if (value.solAmount > 0n) {
        const zone = resolveZoneProgramId(zoneProgramId, value.solData);
        values.push(new Utxo({
            owner: value.ownerPublicKey,
            asset: solMint,
            amount: value.solAmount,
            blinding: deriveBlinding(value.blindingSeed, 1),
            data: value.solData,
            ...(zone === undefined ? {} : { zoneProgramId: zone }),
        }));
    }
    return values;
}
export function encodePlaintextTransfer(value) {
    if (value.recipientSlots.length > 0xff) {
        throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
    }
    const writer = new Writer();
    writer.u8(value.typePrefix);
    writer.bytes(checked(value.blindingSeed, 32, "blinding seed"));
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
export function decodePlaintextTransfer(bytes, expectedTypePrefix = TRANSFER_PLAINTEXT) {
    const reader = new Reader(bytes);
    const typePrefix = reader.u8();
    if (typePrefix !== expectedTypePrefix) {
        throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { typePrefix });
    }
    const blindingSeed = reader.take(32);
    const sender = reader.option(() => {
        const ownerPublicKey = ShieldedPublicKey.fromBytes(reader.take(34));
        const spl = reader.option(() => ({
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
    const recipientSlots = Array.from({ length: reader.u8() }, () => ({
        ownerPublicKey: ShieldedPublicKey.fromBytes(reader.take(34)),
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
export function plaintextTransferUtxos(value, assets, solMint, zoneProgramId) {
    const values = [];
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
            values.push(new Utxo({
                owner: sender.ownerPublicKey,
                asset: assets.resolve(sender.spl.assetId),
                amount: sender.spl.amount,
                blinding: deriveBlinding(value.blindingSeed, 0),
                data: sender.splData,
                ...(zone === undefined ? {} : { zoneProgramId: zone }),
            }));
        }
        if (sender.solAmount !== undefined) {
            const zone = resolveZoneProgramId(zoneProgramId, sender.solData);
            values.push(new Utxo({
                owner: sender.ownerPublicKey,
                asset: solMint,
                amount: sender.solAmount,
                blinding: deriveBlinding(value.blindingSeed, 1),
                data: sender.solData,
                ...(zone === undefined ? {} : { zoneProgramId: zone }),
            }));
        }
    }
    value.recipientSlots.forEach((recipient, index) => {
        const position = index + 2;
        if (position > 0xff)
            throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
        const zone = resolveZoneProgramId(zoneProgramId, recipient.data);
        values.push(new Utxo({
            owner: recipient.ownerPublicKey,
            asset: assets.resolve(recipient.assetId),
            amount: recipient.amount,
            blinding: deriveBlinding(value.blindingSeed, position),
            data: recipient.data,
            ...(zone === undefined ? {} : { zoneProgramId: zone }),
        }));
    });
    return values;
}
export function encodeSplitBundle(value) {
    const writer = new Writer();
    writer.bytes(value.ownerPublicKey.toBytes());
    writer.u8(value.numOutputs);
    writer.u64(value.assetId);
    writer.u64(value.assetAmount);
    writer.bytes(checked(value.blindingSeed, 32, "blinding seed"));
    writeData(writer, value.data);
    return writer.finish();
}
export function decodeSplitBundle(bytes) {
    const reader = new Reader(bytes);
    const result = {
        ownerPublicKey: ShieldedPublicKey.fromBytes(reader.take(34)),
        numOutputs: reader.u8(),
        assetId: reader.u64(),
        assetAmount: reader.u64(),
        blindingSeed: reader.take(32),
        data: readData(reader),
    };
    reader.exact();
    return result;
}
export function encodeSplitEncrypted(value) {
    if (value.typePrefix !== SPLIT) {
        throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", {
            typePrefix: value.typePrefix,
        });
    }
    const writer = new Writer();
    writer.u8(value.typePrefix);
    writer.bytes(value.txViewingPublicKey.toBytes());
    writer.bytes(checked(value.salt, 16, "salt"));
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
export function decodeSplitEncrypted(bytes) {
    const reader = new Reader(bytes);
    const typePrefix = reader.u8();
    if (typePrefix !== SPLIT) {
        throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", { typePrefix });
    }
    const txViewingPublicKey = P256PublicKey.fromBytes(reader.take(33));
    const salt = reader.take(16);
    const ciphertext = reader.take(reader.u16());
    reader.exact();
    return { typePrefix, txViewingPublicKey, salt, ciphertext };
}
export function splitBundleUtxos(value, assets, zoneProgramId) {
    if (value.numOutputs === 0 && !value.data.isEmpty()) {
        throw new TransactionError("TRANSACTION_DATA_WITHOUT_OUTPUT");
    }
    const zone = resolveZoneProgramId(zoneProgramId, value.data);
    const asset = assets.resolve(value.assetId);
    return Array.from({ length: value.numOutputs }, (_, position) => new Utxo({
        owner: value.ownerPublicKey,
        asset,
        amount: value.assetAmount,
        blinding: deriveBlinding(value.blindingSeed, position),
        data: value.data,
        ...(zone === undefined ? {} : { zoneProgramId: zone }),
    }));
}
export function encodeOutputData(scheme, body, encoding = outputDataEncoding(scheme)) {
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
export function readOutputData(bytes) {
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
        scheme: encryptedSchemeFromByte(blob[0]),
        body: blob.slice(1),
    };
}
export function decodeOutputData(bytes) {
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
function outputDataEncodingTag(encoding) {
    switch (encoding) {
        case "plaintext":
            return 0;
        case "encrypted":
            return 1;
        case "verifiable":
            return 2;
    }
}
function outputDataEncodingFromTag(tag) {
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
export function encodeProofless(value) {
    const writer = new Writer();
    writer.bytes(checked(value.owner, 32, "owner hash"));
    writer.bytes(checked(value.blinding, 32, "blinding"));
    writer.bytes(decodeAddress(value.asset));
    writer.u64(value.amount);
    const optionalBytes = (bytes) => {
        writer.option(bytes, (present) => {
            writer.u32(present.length);
            writer.bytes(present);
        });
    };
    writer.option(value.dataHash, (hash) => {
        writer.bytes(checked(hash, 32, "data hash"));
    });
    optionalBytes(value.utxoData);
    writer.option(value.zoneProgramId, (address) => {
        writer.bytes(decodeAddress(address));
    });
    writer.option(value.zoneDataHash, (hash) => {
        writer.bytes(checked(hash, 32, "zone data hash"));
    });
    optionalBytes(value.zoneData);
    optionalBytes(value.memo);
    return writer.finish();
}
export function decodeProofless(bytes) {
    const reader = new Reader(bytes);
    const owner = reader.take(32);
    const blinding = reader.take(32);
    const asset = encodeAddress(reader.take(32));
    const amount = reader.u64();
    const dataHash = reader.option(() => reader.take(32));
    const optionalBytes = () => reader.option(() => reader.take(reader.u32()));
    const utxoData = optionalBytes();
    const zoneProgramId = reader.option(() => encodeAddress(reader.take(32)));
    const zoneDataHash = reader.option(() => reader.take(32));
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
export function prooflessUtxo(value, owner) {
    const records = [];
    if (value.zoneData)
        records.push({ kind: "zoneData", bytes: value.zoneData });
    if (value.utxoData)
        records.push({ kind: "utxoData", bytes: value.utxoData });
    if (value.memo)
        records.push({ kind: "memo", bytes: value.memo });
    return new Utxo({
        owner,
        asset: value.asset,
        amount: value.amount,
        blinding: value.blinding,
        data: new Data(records),
        ...(value.zoneProgramId === undefined ? {} : { zoneProgramId: value.zoneProgramId }),
    });
}
export function encryptConfidential(tx, recipient, value, salt, slotIndex) {
    return concat(recipient.toBytes(), inTransactionCategory(() => tx.encryptSlot(recipient, encodeConfidential(value), salt, slotIndex)));
}
export function encryptAnonymous(tx, recipient, plaintext, salt, slotIndex) {
    return inTransactionCategory(() => tx.encryptSlot(recipient, plaintext, salt, slotIndex));
}
export function decryptAnonymous(key, txViewingPublicKey, ciphertext, salt, slotIndex) {
    return inTransactionCategory(() => key.decryptUtxo(ciphertext, txViewingPublicKey, salt, slotIndex));
}
export const encryptSplit = encryptAnonymous;
export const decryptSplit = decryptAnonymous;
/**
 * The published body carries the counterparty key in front of the ciphertext.
 * Rust reports a body too short to hold one as `InvalidLength { expected: 33 }`
 * even though 33 is a minimum, so the detail keys match across the two.
 */
function splitEmbeddedKey(body) {
    if (body.length < 33) {
        throw new TransactionError("TRANSACTION_INVALID_LENGTH", {
            expected: 33,
            actual: body.length,
        });
    }
    return {
        key: P256PublicKey.fromBytes(body.slice(0, 33)),
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
function inTransactionCategory(run) {
    try {
        return run();
    }
    catch (error) {
        if (error instanceof TransactionError)
            throw error;
        const code = error.code;
        throw new TransactionError("TRANSACTION_KEYPAIR", typeof code === "string" ? { keypair: code } : {});
    }
}
export function decryptConfidential(key, txViewingPublicKey, body, salt, slotIndex) {
    const { rest } = inTransactionCategory(() => splitEmbeddedKey(body));
    return decodeConfidential(inTransactionCategory(() => key.decryptUtxo(rest, txViewingPublicKey, salt, slotIndex)));
}
export function decryptConfidentialAsSender(tx, body, salt, slotIndex) {
    const { key, rest } = inTransactionCategory(() => splitEmbeddedKey(body));
    return decodeConfidential(inTransactionCategory(() => tx.decryptSlotEphemeral(key, rest, salt, slotIndex)));
}
function requireOwner(utxo, owner) {
    if (!equal(utxo.owner.toBytes(), owner.toBytes())) {
        throw new TransactionError("TRANSACTION_INPUT_OWNER_MISMATCH", { index: 0 });
    }
}
export function decodeContextForSlot(viewingKey, transaction, slotIndex) {
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
function singleUtxo(utxos) {
    const first = utxos[0];
    if (utxos.length !== 1 || first === undefined) {
        throw new TransactionError("TRANSACTION_INVALID_OUTPUT_COUNT", {
            expected: 1,
            actual: utxos.length,
        });
    }
    return first;
}
function validateOwner(utxo, owner, index) {
    if (!equal(utxo.owner.toBytes(), owner.toBytes())) {
        throw new TransactionError("TRANSACTION_OUTPUT_OWNER_MISMATCH", { index });
    }
}
function validateZone(utxo, zoneProgramId, index) {
    if (utxo.zoneProgramId !== zoneProgramId) {
        throw new TransactionError("TRANSACTION_OUTPUT_ZONE_MISMATCH", { index });
    }
}
/** The blinding position a UTXO sits at, or `undefined` if the seed derives none. */
function blindingPosition(seed, blinding) {
    for (let position = 0; position <= 0xff; position++) {
        if (equal(deriveBlinding(seed, position), blinding))
            return position;
    }
    return undefined;
}
export function plaintextTransferFromUtxos(utxos, owner, cx) {
    const blindingSeed = checked(cx.blindingSeed, 32, "blinding seed");
    let senderOwner;
    let spl;
    let solAmount;
    let splData = new Data();
    let solData = new Data();
    const recipients = [];
    const seen = new Set();
    for (const [index, utxo] of utxos.entries()) {
        validateZone(utxo, owner.zoneProgramId, index);
        const position = blindingPosition(blindingSeed, utxo.blinding);
        if (position === undefined)
            throw new TransactionError("TRANSACTION_MISSING_OUTPUT", { index });
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
        }
        else if (position === 1) {
            validateOwner(utxo, owner.owner, index);
            if (utxo.asset !== SOL_MINT) {
                throw new TransactionError("TRANSACTION_OUTPUT_ASSET_MISMATCH", { index });
            }
            senderOwner = owner.owner;
            solAmount = utxo.amount;
            solData = new Data(utxo.data.records());
        }
        else {
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
        if (expected > 0xff)
            throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
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
export function anonymousRecipientFromUtxos(utxos, owner, cx) {
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
export function anonymousSenderFromUtxos(utxos, owner, cx) {
    if (utxos.length === 0)
        throw new TransactionError("TRANSACTION_MISSING_OUTPUT");
    const blindingSeed = checked(cx.blindingSeed, 32, "blinding seed");
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
        }
        else {
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
export function splitBundleFromUtxos(utxos, owner, cx) {
    const first = utxos[0];
    if (first === undefined)
        throw new TransactionError("TRANSACTION_MISSING_OUTPUT");
    if (utxos.length > 0xff)
        throw new TransactionError("TRANSACTION_TOO_MANY_OUTPUTS");
    const blindingSeed = checked(cx.blindingSeed, 32, "blinding seed");
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
export function prooflessFromUtxos(utxos, owner, cx) {
    const utxo = singleUtxo(utxos);
    validateOwner(utxo, owner.owner, 0);
    validateZone(utxo, owner.zoneProgramId, 0);
    const utxoData = utxo.data.utxoData();
    const zoneData = utxo.data.zoneData();
    const memo = utxo.data.memo();
    return {
        owner: checked(cx.ownerHash, 32, "owner hash"),
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
function sameData(left, right) {
    const leftRecords = left.records();
    const rightRecords = right.records();
    if (leftRecords.length !== rightRecords.length)
        return false;
    return leftRecords.every((record, index) => {
        const other = rightRecords[index];
        return other !== undefined && record.kind === other.kind && equal(record.bytes, other.bytes);
    });
}
