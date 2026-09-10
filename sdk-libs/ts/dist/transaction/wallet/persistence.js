import { address as kitAddress, assertIsSignature, getBase64Decoder, getBase64Encoder, } from "@solana/kit";
import { P256PublicKey, ShieldedPublicKey } from "../../keypair/public-key.js";
import { ShieldedAddress } from "../../keypair/shielded.js";
import { Data } from "../data.js";
import { TransactionError } from "../error.js";
import { Utxo } from "../utxo.js";
import { AssetRegistry, SOL_ASSET_ID } from "./asset.js";
import { Wallet, hex, } from "./state.js";
const decodeBase64 = getBase64Encoder();
const encodeBase64 = getBase64Decoder();
const U64_MAX = 0xffffffffffffffffn;
const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;
export function serializeWallet(wallet) {
    if (!(wallet instanceof Wallet))
        fail("wallet");
    const state = wallet._state();
    const snapshot = {
        version: 1,
        identity: {
            signingPublicKey: encode(wallet.identity.signingPublicKey.toBytes()),
            nullifierPublicKey: encode(wallet.identity.nullifierPublicKey),
            viewingPublicKey: encode(wallet.identity.viewingPublicKey.toBytes()),
        },
        assets: wallet.registry
            .entries()
            .filter(([assetId]) => assetId !== SOL_ASSET_ID)
            .map(([assetId, mint]) => Object.freeze({ assetId: assetId.toString(), mint })),
        viewingKeyHistory: state.viewingKeyHistory.map(serializeViewingKeyEntry),
        utxos: state.utxos.map(serializeUtxo),
        transactions: state.transactions.map(serializeTransaction),
        nullifiers: [...state.nullifiers].sort().map((value) => encode(unhex(value))),
        lastSynced: wallet.lastSynced.toString(),
    };
    return JSON.stringify(snapshot);
}
export function deserializeWallet(serialized) {
    try {
        if (typeof serialized !== "string")
            fail("serialized");
        return hydrate(JSON.parse(serialized));
    }
    catch (cause) {
        if (cause instanceof TransactionError)
            throw cause;
        throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "wallet" }, cause);
    }
}
function hydrate(value) {
    const snapshot = record(value, "wallet");
    if (snapshot["version"] !== 1)
        fail("version");
    const identityValue = record(snapshot["identity"], "identity");
    const identity = ShieldedAddress.fromPublicKeys(ShieldedPublicKey.fromBytes(bytes(identityValue["signingPublicKey"], 34, "identity.signingPublicKey")), bytes(identityValue["nullifierPublicKey"], 32, "identity.nullifierPublicKey"), P256PublicKey.fromBytes(bytes(identityValue["viewingPublicKey"], 33, "identity.viewingPublicKey")));
    const registry = new AssetRegistry(array(snapshot["assets"], "assets").map((entry, index) => {
        const item = record(entry, `assets[${String(index)}]`);
        return [
            unsigned(item["assetId"], `assets[${String(index)}].assetId`),
            address(item["mint"], `assets[${String(index)}].mint`),
        ];
    }));
    const viewingKeyHistory = array(snapshot["viewingKeyHistory"], "viewingKeyHistory").map(deserializeViewingKeyEntry);
    if (!viewingKeyHistory.some((entry) => encode(entry.viewingPublicKey.toBytes()) === encode(identity.viewingPublicKey.toBytes()))) {
        fail("viewingKeyHistory");
    }
    const decodedUtxos = array(snapshot["utxos"], "utxos").map(deserializeUtxo);
    const expectedOwner = encode(identity.signingPublicKey.toBytes());
    if (decodedUtxos.some((entry) => encode(entry.utxo.owner.toBytes()) !== expectedOwner)) {
        fail("utxos.owner");
    }
    const transactions = array(snapshot["transactions"], "transactions").map(deserializeTransaction);
    const nullifiers = new Set(array(snapshot["nullifiers"], "nullifiers").map((value, index) => hex(bytes(value, 32, `nullifiers[${String(index)}]`))));
    const utxos = decodedUtxos.map((entry) => entry.spent || !nullifiers.has(hex(entry.nullifier))
        ? entry
        : Object.freeze({ ...entry, spent: true }));
    const wallet = new Wallet({ identity, registry });
    wallet._replace({
        utxos,
        transactions,
        nullifiers,
        viewingKeyHistory,
        lastSynced: signed(snapshot["lastSynced"], "lastSynced"),
    });
    return wallet;
}
function serializeViewingKeyEntry(value) {
    return {
        viewingPublicKey: encode(value.viewingPublicKey.toBytes()),
        createdAt: value.createdAt.toString(),
    };
}
function deserializeViewingKeyEntry(value, index) {
    const path = `viewingKeyHistory[${String(index)}]`;
    const entry = record(value, path);
    if (Object.keys(entry).some((key) => key !== "viewingPublicKey" && key !== "createdAt")) {
        fail(path);
    }
    return {
        viewingPublicKey: P256PublicKey.fromBytes(bytes(entry["viewingPublicKey"], 33, `${path}.viewingPublicKey`)),
        createdAt: signed(entry["createdAt"], `${path}.createdAt`),
    };
}
function serializeUtxo(value) {
    return {
        owner: encode(value.utxo.owner.toBytes()),
        asset: value.utxo.asset,
        amount: value.utxo.amount.toString(),
        blinding: encode(value.utxo.blinding),
        data: value.utxo.data.records().map((record) => ({
            kind: record.kind,
            bytes: encode(record.bytes),
        })),
        ...(value.utxo.zoneProgramId === undefined ? {} : { zoneProgramId: value.utxo.zoneProgramId }),
        outputContext: {
            hash: encode(value.outputContext.hash),
            tree: value.outputContext.tree,
            leafIndex: value.outputContext.leafIndex.toString(),
        },
        nullifier: encode(value.nullifier),
        ...(value.dataHash === undefined ? {} : { dataHash: encode(value.dataHash) }),
        ...(value.zoneDataHash === undefined ? {} : { zoneDataHash: encode(value.zoneDataHash) }),
        spent: value.spent,
    };
}
function deserializeUtxo(value, index) {
    const path = `utxos[${String(index)}]`;
    const entry = record(value, path);
    const context = record(entry["outputContext"], `${path}.outputContext`);
    const records = array(entry["data"], `${path}.data`).map((value, recordIndex) => {
        const recordPath = `${path}.data[${String(recordIndex)}]`;
        const item = record(value, recordPath);
        const kind = item["kind"];
        if (kind !== "zoneData" && kind !== "utxoData" && kind !== "memo") {
            fail(`${recordPath}.kind`);
        }
        return {
            kind,
            bytes: bytes(item["bytes"], undefined, `${recordPath}.bytes`),
        };
    });
    return {
        utxo: new Utxo({
            owner: ShieldedPublicKey.fromBytes(bytes(entry["owner"], 34, `${path}.owner`)),
            asset: address(entry["asset"], `${path}.asset`),
            amount: unsigned(entry["amount"], `${path}.amount`),
            blinding: bytes(entry["blinding"], 32, `${path}.blinding`),
            data: new Data(records),
            ...(entry["zoneProgramId"] === undefined
                ? {}
                : { zoneProgramId: address(entry["zoneProgramId"], `${path}.zoneProgramId`) }),
        }),
        outputContext: {
            hash: bytes(context["hash"], 32, `${path}.outputContext.hash`),
            tree: address(context["tree"], `${path}.outputContext.tree`),
            leafIndex: unsigned(context["leafIndex"], `${path}.outputContext.leafIndex`),
        },
        nullifier: bytes(entry["nullifier"], 32, `${path}.nullifier`),
        ...(entry["dataHash"] === undefined
            ? {}
            : { dataHash: bytes(entry["dataHash"], 32, `${path}.dataHash`) }),
        ...(entry["zoneDataHash"] === undefined
            ? {}
            : { zoneDataHash: bytes(entry["zoneDataHash"], 32, `${path}.zoneDataHash`) }),
        spent: boolean(entry["spent"], `${path}.spent`),
    };
}
function serializeTransaction(value) {
    return {
        id: {
            signature: value.id.signature,
            slot: value.id.slot.toString(),
            index: value.id.index.toString(),
        },
        kind: value.kind,
        direction: value.direction,
        status: value.status,
        asset: value.asset,
        amount: value.amount.toString(),
        ...(value.counterpartyViewingPublicKey === undefined
            ? {}
            : { counterpartyViewingPublicKey: encode(value.counterpartyViewingPublicKey.toBytes()) }),
    };
}
function deserializeTransaction(value, index) {
    const path = `transactions[${String(index)}]`;
    const item = record(value, path);
    const id = record(item["id"], `${path}.id`);
    const kind = item["kind"];
    if (kind !== "deposit" &&
        kind !== "privateTransfer" &&
        kind !== "publicWithdrawal" &&
        kind !== "split" &&
        kind !== "merge") {
        fail(`${path}.kind`);
    }
    const direction = item["direction"];
    if (direction !== "inbound" && direction !== "outbound" && direction !== "selfTransfer") {
        fail(`${path}.direction`);
    }
    if (item["status"] !== "confirmed")
        fail(`${path}.status`);
    return {
        id: {
            signature: signature(id["signature"], `${path}.id.signature`),
            slot: unsigned(id["slot"], `${path}.id.slot`),
            index: unsigned(id["index"], `${path}.id.index`),
        },
        kind,
        direction,
        status: "confirmed",
        asset: address(item["asset"], `${path}.asset`),
        amount: unsigned(item["amount"], `${path}.amount`),
        ...(item["counterpartyViewingPublicKey"] === undefined
            ? {}
            : {
                counterpartyViewingPublicKey: P256PublicKey.fromBytes(bytes(item["counterpartyViewingPublicKey"], 33, `${path}.counterpartyViewingPublicKey`)),
            }),
    };
}
function encode(value) {
    return encodeBase64.decode(value);
}
function unhex(value) {
    if (!/^[0-9a-f]{64}$/.test(value))
        fail("nullifiers");
    return Uint8Array.from({ length: 32 }, (_, index) => Number.parseInt(value.slice(index * 2, index * 2 + 2), 16));
}
function bytes(value, length, field) {
    if (typeof value !== "string")
        fail(field);
    try {
        const decoded = new Uint8Array(decodeBase64.encode(value));
        if (encode(decoded) !== value || (length !== undefined && decoded.length !== length)) {
            fail(field);
        }
        return decoded;
    }
    catch (cause) {
        if (cause instanceof TransactionError)
            throw cause;
        fail(field);
    }
}
function unsigned(value, field) {
    const parsed = decimal(value, field);
    if (parsed < 0n || parsed > U64_MAX)
        fail(field);
    return parsed;
}
function signed(value, field) {
    const parsed = decimal(value, field);
    if (parsed < I64_MIN || parsed > I64_MAX)
        fail(field);
    return parsed;
}
function decimal(value, field) {
    if (typeof value !== "string" || !/^(?:0|-?[1-9][0-9]*)$/.test(value))
        fail(field);
    try {
        return BigInt(value);
    }
    catch {
        fail(field);
    }
}
function address(value, field) {
    if (typeof value !== "string")
        fail(field);
    try {
        return kitAddress(value);
    }
    catch {
        fail(field);
    }
}
function signature(value, field) {
    if (typeof value !== "string")
        fail(field);
    try {
        assertIsSignature(value);
        return value;
    }
    catch {
        fail(field);
    }
}
function boolean(value, field) {
    if (typeof value !== "boolean")
        fail(field);
    return value;
}
function array(value, field) {
    if (!Array.isArray(value))
        fail(field);
    return value;
}
function record(value, field) {
    if (typeof value !== "object" || value === null || Array.isArray(value))
        fail(field);
    return value;
}
function fail(field) {
    throw new TransactionError("TRANSACTION_DESERIALIZE", { field });
}
