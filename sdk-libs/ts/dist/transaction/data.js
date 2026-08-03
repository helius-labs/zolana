import { TransactionError } from "./error.js";
const ORDER = {
    zoneData: 1,
    utxoData: 2,
    memo: 3,
};
function copyRecord(record) {
    return Object.freeze({ kind: record.kind, bytes: new Uint8Array(record.bytes) });
}
export class Data {
    #records;
    constructor(records = []) {
        if (!Array.isArray(records)) {
            throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "records" });
        }
        this.#records = Object.freeze(records.map((record, index) => copyRecord(checkedRecord(record, index))));
        this.validate();
    }
    validate() {
        let previous = 0;
        const seen = new Set();
        for (const record of this.#records) {
            if (seen.has(record.kind)) {
                throw new TransactionError("TRANSACTION_DUPLICATE_DATA_RECORD", { kind: record.kind });
            }
            const order = ORDER[record.kind];
            if (order < previous) {
                throw new TransactionError("TRANSACTION_NON_CANONICAL_DATA_ORDER");
            }
            seen.add(record.kind);
            previous = order;
        }
    }
    records() {
        return this.#records.map(copyRecord);
    }
    zoneData() {
        return this.#get("zoneData");
    }
    utxoData() {
        return this.#get("utxoData");
    }
    memo() {
        return this.#get("memo");
    }
    isEmpty() {
        return this.#records.length === 0;
    }
    #get(kind) {
        const record = this.#records.find((candidate) => candidate.kind === kind);
        return record ? new Uint8Array(record.bytes) : undefined;
    }
}
function checkedRecord(value, index) {
    if (typeof value !== "object" || value === null) {
        throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "record", index });
    }
    const record = value;
    if (record.kind !== "zoneData" && record.kind !== "utxoData" && record.kind !== "memo") {
        throw new TransactionError("TRANSACTION_BAD_DISCRIMINATOR", {
            field: "dataRecordKind",
            index,
            kind: String(record.kind),
        });
    }
    if (!(record.bytes instanceof Uint8Array)) {
        throw new TransactionError("TRANSACTION_DESERIALIZE", {
            field: "dataRecordBytes",
            index,
        });
    }
    return record;
}
