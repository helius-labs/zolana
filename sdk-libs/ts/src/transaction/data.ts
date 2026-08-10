import { TransactionError } from "./error.js";

export type DataRecord =
  | Readonly<{ kind: "ringData"; bytes: Uint8Array }>
  | Readonly<{ kind: "utxoData"; bytes: Uint8Array }>
  | Readonly<{ kind: "memo"; bytes: Uint8Array }>;

const ORDER: Readonly<Record<DataRecord["kind"], number>> = {
  ringData: 1,
  utxoData: 2,
  memo: 3,
};

function copyRecord(record: DataRecord): DataRecord {
  return Object.freeze({ kind: record.kind, bytes: new Uint8Array(record.bytes) });
}

export class Data {
  readonly #records: readonly DataRecord[];

  constructor(records: readonly DataRecord[] = []) {
    if (!Array.isArray(records)) {
      throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "records" });
    }
    this.#records = Object.freeze(
      records.map((record, index) => copyRecord(checkedRecord(record, index))),
    );
    this.validate();
  }

  validate(): void {
    let previous = 0;
    const seen = new Set<DataRecord["kind"]>();
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

  records(): readonly DataRecord[] {
    return this.#records.map(copyRecord);
  }

  ringData(): Uint8Array | undefined {
    return this.#get("ringData");
  }

  utxoData(): Uint8Array | undefined {
    return this.#get("utxoData");
  }

  memo(): Uint8Array | undefined {
    return this.#get("memo");
  }

  isEmpty(): boolean {
    return this.#records.length === 0;
  }

  #get(kind: DataRecord["kind"]): Uint8Array | undefined {
    const record = this.#records.find((candidate) => candidate.kind === kind);
    return record ? new Uint8Array(record.bytes) : undefined;
  }
}

function checkedRecord(value: unknown, index: number): DataRecord {
  if (typeof value !== "object" || value === null) {
    throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "record", index });
  }
  const record = value as Readonly<{ kind?: unknown; bytes?: unknown }>;
  if (record.kind !== "ringData" && record.kind !== "utxoData" && record.kind !== "memo") {
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
  return record as DataRecord;
}
