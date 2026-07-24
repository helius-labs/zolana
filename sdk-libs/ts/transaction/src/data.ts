import { TransactionError } from "./error.js";

export type DataRecord =
  | Readonly<{ kind: "zoneData"; bytes: Uint8Array }>
  | Readonly<{ kind: "utxoData"; bytes: Uint8Array }>
  | Readonly<{ kind: "memo"; bytes: Uint8Array }>;

const ORDER: Readonly<Record<DataRecord["kind"], number>> = {
  zoneData: 1,
  utxoData: 2,
  memo: 3,
};

function copyRecord(record: DataRecord): DataRecord {
  return Object.freeze({ kind: record.kind, bytes: new Uint8Array(record.bytes) });
}

export class Data {
  readonly #records: readonly DataRecord[];

  constructor(records: readonly DataRecord[] = []) {
    this.#records = Object.freeze(records.map(copyRecord));
    this.validate();
  }

  validate(): void {
    let previous = 0;
    const seen = new Set<DataRecord["kind"]>();
    for (const record of this.#records) {
      if (!(record.bytes instanceof Uint8Array) || record.bytes.length > 0xffff) {
        throw new TransactionError("TRANSACTION_INVALID_DATA_LENGTH", {
          kind: record.kind,
          maximum: 0xffff,
          actual: record.bytes instanceof Uint8Array ? record.bytes.length : -1,
        });
      }
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

  zoneData(): Uint8Array | undefined {
    return this.#get("zoneData");
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
