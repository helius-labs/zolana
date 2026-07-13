import { writeU16Le } from "./bytes.js";

export type DataRecord =
  | { kind: "zoneData"; data: Uint8Array }
  | { kind: "utxoData"; data: Uint8Array }
  | { kind: "memo"; data: Uint8Array };

export class Data {
  readonly records: DataRecord[];

  constructor(records: DataRecord[] = []) {
    this.records = records.map((record) => ({ kind: record.kind, data: new Uint8Array(record.data) }));
    this.validate();
  }

  static empty(): Data {
    return new Data();
  }

  isEmpty(): boolean {
    return this.records.length === 0;
  }

  validate(): void {
    let lastOrder = 0;
    const seen = new Set<string>();
    for (const record of this.records) {
      const order = dataRecordOrder(record);
      if (seen.has(record.kind)) throw new Error("duplicate data record");
      if (order < lastOrder) throw new Error("non-canonical data record order");
      seen.add(record.kind);
      lastOrder = order;
    }
  }

  zoneData(): Uint8Array | undefined {
    return this.records.find((record) => record.kind === "zoneData")?.data;
  }

  utxoData(): Uint8Array | undefined {
    return this.records.find((record) => record.kind === "utxoData")?.data;
  }

  memo(): Uint8Array | undefined {
    return this.records.find((record) => record.kind === "memo")?.data;
  }

  withRecord(record: DataRecord): Data {
    const order = dataRecordOrder(record);
    const records = this.records.filter((existing) => dataRecordOrder(existing) !== order);
    records.push({ kind: record.kind, data: new Uint8Array(record.data) });
    records.sort((a, b) => dataRecordOrder(a) - dataRecordOrder(b));
    return new Data(records);
  }

  serialize(): Uint8Array {
    if (this.records.length > 0xff) throw new Error("too many data records");
    const out: number[] = [this.records.length];
    for (const record of this.records) {
      out.push(dataRecordOrder(record));
      writeU16Le(out, record.data.length);
      out.push(...record.data);
    }
    return new Uint8Array(out);
  }
}

function dataRecordOrder(record: DataRecord): number {
  switch (record.kind) {
    case "zoneData":
      return 1;
    case "utxoData":
      return 2;
    case "memo":
      return 3;
  }
}
