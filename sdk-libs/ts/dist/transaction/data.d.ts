export type DataRecord = Readonly<{
    kind: "zoneData";
    bytes: Uint8Array;
}> | Readonly<{
    kind: "utxoData";
    bytes: Uint8Array;
}> | Readonly<{
    kind: "memo";
    bytes: Uint8Array;
}>;
export declare class Data {
    #private;
    constructor(records?: readonly DataRecord[]);
    validate(): void;
    records(): readonly DataRecord[];
    zoneData(): Uint8Array | undefined;
    utxoData(): Uint8Array | undefined;
    memo(): Uint8Array | undefined;
    isEmpty(): boolean;
}
