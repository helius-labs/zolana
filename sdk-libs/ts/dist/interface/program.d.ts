export interface AddressTreeParams {
    readonly inputQueueBatchSize: bigint;
    readonly inputQueueZkpBatchSize: bigint;
    readonly rootHistoryCapacity: number;
    readonly height: number;
}
export declare const SHIELDED_POOL_PROGRAM_ID: import("@solana/kit").Address<"sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA">;
export declare const USER_REGISTRY_PROGRAM_ID: import("@solana/kit").Address<"EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc">;
export declare const DEFAULT_TREE_ADDRESS: import("@solana/kit").Address<"treeYbr45LjxovKvtD46uEphM64kwoFFPYhVNw1A8x8">;
export declare const SOL_INTERFACE: import("@solana/kit").Address;
export declare const SHIELDED_POOL_CPI_AUTHORITY: import("@solana/kit").Address;
export declare const SPL_TOKEN_PROGRAM_ID: import("@solana/kit").Address<"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA">;
export declare const SPL_TOKEN_2022_PROGRAM_ID: import("@solana/kit").Address<"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb">;
export declare const ASSOCIATED_TOKEN_PROGRAM_ID: import("@solana/kit").Address<"ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL">;
export declare const DUMMY_DOMAIN: 1;
export declare const UTXO_DOMAIN: 3;
export declare const InstructionTag: Readonly<{
    readonly createProtocolConfig: 0;
    readonly updateProtocolConfig: 1;
    readonly createTree: 2;
    readonly pauseTree: 3;
    readonly batchUpdateNullifierTree: 4;
    readonly createAssetCounter: 5;
    readonly createSplInterface: 6;
    readonly createRingConfig: 7;
    readonly updateRingConfig: 8;
    readonly updateRingConfigOwner: 9;
    readonly emitEvent: 10;
    readonly deposit: 11;
    readonly transact: 12;
    readonly mergeTransact: 13;
    readonly ringDeposit: 14;
    readonly ringTransact: 15;
    readonly ringMergeTransact: 16;
    readonly ringAuthorityTransact: 17;
}>;
export type InstructionTag = (typeof InstructionTag)[keyof typeof InstructionTag];
export declare function addressTreeParams(): AddressTreeParams;
