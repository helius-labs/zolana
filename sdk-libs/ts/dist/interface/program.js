import { address } from "@solana/kit";
import { encodeBase58 } from "./internal.js";
import { ADDRESS_TREE_HEIGHT, ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE, ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE, ADDRESS_TREE_ROOT_HISTORY_CAPACITY, } from "./state.js";
export const SHIELDED_POOL_PROGRAM_ID = address("sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA");
export const USER_REGISTRY_PROGRAM_ID = address("EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc");
export const DEFAULT_TREE_ADDRESS = address("treeYbr45LjxovKvtD46uEphM64kwoFFPYhVNw1A8x8");
export const SOL_INTERFACE = encodeBase58(Uint8Array.from([
    153, 202, 212, 28, 214, 25, 170, 103, 127, 203, 31, 129, 56, 221, 77, 131, 217, 62, 194, 23,
    222, 98, 111, 179, 160, 182, 255, 213, 208, 236, 115, 61,
]));
export const SHIELDED_POOL_CPI_AUTHORITY = encodeBase58(Uint8Array.from([
    88, 254, 248, 74, 86, 156, 76, 98, 4, 160, 29, 78, 152, 238, 8, 247, 252, 20, 54, 18, 242, 184,
    160, 99, 112, 248, 135, 246, 47, 245, 181, 43,
]));
export const SPL_TOKEN_PROGRAM_ID = address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const SPL_TOKEN_2022_PROGRAM_ID = address("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
export const ASSOCIATED_TOKEN_PROGRAM_ID = address("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
export const DUMMY_DOMAIN = 1;
export const UTXO_DOMAIN = 3;
export const InstructionTag = Object.freeze({
    createProtocolConfig: 0,
    updateProtocolConfig: 1,
    createTree: 2,
    pauseTree: 3,
    batchUpdateNullifierTree: 4,
    createAssetCounter: 5,
    createSplInterface: 6,
    createRingConfig: 7,
    updateRingConfig: 8,
    updateRingConfigOwner: 9,
    emitEvent: 10,
    deposit: 11,
    transact: 12,
    mergeTransact: 13,
    ringDeposit: 14,
    ringTransact: 15,
    ringMergeTransact: 16,
    ringAuthorityTransact: 17,
});
export function addressTreeParams() {
    return Object.freeze({
        inputQueueBatchSize: ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
        inputQueueZkpBatchSize: ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
        rootHistoryCapacity: ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
        height: ADDRESS_TREE_HEIGHT,
    });
}
