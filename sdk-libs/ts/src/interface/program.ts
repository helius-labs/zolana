import { address } from "@solana/kit";

import { encodeBase58 } from "./internal.js";
import {
  NULLIFIER_TREE_HEIGHT,
  NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE,
  NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
} from "./state.js";
import type { TreeFeeSchedule } from "./types.js";

export interface NullifierTreeParams {
  readonly inputQueueBatchSize: bigint;
  readonly inputQueueZkpBatchSize: bigint;
  readonly height: number;
}

export interface CreateTreeData {
  readonly treeId: number;
  readonly nullifierParams: NullifierTreeParams;
  readonly fees: TreeFeeSchedule;
}

export const SHIELDED_POOL_PROGRAM_ID = address("sppU489D7A4U1exNo1oeMGZtLEofq3a6o2fR7UeoWB6");
export const USER_REGISTRY_PROGRAM_ID = address("regyS5rkAcw2YzDJCmTwCTHs2s246FXxbmuRZ42u2PD");
export const SOL_INTERFACE = encodeBase58(
  Uint8Array.from([
    25, 103, 86, 200, 133, 185, 152, 90, 206, 95, 120, 116, 156, 29, 95, 209, 115, 140, 160, 250,
    226, 120, 50, 30, 39, 35, 88, 131, 164, 254, 252, 146,
  ]),
);
export const SHIELDED_POOL_CPI_AUTHORITY = encodeBase58(
  Uint8Array.from([
    69, 71, 220, 185, 216, 143, 158, 144, 194, 192, 35, 58, 192, 36, 234, 87, 129, 254, 240, 115,
    136, 34, 89, 207, 13, 241, 99, 80, 189, 28, 84, 235,
  ]),
);
export const SPL_TOKEN_PROGRAM_ID = address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const SPL_TOKEN_2022_PROGRAM_ID = address("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
export const ASSOCIATED_TOKEN_PROGRAM_ID = address("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
export const DUMMY_DOMAIN = 1 as const;
export const ADDRESS_DOMAIN = 2 as const;
export const UTXO_DOMAIN = 3 as const;

export const InstructionTag = Object.freeze({
  createProtocolConfig: 0,
  updateProtocolConfig: 1,
  createTree: 2,
  pauseTree: 3,
  setTreeFees: 4,
  claimTreeLamports: 5,
  createAssetCounter: 6,
  createSplInterface: 7,
  createRingConfig: 8,
  updateRingConfig: 9,
  updateRingConfigOwner: 10,
  setRingActivation: 11,
  batchUpdateNullifierTree: 12,
  closeNullifierPdas: 13,
  emitEvent: 14,
  deposit: 15,
  transact: 16,
  mergeTransact: 17,
  ringDeposit: 18,
  ringTransact: 19,
  ringMergeTransact: 20,
  ringAuthorityTransact: 21,
} as const);
export type InstructionTag = (typeof InstructionTag)[keyof typeof InstructionTag];

export function nullifierTreeParams(): NullifierTreeParams {
  return Object.freeze({
    inputQueueBatchSize: NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE,
    inputQueueZkpBatchSize: NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
    height: NULLIFIER_TREE_HEIGHT,
  });
}
