import { address } from "@solana/kit";

import { encodeBase58 } from "./internal.js";
import {
  ADDRESS_TREE_HEIGHT,
  ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
  ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
  ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
} from "./state.js";

export interface AddressTreeParams {
  readonly inputQueueBatchSize: bigint;
  readonly inputQueueZkpBatchSize: bigint;
  readonly rootHistoryCapacity: number;
  readonly height: number;
}

export const SHIELDED_POOL_PROGRAM_ID = address("sppXZU59VoYodv9Accs4hHNTjYiuYmDFyFVjUjPxFsG");
export const USER_REGISTRY_PROGRAM_ID = address("regyS5rkAcw2YzDJCmTwCTHs2s246FXxbmuRZ42u2PD");
export const DEFAULT_TREE_ADDRESS = address("trEEbaNobcTESNmtsPBj3FX27q5sDCQePV2kb12FYho");
export const SOL_INTERFACE = encodeBase58(
  Uint8Array.from([
    226, 231, 179, 96, 7, 216, 134, 74, 16, 116, 193, 73, 186, 110, 210, 48, 2, 97, 154, 130, 121,
    53, 28, 232, 140, 221, 183, 236, 109, 212, 72, 117,
  ]),
);
export const SHIELDED_POOL_CPI_AUTHORITY = encodeBase58(
  Uint8Array.from([
    109, 182, 246, 114, 43, 36, 173, 152, 203, 138, 114, 231, 209, 50, 184, 236, 107, 139, 188, 29,
    115, 163, 218, 113, 6, 134, 33, 44, 204, 50, 186, 87,
  ]),
);
export const SPL_TOKEN_PROGRAM_ID = address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const SPL_TOKEN_2022_PROGRAM_ID = address("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
export const ASSOCIATED_TOKEN_PROGRAM_ID = address("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
export const DUMMY_DOMAIN = 1 as const;
export const UTXO_DOMAIN = 3 as const;

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
  closeNullifierMarkers: 18,
} as const);
export type InstructionTag = (typeof InstructionTag)[keyof typeof InstructionTag];

export function addressTreeParams(): AddressTreeParams {
  return Object.freeze({
    inputQueueBatchSize: ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
    inputQueueZkpBatchSize: ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
    rootHistoryCapacity: ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
    height: ADDRESS_TREE_HEIGHT,
  });
}
