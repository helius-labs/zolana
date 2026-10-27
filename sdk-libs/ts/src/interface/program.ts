import { address } from "@solana/kit";

import { encodeBase58 } from "./internal.js";
import {
  NULLIFIER_TREE_HEIGHT,
  NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE,
  NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
} from "./state.js";
import type { Bytes32, TreeFeeSchedule } from "./types.js";

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

export const SHIELDED_POOL_PROGRAM_ID = address("ring1GaLCuJnkUMVkX2JeZLTTX17wKsV4fZmPVzXANW");
export const USER_REGISTRY_PROGRAM_ID = address("regy3WAeRXMYuMYxr5iK3Bf9Arr3PcxGxyzAddbiqDQ");
export const SOL_INTERFACE = encodeBase58(
  Uint8Array.from([
    174, 9, 251, 185, 56, 68, 80, 105, 187, 159, 161, 65, 25, 120, 15, 51, 227, 171, 191, 213, 18,
    39, 39, 20, 57, 237, 147, 228, 185, 57, 125, 253,
  ]),
);
export const SHIELDED_POOL_CPI_AUTHORITY = encodeBase58(
  Uint8Array.from([
    171, 251, 122, 72, 2, 39, 82, 91, 136, 185, 82, 1, 239, 236, 213, 162, 38, 77, 248, 238, 242,
    103, 137, 104, 67, 64, 244, 78, 118, 136, 230, 59,
  ]),
);
export const SPL_TOKEN_PROGRAM_ID = address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const SPL_TOKEN_2022_PROGRAM_ID = address("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
export const ASSOCIATED_TOKEN_PROGRAM_ID = address("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
export const DUMMY_DOMAIN = 1 as const;
export const ADDRESS_DOMAIN = 2 as const;
export const UTXO_DOMAIN = 3 as const;

/**
 * @internal Mirrors Rust `ZERO_NULLIFIER_PUBKEY`, `Poseidon(0)`: the nullifier
 * public key of the zero secret, which address inputs and ring namespace
 * entries commit to.
 */
export const ZERO_NULLIFIER_PK = Uint8Array.from([
  0x2a, 0x09, 0xa9, 0xfd, 0x93, 0xc5, 0x90, 0xc2, 0x6b, 0x91, 0xef, 0xfb, 0xb2, 0x49, 0x9f, 0x07,
  0xe8, 0xf7, 0xaa, 0x12, 0xe2, 0xb4, 0x94, 0x0a, 0x3a, 0xed, 0x24, 0x11, 0xcb, 0x65, 0xe1, 0x1c,
]) as Bytes32;

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
  createCache: 22,
  closeCache: 23,
} as const);
export type InstructionTag = (typeof InstructionTag)[keyof typeof InstructionTag];

export function nullifierTreeParams(): NullifierTreeParams {
  return Object.freeze({
    inputQueueBatchSize: NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE,
    inputQueueZkpBatchSize: NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
    height: NULLIFIER_TREE_HEIGHT,
  });
}
