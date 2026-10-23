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

export const SHIELDED_POOL_PROGRAM_ID = address("spp3CfN2Y7se74A27bBpnAkmjXyEb2YmmZafhFrC9xt");
export const USER_REGISTRY_PROGRAM_ID = address("regy3WAeRXMYuMYxr5iK3Bf9Arr3PcxGxyzAddbiqDQ");
export const SOL_INTERFACE = encodeBase58(
  Uint8Array.from([
    57, 234, 222, 217, 123, 228, 230, 232, 84, 166, 31, 212, 32, 61, 124, 189, 111, 192, 176, 105,
    98, 211, 150, 177, 42, 231, 139, 133, 216, 66, 188, 207,
  ]),
);
export const SHIELDED_POOL_CPI_AUTHORITY = encodeBase58(
  Uint8Array.from([
    231, 159, 118, 137, 156, 23, 134, 42, 170, 73, 246, 220, 194, 211, 204, 77, 34, 241, 59, 125,
    158, 152, 138, 84, 162, 33, 96, 26, 58, 253, 91, 23,
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
