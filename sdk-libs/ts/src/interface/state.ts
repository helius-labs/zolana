import { unsignedBigint } from "./internal.js";
import type { TreeFeeSchedule } from "./types.js";

export const StateDiscriminator = Object.freeze({
  treeAccount: 1,
  protocolConfig: 3,
  ringConfig: 4,
  splAssetRegistry: 5,
  splAssetCounter: 6,
} as const);

export const FIRST_ASSET_ID = 2n;
export const STATE_HEIGHT = 32;
/** Final roots for the latest 500 slots that actually updated the state tree. */
export const STATE_ROOT_HISTORY_CAPACITY = 500;
export const NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE = 25_000n;
export const NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE = 250n;
export const NULLIFIER_TREE_HEIGHT = 40;
export const NULLIFIER_TREE_ROOT_HISTORY_CAPACITY = Number(
  NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE / NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
);
export const DEFAULT_APPEND_REIMBURSEMENT_LAMPORTS = 5_000n;
export const DEFAULT_CLOSE_REIMBURSEMENT_LAMPORTS = 170n;

const U64_MAX = (1n << 64n) - 1n;

/// Fee schedule whose per-nullifier fee exactly covers the default append and
/// close reimbursements per ZKP batch, rounded up. Mirrors Rust
/// `default_tree_fees`: a zero batch size yields the all-zero schedule.
export function defaultTreeFees(zkpBatchSize: bigint): TreeFeeSchedule {
  const batchSize = unsignedBigint(zkpBatchSize, U64_MAX, "zkpBatchSize");
  if (batchSize === 0n) {
    return Object.freeze({
      feePerNullifier: 0n,
      appendReimbursement: 0n,
      closeReimbursement: 0n,
    });
  }
  const perBatch =
    batchSize * DEFAULT_CLOSE_REIMBURSEMENT_LAMPORTS + DEFAULT_APPEND_REIMBURSEMENT_LAMPORTS;
  const remainder = perBatch % batchSize === 0n ? 0n : 1n;
  return Object.freeze({
    feePerNullifier: perBatch / batchSize + remainder,
    appendReimbursement: DEFAULT_APPEND_REIMBURSEMENT_LAMPORTS,
    closeReimbursement: DEFAULT_CLOSE_REIMBURSEMENT_LAMPORTS,
  });
}

export const PROTOCOL_CONFIG_SIZE = 166;
export const TREE_ACCOUNT_SIZE = 39_952;
/// The program allocates a tree PDA in chunks of this many bytes; creation
/// repeats the create-tree instruction once per chunk within one transaction.
export const TREE_ALLOCATION_STEP = 10 * 1024;
export const TREE_CREATION_STEP_COUNT = Math.ceil(TREE_ACCOUNT_SIZE / TREE_ALLOCATION_STEP);
export const TREE_FEES_OFFSET = 8;
export const TREE_FEE_BALANCE_OFFSET = 32;
export const STATE_ROOT_OFFSET = 80;
