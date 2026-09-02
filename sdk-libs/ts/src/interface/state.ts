export const StateDiscriminator = Object.freeze({
  treeAccount: 1,
  protocolConfig: 3,
  ringConfig: 4,
  splAssetRegistry: 5,
  splAssetCounter: 6,
} as const);

export const FIRST_ASSET_ID = 2n;
export const STATE_HEIGHT = 32;
export const NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE = 30_000n;
export const NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE = 250n;
export const NULLIFIER_TREE_HEIGHT = 40;
export const NULLIFIER_TREE_ROOT_HISTORY_CAPACITY = Number(
  NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE / NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
);
/// Lamports reimbursed for each applied nullifier-tree ZKP batch.
export const FORESTER_REIMBURSEMENT_LAMPORTS = 5_000n;

/// Derive the fee charged for each element inserted into a tree's nullifier
/// queue. `undefined` mirrors the `None` Rust returns for a zero batch size.
export function foresterFeePerQueueElement(zkpBatchSize: bigint): bigint | undefined {
  return zkpBatchSize === 0n ? undefined : FORESTER_REIMBURSEMENT_LAMPORTS / zkpBatchSize;
}
export const TREE_ACCOUNT_SIZE = 34_856;
/// The program allocates a tree PDA in chunks of this many bytes; creation
/// repeats the create-tree instruction once per chunk within one transaction.
export const TREE_ALLOCATION_STEP = 10 * 1024;
export const TREE_CREATION_STEP_COUNT = Math.ceil(TREE_ACCOUNT_SIZE / TREE_ALLOCATION_STEP);
export const STATE_ROOT_OFFSET = 80;
