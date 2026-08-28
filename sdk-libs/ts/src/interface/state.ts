export const StateDiscriminator = Object.freeze({
  treeAccount: 1,
  protocolConfig: 3,
  ringConfig: 4,
  splAssetRegistry: 5,
  splAssetCounter: 6,
} as const);

export const FIRST_ASSET_ID = 2n;
export const STATE_HEIGHT = 32;
export const ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE = 30_000n;
export const ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE = 250n;
export const ADDRESS_TREE_HEIGHT = 40;
export const ADDRESS_TREE_ROOT_HISTORY_CAPACITY = Number(
  ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE / ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
);
/// Lamports reimbursed for each applied nullifier-tree ZKP batch.
export const FORESTER_REIMBURSEMENT_LAMPORTS = 5_000n;

/// Derive the fee charged for each element inserted into a tree's nullifier
/// queue. `undefined` mirrors the `None` Rust returns for a zero batch size.
export function foresterFeePerQueueElement(zkpBatchSize: bigint): bigint | undefined {
  return zkpBatchSize === 0n ? undefined : FORESTER_REIMBURSEMENT_LAMPORTS / zkpBatchSize;
}
export const TREE_ACCOUNT_SIZE = 1_185_664;
export const STATE_ROOT_OFFSET = 16;
