export const StateDiscriminator = Object.freeze({
  treeAccount: 1,
  protocolConfig: 3,
  zoneConfig: 4,
  splAssetRegistry: 5,
  splAssetCounter: 6,
} as const);

export const FIRST_ASSET_ID = 2n;
export const STATE_HEIGHT = 32;
export const ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE = 30_000n;
export const ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE = 250n;
export const ADDRESS_TREE_HEIGHT = 40;
export const ADDRESS_TREE_ROOT_HISTORY_CAPACITY = 120;
export const TREE_ACCOUNT_SIZE = 1_186_136;
export const STATE_ROOT_OFFSET = 16;
