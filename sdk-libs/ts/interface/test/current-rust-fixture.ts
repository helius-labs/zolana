import type { Address, AddressTreeParams } from "../src/index.js";

export const CURRENT_RUST_INTERFACE_FIXTURE = Object.freeze({
  sourceCommit: "4a60db74",
  sources: Object.freeze([
    "program-libs/interface/src/instruction/instruction_data/batch_update_nullifier_tree.rs",
    "program-libs/interface/src/instruction/builders/create_tree.rs",
    "program-libs/interface/src/state/discriminator.rs",
    "program-libs/interface/src/state/tree.rs",
  ]),
  discriminators: Object.freeze({
    treeAccount: 1,
    protocolConfig: 3,
    zoneConfig: 4,
    splAssetRegistry: 5,
    splAssetCounter: 6,
  }),
  tree: Object.freeze({
    accountSize: 1_186_136,
    stateRootOffset: 16,
    stateHeight: 32,
    addressTreeHeight: 40,
    inputQueueBatchSize: 30_000n,
    inputQueueZkpBatchSize: 250n,
    rootHistoryCapacity: 120,
  }),
  customTreeParams: Object.freeze({
    index: 0n,
    programOwner: "11111111111111111111111111111111" as Address,
    forester: "11111111111111111111111111111111" as Address,
    inputQueueBatchSize: 30_000n,
    inputQueueZkpBatchSize: 250n,
    rootHistoryCapacity: 120,
    networkFee: 1n,
    rolloverThreshold: 2n,
    closeThreshold: 3n,
    height: 40,
  } satisfies AddressTreeParams),
});
