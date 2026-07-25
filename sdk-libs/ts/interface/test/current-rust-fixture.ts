import type { Address, AddressTreeParams } from "../src/index.js";

export const CURRENT_RUST_INTERFACE_FIXTURE = Object.freeze({
  sourceCommit: "484ac5ed",
  sources: Object.freeze([
    "program-libs/interface/src/merge_utils.rs",
    "program-libs/interface/src/instruction/instruction_data/batch_update_nullifier_tree.rs",
    "program-libs/interface/src/instruction/instruction_data/merge_transact.rs",
    "program-libs/interface/src/instruction/builders/create_tree.rs",
    "program-libs/interface/src/state/discriminator.rs",
    "program-libs/interface/src/state/tree.rs",
  ]),
  ciphertextHashes: Object.freeze([
    Object.freeze({
      length: 1,
      hash: "2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c",
    }),
    Object.freeze({
      length: 15,
      hash: "2707075abaeed4475e86fc868690814e50dd764385db52b6373a3a6eeff9f0fb",
    }),
    Object.freeze({
      length: 16,
      hash: "230a4f2930567a68491a39fa84933b00991989bf68a5fd58b85d823d7169b7a7",
    }),
    Object.freeze({
      length: 17,
      hash: "1176d3feb89bdd89fdbe19aacd1e8e4ad8fae63dfce390829d7b15282a8960bb",
    }),
    Object.freeze({
      length: 191,
      hash: "0eee0edbf9501a52997fe7c8d27fb6038bea14814248db89b3da909f087dde89",
    }),
    Object.freeze({
      length: 192,
      hash: "124ffdcec1053549916312dbbc0229a7491737092e5a7d0da8be17c8376b340a",
    }),
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
