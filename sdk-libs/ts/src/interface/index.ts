export { initializePoseidon, isPoseidonInitialized } from "../hasher/index.js";

export {
  decodeProtocolConfig,
  decodeSplAssetCounter,
  decodeSplAssetRegistry,
  decodeZoneConfig,
} from "./accounts.js";
export { MERGE_INPUT_COUNT } from "./constants.js";
export { InterfaceError, ShieldedPoolError, decodeShieldedPoolError } from "./errors.js";
export type {
  DecodedShieldedPoolError,
  InterfaceErrorCode,
  ShieldedPoolErrorCode,
  ShieldedPoolErrorName,
} from "./errors.js";
export { externalDataHash } from "./external-data-hash.js";
export type { ExternalDataHashInput } from "./external-data-hash.js";
export { depositInstruction, transactInstruction } from "./instructions/index.js";
export {
  ciphertextHash,
  ownerPkFieldCompressed,
  pack33,
  pkFieldCompressed,
} from "./merge-utils.js";
export {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  DEFAULT_TREE_ADDRESS,
  DUMMY_DOMAIN,
  InstructionTag,
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SPL_TOKEN_2022_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
  USER_REGISTRY_PROGRAM_ID,
  UTXO_DOMAIN,
  addressTreeParams,
} from "./program.js";
export type { AddressTreeParams } from "./program.js";
export { SPP_SUPPORTED_SHAPES, selectSppShape, validateSppShape } from "./shape.js";
export type { Shape } from "./shape.js";
export {
  ADDRESS_TREE_HEIGHT,
  ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
  ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
  ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
  FIRST_ASSET_ID,
  FORESTER_REIMBURSEMENT_LAMPORTS,
  STATE_HEIGHT,
  STATE_ROOT_OFFSET,
  StateDiscriminator,
  TREE_ACCOUNT_SIZE,
  foresterFeePerQueueElement,
} from "./state.js";
export {
  TRANSACTION_SIZE_LIMIT,
  checkedTransactionSize,
  transactionSize,
} from "./transaction-size.js";
export type * from "./types.js";
