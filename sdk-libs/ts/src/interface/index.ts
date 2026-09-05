export { initializePoseidon, isPoseidonInitialized } from "../hasher/index.js";

export {
  decodeProtocolConfig,
  decodeSplAssetCounter,
  decodeSplAssetRegistry,
  decodeRingConfig,
} from "./accounts.js";
export { decodeTreeFeeSchedule, decodeTreeFees, encodeTreeFeeSchedule } from "./codecs/index.js";
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
export {
  depositInstruction,
  nullifierPdaAccounts,
  ringDepositInstruction,
  ringTransactAccounts,
  transactInstruction,
} from "./instructions/index.js";
export { DepositAsset, TransactWithdrawal } from "./types.js";
export {
  ciphertextHash,
  ownerPkFieldCompressed,
  pack33,
  pkFieldCompressed,
} from "./merge-utils.js";
export {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  DUMMY_DOMAIN,
  InstructionTag,
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SPL_TOKEN_2022_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
  USER_REGISTRY_PROGRAM_ID,
  UTXO_DOMAIN,
  nullifierTreeParams,
} from "./program.js";
export type { CreateTreeData, NullifierTreeParams } from "./program.js";
export { SPP_SUPPORTED_SHAPES, selectSppShape, validateSppShape } from "./shape.js";
export type { Shape } from "./shape.js";
export {
  DEFAULT_APPEND_REIMBURSEMENT_LAMPORTS,
  DEFAULT_CLOSE_REIMBURSEMENT_LAMPORTS,
  FIRST_ASSET_ID,
  NULLIFIER_TREE_HEIGHT,
  NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE,
  NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
  NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
  PROTOCOL_CONFIG_SIZE,
  STATE_HEIGHT,
  STATE_ROOT_HISTORY_CAPACITY,
  STATE_ROOT_OFFSET,
  StateDiscriminator,
  TREE_ACCOUNT_SIZE,
  TREE_ALLOCATION_STEP,
  TREE_CREATION_STEP_COUNT,
  TREE_FEES_OFFSET,
  TREE_FEE_BALANCE_OFFSET,
  defaultTreeFees,
} from "./state.js";
export {
  TRANSACTION_SIZE_LIMIT,
  checkedTransactionSize,
  transactionSize,
} from "./transaction-size.js";
export type * from "./types.js";
export type { ErrorEnvelope } from "../errors/internal.js";
