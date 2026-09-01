export { initializePoseidon, isPoseidonInitialized } from "../hasher/index.js";
export { WALLET_ERROR_CODES, WalletError, type WalletErrorCode } from "./error.js";
export {
  ClientEd25519WalletAuthority,
  ClientNullifierWalletAuthority,
  KeypairWalletAuthority,
  type AnonymousRecipientSlot,
  type ApprovalRequest,
  type AuditWitness,
  type EncryptedCustomRingTransfer,
  type EncryptedEnvelope,
  type EncryptedSplit,
  type EncryptedTransfer,
  type PrivateTransactionAuthority,
  type SyncWalletAuthority,
  type TransactionViewingSecretProvider,
  type WalletAuthority,
  type WalletSyncMaterial,
} from "../transaction/wallet/authority.js";
export type { SpendableUtxoOpening } from "../transaction/wallet/state.js";
export { buildDepositTransaction, type DepositTransactionParams } from "./deposit.js";
export { fetchTransactionSlots, type TransactionSlots } from "./transaction-slots.js";
export {
  buildSplitTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
  type PrivateTransactionParams,
  type SplitTransactionParams,
  type TransferDestination,
  type TransferTransactionParams,
  type WithdrawalTransactionParams,
} from "./transactions.js";
export { buildMergeTransaction, type MergeTransactionParams } from "./merge.js";
export {
  backfillAssetRegistry,
  getPrivateTokenBalances,
  getPrivateTransactions,
  syncWallet,
  type SyncWalletConfig,
} from "./sync.js";
export {
  buildRegistrationTransaction,
  buildSetMergingEnabledTransaction,
  decodeUserRecordAccount,
  fetchUserRecord,
  fetchUserRecordChecked,
  fetchViewingKeyOwners,
  isWalletRegistered,
  recipientConfidentialViewTag,
  resolveRegisteredAddress,
  resolvedAddressFromRecord,
  validateRegisteredKeypair,
  viewingKeyIndex,
  type ResolvedAddress,
  type UserRecord,
} from "./registry.js";
