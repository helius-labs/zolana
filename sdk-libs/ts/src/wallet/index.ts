export { initializePoseidon, isPoseidonInitialized } from "../hasher/index.js";
export { AssetMetadataCache, fetchAssetMetadata, type AssetMetadata } from "./asset-metadata.js";
export { WALLET_ERROR_CODES, WalletError, type WalletErrorCode } from "./error.js";
export {
  LocalShieldedKeys,
  type DecryptLabel,
  type DecryptRequest,
  type DeriveRequest,
  type ShieldedKeys,
  type TransactionKeyRequest,
} from "../transaction/wallet/keys.js";
export { LocalKeys } from "../client/keys.js";
export type { ProofAuthority, ProofService, WalletKeys } from "../client/ports.js";
export type {
  AnonymousRecipientSlot,
  AuditWitness,
  EncryptedCustomRingTransfer,
  EncryptedEnvelope,
  EncryptedSplit,
  EncryptedTransfer,
} from "../transaction/wallet/encrypt-rails.js";
export {
  approveIntent,
  approveUnattended,
  intentHash,
  type ApprovalHandler,
  type ApprovalRequest,
  type IntentApproval,
  type TransactionIntent,
} from "../transaction/wallet/intent.js";
export {
  buildDepositTransaction,
  type DepositClient,
  type DepositTransactionParams,
} from "./deposit.js";
export { fetchTransactionSlots, type TransactionSlots } from "./transaction-slots.js";
export {
  buildSplitTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
  type PrivateTransactionParams,
  type SplitTransactionParams,
  type TransferDestination,
  type PrivateTransactionClient,
  type TransferTransactionParams,
  type WithdrawalTransactionParams,
} from "./transactions.js";
export { buildMergeTransaction, type MergeClient, type MergeTransactionParams } from "./merge.js";
export {
  backfillAssetRegistry,
  getPrivateTokenBalances,
  getPrivateTransactions,
  syncWallet,
  type SyncClient,
  type SyncWalletConfig,
  type SyncWalletInput,
} from "./sync.js";
export {
  loadPersistedWallet,
  syncPersistedWallet,
  type SyncPersistedWalletResult,
  type WalletStateCipher,
  type WalletStateStore,
} from "./persisted.js";
export { walletSnapshotCipher } from "./snapshot-cipher.js";
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
export type { ErrorEnvelope } from "../errors/internal.js";
