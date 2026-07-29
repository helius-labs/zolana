export type { TransactionSigner } from "@solana/kit";
export type { TransactionSignOnlySigner } from "../client/index.js";

export { initializePoseidon, isPoseidonInitialized } from "../hasher/index.js";
export { WALLET_ERROR_CODES, WalletError, type WalletErrorCode } from "./error.js";
export {
  LocalWalletAuthority,
  type AnonymousRecipientSlot,
  type ApprovalRequest,
  type EncryptedEnvelope,
  type EncryptedSplit,
  type EncryptedTransfer,
  type P256Signature,
  type SyncWalletAuthority,
  type WalletAuthority,
  type WalletSyncMaterial,
} from "../transaction/wallet/authority.js";
export {
  Deposit,
  buildDepositTransaction,
  createDeposit,
  deposit,
  submitDeposit,
  type DepositActionParams,
  type DepositParams,
  type DepositSplAccounts,
  type SubmittedDeposit,
} from "./deposit.js";
export {
  UnsignedPrivateTransaction,
  createSplit,
  createTransfer,
  createWithdrawal,
  type CreatedSplit,
  type CreatedTransfer,
  type CreatedWithdrawal,
  type SplitParams,
  type TransferDestination,
  type TransferParams,
  type TransferRecipient,
  type WithdrawalParams,
} from "./actions.js";
export {
  split,
  transfer,
  withdraw,
  type PrivateActionParams,
  type SplitActionParams,
  type SubmittedSplit,
  type SubmittedTransfer,
  type SubmittedWithdrawal,
  type TransferActionParams,
  type WithdrawalActionParams,
} from "./execute.js";
export { buildPrivateTransaction, signPrivateTransaction } from "./private-transaction.js";
export {
  MergeMaterial,
  createAssociatedTokenAccount,
  createMerge,
  merge,
  submitMergeTransaction,
  type CreatedMerge,
  type MergeActionParams,
  type MergeParams,
  type SubmitMergeTransaction,
  type SubmittedMerge,
  type SubmittedMergeAction,
} from "./submit.js";
export {
  backfillAssetRegistry,
  getPrivateTokenBalances,
  getPrivateTransactions,
  syncWallet,
  type CounterpartyCounter,
  type SyncWalletConfig,
  type SyncWalletReport,
  type ViewingKeyCounters,
} from "./sync.js";
export {
  buildRegistrationTransaction,
  decodeUserRecordAccount,
  ensureRegistered,
  fetchUserRecord,
  fetchUserRecordChecked,
  isWalletRegistered,
  registerIfAbsent,
  recipientConfidentialViewTag,
  resolveRegisteredAddress,
  resolvedAddressFromRecord,
  senderViewingPublicKey,
  setMergingEnabled,
  validateRegisteredKeypair,
  type ResolvedAddress,
  type StrictRegistration,
  type SyncDelegateEntry,
  type UserRecord,
} from "./registry.js";
