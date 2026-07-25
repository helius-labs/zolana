export { WALLET_ERROR_CODES, WalletError, type WalletErrorCode } from "./error.js";
export {
  LocalWalletAuthority,
  type AnonymousRecipientSlot,
  type ApprovalRequest,
  type EncryptedSplit,
  type EncryptedTransfer,
  type P256Signature,
  type SyncWalletAuthority,
  type WalletAuthority,
  type WalletSyncMaterial,
} from "./wallet-authority.js";
export {
  Deposit,
  buildDepositTransaction,
  createDeposit,
  deposit,
  type DepositParams,
  type DepositSplAccounts,
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
  type TransferParams,
  type TransferRecipient,
  type WithdrawalParams,
} from "./actions.js";
export { buildPrivateTransaction, signPrivateTransaction } from "./private-transaction.js";
export {
  MergeMaterial,
  createAssociatedTokenAccount,
  createMerge,
  submitMergeTransaction,
  type CreatedMerge,
  type MergeParams,
  type SubmitMergeTransaction,
  type SubmittedMerge,
  type TransactionSigner,
} from "./submit.js";
export {
  backfillAssetRegistry,
  getPrivateTokenBalances,
  getPrivateTransactions,
  syncWallet,
  type CounterpartyCounter,
  type SyncWalletConfig,
  type ViewingKeyCounters,
} from "./sync.js";
export {
  buildRegistrationTransaction,
  decodeUserRecordAccount,
  ensureRegistered,
  fetchUserRecord,
  fetchUserRecordChecked,
  fetchUserRecordOptionalChecked,
  isWalletRegistered,
  registerIfAbsent,
  recipientConfidentialViewTag,
  resolveRegisteredAddress,
  resolvedAddressFromRecord,
  senderViewingPublicKey,
  tryResolveRegisteredAddress,
  validateRegisteredKeypair,
  type ResolvedAddress,
  type StrictRegistration,
  type SyncDelegateEntry,
  type UserRecord,
} from "./registry.js";
