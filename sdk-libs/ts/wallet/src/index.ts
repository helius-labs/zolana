export { WalletError } from "./error.js";
export {
  LocalWalletAuthority,
  type ApprovalRequest,
  type WalletAuthority,
} from "./wallet-authority.js";
export { Deposit, buildDepositTransaction, createDeposit, type DepositParams } from "./deposit.js";
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
  getPrivateTokenBalances,
  getPrivateTransactions,
  syncWallet,
  type SyncWalletConfig,
} from "./sync.js";
export {
  buildRegistrationTransaction,
  fetchUserRecord,
  isWalletRegistered,
  resolveRegisteredAddress,
  type ResolvedAddress,
} from "./registry.js";
