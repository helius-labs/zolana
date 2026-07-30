import { ZolanaClient, type ZolanaClientConfig } from "./client/index.js";
import { initializePoseidon } from "./hasher/index.js";

export type { TransactionSigner } from "@solana/kit";
export { initializePoseidon };
export { HasherWasmError } from "./hasher/index.js";

export async function createZolanaClient(config: ZolanaClientConfig): Promise<ZolanaClient> {
  const client = new ZolanaClient(config);
  await initializePoseidon();
  return client;
}

export {
  CANONICAL_CLIENT_ERROR_CODES,
  ClientError,
  DEFAULT_INDEXER_POLL_CONFIG,
  type ClientErrorCode,
  type IndexerPollConfig,
  type SubmittedPrivateTransaction,
  type TransactionSignOnlySigner,
  type ZolanaClientConfig,
} from "./client/index.js";
export {
  DEFAULT_TREE_ADDRESS,
  SHIELDED_POOL_PROGRAM_ID,
  SPL_TOKEN_2022_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
  USER_REGISTRY_PROGRAM_ID,
  type Address,
  type Bytes16,
  type Bytes31,
  type Bytes32,
  type Bytes33,
  type Bytes64,
  type RequestContext,
  type Signature,
} from "./interface/index.js";
export {
  CompressedShieldedAddress,
  KeypairError,
  NullifierKey,
  P256PublicKey,
  ShieldedAddress,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
  type KeypairErrorCode,
} from "./keypair/index.js";
export {
  Data,
  LocalWalletAuthority,
  SOL_MINT,
  TransactionError,
  Utxo,
  Wallet,
  deserializeWallet,
  serializeWallet,
  type SerializedWalletState,
  type SyncReport,
  type TransactionErrorCode,
  type WalletAuthority,
  type WalletUtxo,
} from "./transaction/index.js";
export {
  buildPrivateTransaction,
  createAssociatedTokenAccount,
  createDeposit,
  createMerge,
  createSplit,
  createTransfer,
  createWithdrawal,
  deposit,
  ensureRegistered,
  getPrivateTokenBalances,
  getPrivateTransactions,
  merge,
  registerIfAbsent,
  setMergingEnabled,
  signPrivateTransaction,
  split,
  submitDeposit,
  syncWallet,
  transfer,
  withdraw,
  WalletError,
  type DepositActionParams,
  type MergeActionParams,
  type PrivateActionParams,
  type SplitActionParams,
  type SubmittedDeposit,
  type SubmittedMergeAction,
  type SubmittedSplit,
  type SubmittedTransfer,
  type SubmittedWithdrawal,
  type TransferActionParams,
  type TransferDestination,
  type SyncWalletReport,
  type WalletErrorCode,
  type WithdrawalActionParams,
} from "./wallet/index.js";
