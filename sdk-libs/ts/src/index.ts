import { ZolanaClient, type ZolanaClientConfig } from "./client/index.js";
import { initializePoseidon } from "./hasher/index.js";

export type { ErrorEnvelope } from "./errors/internal.js";
export type { TransactionSigner } from "@solana/kit";
export { initializePoseidon };

/**
 * Connects a client and loads the hasher it needs.
 *
 * `solanaRpcUrl` is shared by all services unless a service-specific URL is
 * provided. Omitting all URLs uses the local stack ports.
 */
export async function createZolanaClient(config: ZolanaClientConfig = {}): Promise<ZolanaClient> {
  await initializePoseidon();
  return new ZolanaClient(config);
}

export {
  CANONICAL_CLIENT_ERROR_CODES,
  ClientError,
  DEFAULT_INDEXER_POLL_CONFIG,
  type ClientErrorCode,
  type IndexerPollConfig,
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
  ClientEd25519WalletAuthority,
  KeypairWalletAuthority,
  SOL_MINT,
  TransactionError,
  Utxo,
  Wallet,
  deserializeWallet,
  serializeWallet,
  type SerializedWalletState,
  type SyncReport,
  type TransactionErrorCode,
  type SpendAuthority,
  type SpendSession,
  type SyncAuthority,
  type WalletAuthority,
  type WalletUtxo,
} from "./transaction/index.js";
export {
  buildDepositTransaction,
  buildMergeTransaction,
  buildRegistrationTransaction,
  buildSetMergingEnabledTransaction,
  buildSplitTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
  fetchTransactionSlots,
  fetchViewingKeyOwners,
  getPrivateTokenBalances,
  getPrivateTransactions,
  syncWallet,
  viewingKeyIndex,
  WalletError,
  type DepositTransactionParams,
  type MergeTransactionParams,
  type PrivateTransactionParams,
  type SplitTransactionParams,
  type SyncClient,
  type SyncWalletConfig,
  type TransactionSlots,
  type TransferDestination,
  type TransferTransactionParams,
  type WalletErrorCode,
  type WithdrawalTransactionParams,
} from "./wallet/index.js";
export {
  buildRingDepositTransaction,
  buildRingExitTransaction,
  buildRingLookupTableTransaction,
  buildRingTransferTransaction,
  buildRingWithdrawalTransaction,
  createPasskey,
  fetchReaderGrant,
  fetchRingProgramConfig,
  listRegisteredRings,
  grantReadAccessInstruction,
  parseReaderKey,
  passkeyReader,
  readerKeyToString,
  readAccessRecordAddress,
  revokeReadAccessInstruction,
  setRingAuthorityInstruction,
  RingError,
  RingRpc,
  type DecryptedRingTransaction,
  type DecryptedRingTransactionsPage,
  type RingDepositTransactionParams,
  type RingErrorCode,
  type Passkey,
  type ReaderKey,
  type ReadAccessRecord,
  type RingLookupTable,
  type RegisteredRing,
  type RingProgramConfig,
  type RingReadSigner,
  type RingTransferTransactionParams,
  type RingWithdrawalTransactionParams,
} from "./ring/index.js";
