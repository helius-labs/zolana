import { ZolanaClient, type ZolanaClientConfig } from "./client/index.js";
import { initializePoseidon } from "./hasher/index.js";

export type { TransactionSigner } from "@solana/kit";
export { initializePoseidon };
export { HasherWasmError } from "./hasher/index.js";

/**
 * Connects a client and loads the hasher it needs.
 *
 * `solanaRpcUrl` serves the indexer and the prover too, which is the shape a
 * Helius URL takes. Name `indexerUrl` or `proverUrl` for a deployment that
 * splits them. A config that names no URL reaches the local validator, photon,
 * and prover on their own ports.
 */
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
  decryptToBalances,
  deserializeWallet,
  serializeWallet,
  type PrivateBalances,
  type SerializedWalletState,
  type SyncReport,
  type TransactionErrorCode,
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
  getPrivateTokenBalances,
  getPrivateTransactions,
  syncWallet,
  WalletError,
  type DepositTransactionParams,
  type MergeTransactionParams,
  type PrivateTransactionParams,
  type SplitTransactionParams,
  type SyncWalletConfig,
  type TransferDestination,
  type TransferTransactionParams,
  type WalletErrorCode,
  type WithdrawalTransactionParams,
} from "./wallet/index.js";
