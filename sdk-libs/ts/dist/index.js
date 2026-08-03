import { ZolanaClient } from "./client/index.js";
import { initializePoseidon } from "./hasher/index.js";
export { initializePoseidon };
export { HasherWasmError } from "./hasher/index.js";
export async function createZolanaClient(config) {
    const client = new ZolanaClient(config);
    await initializePoseidon();
    return client;
}
export { CANONICAL_CLIENT_ERROR_CODES, ClientError, DEFAULT_INDEXER_POLL_CONFIG, } from "./client/index.js";
export { DEFAULT_TREE_ADDRESS, SHIELDED_POOL_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID, USER_REGISTRY_PROGRAM_ID, } from "./interface/index.js";
export { CompressedShieldedAddress, KeypairError, NullifierKey, P256PublicKey, ShieldedAddress, ShieldedKeypair, ShieldedPublicKey, SigningKey, ViewingKey, } from "./keypair/index.js";
export { Data, LocalWalletAuthority, SOL_MINT, TransactionError, Utxo, Wallet, deserializeWallet, serializeWallet, } from "./transaction/index.js";
export { buildDepositTransaction, buildMergeTransaction, buildRegistrationTransaction, buildSetMergingEnabledTransaction, buildSplitTransaction, buildTransferTransaction, buildWithdrawalTransaction, getPrivateTokenBalances, getPrivateTransactions, syncWallet, WalletError, } from "./wallet/index.js";
