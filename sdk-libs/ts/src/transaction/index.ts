export { initializePoseidon, isPoseidonInitialized } from "../hasher/index.js";
export { Data } from "./data.js";
export type { DataRecord } from "./data.js";
export {
  TRANSACTION_ERROR_CODES,
  TransactionError,
  transactionError,
  type TransactionErrorCause,
  type TransactionErrorCode,
  type TransactionErrorDetails,
  type TransactionErrorValue,
} from "./error.js";
export {
  BN254_MODULUS_DEC,
  ConfidentialSplit,
  MERGE_INPUTS,
  Merge,
  PreparedMerge,
  PreparedSplit,
  SENDER_SLOT_COUNT,
  SPP_SUPPORTED_SHAPES,
  SppProofInputs,
  ConfidentialTransfer,
  assetField,
  canonicalShape,
  createEncryptedTransaction,
  createExternalData,
  createInputUtxo,
  encodeConfidentialSlots,
  privateTxHash,
  resolveShape,
  signedToField,
  slotOrdinal,
} from "./instructions/index.js";
export type {
  EncryptedTransaction,
  ExternalData,
  ExternalDataInit,
  IndexedShieldedTransaction,
  InputUtxo,
  InputUtxoContext,
  OutputContext,
  OutputSlot,
  PreparedTransfer,
  PrivateTxHashInput,
  PublicAmounts,
  Shape,
  WithdrawalTarget,
} from "./instructions/index.js";
export { ProofInputUtxo, Utxo, createProofOutput, deriveBlinding, ownerUtxoHash } from "./utxo.js";
export type { Blinding, ProofOutputInit, ProofOutputUtxo, UtxoInit } from "./utxo.js";
export {
  AssetRegistry,
  DEFAULT_TAG_WINDOW,
  LocalWalletAuthority,
  SOL_ASSET_ID,
  SOL_MINT,
  Wallet,
  decryptTransactions,
  deserializeWallet,
  serializeWallet,
} from "./wallet/index.js";
export type {
  AnonymousRecipientSlot,
  ApprovalRequest,
  AssetBalance,
  CounterpartyCounter,
  EncryptedEnvelope,
  EncryptedSplit,
  EncryptedTransfer,
  Filter,
  P256Signature,
  PrivateTransaction,
  PrivateTransactionDirection,
  PrivateTransactionId,
  PrivateTransactionKind,
  PrivateTransactionStatus,
  SplitBundlePlaintext,
  SyncWalletAuthority,
  SyncReport,
  SerializedWalletState,
  ViewingKeyEntry,
  WalletAuthority,
  WalletSyncConfig,
  WalletSyncMaterial,
  WalletUtxo,
} from "./wallet/index.js";
/** Wire type prefixes, defined once beside the reader and writer that enforce them. */
export { MERGE, SPLIT, TRANSFER, TRANSFER_PLAINTEXT } from "./serialization/codecs.js";
export {
  EncryptedScheme,
  anonymousRecipientFromUtxos,
  anonymousSenderFromUtxos,
  decodeContextForSlot,
  encryptedSchemeFromByte,
  encryptedSchemeToByte,
  outputDataEncoding,
  plaintextTransferFromUtxos,
  prooflessFromUtxos,
  splitBundleFromUtxos,
  type DecodeContext,
  type OutputDataEncoding,
  type OwnerContext,
} from "./serialization/index.js";

export const VIEW_TAG_LEN = 32;
