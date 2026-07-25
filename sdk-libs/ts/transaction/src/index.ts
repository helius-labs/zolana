export { Data } from "./data.js";
export type { DataRecord } from "./data.js";
export {
  TRANSACTION_ERROR_CODES,
  TransactionError,
  authorityError,
  transactionError,
  unknownTransactionError,
  type TransactionErrorCause,
  type TransactionErrorCode,
  type TransactionErrorDetails,
  type TransactionErrorValue,
} from "./error.js";
export {
  ConfidentialSplit,
  MERGE_INPUTS,
  Merge,
  MergeZone,
  PreparedMerge,
  PreparedMergeZone,
  PreparedSplit,
  SPP_SUPPORTED_SHAPES,
  SppProofInputs,
  ConfidentialTransfer,
  canonicalShape,
  createExternalData,
  prepareZoneAuthority,
  resolveShape,
  slotOrdinal,
} from "./instructions/index.js";
export type {
  ExternalData,
  InputUtxoContext,
  OutputContext,
  PreparedTransfer,
  PreparedZoneAuthority,
  PublicAmounts,
  Shape,
  WithdrawalTarget,
} from "./instructions/index.js";
export { ProofInputUtxo, Utxo, deriveBlinding, ownerUtxoHash } from "./utxo.js";
export type { Blinding, ProofOutputUtxo, UtxoInit } from "./utxo.js";
export {
  AssetRegistry,
  LocalWalletAuthority,
  SOL_ASSET_ID,
  SOL_MINT,
  Wallet,
  decryptTransactions,
} from "./wallet/index.js";
export type {
  AnonymousRecipientSlot,
  ApprovalRequest,
  AssetBalance,
  CounterpartyCounter,
  EncryptedEnvelope,
  EncryptedSplit,
  EncryptedTransfer,
  P256Signature,
  PrivateTransaction,
  SplitBundlePlaintext,
  SyncWalletAuthority,
  SyncReport,
  ViewingKeyEntry,
  WalletAuthority,
  WalletSyncConfig,
  WalletSyncMaterial,
  WalletUtxo,
} from "./wallet/index.js";
export {
  EncryptedScheme,
  anonymousRecipientFromUtxos,
  anonymousSenderFromUtxos,
  encryptedSchemeFromByte,
  encryptedSchemeToByte,
  outputDataEncoding,
  plaintextTransferFromUtxos,
  prooflessFromUtxos,
  splitBundleFromUtxos,
  type OutputDataEncoding,
  type OwnerContext,
} from "./serialization/index.js";

export const TRANSFER = 1;
export const SPLIT = 2;
export const MERGE = 3;
export const TRANSFER_PLAINTEXT = 4;
export const VIEW_TAG_LEN = 32;
export const DEFAULT_TAG_WINDOW = 64n;
