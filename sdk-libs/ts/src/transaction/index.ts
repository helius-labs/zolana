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
  WithdrawalTarget,
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
  ChangeLayout,
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
} from "./instructions/index.js";
export { ProofInputUtxo, Utxo, createProofOutput, deriveBlinding, ownerUtxoHash } from "./utxo.js";
export type { Blinding, ProofOutputInit, ProofOutputUtxo, UtxoInit } from "./utxo.js";
export {
  AssetRegistry,
  ClientEd25519WalletAuthority,
  KeypairWalletAuthority,
  SOL_ASSET_ID,
  SOL_MINT,
  Wallet,
  decryptToBalances,
  decryptTransactions,
  deserializeWallet,
  serializeWallet,
} from "./wallet/index.js";
export {
  approveIntent,
  intentHash,
  type IntentApproval,
  type TransactionIntent,
} from "./wallet/index.js";
export type {
  AnonymousRecipientSlot,
  ApprovalRequest,
  AssetBalance,
  AuditWitness,
  PrivateBalances,
  EncryptedCustomRingTransfer,
  EncryptedEnvelope,
  EncryptedSplit,
  EncryptedTransfer,
  Filter,
  PrivateTransaction,
  PrivateTransactionDirection,
  PrivateTransactionId,
  PrivateTransactionKind,
  PrivateTransactionStatus,
  RingBalance,
  SplitBundlePlaintext,
  SpendAuthority,
  SpendSession,
  SyncAuthority,
  SyncWalletAuthority,
  SyncReport,
  SerializedWalletState,
  ViewingKeyEntry,
  WalletAuthority,
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
// The plaintext decoders, for a client that decrypts somewhere other than in
// this process. `syncWallet` decrypts and decodes together and needs the
// viewing key locally; a client whose viewing key is held remotely gets
// plaintext back and still has to read it. `decodeOutputData` names the scheme
// of a slot payload and hands back the body to decrypt; the per-scheme decoders
// turn the returned plaintext into fields.
export {
  decodeAnonymousRecipient,
  decodeAnonymousSender,
  decodeConfidential,
  decodeData,
  decodeOutputData,
  decodePlaintextTransfer,
  decodeProofless,
  decodeSplitBundle,
  decodeSplitEncrypted,
  type AnonymousRecipientPlaintext,
  type AnonymousSenderPlaintext,
  type ConfidentialOutputPlaintext,
  type ProoflessOutput,
  type SplitEncryptedUtxos,
  type TransferPlaintextUtxos,
} from "./serialization/index.js";

export const VIEW_TAG_LEN = 32;
export type { ErrorEnvelope } from "../errors/internal.js";
