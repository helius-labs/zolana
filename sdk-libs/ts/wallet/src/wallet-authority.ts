/**
 * Authority material owned by `@zolana/transaction`; re-exported here so the
 * wallet package surface matches the Rust module, which is re-exports only.
 */
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
} from "@zolana/transaction";
