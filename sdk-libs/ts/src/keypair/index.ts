export {
  SOLANA_OWNER_TAG,
  initializePoseidon,
  isPoseidonInitialized,
  solanaOwnerIdentity,
} from "../hasher/index.js";

export { randomBlinding, randomSalt } from "./bytes.js";
export type { Bytes16, Bytes31, Bytes32, Bytes33, Bytes34, Bytes64 } from "./bytes.js";
export type { SignatureType, ViewTag } from "./public-key.js";
export type { Salt } from "./viewing-key.js";
export {
  KeypairError,
  KEYPAIR_ERROR_RUST_VARIANT,
  type KeypairErrorCode,
  type KeypairErrorDetails,
} from "./error.js";
// The Rust-public constants from `zolana_keypair::constants` and the public
// half of the `zolana_keypair::derivation` registry.
export {
  BLINDING_LENGTH,
  SALT_LENGTH,
  SHIELDED_PUBLIC_KEY_LENGTH,
  VIEW_TAG_LENGTH,
} from "./constants.js";
export {
  ED25519_DERIVATION_MSG,
  ED25519_SEED_LEN,
  DERIVATION_PAYLOAD_PREFIX,
  OFFCHAIN_MESSAGE_MAGIC,
  TSPP_APPLICATION_DOMAIN,
  ed25519DerivationMessage,
  ed25519DerivationPayload,
  isDerivationInput,
} from "./derivation.js";
export { poseidon } from "./poseidon.js";
export { ownerHash, sha256Be, sha256Bytes, splitBigEndian128 } from "./hash.js";
export { mergePrivateTxBlinding, symmetricApply } from "./merge/index.js";
export { outputBlindingSeed, privateTxBlinding, transactOutputBlinding } from "./transact/index.js";
export {
  auditorMessageData,
  auditorViewTag,
  auditDisclosureLength,
  anonymousAuditDisclosureShape,
  policyPublicInputHash,
  decryptTransactionViewingSecret,
  encryptTransactionViewingSecret,
  isDummyAnonymousOutput,
  openAnonymousAuditDisclosure,
  openAuditOutputDisclosure,
  parseAuditorMessage,
} from "./audit.js";
export type {
  AnonymousAuditDisclosure,
  AnonymousOutputOpening,
  AuditDisclosureInput,
  AuditDisclosureShape,
  AuditInputOpening,
  AuditOutputOpening,
  AuditorEncryption,
  AuditorMessage,
  CustomRingBasePublicInput,
} from "./audit.js";
export { ShieldedPublicKey } from "./public-key.js";
export { SigningKey } from "./signing-key.js";
export { NullifierKey } from "./nullifier-key.js";
export { ViewingKey } from "./viewing-key.js";
export {
  CompressedShieldedAddress,
  ShieldedAddress,
  ShieldedKeypair,
  type ShieldedKeypairLike,
  type ViewingKeyLike,
} from "./shielded.js";

/** Mirrors Rust's `Signature` alias: 64 raw bytes. */
export type Signature = import("./bytes.js").Bytes64;
export type { ErrorEnvelope } from "../errors/internal.js";

export { X25519PublicKey, X25519Secret } from "./x25519.js";
