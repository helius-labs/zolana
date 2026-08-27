export { initializePoseidon, isPoseidonInitialized } from "../hasher/index.js";

export { randomBlinding, randomSalt } from "./bytes.js";
export type { Bytes16, Bytes31, Bytes32, Bytes33, Bytes34, Bytes64 } from "./bytes.js";
export type { EcdsaSignature } from "./signing-key.js";
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
  P256_PUBLIC_KEY_LENGTH,
  SALT_LENGTH,
  SHIELDED_PUBLIC_KEY_LENGTH,
  VIEW_TAG_LENGTH,
} from "./constants.js";
export {
  DST_VIEW_ROOT_P_CONST,
  ED25519_DERIVATION_MSG,
  ED25519_SEED_LEN,
  DERIVATION_PAYLOAD_PREFIX,
  OFFCHAIN_MESSAGE_MAGIC,
  P256_SEED_LEN,
  P_CONST_SEC1,
  P_DERIVE_SEC1,
  P_PDA_SEC1,
  TSPP_APPLICATION_DOMAIN,
  ed25519DerivationMessage,
  ed25519DerivationPayload,
  isDerivationInput,
} from "./derivation.js";
export { poseidon } from "./poseidon.js";
export { ownerHash, sha256Be, sha256Bytes, splitBigEndian128 } from "./hash.js";
export { symmetricApply } from "./merge/index.js";
export {
  auditorMessageData,
  auditorViewTag,
  customRingPublicInputHash,
  decryptTransactionViewingSecret,
  encryptTransactionViewingSecret,
  parseAuditorMessage,
} from "./audit.js";
export type { AuditorEncryption, AuditorMessage } from "./audit.js";
export { P256PublicKey, ShieldedPublicKey } from "./public-key.js";
export { SigningKey } from "./signing-key.js";
export { NullifierKey } from "./nullifier-key.js";
export { ViewingKey } from "./viewing-key.js";
export {
  CompressedShieldedAddress,
  ShieldedAddress,
  ShieldedKeypair,
  type P256Signature,
  type ShieldedKeypairLike,
  type ViewingKeyLike,
} from "./shielded.js";

/** Mirrors Rust's `Signature` / `ECDSASignature` aliases: 64 raw bytes. */
export type Signature = import("./bytes.js").Bytes64;
