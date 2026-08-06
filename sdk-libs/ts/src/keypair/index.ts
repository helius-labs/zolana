export { initializePoseidon, isPoseidonInitialized } from "../hasher/index.js";

export { randomBlinding, randomSalt } from "./bytes.js";
export type { Bytes16, Bytes31, Bytes32, Bytes33, Bytes34, Bytes64 } from "./bytes.js";
export type { EcdsaSignature } from "./signing-key.js";
export type { Curve, SigningCurve, ViewTag } from "./public-key.js";
export type { Salt } from "./viewing-key.js";
export {
  KeypairError,
  KEYPAIR_ERROR_RUST_VARIANT,
  type KeypairErrorCode,
  type KeypairErrorDetails,
} from "./error.js";
export {
  BLINDING_LENGTH,
  DERIVATION_PAYLOAD_PREFIX,
  DST_DERIVE_P_DERIVE,
  DST_PDA_ROOT_P_PDA,
  DST_VIEW_ROOT_P_CONST,
  ED25519_DERIVATION_MSG,
  INFO_NF_KEY_ECDH,
  INFO_NF_KEY_ED25519,
  INFO_PDA_NF_KEY,
  INFO_PDA_VIEW_KEY,
  INFO_VIEW_KEY_ECDH,
  INFO_VIEW_KEY_ED25519,
  P_DERIVE_SEC1,
  P_PDA_SEC1,
  P256_PUBLIC_KEY_LENGTH,
  P_CONST_SEC1,
  SALT_LENGTH,
  SHIELDED_PUBLIC_KEY_LENGTH,
  VIEW_TAG_LENGTH,
} from "./constants.js";
export {
  OFFCHAIN_MESSAGE_MAGIC,
  TSPP_APPLICATION_DOMAIN,
  ed25519DerivationMessage,
  isDerivationInput,
} from "./derivation.js";
export { poseidon } from "./poseidon.js";
export { hashField, ownerHash, sha256Be, sha256Bytes, splitBigEndian128 } from "./hash.js";
export { P256PublicKey, ShieldedPublicKey } from "./public-key.js";
export { SigningKey } from "./signing-key.js";
export { NullifierKey } from "./nullifier-key.js";
export { ViewingKey } from "./viewing-key.js";
export { ShieldedPda } from "./pda.js";
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
