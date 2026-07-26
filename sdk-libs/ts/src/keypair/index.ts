export { initializePoseidon, isPoseidonInitialized } from "../hasher/index.js";
import { type Bytes31, type Bytes16, randomBytes } from "./bytes.js";

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
// The Rust-public constants from `zolana_keypair::constants`. The `INFO_*`
// labels and the HPKE prefixes stay internal because Rust keeps them
// `pub(crate)`.
export {
  BLINDING_LENGTH,
  DST_VIEW_ROOT,
  P256_PUBLIC_KEY_LENGTH,
  P_CONST_SEC1,
  SALT_LENGTH,
  SHIELDED_PUBLIC_KEY_LENGTH,
  VIEW_TAG_LENGTH,
} from "./constants.js";
export { poseidon } from "./poseidon.js";
export { hashField, ownerHash, sha256Be, sha256Bytes, splitBigEndian128 } from "./hash.js";
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

export function randomBlinding(): Bytes31 {
  return randomBytes(31) as Bytes31;
}

export function randomSalt(): Bytes16 {
  return randomBytes(16) as Bytes16;
}
