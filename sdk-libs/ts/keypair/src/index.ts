import { type Bytes31, type Bytes16, randomBytes } from "./bytes.js";

export type { EcdsaSignature } from "./signing-key.js";
export type { SignatureType, ViewTag } from "./public-key.js";
export type { Salt } from "./viewing-key.js";
export { KeypairError, type KeypairErrorCode } from "./error.js";
export { P256PublicKey, ShieldedPublicKey } from "./public-key.js";
export { SigningKey } from "./signing-key.js";
export { NullifierKey } from "./nullifier-key.js";
export { ViewingKey } from "./viewing-key.js";
export {
  ShieldedKeypair,
  type CompressedShieldedAddress,
  type ShieldedAddress,
  type ShieldedKeypairLike,
  type ViewingKeyLike,
} from "./shielded.js";

export function randomBlinding(): Bytes31 {
  return randomBytes(31) as Bytes31;
}

export function randomSalt(): Bytes16 {
  return randomBytes(16) as Bytes16;
}
