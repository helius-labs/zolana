/**
 * The backend-agnostic capability interfaces, mirroring
 * `sdk-libs/keypair/src/traits/mod.rs`. They are re-exported from the package
 * root as well; this subpath exists so a consumer can depend on the abstraction
 * without pulling in the concrete key implementations by name.
 */
export type { ShieldedKeypairLike, ViewingKeyLike } from "../shielded.js";
