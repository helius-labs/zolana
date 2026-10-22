import type { ClientErrorCode } from "../client/error.js";

/** Rust `RingError::is_projection_lag`, the answer holds only for the state it was asked under. */
export const MEMBER_REGISTRY_PROJECTION_ERRORS: ReadonlySet<ClientErrorCode> = new Set([
  "CLIENT_INDEXER_PROOF_DATA_NOT_READY",
  "CLIENT_MEMBER_REGISTRY_OUT_OF_SYNC",
  "CLIENT_MEMBER_REGISTRY_ROOT_CHANGED",
  "CLIENT_RECORD_QUEUE_CHANGED",
]);
