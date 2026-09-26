import type { ClientErrorCode } from "../client/error.js";

export const KEY_REGISTRY_PROJECTION_ERRORS: ReadonlySet<ClientErrorCode> = new Set([
  "CLIENT_KEY_REGISTRY_OUT_OF_SYNC",
  "CLIENT_KEY_REGISTRY_ROOT_CHANGED",
]);

export const SPEND_RECORD_PROJECTION_ERRORS: ReadonlySet<ClientErrorCode> = new Set([
  "CLIENT_SPEND_RECORD_OUT_OF_SYNC",
]);
