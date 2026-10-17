import type { ClientErrorCode } from "../client/error.js";

export const MEMBER_REGISTRY_PROJECTION_ERRORS: ReadonlySet<ClientErrorCode> = new Set([
  "CLIENT_MEMBER_REGISTRY_OUT_OF_SYNC",
  "CLIENT_MEMBER_REGISTRY_ROOT_CHANGED",
]);
