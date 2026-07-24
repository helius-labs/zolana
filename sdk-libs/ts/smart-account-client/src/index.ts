export { SmartAccountClientError } from "./error.js";
export {
  allPermissions,
  createSmartAccountInstruction,
  executeSyncInstruction,
} from "./instructions.js";
export type { Permissions, SmartAccountSigner } from "./instructions.js";
export {
  programConfigAddress,
  settingsAddress,
  smartAccountAddress,
  treasuryAddress,
} from "./pda.js";
export { SMART_ACCOUNT_PROGRAM_ID_VALUE as SMART_ACCOUNT_PROGRAM_ID } from "./pda.js";
