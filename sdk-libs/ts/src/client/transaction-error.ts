import { wireDecoder } from "../interface/decode.js";
import { ClientError } from "./error.js";

// Pinned to Rust's serde representation by test-vectors/solana_transaction_errors.json.
const TRANSACTION_VARIANTS: ReadonlySet<string> = new Set([
  "AccountInUse",
  "AccountLoadedTwice",
  "AccountNotFound",
  "ProgramAccountNotFound",
  "InsufficientFundsForFee",
  "InvalidAccountForFee",
  "AlreadyProcessed",
  "BlockhashNotFound",
  "CallChainTooDeep",
  "MissingSignatureForFee",
  "InvalidAccountIndex",
  "SignatureFailure",
  "InvalidProgramForExecution",
  "SanitizeFailure",
  "ClusterMaintenance",
  "AccountBorrowOutstanding",
  "WouldExceedMaxBlockCostLimit",
  "UnsupportedVersion",
  "InvalidWritableAccount",
  "WouldExceedMaxAccountCostLimit",
  "WouldExceedAccountDataBlockLimit",
  "TooManyAccountLocks",
  "AddressLookupTableNotFound",
  "InvalidAddressLookupTableOwner",
  "InvalidAddressLookupTableData",
  "InvalidAddressLookupTableIndex",
  "InvalidRentPayingAccount",
  "WouldExceedMaxVoteCostLimit",
  "WouldExceedAccountDataTotalLimit",
  "MaxLoadedAccountsDataSizeExceeded",
  "InvalidLoadedAccountsDataSizeLimit",
  "ResanitizationNeeded",
  "UnbalancedTransaction",
  "ProgramCacheHitMaxLimit",
  "CommitCancelled",
]);

const INSTRUCTION_VARIANTS: ReadonlySet<string> = new Set([
  "GenericError",
  "InvalidArgument",
  "InvalidInstructionData",
  "InvalidAccountData",
  "AccountDataTooSmall",
  "InsufficientFunds",
  "IncorrectProgramId",
  "MissingRequiredSignature",
  "AccountAlreadyInitialized",
  "UninitializedAccount",
  "UnbalancedInstruction",
  "ModifiedProgramId",
  "ExternalAccountLamportSpend",
  "ExternalAccountDataModified",
  "ReadonlyLamportChange",
  "ReadonlyDataModified",
  "DuplicateAccountIndex",
  "ExecutableModified",
  "RentEpochModified",
  "NotEnoughAccountKeys",
  "AccountDataSizeChanged",
  "AccountNotExecutable",
  "AccountBorrowFailed",
  "AccountBorrowOutstanding",
  "DuplicateAccountOutOfSync",
  "InvalidError",
  "ExecutableDataModified",
  "ExecutableLamportChange",
  "ExecutableAccountNotRentExempt",
  "UnsupportedProgramId",
  "CallDepth",
  "MissingAccount",
  "ReentrancyNotAllowed",
  "MaxSeedLengthExceeded",
  "InvalidSeeds",
  "InvalidRealloc",
  "ComputationalBudgetExceeded",
  "PrivilegeEscalation",
  "ProgramEnvironmentSetupFailure",
  "ProgramFailedToComplete",
  "ProgramFailedToCompile",
  "Immutable",
  "IncorrectAuthority",
  "BorshIoError",
  "AccountNotRentExempt",
  "InvalidAccountOwner",
  "ArithmeticOverflow",
  "UnsupportedSysvar",
  "IllegalOwner",
  "MaxAccountsDataAllocationsExceeded",
  "MaxAccountsExceeded",
  "MaxInstructionTraceLengthExceeded",
  "BuiltinProgramsMustConsumeComputeUnits",
]);

const invalid = (): ClientError =>
  new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
    details: { method: "getSignatureStatuses", path: "err" },
  });
const decode = wireDecoder(invalid);

/** Validate the closed wire enum and serialize only decoded variants and bounded integers. */
export function transactionErrorText(error: unknown): string | null {
  if (error === null) return null;
  if (typeof error === "string") {
    if (!TRANSACTION_VARIANTS.has(error)) throw invalid();
    return error;
  }
  const value = decode.record(error, "err");
  const fields = Object.keys(value);
  if (fields.length !== 1) throw invalid();
  switch (fields[0]) {
    case "InstructionError": {
      const tuple = decode.list(value["InstructionError"], "err");
      if (tuple.length !== 2) throw invalid();
      return JSON.stringify({
        InstructionError: [unsigned(tuple[0], 255), instructionError(tuple[1])],
      });
    }
    case "DuplicateInstruction":
      return JSON.stringify({ DuplicateInstruction: unsigned(value["DuplicateInstruction"], 255) });
    case "InsufficientFundsForRent":
      return JSON.stringify({
        InsufficientFundsForRent: {
          account_index: unsigned(
            onlyField(value["InsufficientFundsForRent"], "account_index"),
            255,
          ),
        },
      });
    case "ProgramExecutionTemporarilyRestricted":
      return JSON.stringify({
        ProgramExecutionTemporarilyRestricted: {
          account_index: unsigned(
            onlyField(value["ProgramExecutionTemporarilyRestricted"], "account_index"),
            255,
          ),
        },
      });
    default:
      throw invalid();
  }
}

function instructionError(error: unknown): string | Readonly<{ Custom: number }> {
  if (typeof error === "string") {
    if (!INSTRUCTION_VARIANTS.has(error)) throw invalid();
    return error;
  }
  return { Custom: unsigned(onlyField(error, "Custom"), 0xffff_ffff) };
}

function onlyField(value: unknown, field: string): unknown {
  const record = decode.record(value, "err");
  if (Object.keys(record).length !== 1 || !Object.hasOwn(record, field)) throw invalid();
  return record[field];
}

function unsigned(value: unknown, max: number): number {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max) {
    return value;
  }
  if (typeof value === "bigint" && value >= 0n && value <= BigInt(max)) return Number(value);
  throw invalid();
}
