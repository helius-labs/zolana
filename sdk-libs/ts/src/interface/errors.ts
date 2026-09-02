export type InterfaceErrorCode =
  | "INTERFACE_INVALID_ADDRESS"
  | "INTERFACE_INVALID_LENGTH"
  | "INTERFACE_INVALID_INTEGER"
  | "INTERFACE_INVALID_DISCRIMINATOR"
  | "INTERFACE_INVALID_ACCOUNT_DATA"
  | "INTERFACE_INVALID_SHAPE"
  | "INTERFACE_TRANSACTION_TOO_LARGE"
  | "INTERFACE_HASH"
  | "INTERFACE_CODEC";

export const ShieldedPoolError = Object.freeze({
  InvalidInstructionData: 7000,
  InvalidTreeAccounts: 7001,
  NullifierTreeUpdateFailed: 7002,
  UnauthorizedCaller: 7003,
  StateAppendFailed: 7004,
  ExpiredTransaction: 7005,
  InvalidTransactShape: 7006,
  InvalidTransactProofEncoding: 7007,
  TransactProofVerificationFailed: 7008,
  InvalidSettlementAccounts: 7009,
  PublicSettlementFailed: 7010,
  InvalidSplAssetRegistry: 7011,
  InvalidProtocolConfig: 7012,
  TreePaused: 7013,
  InvalidRingConfig: 7014,
  StaleNullifierRoot: 7015,
  InvalidPda: 7016,
  MergeDisabled: 7017,
  InvalidUserRecord: 7018,
  InvalidMergeShape: 7019,
  InvalidMergeOutputScheme: 7020,
  MismatchedTransactProofRail: 7021,
  RingAuthorityTransactDisabled: 7022,
  BothPublicAmountsSet: 7023,
  MissingP256SigningKey: 7024,
  OwnerTagAccountMissing: 7025,
  InvalidForesterFee: 7026,
  InsufficientForesterFeeBalance: 7027,
  InvalidSystemProgram: 7028,
  EmptyDepositBatch: 7029,
  InvalidDepositAssetIndex: 7030,
  DuplicateDepositAsset: 7031,
  DepositAmountOverflow: 7032,
  UnreferencedDepositAsset: 7033,
  TooManyDepositAssets: 7034,
  TooManyInterfaceTransfers: 7035,
  ZeroInterfaceTransferAmount: 7036,
  TooManyPublicAssets: 7037,
  PublicAssetAmountOverflow: 7038,
  MismatchedCircuitType: 7039,
  SplTokenAuthorityMustSign: 7040,
  UnsupportedSplTokenProgram: 7041,
  InvalidSplTokenMint: 7042,
  UnsupportedToken2022Extension: 7043,
  NullifierTreeTooFullForMerge: 7044,
  ZeroNetInterfaceTransferAmount: 7045,
  SplAssetCounterAlreadyInitialized: 7046,
  RingPaused: 7047,
  NullifierAlreadyQueued: 7048,
  InsufficientNullifierPdaRent: 7049,
  NullifierPdaNotClosable: 7050,
  InvalidNullifierPda: 7051,
  InvalidTreeId: 7052,
  NullifierPdaTreeMismatch: 7053,
  TreeIdOverflow: 7054,
  InvalidReimbursementRecipient: 7055,
} as const);

export type ShieldedPoolErrorName = keyof typeof ShieldedPoolError;
export type ShieldedPoolErrorCode = (typeof ShieldedPoolError)[ShieldedPoolErrorName];

const shieldedPoolErrorNames = new Map<number, ShieldedPoolErrorName>(
  Object.entries(ShieldedPoolError).map(([name, code]) => [code, name as ShieldedPoolErrorName]),
);

export type DecodedShieldedPoolError =
  | Readonly<{
      kind: "known";
      code: ShieldedPoolErrorCode;
      name: ShieldedPoolErrorName;
    }>
  | Readonly<{
      kind: "unknown";
      code: number;
    }>;

export function decodeShieldedPoolError(code: number): DecodedShieldedPoolError {
  if (!Number.isSafeInteger(code) || code < 0 || code > 0xffffffff) {
    throw new InterfaceError("INTERFACE_INVALID_INTEGER", {
      name: "customProgramErrorCode",
      minimum: 0,
      maximum: 0xffffffff,
      actual: code,
    });
  }
  const name = shieldedPoolErrorNames.get(code);
  return name === undefined
    ? Object.freeze({ kind: "unknown", code })
    : Object.freeze({ kind: "known", code: code as ShieldedPoolErrorCode, name });
}

import {
  extractCauseCode,
  hideCause,
  sanitizeDetails,
  type ErrorEnvelope,
} from "../errors/internal.js";

export class InterfaceError extends Error {
  readonly code: InterfaceErrorCode;
  readonly causeCode?: string;
  readonly details?: Readonly<Record<string, unknown>>;
  override readonly cause?: unknown;

  constructor(
    code: InterfaceErrorCode,
    details?: Readonly<Record<string, unknown>>,
    cause?: unknown,
  ) {
    super(code);
    this.name = "InterfaceError";
    this.code = code;
    const safe = sanitizeDetails(details);
    if (safe !== undefined) this.details = safe;
    const inner = extractCauseCode(cause);
    if (inner !== undefined) this.causeCode = inner;
    hideCause(this, cause);
  }

  toJSON(): ErrorEnvelope {
    return {
      name: this.name,
      code: this.code,
      ...(this.details === undefined ? {} : { details: this.details }),
      ...(this.causeCode === undefined ? {} : { causeCode: this.causeCode }),
    };
  }
}
