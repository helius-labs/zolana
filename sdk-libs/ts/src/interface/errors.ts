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
  RingAuthorityTransactDisabled: 7020,
  OwnerTagAccountMissing: 7021,
  InvalidForesterFee: 7022,
  InsufficientForesterFeeBalance: 7023,
  InvalidSystemProgram: 7024,
  EmptyDepositBatch: 7025,
  InvalidDepositAssetIndex: 7026,
  DuplicateDepositAsset: 7027,
  DepositAmountOverflow: 7028,
  UnreferencedDepositAsset: 7029,
  TooManyDepositAssets: 7030,
  TooManyInterfaceTransfers: 7031,
  ZeroInterfaceTransferAmount: 7032,
  TooManyPublicAssets: 7033,
  PublicAssetAmountOverflow: 7034,
  MismatchedCircuitType: 7035,
  SplTokenAuthorityMustSign: 7036,
  UnsupportedSplTokenProgram: 7037,
  InvalidSplTokenMint: 7038,
  UnsupportedToken2022Extension: 7039,
  ZeroNetInterfaceTransferAmount: 7040,
  SplAssetCounterAlreadyInitialized: 7041,
  RingPaused: 7042,
  NullifierAlreadyQueued: 7043,
  InsufficientNullifierPdaRent: 7044,
  NullifierPdaNotClosable: 7045,
  InvalidNullifierPda: 7046,
  InvalidTreeId: 7047,
  NullifierPdaTreeMismatch: 7048,
  TreeIdOverflow: 7049,
  InvalidReimbursementRecipient: 7050,
  NonCanonicalOutputUtxoHash: 7051,
  NonCanonicalInputNullifier: 7052,
  NonCanonicalPrivateTxHash: 7053,
  NonCanonicalRingDataHash: 7054,
  NonCanonicalDepositField: 7055,
  NonCanonicalRoot: 7056,
  NoClaimableTreeLamports: 7057,
  DepositBlindingDerivationFailed: 7058,
  RingNotActivated: 7059,
  TooManyExternalDataHashSlices: 7060,
  InvalidTreeContextCount: 7061,
  InputTreeIndexOutOfRange: 7062,
  InputsNotGroupedByTree: 7063,
  UnreferencedTreeContext: 7064,
  DuplicateInputTree: 7065,
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
