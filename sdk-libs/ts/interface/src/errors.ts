export type InterfaceErrorCode =
  | "INTERFACE_INVALID_ADDRESS"
  | "INTERFACE_INVALID_LENGTH"
  | "INTERFACE_INVALID_INTEGER"
  | "INTERFACE_INVALID_DISCRIMINATOR"
  | "INTERFACE_INVALID_ACCOUNT_DATA"
  | "INTERFACE_INVALID_PDA"
  | "INTERFACE_INVALID_SHAPE"
  | "INTERFACE_INVALID_TRANSACTION"
  | "INTERFACE_SIGNER_NOT_REQUIRED"
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
  InvalidZoneConfig: 7014,
  StaleNullifierRoot: 7015,
  InvalidPda: 7016,
  MergeDisabled: 7017,
  InvalidUserRecord: 7018,
  InvalidMergeShape: 7019,
  InvalidMergeOutputScheme: 7020,
  MismatchedTransactProofRail: 7021,
  ZoneAuthorityTransactDisabled: 7022,
  BothPublicAmountsSet: 7023,
  MissingP256SigningKey: 7024,
  OwnerTagAccountMissing: 7025,
  InvalidForesterFee: 7026,
  InsufficientForesterFeeBalance: 7027,
  InvalidSystemProgram: 7028,
} as const);

export type ShieldedPoolErrorName = keyof typeof ShieldedPoolError;
export type ShieldedPoolErrorCode = (typeof ShieldedPoolError)[ShieldedPoolErrorName];

/**
 * Static `Display` strings from Rust `ShieldedPoolError` (`thiserror`). None
 * interpolate values; a caller mapping codes across languages can compare these
 * literally against `error.to_string()` on the Rust side.
 */
export const ShieldedPoolErrorMessages = Object.freeze({
  InvalidInstructionData: "invalid instruction data",
  InvalidTreeAccounts: "pool tree accounts are invalid",
  NullifierTreeUpdateFailed: "nullifier tree maintenance failed",
  UnauthorizedCaller: "caller is not authorized",
  StateAppendFailed: "state sub-tree append failed",
  ExpiredTransaction: "transaction has expired",
  InvalidTransactShape: "transact instruction shape is invalid",
  InvalidTransactProofEncoding: "transact proof encoding is invalid",
  TransactProofVerificationFailed: "transact proof verification failed",
  InvalidSettlementAccounts: "transact settlement accounts are invalid",
  PublicSettlementFailed: "transact public settlement failed",
  InvalidSplAssetRegistry: "SPL asset registry account is invalid",
  InvalidProtocolConfig: "protocol config account is invalid",
  TreePaused: "pool tree is paused",
  InvalidZoneConfig: "zone config account is invalid",
  StaleNullifierRoot: "nullifier root index references a zeroed (stale) root-history slot",
  InvalidPda: "account address does not match its canonical PDA derivation",
  MergeDisabled: "merging is not enabled for this user",
  InvalidUserRecord: "user record account is invalid",
  InvalidMergeShape: "merge_transact instruction shape is invalid",
  InvalidMergeOutputScheme: "merge output ciphertext must be verifiably encrypted",
  MismatchedTransactProofRail: "transact proof rail does not match the instruction inputs",
  ZoneAuthorityTransactDisabled: "zone_authority_transact is disabled for this zone",
  BothPublicAmountsSet:
    "transact sets both public_sol_amount and public_spl_amount; at most one is allowed",
  MissingP256SigningKey:
    "output owner tag references the p256 signing key but p256_signing_pk_x is absent",
  OwnerTagAccountMissing: "output owner tag account index is out of range",
  InvalidForesterFee:
    "forester fee calculation overflowed or used an invalid tree configuration",
  InsufficientForesterFeeBalance:
    "tree does not contain enough fee funds to reimburse the forester",
  InvalidSystemProgram: "system program account is invalid",
} as const satisfies Record<ShieldedPoolErrorName, string>);

const shieldedPoolErrorNames = new Map<number, ShieldedPoolErrorName>(
  Object.entries(ShieldedPoolError).map(([name, code]) => [code, name as ShieldedPoolErrorName]),
);

export type DecodedShieldedPoolError =
  | Readonly<{
      kind: "known";
      code: ShieldedPoolErrorCode;
      name: ShieldedPoolErrorName;
      message: string;
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
    : Object.freeze({
        kind: "known",
        code: code as ShieldedPoolErrorCode,
        name,
        message: ShieldedPoolErrorMessages[name],
      });
}

export class InterfaceError extends Error {
  readonly code: InterfaceErrorCode;
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
    if (details !== undefined) this.details = details;
    if (cause !== undefined) this.cause = cause;
  }
}
