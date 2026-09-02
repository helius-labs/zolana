export type InterfaceErrorCode = "INTERFACE_INVALID_ADDRESS" | "INTERFACE_INVALID_LENGTH" | "INTERFACE_INVALID_INTEGER" | "INTERFACE_INVALID_DISCRIMINATOR" | "INTERFACE_INVALID_ACCOUNT_DATA" | "INTERFACE_INVALID_SHAPE" | "INTERFACE_TRANSACTION_TOO_LARGE" | "INTERFACE_HASH" | "INTERFACE_CODEC";
export declare const ShieldedPoolError: Readonly<{
    readonly InvalidInstructionData: 7000;
    readonly InvalidTreeAccounts: 7001;
    readonly NullifierTreeUpdateFailed: 7002;
    readonly UnauthorizedCaller: 7003;
    readonly StateAppendFailed: 7004;
    readonly ExpiredTransaction: 7005;
    readonly InvalidTransactShape: 7006;
    readonly InvalidTransactProofEncoding: 7007;
    readonly TransactProofVerificationFailed: 7008;
    readonly InvalidSettlementAccounts: 7009;
    readonly PublicSettlementFailed: 7010;
    readonly InvalidSplAssetRegistry: 7011;
    readonly InvalidProtocolConfig: 7012;
    readonly TreePaused: 7013;
    readonly InvalidZoneConfig: 7014;
    readonly StaleNullifierRoot: 7015;
    readonly InvalidPda: 7016;
    readonly MergeDisabled: 7017;
    readonly InvalidUserRecord: 7018;
    readonly InvalidMergeShape: 7019;
    readonly InvalidMergeOutputScheme: 7020;
    readonly MismatchedTransactProofRail: 7021;
    readonly ZoneAuthorityTransactDisabled: 7022;
    readonly BothPublicAmountsSet: 7023;
    readonly MissingP256SigningKey: 7024;
    readonly OwnerTagAccountMissing: 7025;
    readonly InvalidForesterFee: 7026;
    readonly InsufficientForesterFeeBalance: 7027;
    readonly InvalidSystemProgram: 7028;
}>;
export type ShieldedPoolErrorName = keyof typeof ShieldedPoolError;
export type ShieldedPoolErrorCode = (typeof ShieldedPoolError)[ShieldedPoolErrorName];
export type DecodedShieldedPoolError = Readonly<{
    kind: "known";
    code: ShieldedPoolErrorCode;
    name: ShieldedPoolErrorName;
}> | Readonly<{
    kind: "unknown";
    code: number;
}>;
export declare function decodeShieldedPoolError(code: number): DecodedShieldedPoolError;
export declare class InterfaceError extends Error {
    readonly code: InterfaceErrorCode;
    readonly details?: Readonly<Record<string, unknown>>;
    readonly cause?: unknown;
    constructor(code: InterfaceErrorCode, details?: Readonly<Record<string, unknown>>, cause?: unknown);
}
