import { ShieldedPoolError } from "./generated/error-codes.js";

export { ShieldedPoolError };

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
