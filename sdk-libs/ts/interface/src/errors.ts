export type InterfaceErrorCode =
  | "INTERFACE_INVALID_ADDRESS"
  | "INTERFACE_INVALID_LENGTH"
  | "INTERFACE_INVALID_INTEGER"
  | "INTERFACE_INVALID_DISCRIMINATOR"
  | "INTERFACE_INVALID_ACCOUNT_DATA"
  | "INTERFACE_INVALID_PDA"
  | "INTERFACE_CODEC";

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
