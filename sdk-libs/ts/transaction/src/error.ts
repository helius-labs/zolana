export type TransactionErrorCode = `TRANSACTION_${string}`;

export class TransactionError extends Error {
  readonly code: TransactionErrorCode;
  readonly details: Readonly<Record<string, unknown>> | undefined;
  override readonly cause: unknown;

  constructor(
    code: TransactionErrorCode,
    details?: Readonly<Record<string, unknown>>,
    cause?: unknown,
  ) {
    super(code);
    this.name = "TransactionError";
    this.code = code;
    this.details = details;
    this.cause = cause;
  }
}

export function transactionError(
  code: TransactionErrorCode,
  details?: Readonly<Record<string, unknown>>,
  cause?: unknown,
): TransactionError {
  return new TransactionError(code, details, cause);
}
