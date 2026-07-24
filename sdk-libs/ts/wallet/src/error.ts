export type WalletErrorCode = `WALLET_${string}`;

export class WalletError extends Error {
  readonly code: WalletErrorCode;
  readonly details?: Readonly<Record<string, unknown>>;
  override readonly cause?: unknown;

  constructor(
    code: WalletErrorCode,
    options?: Readonly<{
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    }>,
  ) {
    super(code);
    this.name = "WalletError";
    this.code = code;
    if (options?.details !== undefined) this.details = Object.freeze({ ...options.details });
    if (options?.cause !== undefined) this.cause = options.cause;
  }
}

export function wrapWalletError(
  code: WalletErrorCode,
  cause: unknown,
  details?: Readonly<Record<string, unknown>>,
): WalletError {
  if (cause instanceof WalletError) return cause;
  return new WalletError(code, {
    ...(details === undefined ? {} : { details }),
    cause,
  });
}
