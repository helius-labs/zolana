export type ClientErrorCode = `CLIENT_${string}`;

export class ClientError extends Error {
  readonly code: ClientErrorCode;
  readonly details?: Readonly<Record<string, unknown>>;
  override readonly cause?: unknown;

  constructor(
    code: ClientErrorCode,
    options: Readonly<{
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    }> = {},
  ) {
    super(code);
    this.name = "ClientError";
    this.code = code;
    if (options.details !== undefined) this.details = Object.freeze({ ...options.details });
    if (options.cause !== undefined) this.cause = options.cause;
  }
}
