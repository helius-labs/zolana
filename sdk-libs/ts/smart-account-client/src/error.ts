export class SmartAccountClientError extends Error {
  readonly code: `SMART_ACCOUNT_${string}`;
  readonly details?: Readonly<Record<string, unknown>>;
  override readonly cause?: unknown;

  constructor(
    code: `SMART_ACCOUNT_${string}`,
    message: string,
    options?: Readonly<{
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    }>,
  ) {
    super(message);
    this.name = "SmartAccountClientError";
    this.code = code;
    if (options?.details !== undefined) this.details = { ...options.details };
    if (options?.cause !== undefined) this.cause = options.cause;
  }
}

export function invalidInteger(name: string, value: number | bigint): SmartAccountClientError {
  return new SmartAccountClientError("SMART_ACCOUNT_INVALID_INTEGER", `${name} is out of range`, {
    details: { name, value: value.toString() },
  });
}
