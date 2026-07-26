export class KitError extends Error {
  readonly code: `KIT_${string}`;
  readonly details?: Readonly<Record<string, unknown>>;
  override readonly cause?: unknown;

  constructor(
    code: `KIT_${string}`,
    message: string,
    options?: Readonly<{
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    }>,
  ) {
    super(message);
    this.name = "KitError";
    this.code = code;
    if (options?.details !== undefined) this.details = { ...options.details };
    if (options?.cause !== undefined) this.cause = options.cause;
  }
}
