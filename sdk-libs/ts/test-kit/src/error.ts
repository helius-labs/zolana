export type TestKitErrorCode =
  | "TEST_KIT_ABORTED"
  | "TEST_KIT_FIXTURE"
  | "TEST_KIT_INVALID_CONFIG"
  | "TEST_KIT_PROCESS"
  | "TEST_KIT_READINESS"
  | "TEST_KIT_TIMEOUT";

export class TestKitError extends Error {
  readonly code: TestKitErrorCode;
  readonly details: Readonly<Record<string, unknown>> | undefined;
  override readonly cause: unknown;

  constructor(
    code: TestKitErrorCode,
    options: Readonly<{
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
    }> = {},
  ) {
    super(code, { cause: options.cause });
    this.name = "TestKitError";
    this.code = code;
    this.details = options.details;
    this.cause = options.cause;
  }
}
