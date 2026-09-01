/** @internal Key names that must never reach a thrown error's details. */
export const SECRET_KEY_PATTERN = /(secret|private|seed|blinding|nonce|scalar|signature)/iu;

/**
 * The `toJSON` shape of SDK errors, `causeCodes` lists the wrapped operation
 * chain outermost first.
 */
export interface ErrorEnvelope {
  readonly name: string;
  readonly code: string;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly causeCode?: string;
  readonly causeCodes?: readonly string[];
}

/** @internal Primitives survive, secret-named keys and everything else do not. */
export function sanitizeDetails(
  details: Readonly<Record<string, unknown>> | undefined,
): Readonly<Record<string, unknown>> | undefined {
  if (details === undefined) return undefined;
  const entries = Object.entries(details).flatMap(([key, value]) => {
    if (SECRET_KEY_PATTERN.test(key)) return [];
    const safe = sanitizeValue(value);
    return safe === undefined ? [] : [[key, safe] as const];
  });
  if (entries.length === 0) return undefined;
  return Object.freeze(Object.fromEntries(entries));
}

function sanitizeValue(value: unknown): unknown {
  switch (typeof value) {
    case "string":
    case "number":
    case "boolean":
      return value;
    case "bigint":
      return value.toString();
    default:
      return undefined;
  }
}

/** @internal */
export function extractCauseCode(cause: unknown): string | undefined {
  if (typeof cause !== "object" || cause === null) return undefined;
  const code = (cause as Readonly<{ code?: unknown }>).code;
  return typeof code === "string" ? code : undefined;
}

/** @internal The chain the wrapped cause carries, its own code first. */
export function extractCauseCodes(cause: unknown): readonly string[] {
  const code = extractCauseCode(cause);
  if (code === undefined) return [];
  const nested = (cause as Readonly<{ causeCodes?: unknown }>).causeCodes;
  if (Array.isArray(nested) && nested.every((entry) => typeof entry === "string")) {
    return [code, ...(nested as readonly string[])];
  }
  return [code];
}

/** @internal Kept for debugging, invisible to enumeration and serialization. */
export function hideCause(error: Error, cause: unknown): void {
  if (cause === undefined) return;
  Object.defineProperty(error, "cause", {
    value: cause,
    enumerable: false,
    writable: false,
    configurable: true,
  });
}
