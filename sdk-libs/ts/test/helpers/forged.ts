/** Deliberately mistyped test input, the cast gate bans ad hoc double casts. */
export function forged<T>(value: unknown): T {
  return value as T;
}
