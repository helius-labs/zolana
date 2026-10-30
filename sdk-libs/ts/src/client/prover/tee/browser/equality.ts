/** Equality for the JSON values compared by the pinned TUF model classes. */
export function isDeepStrictEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (typeof left !== "object" || left === null || typeof right !== "object" || right === null)
    return false;
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((value: unknown, index: number) => isDeepStrictEqual(value, right[index]))
    );
  }
  if (
    Object.getPrototypeOf(left) !== Object.prototype ||
    Object.getPrototypeOf(right) !== Object.prototype
  ) {
    throw new Error("TUF equality requires JSON objects");
  }
  const entries = Object.entries(left);
  const other = new Map<string, unknown>(Object.entries(right));
  return (
    entries.length === other.size &&
    entries.every(
      ([key, value]: [string, unknown]) =>
        other.has(key) && isDeepStrictEqual(value, other.get(key)),
    )
  );
}

export default { isDeepStrictEqual };
