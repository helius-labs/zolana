/** JSON.parse with duplicate-name and nesting rejection before model decoding. */
export function uniqueJson(text: string): unknown {
  let offset = 0;
  const invalid = (): never => {
    throw new Error("invalid policy JSON");
  };
  const space = (): void => {
    while (/^[\x20\t\r\n]$/u.test(text[offset] ?? "")) offset++;
  };
  const string = (): string => {
    if (text[offset] !== '"') return invalid();
    const start = offset++;
    while (offset < text.length) {
      const char = text[offset++];
      if (char === "\\") {
        offset++;
        continue;
      }
      if (char === '"') {
        const value: unknown = JSON.parse(text.slice(start, offset));
        if (typeof value !== "string") return invalid();
        return value;
      }
    }
    return invalid();
  };
  const value = (depth: number): void => {
    if (depth > 32) return invalid();
    space();
    const opening = text[offset];
    if (opening === '"') {
      string();
      return;
    }
    if (opening === "{" || opening === "[") {
      offset++;
      space();
      const closing = opening === "{" ? "}" : "]";
      const keys = new Set<string>();
      if (text[offset] === closing) {
        offset++;
        return;
      }
      for (;;) {
        space();
        if (opening === "{") {
          const key = string();
          if (keys.has(key)) return invalid();
          keys.add(key);
          space();
          if (text[offset++] !== ":") return invalid();
        }
        value(depth + 1);
        space();
        if (text[offset] === closing) {
          offset++;
          return;
        }
        if (text[offset++] !== ",") return invalid();
      }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(
      text.slice(offset),
    );
    if (token === null) return invalid();
    offset += token[0].length;
  };
  value(0);
  space();
  if (offset !== text.length) return invalid();
  const parsed: unknown = JSON.parse(text);
  return parsed;
}
