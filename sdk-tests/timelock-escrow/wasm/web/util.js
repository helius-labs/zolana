export async function fetchBytes(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url}: ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

export function toBytes(source) {
  return source instanceof Uint8Array ? source : new Uint8Array(source);
}

export function plain(value) {
  if (value instanceof Uint8Array) {
    return Array.from(value);
  }
  if (typeof value === "bigint") {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`${value} does not fit a JSON number`);
    }
    return Number(value);
  }
  if (Array.isArray(value)) {
    return value.map(plain);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, plain(entry)]));
  }
  return value;
}

export function failure(error) {
  return { error: { name: error?.name ?? "Error", message: String(error?.message ?? error) } };
}
