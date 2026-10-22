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
  const location = typeof error?.location === "string" ? { location: error.location } : {};
  return {
    error: { name: error?.name ?? "Error", message: String(error?.message ?? error), ...location },
  };
}

// These manifests are created by the native fixture generator and served by
// the local test server. Applications must pin their digest in trusted metadata.
export async function keyChecksum(url) {
  const text = new TextDecoder().decode(await fetchBytes(`${url}.sha256`));
  const digest = text.trim().split(/\s+/)[0];
  if (!/^[0-9a-fA-F]{64}$/.test(digest)) throw new Error("invalid key checksum");
  return Uint8Array.from(digest.match(/../g), (byte) => parseInt(byte, 16));
}
