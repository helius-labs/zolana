// The bundled TUF engine uses only these Ed25519/SHA-256 operations. The
// repository profile rejects other algorithms before entering the engine.
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

class Ed25519PublicKey {
  constructor(readonly bytes: Uint8Array) {}
}

export function createPublicKey(value: unknown): Ed25519PublicKey {
  if (
    typeof value !== "object" ||
    value === null ||
    !("key" in value) ||
    !(value.key instanceof Uint8Array) ||
    !("format" in value) ||
    value.format !== "der" ||
    !("type" in value) ||
    value.type !== "spki"
  )
    throw new Error("unsupported public key");
  const prefix = hexToBytes("302a300506032b6570032100");
  if (
    value.key.length !== prefix.length + 32 ||
    !equalBytes(value.key.subarray(0, prefix.length), prefix)
  ) {
    throw new Error("unsupported public key");
  }
  return new Ed25519PublicKey(value.key.slice(prefix.length));
}

export function verify(
  algorithm: unknown,
  data: unknown,
  options: unknown,
  signature: unknown,
): boolean {
  if (
    algorithm !== undefined ||
    !(data instanceof Uint8Array) ||
    !(signature instanceof Uint8Array) ||
    typeof options !== "object" ||
    options === null ||
    !("key" in options) ||
    !(options.key instanceof Ed25519PublicKey)
  )
    throw new Error("unsupported signature operation");
  return ed25519.verify(signature, data, options.key.bytes, { zip215: false });
}

class Sha256Hash {
  readonly #hash = sha256.create();
  update(value: Uint8Array | string): this {
    this.#hash.update(typeof value === "string" ? utf8ToBytes(value) : value);
    return this;
  }
  digest(encoding?: string): Uint8Array | string {
    const bytes = this.#hash.digest();
    if (encoding === undefined) return bytes;
    if (encoding !== "hex") throw new Error("unsupported digest encoding");
    return bytesToHex(bytes);
  }
}

export function createHash(algorithm: string): Sha256Hash {
  if (algorithm !== "sha256") throw new Error("unsupported hash");
  return new Sha256Hash();
}

export default { createPublicKey, verify, createHash };
