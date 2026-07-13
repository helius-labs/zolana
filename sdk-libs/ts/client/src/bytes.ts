import { PublicKey } from "@solana/web3.js";

export type Bytes32 = Uint8Array;
export type Bytes31 = Uint8Array;
export type Bytes16 = Uint8Array;

export function assertLength(bytes: Uint8Array, length: number, name = "bytes"): Uint8Array {
  if (bytes.length !== length) {
    throw new Error(`${name} must be ${length} bytes, got ${bytes.length}`);
  }
  return bytes;
}

export function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const len = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

export function bigIntToBytes(value: bigint, length = 32): Uint8Array {
  if (value < 0n) throw new Error("cannot encode negative bigint");
  const out = new Uint8Array(length);
  let cursor = length - 1;
  let v = value;
  while (v > 0n && cursor >= 0) {
    out[cursor] = Number(v & 0xffn);
    v >>= 8n;
    cursor -= 1;
  }
  if (v > 0n) throw new Error(`bigint does not fit in ${length} bytes`);
  return out;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

export function rightAlign(bytes: Uint8Array, length = 32): Uint8Array {
  if (bytes.length > length) {
    throw new Error(`field element exceeds ${length} bytes`);
  }
  const out = new Uint8Array(length);
  out.set(bytes, length - bytes.length);
  return out;
}

export function u64Be(value: bigint | number): Uint8Array {
  const v = BigInt(value);
  if (v < 0n || v > 0xffff_ffff_ffff_ffffn) {
    throw new Error("u64 out of range");
  }
  return bigIntToBytes(v, 8);
}

export function u32Be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("u32 out of range");
  }
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

export function writeU16Le(out: number[], value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error("u16 out of range");
  }
  out.push(value & 0xff, (value >>> 8) & 0xff);
}

export function writeU64Le(out: number[], value: bigint | number): void {
  let v = BigInt(value);
  if (v < 0n || v > 0xffff_ffff_ffff_ffffn) {
    throw new Error("u64 out of range");
  }
  for (let i = 0; i < 8; i += 1) {
    out.push(Number(v & 0xffn));
    v >>= 8n;
  }
}

export function publicKeyBytes(key: PublicKey | Uint8Array | string): Uint8Array {
  if (key instanceof PublicKey) return key.toBytes();
  if (typeof key === "string") return new PublicKey(key).toBytes();
  return assertLength(key, 32, "public key");
}

export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function fromHex(hex: string): Uint8Array {
  const normalized = hex.startsWith("0x") ? hex.slice(2) : hex;
  const even = normalized.length % 2 === 0 ? normalized : `0${normalized}`;
  return new Uint8Array(Buffer.from(even, "hex"));
}

export function hexToBe32(hex: string): Uint8Array {
  const bytes = fromHex(hex);
  if (bytes.length <= 32) return rightAlign(bytes, 32);
  return bytes.slice(bytes.length - 32);
}
