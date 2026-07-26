import { readFileSync } from "node:fs";

const readBytes = readFileSync as unknown as (path: URL) => Uint8Array;
const readText = readFileSync as unknown as (path: URL, encoding: "utf8") => string;

interface Manifest {
  readonly files: readonly Readonly<{ path: string; sha256: string }>[];
}

export function hexBytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
}

export function hex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function base58(value: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const digits = [0];
  for (const byte of value) {
    let carry = byte;
    for (let index = 0; index < digits.length; index++) {
      const next = (digits[index] ?? 0) * 256 + carry;
      digits[index] = next % 58;
      carry = Math.floor(next / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let prefix = "";
  for (let index = 0; index < value.length - 1 && value[index] === 0; index++) prefix += "1";
  return (
    prefix +
    digits
      .reverse()
      .map((digit) => alphabet[digit])
      .join("")
  );
}

export function fromBase58(value: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const bytes = [0];
  for (const character of value) {
    let carry = alphabet.indexOf(character);
    if (carry < 0) throw new Error("invalid base58");
    for (let index = 0; index < bytes.length; index++) {
      const next = (bytes[index] ?? 0) * 58 + carry;
      bytes[index] = next & 0xff;
      carry = next >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let index = 0; index < value.length - 1 && value[index] === "1"; index++) bytes.push(0);
  return Uint8Array.from(bytes.reverse());
}

export async function fixture<T>(path: string): Promise<T> {
  const fixtureUrl = new URL(`../../../fixtures/${path}.json`, import.meta.url);
  const manifestUrl = new URL("../../../fixtures/manifest.json", import.meta.url);
  const bytes = readBytes(fixtureUrl);
  const manifest = JSON.parse(readText(manifestUrl, "utf8")) as Manifest;
  const manifestPath = `${path}.json`;
  const entry = manifest.files.find((candidate) => candidate.path === manifestPath);
  if (entry === undefined) throw new Error(`missing fixture manifest entry: ${manifestPath}`);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", Uint8Array.from(bytes));
  if (hex(new Uint8Array(digest)) !== entry.sha256) {
    throw new Error(`fixture hash mismatch: ${manifestPath}`);
  }
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

export function walletFixture<T>(name: string): Promise<T> {
  return fixture<T>(`wallet/${name}`);
}
