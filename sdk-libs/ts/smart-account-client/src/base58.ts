import type { Address } from "@zolana/interface";

import { SmartAccountClientError } from "./error.js";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE = 58n;
const ADDRESS_LENGTH = 32;
const alphabetIndexes = new Map(Array.from(ALPHABET, (character, index) => [character, index]));

export function decodeAddress(address: Address): Uint8Array {
  if (typeof address !== "string" || address.length === 0) {
    throw invalidAddress(address);
  }

  let value = 0n;
  for (const character of address) {
    const index = alphabetIndexes.get(character);
    if (index === undefined) throw invalidAddress(address);
    value = value * BASE + BigInt(index);
  }

  const bytes: number[] = [];
  while (value > 0n) {
    bytes.push(Number(value & 0xffn));
    value >>= 8n;
  }
  bytes.reverse();

  let leadingZeros = 0;
  while (leadingZeros < address.length && address[leadingZeros] === "1") leadingZeros += 1;
  const decoded = new Uint8Array(leadingZeros + bytes.length);
  decoded.set(bytes, leadingZeros);

  if (decoded.length !== ADDRESS_LENGTH || encodeAddress(decoded) !== address) {
    throw invalidAddress(address);
  }
  return decoded;
}

export function encodeAddress(bytes: Uint8Array): Address {
  if (bytes.length !== ADDRESS_LENGTH) {
    throw new SmartAccountClientError(
      "SMART_ACCOUNT_INVALID_ADDRESS",
      "address bytes must contain 32 bytes",
      { details: { actualLength: bytes.length, expectedLength: ADDRESS_LENGTH } },
    );
  }

  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);

  let encoded = "";
  while (value > 0n) {
    encoded = ALPHABET.charAt(Number(value % BASE)) + encoded;
    value /= BASE;
  }

  let leadingZeros = 0;
  while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) leadingZeros += 1;
  return `${"1".repeat(leadingZeros)}${encoded}` as Address;
}

function invalidAddress(value: unknown): SmartAccountClientError {
  return new SmartAccountClientError("SMART_ACCOUNT_INVALID_ADDRESS", "invalid Solana address", {
    details: { value: typeof value === "string" ? value : typeof value },
  });
}
