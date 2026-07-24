import type { Address } from "@zolana/interface";

import { decodeAddress, encodeAddress } from "./base58.js";
import { SmartAccountClientError, invalidInteger } from "./error.js";
import { sha256 } from "./sha256.js";

export const SMART_ACCOUNT_PROGRAM_ID_VALUE =
  "SMRTzfY6DfH5ik3TKiyLFfXexV8uSG3d2UksSCYdunG" as Address;

const textEncoder = new TextEncoder();
const SEED_PREFIX = textEncoder.encode("smart_account");
const PROGRAM_CONFIG_SEED = textEncoder.encode("program_config");
const SETTINGS_SEED = textEncoder.encode("settings");
const SMART_ACCOUNT_SEED = textEncoder.encode("smart_account");
const TREASURY_SEED = textEncoder.encode("treasury");
const PDA_MARKER = textEncoder.encode("ProgramDerivedAddress");
const U128_MAX = (1n << 128n) - 1n;
const FIELD_PRIME = (1n << 255n) - 19n;
const CURVE_D = mod(-121665n * inverse(121666n));
const SQRT_M1 = pow(2n, (FIELD_PRIME - 1n) / 4n);

export function programConfigAddress(): readonly [Address, number] {
  return findProgramAddress([SEED_PREFIX, PROGRAM_CONFIG_SEED]);
}

export function treasuryAddress(): Address {
  return findProgramAddress([SEED_PREFIX, TREASURY_SEED])[0];
}

export function settingsAddress(seed: bigint): readonly [Address, number] {
  if (typeof seed !== "bigint" || seed < 0n || seed > U128_MAX) {
    throw invalidInteger("settingsSeed", seed);
  }
  return findProgramAddress([SEED_PREFIX, SETTINGS_SEED, unsignedLittleEndian(seed, 16)]);
}

export function smartAccountAddress(
  settings: Address,
  accountIndex: number,
): readonly [Address, number] {
  assertUnsignedInteger("accountIndex", accountIndex, 0xff);
  return findProgramAddress([
    SEED_PREFIX,
    decodeAddress(settings),
    SMART_ACCOUNT_SEED,
    Uint8Array.of(accountIndex),
  ]);
}

export function assertUnsignedInteger(name: string, value: number, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw invalidInteger(name, value);
  }
}

export function unsignedLittleEndian(value: bigint, byteLength: number): Uint8Array {
  const bytes = new Uint8Array(byteLength);
  let remaining = value;
  for (let index = 0; index < byteLength; index += 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function findProgramAddress(seeds: readonly Uint8Array[]): readonly [Address, number] {
  const program = decodeAddress(SMART_ACCOUNT_PROGRAM_ID_VALUE);
  for (let bump = 0xff; bump >= 0; bump -= 1) {
    const digest = sha256(concatBytes(...seeds, Uint8Array.of(bump), program, PDA_MARKER));
    if (!isEd25519Point(digest)) return [encodeAddress(digest), bump];
  }
  throw new SmartAccountClientError(
    "SMART_ACCOUNT_INVALID_PDA",
    "unable to derive program address",
  );
}

function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function isEd25519Point(encoded: Uint8Array): boolean {
  const point = new Uint8Array(encoded);
  const finalByte = point[31] ?? 0;
  const sign = finalByte >>> 7;
  point[31] = finalByte & 0x7f;
  const y = littleEndianBigInt(point);
  if (y >= FIELD_PRIME) return false;

  const ySquared = mod(y * y);
  const xSquared = mod((ySquared - 1n) * inverse(CURVE_D * ySquared + 1n));
  let x = pow(xSquared, (FIELD_PRIME + 3n) / 8n);
  if (mod(x * x - xSquared) !== 0n) x = mod(x * SQRT_M1);
  if (mod(x * x - xSquared) !== 0n) return false;
  if (x === 0n && sign === 1) return false;
  return true;
}

function littleEndianBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index] ?? 0);
  }
  return value;
}

function inverse(value: bigint): bigint {
  return pow(mod(value), FIELD_PRIME - 2n);
}

function pow(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let factor = mod(base);
  let power = exponent;
  while (power > 0n) {
    if ((power & 1n) === 1n) result = mod(result * factor);
    factor = mod(factor * factor);
    power >>= 1n;
  }
  return result;
}

function mod(value: bigint): bigint {
  const remainder = value % FIELD_PRIME;
  return remainder >= 0n ? remainder : remainder + FIELD_PRIME;
}
