import { addressBytes, copyBytes, fail, sha256, unsigned, unsignedBigint } from "./internal.js";
import { poseidon } from "./merge-utils.js";
import { CACHE_CAPACITY } from "./state.js";
import { treeIdField } from "./tree-slot.js";
import type { Address, Bytes32, CacheAccess, CacheWrite } from "./types.js";

const U64_MAX = (1n << 64n) - 1n;
const CACHE_WRITE_DOMAIN = new TextEncoder().encode("cache_write");

export const MAX_CACHE_WRITES = 8;
export const CACHE_WRITE_NONE: CacheWrite = Object.freeze({ output: 0xff, slot: 0xff });
export const NO_CACHE_WRITES: readonly CacheWrite[] = Object.freeze(
  Array.from({ length: MAX_CACHE_WRITES }, () => CACHE_WRITE_NONE),
);

export type CachedInputFields = readonly [Bytes32, Bytes32];

function zero(): Bytes32 {
  return new Uint8Array(32) as Bytes32;
}

function rightHashChain4(values: readonly Bytes32[]): Bytes32 {
  const last = values.at(-1);
  if (last === undefined) return zero();
  let chain = last;
  for (let end = values.length - 1; end > 0;) {
    const start = Math.max(end - 3, 0);
    const group = values.slice(start, end);
    chain = poseidon([...group, ...Array.from({ length: 3 - group.length }, zero), chain]);
    end = start;
  }
  return copyBytes(chain, 32, "cacheReadHashChain") as Bytes32;
}

function popcount(value: bigint): number {
  let count = 0;
  for (let rest = value; rest !== 0n; rest >>= 1n) count += Number(rest & 1n);
  return count;
}

function isU64(value: unknown): value is bigint {
  return typeof value === "bigint" && value >= 0n && value <= U64_MAX;
}

export function emptyCachedInputFields(inputCount: number): CachedInputFields {
  const count = unsigned(inputCount, CACHE_CAPACITY, "inputCount");
  return Object.freeze([zero(), rightHashChain4(Array.from({ length: count }, zero))] as const);
}

export function cachedInputFields(
  readBitmap: bigint,
  treeId: number,
  slots: readonly Uint8Array[],
  inputCount: number,
): CachedInputFields {
  const bitmap = unsignedBigint(readBitmap, U64_MAX, "readBitmap");
  const treeIdElement = treeIdField(treeId);
  const count = unsigned(inputCount, CACHE_CAPACITY, "inputCount");
  if (slots.length !== CACHE_CAPACITY) {
    fail("INTERFACE_INVALID_LENGTH", {
      name: "slots",
      expected: CACHE_CAPACITY,
      actual: slots.length,
    });
  }
  if (bitmap === 0n) return emptyCachedInputFields(count);
  if (bitmap >> BigInt(CACHE_CAPACITY) !== 0n || popcount(bitmap) > count) {
    fail("INTERFACE_INVALID_SHAPE", { name: "readBitmap", inputs: count });
  }
  const reads = slots.flatMap((slot, index) =>
    ((bitmap >> BigInt(index)) & 1n) === 1n
      ? [copyBytes(slot, 32, `slots[${String(index)}]`) as Bytes32]
      : [],
  );
  const list = [...reads, ...Array.from({ length: count - reads.length }, zero)];
  return Object.freeze([treeIdElement, rightHashChain4(list)] as const);
}

function writeSlotBytes(writeSlots: readonly CacheWrite[]): Uint8Array {
  if (writeSlots.length !== MAX_CACHE_WRITES) {
    fail("INTERFACE_INVALID_LENGTH", {
      name: "writeSlots",
      expected: MAX_CACHE_WRITES,
      actual: writeSlots.length,
    });
  }
  const bytes = new Uint8Array(2 * MAX_CACHE_WRITES);
  writeSlots.forEach((entry, index) => {
    bytes[2 * index] = unsigned(entry.output, 0xff, `writeSlots[${String(index)}].output`);
    bytes[2 * index + 1] = unsigned(entry.slot, 0xff, `writeSlots[${String(index)}].slot`);
  });
  return bytes;
}

export function bindCacheWrite(
  externalDataHash: Uint8Array,
  destination?: Readonly<{ cache: Address; writeSlots: readonly CacheWrite[] }>,
): Bytes32 {
  const hash = copyBytes(externalDataHash, 32, "externalDataHash");
  if (destination === undefined) return hash as Bytes32;
  const writes = writeSlotBytes(destination.writeSlots);
  const cache = addressBytes(destination.cache, "cache");
  const preimage = new Uint8Array(CACHE_WRITE_DOMAIN.length + 32 + 32 + writes.length);
  preimage.set(CACHE_WRITE_DOMAIN, 0);
  preimage.set(hash, CACHE_WRITE_DOMAIN.length);
  preimage.set(cache, CACHE_WRITE_DOMAIN.length + 32);
  preimage.set(writes, CACHE_WRITE_DOMAIN.length + 64);
  const digest = sha256(preimage);
  digest[0] = 0;
  return digest as Bytes32;
}

function isNone(entry: CacheWrite): boolean {
  return entry.output === CACHE_WRITE_NONE.output && entry.slot === CACHE_WRITE_NONE.slot;
}

export function cacheWrites(writeSlots: readonly CacheWrite[]): readonly CacheWrite[] {
  const used = writeSlots.findIndex(isNone);
  return writeSlots.slice(0, used === -1 ? writeSlots.length : used);
}

export function writesCache(access: CacheAccess): boolean {
  const first = access.writeSlots[0];
  return first !== undefined && !isNone(first);
}

export function validCacheWrites(writeSlots: readonly CacheWrite[], outputCount: number): boolean {
  if (!Array.isArray(writeSlots) || writeSlots.length !== MAX_CACHE_WRITES) return false;
  if (!writeSlots.every((entry) => isByte(entry.output) && isByte(entry.slot))) return false;
  const writes = cacheWrites(writeSlots);
  return (
    writeSlots.slice(writes.length).every(isNone) &&
    writes.every((entry) => entry.output < outputCount && entry.slot < CACHE_CAPACITY) &&
    writes.every((entry, index) =>
      writes
        .slice(index + 1)
        .every((later) => later.slot !== entry.slot && later.output !== entry.output),
    )
  );
}

function isByte(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 0xff;
}

export function validCacheAccess(
  access: CacheAccess,
  inputCount: number,
  outputCount: number,
): boolean {
  if (!isU64(access.readBitmap) || !Number.isSafeInteger(inputCount) || inputCount < 0) {
    return false;
  }
  return (
    access.readBitmap >> BigInt(CACHE_CAPACITY) === 0n &&
    popcount(access.readBitmap) <= inputCount &&
    validCacheWrites(access.writeSlots, outputCount) &&
    (access.readBitmap !== 0n || writesCache(access))
  );
}
