import {
  poseidon1,
  poseidon2,
  poseidon3,
  poseidon4,
  poseidon5,
  poseidon6,
  poseidon7,
  poseidon8,
  poseidon9,
  poseidon10,
  poseidon11,
  poseidon12,
  poseidon13,
  poseidon14,
  poseidon15,
  poseidon16,
} from "poseidon-lite";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { bigIntToBytes, bytesToBigInt, rightAlign } from "./bytes.js";

const POSEIDON = [
  undefined,
  poseidon1,
  poseidon2,
  poseidon3,
  poseidon4,
  poseidon5,
  poseidon6,
  poseidon7,
  poseidon8,
  poseidon9,
  poseidon10,
  poseidon11,
  poseidon12,
  poseidon13,
  poseidon14,
  poseidon15,
  poseidon16,
] as const;

export function poseidon(inputs: readonly Uint8Array[]): Uint8Array {
  if (inputs.length === 0 || inputs.length > 16) {
    throw new Error(`unsupported poseidon arity ${inputs.length}`);
  }
  const fn = POSEIDON[inputs.length];
  if (!fn) throw new Error(`unsupported poseidon arity ${inputs.length}`);
  const fields = inputs.map((input) => bytesToBigInt(input));
  return bigIntToBytes(fn(fields), 32);
}

export function splitBe128(value: Uint8Array): [Uint8Array, Uint8Array] {
  if (value.length !== 32) {
    throw new Error(`value must be 32 bytes, got ${value.length}`);
  }
  const low = new Uint8Array(32);
  const high = new Uint8Array(32);
  high.set(value.slice(0, 16), 16);
  low.set(value.slice(16, 32), 16);
  return [low, high];
}

export function hashField(value: Uint8Array): Uint8Array {
  const [low, high] = splitBe128(value);
  return poseidon([low, high]);
}

export function boolFe(value: boolean): Uint8Array {
  const out = new Uint8Array(32);
  if (value) out[31] = 1;
  return out;
}

export function feRightAlign(bytes: Uint8Array): Uint8Array {
  return rightAlign(bytes, 32);
}

export function sha256(bytes: Uint8Array): Uint8Array {
  return nobleSha256(bytes);
}

export function sha256Be(bytes: Uint8Array): Uint8Array {
  const digest = new Uint8Array(nobleSha256(bytes));
  digest[0] = 0;
  return digest;
}
