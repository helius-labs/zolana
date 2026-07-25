// The fixture and the artifact both come from `zolana-hasher`, so between them
// they cannot catch `zolana-hasher` being wrong. This is the second opinion:
// the implementation deleted in `ab2e2863`, which derives its round constants
// from the Grain LFSR through `@noble/curves` instead of reading arkworks'
// tables, and so shares neither code nor data with the artifact.
import { Field } from "@noble/curves/abstract/modular.js";
import { grainGenConstants, poseidon as createPoseidon } from "@noble/curves/abstract/poseidon.js";
import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/poseidon-parity-v1.json" with { type: "json" };
import { poseidon } from "../../src/poseidon.js";

const MODULUS = BigInt(fixture.field.modulus);
const PARTIAL_ROUNDS = fixture.parameters.perArity.map((arity) => arity.roundsPartial);
const Fp = Field(MODULUS);
const permutations = new Map<number, ReturnType<typeof createPoseidon>>();

function permutation(arity: number): ReturnType<typeof createPoseidon> {
  const cached = permutations.get(arity);
  if (cached !== undefined) return cached;
  const options = {
    Fp,
    t: arity + 1,
    roundsFull: fixture.parameters.roundsFull,
    roundsPartial: PARTIAL_ROUNDS[arity - 1] ?? 0,
    sboxPower: fixture.parameters.alpha,
  } as const;
  const generated = createPoseidon({ ...options, ...grainGenConstants(options) });
  permutations.set(arity, generated);
  return generated;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function bigIntToBytes(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** The deleted implementation, recovered from `ab2e2863^`. */
function grainPoseidon(inputs: readonly Uint8Array[]): string {
  const values = inputs.map((input) => bytesToBigInt(input));
  const state = permutation(values.length)([0n, ...values]);
  return bytesToHex(bigIntToBytes(state[0] ?? 0n));
}

// xorshift128+, fixed seed, so a failure names an input that reproduces.
function fieldSource(): () => Uint8Array {
  let low = 0x9e3779b97f4a7c15n;
  let high = 0xbf58476d1ce4e5b9n;
  const mask = (1n << 64n) - 1n;
  return function next(): Uint8Array {
    let value = 0n;
    for (let word = 0; word < 4; word += 1) {
      let x = low;
      const y = high;
      low = y;
      x ^= (x << 23n) & mask;
      high = (x ^ y ^ (x >> 17n) ^ (y >> 26n)) & mask;
      value = (value << 64n) | ((high + y) & mask);
    }
    return bigIntToBytes(value % MODULUS);
  };
}

const MAX_INPUTS = fixture.parameters.maxInputs;
const ZERO = new Uint8Array(32);
const ONE = bigIntToBytes(1n);
const BELOW_MODULUS = bigIntToBytes(MODULUS - 1n);
const NEXT_BELOW_MODULUS = bigIntToBytes(MODULUS - 2n);
const HIGH_BIT = bigIntToBytes(1n << 253n);

describe("the compiled hasher against an independent Poseidon", () => {
  const nextField = fieldSource();

  for (let arity = 1; arity <= MAX_INPUTS; arity += 1) {
    const width = arity;

    it(`agrees at the field edges for ${String(width)} inputs`, () => {
      const cases: readonly Uint8Array[][] = [
        Array.from({ length: width }, () => ZERO),
        Array.from({ length: width }, () => ONE),
        Array.from({ length: width }, () => BELOW_MODULUS),
        Array.from({ length: width }, () => NEXT_BELOW_MODULUS),
        Array.from({ length: width }, () => HIGH_BIT),
        Array.from({ length: width }, (_, index) => (index % 2 === 0 ? ZERO : BELOW_MODULUS)),
        Array.from({ length: width }, (_, index) => bigIntToBytes(BigInt(index) + 1n)),
      ];
      for (const inputs of cases) {
        expect(bytesToHex(poseidon(inputs))).toBe(grainPoseidon(inputs));
      }
    });

    it(`agrees over pseudorandom field elements for ${String(width)} inputs`, () => {
      for (let trial = 0; trial < 64; trial += 1) {
        const inputs = Array.from({ length: width }, () => nextField());
        expect(bytesToHex(poseidon(inputs))).toBe(grainPoseidon(inputs));
      }
    });
  }

  // Only arity 2 can show a swapped pair, and a permutation fed the inputs in
  // the wrong order is the divergence a same-arity fixture would not reveal.
  it("agrees on input order", () => {
    for (const pair of [
      [ZERO, ONE],
      [ONE, ZERO],
      [BELOW_MODULUS, ONE],
      [ONE, BELOW_MODULUS],
    ]) {
      expect(bytesToHex(poseidon(pair))).toBe(grainPoseidon(pair));
    }
  });
});
