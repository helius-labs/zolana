import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/program-libs-parity-v1.json" with { type: "json" };
import { bigintToBytes, bytesToBigInt, hashChain } from "../../src/internal.js";

const chain = fixture.hasher.hashChain;

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fieldsOf(inputs: readonly string[]): readonly bigint[] {
  return inputs.map((input) => bytesToBigInt(hexToBytes(input)));
}

function chainHex(inputs: readonly string[]): string {
  return bytesToHex(bigintToBytes(hashChain(fieldsOf(inputs))));
}

function vectorNamed(name: string): (typeof chain.createTwoInputsHashChain)[number] {
  const found = chain.createTwoInputsHashChain.find((entry) => entry.name === name);
  if (found === undefined) throw new Error(`the fixture has no two-input vector ${name}`);
  return found;
}

// The client folds the proof public inputs with its own `hashChain`, and the
// sibling suite in `@zolana/transaction` says nothing about this copy. These are
// the same `create_hash_chain_from_slice` vectors that copy is held to.
describe("client hashChain against create_hash_chain_from_slice", () => {
  for (const vector of chain.createHashChainFromSlice) {
    it(`matches Rust for ${vector.name}`, () => {
      expect(chainHex(vector.inputs)).toBe(vector.output);
    });
  }

  it("returns 32 zero bytes for an empty chain rather than throwing", () => {
    expect(chain.emptyReturnsZero).toBe(true);
    expect(chainHex([])).toBe("0".repeat(64));
  });
});

// `create_two_inputs_hash_chain` is the other half of `hash_chain.rs` and is
// deliberately not ported: outside the hasher's own tests and the generator that
// wrote these vectors, nothing in Rust calls it, so a port would be unreachable.
// The vectors stay recorded rather than compared, as `merkle-tree` records
// `Sha256BE`. What the assertions hold is that the record cannot rot silently and
// that `hashChain` is not a stand-in for the function, which is the substitution
// the shape of the two names invites.
describe("program-libs/hasher/src/hash_chain.rs create_two_inputs_hash_chain", () => {
  it("records the Rust vectors and the length-mismatch rejection", () => {
    expect(chain.createTwoInputsHashChain.map((vector) => vector.name)).toEqual([
      "empty",
      "one-pair",
      "two-pairs",
      "four-pairs",
    ]);
    expect(chain.twoInputsLengthMismatch.code).toBe(7005);
  });

  // The seed is H(first[0], second[0]), which one pair makes indistinguishable
  // from a two-element chain. Rust's own output says so, so the coincidence is
  // pinned rather than assumed.
  it("agrees with a two-element chain at exactly one pair", () => {
    const onePair = vectorNamed("one-pair");
    expect(chainHex([...onePair.first, ...onePair.second])).toBe(onePair.output);
  });

  // From two pairs on it folds three inputs at a time, H(H(i-1), first[i],
  // second[i]), an arity-3 step no arity-2 chain reaches.
  for (const vector of chain.createTwoInputsHashChain.filter((entry) => entry.first.length > 1)) {
    it(`is not any hashChain composition for ${vector.name}`, () => {
      const interleaved = vector.first.flatMap((value, index) => [
        value,
        String(vector.second[index]),
      ]);
      expect(chainHex([...vector.first, ...vector.second])).not.toBe(vector.output);
      expect(chainHex(interleaved)).not.toBe(vector.output);
      expect(
        bytesToHex(
          bigintToBytes(
            hashChain([hashChain(fieldsOf(vector.first)), hashChain(fieldsOf(vector.second))]),
          ),
        ),
      ).not.toBe(vector.output);
    });
  }
});
