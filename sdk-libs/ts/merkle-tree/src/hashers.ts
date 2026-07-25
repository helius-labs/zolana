import { bn254_Fr } from "@noble/curves/bn254.js";
import { grainGenConstants, poseidon } from "@noble/curves/abstract/poseidon.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

import { bigintToBytes, bytes32, type Bytes32 } from "./bytes.js";
import type { Hasher32 } from "./merkle-tree.js";

export interface Hasher32WithBytes extends Hasher32 {
  hashBytes(value: Bytes32): Bytes32;
}

function createPoseidon(inputCount: 1 | 2): (inputs: readonly Bytes32[]) => Bytes32 {
  const width = inputCount + 1;
  const options = {
    Fp: bn254_Fr,
    t: width,
    roundsFull: 8,
    roundsPartial: inputCount === 1 ? 56 : 57,
    sboxPower: 5,
  };
  const permutation = poseidon({ ...options, ...grainGenConstants(options) });

  return function hash(inputs: readonly Bytes32[]): Bytes32 {
    const values = inputs.map(bytesToField);
    const output = permutation([0n, ...values])[0];
    if (output === undefined) {
      throw new Error("Poseidon permutation returned no output");
    }
    return bigintToBytes(output);
  };
}

function bytesToField(value: Bytes32): bigint {
  const checked = bytes32(value, "hashInput");
  let result = 0n;
  for (const byte of checked) {
    result = (result << 8n) | BigInt(byte);
  }
  if (result >= bn254_Fr.ORDER) {
    throw new Error("Poseidon input exceeds the BN254 scalar field");
  }
  return result;
}

function createDigestAdapter(digest: typeof sha256 | typeof keccak_256): Hasher32WithBytes {
  return {
    hash(left, right) {
      const state = digest.create();
      state.update(bytes32(left, "left"));
      state.update(bytes32(right, "right"));
      return bytes32(state.digest(), "hash");
    },
    hashBytes(value) {
      return bytes32(digest(bytes32(value, "value")), "hash");
    },
  };
}

const poseidonOne = createPoseidon(1);
const poseidonTwo = createPoseidon(2);

export const poseidonHasher: Hasher32WithBytes = {
  hash(left, right) {
    return poseidonTwo([bytes32(left, "left"), bytes32(right, "right")]);
  },
  hashBytes(value) {
    return poseidonOne([bytes32(value, "value")]);
  },
};

export const sha256Hasher = createDigestAdapter(sha256);
export const keccakHasher = createDigestAdapter(keccak_256);
