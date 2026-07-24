import { Field } from "@noble/curves/abstract/modular.js";
import { grainGenConstants, poseidon as createPoseidon } from "@noble/curves/abstract/poseidon.js";

import { bigIntToBytes, bytesToBigInt } from "./bytes.js";
import { KeypairError, wrapKeypairError } from "./error.js";

const BN254_MODULUS =
  21_888_242_871_839_275_222_246_405_745_257_275_088_548_364_400_416_034_343_698_204_186_575_808_495_617n;
const PARTIAL_ROUNDS = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68] as const;
const Fp = Field(BN254_MODULUS);
const permutations = new Map<number, ReturnType<typeof createPoseidon>>();

function permutation(inputCount: number): ReturnType<typeof createPoseidon> {
  const cached = permutations.get(inputCount);
  if (cached) return cached;
  if (inputCount < 1 || inputCount > PARTIAL_ROUNDS.length) {
    throw new KeypairError("KEYPAIR_HASH", { inputCount });
  }
  const roundsPartial = PARTIAL_ROUNDS[inputCount - 1];
  if (roundsPartial === undefined) {
    throw new KeypairError("KEYPAIR_HASH", { inputCount });
  }
  const options = {
    Fp,
    t: inputCount + 1,
    roundsFull: 8,
    roundsPartial,
    sboxPower: 5,
  } as const;
  const generated = createPoseidon({ ...options, ...grainGenConstants(options) });
  permutations.set(inputCount, generated);
  return generated;
}

export function poseidon(inputs: readonly Uint8Array[]): Uint8Array {
  try {
    const values = inputs.map((input, index) => {
      if (input.length > 32) {
        throw new KeypairError("KEYPAIR_HASH", { index, maximum: 32, actual: input.length });
      }
      const value = bytesToBigInt(input);
      if (value >= BN254_MODULUS) {
        throw new KeypairError("KEYPAIR_HASH", { index, reason: "nonCanonicalField" });
      }
      return value;
    });
    const result = permutation(values.length)([0n, ...values])[0];
    if (result === undefined) throw new KeypairError("KEYPAIR_HASH");
    return bigIntToBytes(result);
  } catch (error) {
    throw wrapKeypairError("KEYPAIR_HASH", error);
  }
}
