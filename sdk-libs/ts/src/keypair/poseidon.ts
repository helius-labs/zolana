import { MAX_POSEIDON_INPUTS, poseidon as hash } from "../hasher/core.js";

import { KeypairError, wrapKeypairError } from "./error.js";

export function poseidon(inputs: readonly Uint8Array[]): Uint8Array {
  try {
    inputs.forEach((input, index) => {
      if (input.length > 32) {
        throw new KeypairError("KEYPAIR_FIELD_ELEMENT_TOO_LONG", {
          index,
          maximum: 32,
          actual: input.length,
        });
      }
    });
    if (inputs.length < 1 || inputs.length > MAX_POSEIDON_INPUTS) {
      throw new KeypairError("KEYPAIR_POSEIDON", {
        actual: inputs.length,
        minimum: 1,
        maximum: MAX_POSEIDON_INPUTS,
      });
    }
    return hash(inputs);
  } catch (error) {
    throw wrapKeypairError("KEYPAIR_POSEIDON", error);
  }
}
