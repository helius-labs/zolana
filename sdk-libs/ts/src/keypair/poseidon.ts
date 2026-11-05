import { MAX_POSEIDON_INPUTS, poseidonOr, type HasherFailure } from "../hasher/index.js";

import { KeypairError, type KeypairErrorDetails } from "./error.js";

/** The hasher's `poseidon`, rejecting as `KEYPAIR_POSEIDON`. */
export function poseidon(inputs: readonly Uint8Array[]): Uint8Array {
  return poseidonOr(
    inputs,
    (failure) => new KeypairError("KEYPAIR_POSEIDON", failureDetails(failure), failure),
  );
}

function failureDetails({ code, details }: HasherFailure): KeypairErrorDetails | undefined {
  if (details.inputCount !== undefined) {
    return { actual: details.inputCount, minimum: 1, maximum: MAX_POSEIDON_INPUTS };
  }
  if (details.index === undefined) return undefined;
  if (code === "InvalidInputLength") {
    return { index: details.index, maximum: 32, actual: details.length ?? -1 };
  }
  return { index: details.index };
}
