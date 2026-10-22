import { checkMergeRingDataHash } from "../../transaction/merge-data.js";
import { DUMMY_DOMAIN, UTXO_DOMAIN } from "../../interface/program.js";
import { ClientError, fromClientCause } from "../error.js";
import { field } from "../internal.js";
import type { CircuitUtxo, TransferOutput } from "./types.js";

/**
 * Owner-signed ring proofs publish an identity only for default-ring outputs.
 * A missing marker otherwise forces a zero identity, which nobody can spend.
 * Check the circuit domain, not the amount or a caller's dummy flag. Padding
 * retains its existing tag rules and never grants an exemption to a real note.
 */
export function checkRingOutputOwners(
  outputs: readonly TransferOutput[],
  published: readonly bigint[],
): void {
  if (outputs.length !== published.length) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  for (const [index, output] of outputs.entries()) {
    // Classify canonical field values so aliases of zero cannot pass as owners
    // or nondefault rings before the request reaches its serialization boundary.
    field(output.circuit.domain, "domain");
    field(output.isDummy, "isDummy");
    field(output.circuit.ringProgramId, "ringProgramId");
    field(output.ownerPublicKeyHash, "ownerPkHash");
    const publishedOwner = published[index];
    if (publishedOwner === undefined) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    field(publishedOwner, "publishedOutputOwnerPkHash");
    if (output.circuit.domain === BigInt(DUMMY_DOMAIN) && output.isDummy === 1n) continue;
    const isDefault = output.circuit.ringProgramId === 0n;
    if (
      output.circuit.domain !== BigInt(UTXO_DOMAIN) ||
      output.isDummy !== 0n ||
      (isDefault && output.ownerPublicKeyHash === 0n) ||
      publishedOwner !== (isDefault ? output.ownerPublicKeyHash : 0n)
    ) {
      throw new ClientError("CLIENT_OUTPUT_OWNER_MARKER_MISMATCH", { details: { index } });
    }
  }
}

/** Apply the same merge invariant to structural local and indexed proof requests. */
export function checkMergeRingData(
  inputs: readonly Readonly<{ circuit: CircuitUtxo }>[],
  output: TransferOutput,
  expected: bigint,
): void {
  try {
    checkMergeRingDataHash(output.circuit.ringDataHash, expected, "output");
    for (const [index, input] of inputs.entries()) {
      if (input.circuit.domain !== BigInt(DUMMY_DOMAIN))
        checkMergeRingDataHash(input.circuit.ringDataHash, expected, index);
    }
  } catch (cause) {
    throw fromClientCause(cause);
  }
}
