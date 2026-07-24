import {
  canonicalShape as transactionCanonicalShape,
  resolveShape as transactionResolveShape,
} from "@zolana/transaction";

import { assemble, intoProver } from "./assembly.js";
import { ProverClient } from "./client.js";
import { compressProof } from "./proof.js";

export { assemble, compressProof, intoProver, ProverClient };
export type {
  AssembledTransfer,
  CompressedProof,
  Field,
  Proof,
  ProverInputs,
  Shape,
  SpendProof,
  TransferInput,
  TransferInputs,
  TransferOutput,
  TransferP256Inputs,
} from "./types.js";

export function canonicalShape(
  inputs: number,
  outputs: number,
): Readonly<{ inputs: number; outputs: number }> {
  return transactionCanonicalShape(inputs, outputs);
}

export function resolveShape(
  inputs: number,
  outputs: number,
): Readonly<{ inputs: number; outputs: number }> {
  return transactionResolveShape(inputs, outputs);
}
