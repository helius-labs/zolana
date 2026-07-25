import { assemble, createDummyTransferInput, intoProver } from "./assembly.js";
import {
  DEFAULT_ASYNC_POLL_CONFIG,
  PROVE_PATH,
  ProverClient,
  SERVER_ADDRESS,
  proveMerge,
  proveMergeZone,
} from "./client.js";
import { compressProof } from "./proof.js";

export {
  DEFAULT_ASYNC_POLL_CONFIG,
  PROVE_PATH,
  ProverClient,
  SERVER_ADDRESS,
  assemble,
  compressProof,
  createDummyTransferInput,
  intoProver,
  proveMerge,
  proveMergeZone,
};
export { compressedProof, parseProof } from "./proof.js";
export type { AsyncPollConfig } from "./client.js";
export type {
  AssembledTransfer,
  CompressedProof,
  Field,
  MergeInputs,
  P256Proof,
  Proof,
  ProverInputs,
  Shape,
  SpendProof,
  TransferInput,
  TransferInputs,
  TransferOutput,
  TransferP256Inputs,
} from "./types.js";

export {
  SPP_SUPPORTED_SHAPES,
  canonicalShape,
  resolveShape,
  ProofInputUtxo,
} from "@zolana/transaction";
