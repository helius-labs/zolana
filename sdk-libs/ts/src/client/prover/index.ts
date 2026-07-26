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
import { assembleZone, assembleZoneAuthority, assembleZoneP256 } from "./zone.js";

export {
  DEFAULT_ASYNC_POLL_CONFIG,
  PROVE_PATH,
  ProverClient,
  SERVER_ADDRESS,
  assemble,
  assembleZone,
  assembleZoneAuthority,
  assembleZoneP256,
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
  AssembledZone,
  AssembledZoneP256,
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
  ZoneProverInputs,
} from "./types.js";

export {
  SPP_SUPPORTED_SHAPES,
  canonicalShape,
  resolveShape,
  ProofInputUtxo,
} from "../../transaction/index.js";
