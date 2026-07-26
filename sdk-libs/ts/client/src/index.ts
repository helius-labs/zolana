export { initializePoseidon, isPoseidonInitialized } from "@zolana/hasher";
export { ZolanaClient, createAndSendTransaction } from "./client.js";
export type {
  MergeMaterialInput,
  ProvedMerge,
  ProvedMergeZone,
  SignedPrivateTransaction,
} from "./client.js";
export { CANONICAL_CLIENT_ERROR_CODES, ClientError } from "./error.js";
export type {
  CanonicalClientErrorCode,
  ClientErrorCause,
  ClientErrorCode,
  ClientErrorDetails,
  ClientErrorDetailsMap,
  HasherErrorCode,
  RetryErrorCause,
} from "./error.js";
export { ZolanaIndexer } from "./indexer.js";
export { SolanaRpc } from "./solana-rpc.js";
export type { SignatureStatus } from "./solana-rpc.js";
// The Rust crate root re-exports the prover block, so `@zolana/client` carries
// it alongside the `@zolana/client/prover` subpath. `SpendProof` is rooted in
// `./rpc.js`, which both entry points share.
export {
  assemble,
  assembleZone,
  assembleZoneAuthority,
  assembleZoneAuthorityWitness,
  assembleZoneP256,
  canonicalShape,
  compressProof,
  intoProver,
  ProverClient,
  resolveShape,
  SPP_SUPPORTED_SHAPES,
} from "./prover/index.js";
export type {
  AssembledTransfer,
  AssembledZone,
  AssembledZoneP256,
  AsyncPollConfig,
  CompressedProof,
  Field,
  Proof,
  ProverInputs,
  Shape,
  TransferInput,
  TransferInputs,
  TransferOutput,
  TransferP256Inputs,
  ZoneProverInputs,
} from "./prover/index.js";
export {
  DEFAULT_INDEXER_POLL_CONFIG,
  DEFAULT_INDEXER_RPC_CONFIG,
  attempts,
  backoff,
  createIndexerPollConfig,
  createIndexerRpcConfig,
  isRetryable,
  pollUntil,
  retryCause,
  validatePollConfig,
  waitForIndexer,
} from "./retry.js";
export type { PollUntilOptions } from "./retry.js";
export type {
  EncryptedUtxoMatch,
  GetByTagsRequest,
  GetEncryptedUtxosByTagsResponse,
  GetMerkleProofsResponse,
  GetNonInclusionProofsResponse,
  GetShieldedTransactionsByTagsResponse,
  IndexerPollConfig,
  IndexerRpcConfig,
  MerkleContext,
  MerkleProof,
  NonInclusionProof,
  Rpc,
  RpcAccount,
  RpcContext,
  SpendProof,
} from "./rpc.js";