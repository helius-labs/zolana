export { MERGE_TRANSACT_COMPUTE_UNIT_LIMIT, ZolanaClient } from "./client.js";
export type { AuthorizedPrivateTransaction, ProvedMerge, ZolanaClientConfig } from "./client.js";
export { LocalKeys, NullifierKeyProofAuthority } from "./keys.js";
export type {
  BlockhashProvider,
  SlotReader,
  ChainReader,
  IndexerReader,
  KitRpcAccess,
  MergeAssembler,
  MergeCacheTarget,
  ProofAuthority,
  TransactKeys,
  ProofDataSource,
  ProofDataSourceContext,
  IndexedProofAuthority,
  IndexedProofInputs,
  IndexedProofLookup,
  IndexedProofResult,
  IndexedTree,
  ProofResolution,
  ResolvedProofTree,
  PreparedConfidentialEddsaTransferInputs,
  PreparedTransferInput,
  PreparedTransferInputs,
  PreparedMergeInputs,
  ProofReader,
  ProofService,
  ProvenConfidentialEddsaTransact,
  ProvenRingTransact,
  Prover,
  TransactionAssembler,
  TransactionConfirmer,
  TreeContext,
  RegistryRecord,
  UserRecordReader,
  UserRecordsLookup,
  WalletKeys,
} from "./ports.js";
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
export {
  mergeProverRequestBody,
  proverRequestBody,
  type AsyncPollConfig,
  type ProverHealth,
  type ProverRequestBody,
  type ProvingKeyArtifact,
  type ProvingKeyCheck,
  type ProvingKeyReport,
} from "./prover/client.js";
export { defaultTeePolicy, teePolicyFromJson, type GpuRequirement } from "./prover/tee/policy.js";
export { DEFAULT_TEE_PROVER_ENDPOINT } from "../endpoint.js";
export type {
  AwsNitroPolicy,
  DstackTdxPolicy,
  NitroMeasurement,
  TdxMeasurement,
  TeePlatform,
  TeePolicy,
} from "./prover/tee/registry.js";
export type { AttestedProver } from "./prover/tee/verify.js";
export { signTransactMessage, transactMessageDigest } from "./prover/assembly.js";
export { compressProof, parseProof } from "./prover/proof.js";
export type {
  CircuitUtxo,
  CompressedProof,
  ConfidentialEddsaTransferInputs,
  EddsaOwnerAuthorization,
  Field,
  MergeInputs,
  Proof,
  ProvedTransactProof,
  ProverInputs,
  RingTransactRoots,
  TransactOwnerSigner,
  TransferInput,
  TransferInputs,
  TransferOutput,
  TreeSlotFields,
} from "./prover/types.js";
export {
  DEFAULT_INDEXER_POLL_CONFIG,
  DEFAULT_INDEXER_RPC_CONFIG,
  createIndexerPollConfig,
  createIndexerRpcConfig,
  atSlot,
} from "./retry.js";
export type {
  EncryptedUtxoMatch,
  GetByNullifiersRequest,
  GetByTagsRequest,
  GetEncryptedUtxosByTagsResponse,
  GetMerkleProofsResponse,
  GetNonInclusionProofsResponse,
  GetShieldedTransactionsByNullifiersResponse,
  GetShieldedTransactionsBySignatureResponse,
  GetShieldedTransactionsByTagsResponse,
  IndexerPollConfig,
  IndexerRpcConfig,
  MerkleContext,
  MerkleProof,
  NonInclusionProof,
  ProgramAccount,
  RpcAccount,
  RpcContext,
  SpendProof,
} from "./rpc.js";
export type { ErrorEnvelope } from "../errors/internal.js";

export type { RingProvingConfig } from "./ports.js";
