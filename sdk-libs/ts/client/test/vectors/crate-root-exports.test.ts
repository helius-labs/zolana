import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import libFixture from "../../../fixtures/client/lib.json" with { type: "json" };
import * as clientRoot from "../../src/index.js";

const indexPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../src/index.ts");

/** Rust crate-root module to the `@zolana/client` entry point that carries it. */
const MODULE_ENTRY_POINTS: Readonly<Record<string, string>> = {
  client: "@zolana/client",
  error: "@zolana/client",
  indexer: "@zolana/client",
  prover: "@zolana/client and @zolana/client/prover",
  retry: "@zolana/client and @zolana/client/retry",
  rpc: "@zolana/client",
  solana_rpc: "@zolana/client",
};

/** Rust crate-root name to the `@zolana/client` root export that carries it. */
const CARRIED: Readonly<Record<string, string>> = {
  AssembledTransfer: "AssembledTransfer",
  AsyncPollConfig: "AsyncPollConfig",
  ClientError: "ClientError",
  Context: "RpcContext",
  EncryptedUtxoMatch: "EncryptedUtxoMatch",
  GetEncryptedUtxosByTagsResponse: "GetEncryptedUtxosByTagsResponse",
  GetMerkleProofsResponse: "GetMerkleProofsResponse",
  GetNonInclusionProofsResponse: "GetNonInclusionProofsResponse",
  GetShieldedTransactionsByTagsResponse: "GetShieldedTransactionsByTagsResponse",
  IndexerPollConfig: "IndexerPollConfig",
  IndexerRpcConfig: "IndexerRpcConfig",
  MerkleContext: "MerkleContext",
  MerkleProof: "MerkleProof",
  NonInclusionProof: "NonInclusionProof",
  Proof: "Proof",
  ProofCompressed: "CompressedProof",
  ProverClient: "ProverClient",
  ProverInputs: "ProverInputs",
  RetryErrorCause: "RetryErrorCause",
  Rpc: "Rpc",
  SPP_SUPPORTED_SHAPES: "SPP_SUPPORTED_SHAPES",
  Shape: "Shape",
  SignedPrivateTransaction: "SignedPrivateTransaction",
  SolanaRpc: "SolanaRpc",
  SpendProof: "SpendProof",
  TransferInput: "TransferInput",
  TransferInputs: "TransferInputs",
  TransferOutput: "TransferOutput",
  TransferP256Inputs: "TransferP256Inputs",
  ZolanaClient: "ZolanaClient",
  ZolanaIndexer: "ZolanaIndexer",
  assemble: "assemble",
  canonical_shape: "canonicalShape",
  into_prover: "intoProver",
  resolve_shape: "resolveShape",
};

/**
 * Rust crate-root names the TypeScript client root deliberately does not carry, each with the
 * reason. `@zolana/client` depends on `@zolana/transaction`, so a caller reaches the names that
 * Rust re-exports from `zolana_transaction` through that package instead of a duplicate export.
 */
const NOT_CARRIED: Readonly<Record<string, string>> = {
  AssetBalance: "@zolana/transaction owns the wallet value types",
  AsyncProverClient: "ProverClient is the single Promise-based prover client",
  AsyncRpc: "Rpc is the single Promise-based RPC contract",
  AsyncSolanaRpc: "SolanaRpc is the single Promise-based Solana adapter",
  AsyncZolanaIndexer: "ZolanaIndexer is the single Promise-based indexer adapter",
  BatchAddressAppendInputs: "forester circuit inputs; no TypeScript forester surface",
  CircuitType: "the ProverInputs discriminant selects the circuit",
  Commitments: "prover-internal proof commitment representation",
  CompressedCommitments: "prover-internal proof commitment representation",
  ConfidentialTransfer: "@zolana/transaction owns transfer construction",
  ConfirmedInstructionGroups: "confirmation returns output view tags, not instruction groups",
  DEFAULT_TRANSACT_CU_LIMIT: "ZolanaClient applies it; computeUnitLimit overrides it",
  InputUtxoContext: "@zolana/transaction owns the instruction input types",
  MERGE_INPUTS: "@zolana/transaction owns the merge instruction constants",
  Merge: "@zolana/transaction owns merge construction",
  MergeProofResult: "ZolanaClient.proveMerge returns ProvedMerge",
  MergeProver: "ZolanaClient.proveMerge owns merge proving",
  MergeWitness: "prover-internal circuit witness",
  MergeZone: "@zolana/transaction owns zone merge construction",
  MergeZoneProver: "ZolanaClient.proveMergeZone owns zone merge proving",
  MergeZoneWitness: "prover-internal circuit witness",
  NULLIFIER_TREE_HEIGHT: "assembly validates path lengths against it internally",
  OutputContext: "@zolana/transaction owns the indexed output types",
  OutputSlot: "@zolana/transaction owns the indexed output types",
  P256Owner: "prover-internal P256 ownership witness",
  PreparedMerge: "@zolana/transaction owns prepared instruction values",
  PreparedMergeZone: "@zolana/transaction owns prepared instruction values",
  PreparedZoneAuthority: "@zolana/transaction owns prepared instruction values",
  PrivateTransaction: "@zolana/transaction owns the wallet history types",
  PrivateTransactionDirection: "@zolana/transaction owns the wallet history types",
  PrivateTransactionId: "@zolana/transaction owns the wallet history types",
  PrivateTransactionKind: "@zolana/transaction owns the wallet history types",
  PrivateTransactionStatus: "@zolana/transaction owns the wallet history types",
  ProofInputUtxo: "field-encoded prover input; @zolana/transaction owns the public ProofInputUtxo",
  ProveResult: "the Rpc contract returns each proof response directly",
  PublicAmounts: "@zolana/transaction owns SppProofInputs.publicAmounts()",
  STATE_TREE_HEIGHT: "assembly validates path lengths against it internally",
  ShieldedTransaction: "@zolana/indexer-api owns IndexedShieldedTransaction",
  ShieldedTransactionStream: "the indexer paginates by cursor rather than streaming",
  SppProofInputUtxo: "@zolana/transaction names it ProofInputUtxo",
  SppProofInputs: "@zolana/transaction owns the proof input bundle",
  TransferP256ProofResult: "ProverClient.prove returns Proof for both rails",
  TransferP256Prover: "ProverClient.prove owns both transfer rails",
  TransferProofResult: "ProverClient.prove returns Proof for both rails",
  TransferProver: "ProverClient.prove owns both transfer rails",
  TransferSpendInput: "prover-internal spend witness",
  WithdrawalTarget: "@zolana/transaction owns withdrawal targets",
  spawn_prover: "@zolana/test-kit startLocalStack owns local prover processes",
};

/** Zone prover rails deferred to PKP-05 by review-checklist rows C13, C14, and C18. */
const DEFERRED_TO_PKP05: readonly string[] = [
  "ZoneAuthorityProofResult",
  "ZoneAuthorityProver",
  "ZoneAuthorityWitness",
  "ZoneTransferP256ProofResult",
  "ZoneTransferP256Prover",
  "ZoneTransferProofResult",
  "ZoneTransferProver",
];

/** Root exports with no Rust crate-root counterpart, each with the reason it ships. */
const TYPESCRIPT_ONLY: Readonly<Record<string, string>> = {
  CANONICAL_CLIENT_ERROR_CODES: "the frozen ClientError variant codes as a runtime value",
  CanonicalClientErrorCode: "the frozen ClientError variant codes as a type",
  ClientErrorCause: "the structured cause Rust models with error enum payloads",
  ClientErrorCode: "the ClientError code union, including TypeScript-only transport codes",
  ClientErrorDetails: "the structured detail payload per code",
  ClientErrorDetailsMap: "the structured detail payload per code",
  CompressedProof: "carries Rust ProofCompressed",
  DEFAULT_INDEXER_POLL_CONFIG:
    "IndexerPollConfig::default() as a value, since TypeScript has no Default",
  DEFAULT_INDEXER_RPC_CONFIG:
    "IndexerRpcConfig::default() as a value, since TypeScript has no Default",
  Field: "the branded BN254 field element the prover payload carries",
  GetByTagsRequest: "the by-tags request Rust passes as separate arguments",
  HasherErrorCode: "the wrapped hasher codes ClientError::Hasher carries",
  MAX_TRANSACTION_SIZE:
    "the runtime packet limit, which Rust reads from solana-transaction and TypeScript compiles without",
  MergeMaterialInput: "the merge key material ZolanaClient.proveMerge requires",
  PollUntilOptions: "the pollUntil parameters Rust passes as separate arguments",
  ProvedMerge: "the merge proof result ZolanaClient.proveMerge returns",
  ProvedMergeZone: "the zone merge proof result ZolanaClient.proveMergeZone returns",
  RpcAccount: "the account value Rust returns as a tuple",
  RpcContext: "carries Rust rpc::Context",
  attempts: "IndexerPollConfig::attempts as a free function",
  backoff: "IndexerPollConfig::backoff as a free function",
  compressProof: "ProofCompressed::try_from as a free function, since TypeScript has no TryFrom",
  createIndexerPollConfig: "validated IndexerPollConfig construction",
  initializePoseidon:
    "loads the compiled Poseidon, which Rust links rather than instantiates at runtime",
  isPoseidonInitialized: "reports whether the compiled Poseidon has been loaded",
  createIndexerRpcConfig: "validated IndexerRpcConfig construction",
  isRetryable: "ClientError::retry_cause().is_some() as a predicate",
  pollUntil: "the retry loop Rust inlines into each caller",
  retryCause: "ClientError::retry_cause as a free function",
  validatePollConfig: "IndexerPollConfig invariant validation",
  transactionSize:
    "measures a compiled transaction, which Rust gets from solana-transaction's own serializer",
  waitForIndexer: "the indexer catch-up loop Rust inlines into each caller",
};

function exportedNames(source: string, typeOnly: boolean): ReadonlySet<string> {
  const blocks = /export(\s+type)?\s*\{([^}]*)\}/gu;
  const names = new Set<string>();
  for (const [, type, block] of source.matchAll(blocks)) {
    if (Boolean(type) !== typeOnly) continue;
    for (const specifier of block.split(",")) {
      const name = specifier
        .trim()
        .split(/\s+as\s+/u)
        .at(-1);
      if (name) names.add(name);
    }
  }
  return names;
}

describe("manifest-pinned zolana-client crate root", () => {
  it("carries or dispositions every crate-root module", () => {
    expect(Object.keys(MODULE_ENTRY_POINTS).sort()).toEqual([...libFixture.expected.modules]);
  });

  it("carries or dispositions every crate-root name", async () => {
    const source = await readFile(indexPath, "utf8");
    const values = exportedNames(source, false);
    const shipped = new Set([...values, ...exportedNames(source, true)]);

    expect([...values].sort()).toEqual(Object.keys(clientRoot).sort());

    const undispositioned = libFixture.expected.names.filter(
      (name) => !(name in CARRIED) && !(name in NOT_CARRIED) && !DEFERRED_TO_PKP05.includes(name),
    );
    expect(undispositioned).toEqual([]);

    for (const [rustName, tsName] of Object.entries(CARRIED)) {
      expect(shipped, `${rustName} must ship as ${tsName}`).toContain(tsName);
    }

    const crateRoot = new Set(libFixture.expected.names);
    for (const name of [...Object.keys(NOT_CARRIED), ...DEFERRED_TO_PKP05]) {
      expect(crateRoot, `${name} left the crate root`).toContain(name);
      expect(shipped, `${name} is dispositioned but shipped`).not.toContain(name);
    }
  });

  it("explains every root export the crate root does not have", async () => {
    const source = await readFile(indexPath, "utf8");
    const carried = new Set(Object.values(CARRIED));
    const unexplained = [...exportedNames(source, false), ...exportedNames(source, true)].filter(
      (name) => !carried.has(name) && !(name in TYPESCRIPT_ONLY),
    );

    expect(unexplained).toEqual([]);
  });
});
