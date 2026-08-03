import {
  getSetComputeUnitLimitInstruction,
  getSetComputeUnitPriceInstruction,
} from "@solana-program/compute-budget";
import {
  assertIsAddress,
  assertIsSignature,
  getAddressEncoder,
  getBase64Encoder,
  type Address,
  type Commitment,
  type Instruction,
  type Signature,
  type Transaction,
} from "@solana/kit";

import { ZolanaApi } from "../api/index.js";
import {
  mergeTransactInstruction,
  transactInstruction,
  type MergeTransactInstructionData,
} from "../interface/instructions/index.js";
import { DEFAULT_TREE_ADDRESS } from "../interface/program.js";
import { checkedTransactionSize } from "../interface/transaction-size.js";
import type {
  Bytes32,
  RequestContext,
  TransactInstructionData,
  TransactWithdrawal,
} from "../interface/types.js";
import type { NullifierKey } from "../keypair/nullifier-key.js";
import type { ShieldedPublicKey } from "../keypair/public-key.js";
import { PreparedMerge } from "../transaction/instructions/builders.js";
import { SppProofInputs, type InputUtxoContext } from "../transaction/instructions/transact.js";

import { ClientError, fromClientCause } from "./error.js";
import { bigintToBytes, checkedServiceUrl, hashField } from "./internal.js";
import { ZolanaIndexer } from "./indexer.js";
import {
  buildUnsignedTransaction as buildKitUnsignedTransaction,
  createKitClients,
  runKitRpc,
  type LatestBlockhash,
  type SolanaRpc,
  type SolanaRpcSubscriptions,
} from "./kit.js";
import { assemble } from "./prover/assembly.js";
import { ProverClient, type AsyncPollConfig } from "./prover/client.js";
import { assembleMerge } from "./prover/merge.js";
import { compressProof } from "./prover/proof.js";
import { DEFAULT_INDEXER_RPC_CONFIG, validatePollConfig } from "./retry.js";
import {
  type GetByNullifiersRequest,
  type GetByTagsRequest,
  type GetEncryptedUtxosByTagsResponse,
  type GetMerkleProofsResponse,
  type GetNonInclusionProofsResponse,
  type GetShieldedTransactionsByNullifiersResponse,
  type GetShieldedTransactionsBySignatureResponse,
  type GetShieldedTransactionsByTagsResponse,
  type IndexerRpcConfig,
  type RpcAccount,
  type SpendProof,
} from "./rpc.js";

const DEFAULT_TRANSACT_CU_LIMIT = 300_000;
const DEFAULT_COMMITMENT: Commitment = "confirmed";

export interface ZolanaClientConfig {
  readonly solanaRpcUrl: string | URL;
  readonly solanaRpcSubscriptionsUrl?: string | URL;
  readonly indexerUrl: string | URL;
  readonly apiKey?: string;
  readonly proverUrl: string | URL;
  readonly tree?: Address;
  readonly commitment?: Commitment;
  readonly computeUnitLimit?: number;
  readonly computeUnitPriceMicroLamports?: bigint;
  readonly indexerConfig?: IndexerRpcConfig;
  readonly proverAsyncPoll?: AsyncPollConfig;
  readonly fetch?: typeof globalThis.fetch;
}

/** @internal */
export interface AuthorizedPrivateTransaction {
  readonly proofInputs: SppProofInputs;
  readonly withdrawal?: TransactWithdrawal;
  readonly tree: Address;
}

export interface MergeMaterialInput {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly nullifierKey: NullifierKey;
}

export interface ProvedMerge {
  readonly data: MergeTransactInstructionData;
  readonly outputHash: Bytes32;
}

export class ZolanaClient {
  readonly tree: Address;
  readonly solanaRpc: SolanaRpc;
  readonly solanaRpcSubscriptions: SolanaRpcSubscriptions;
  readonly commitment: Commitment;
  readonly #indexer: ZolanaIndexer;
  readonly #prover: ProverClient;
  readonly #computeUnitLimit: number;
  readonly #computeUnitPrice: bigint | undefined;
  readonly #indexerConfig: IndexerRpcConfig;

  constructor(input: ZolanaClientConfig) {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_CONFIG");
    }

    const tree = input.tree ?? DEFAULT_TREE_ADDRESS;
    checkedAddress(tree, "tree");
    const commitment = input.commitment ?? DEFAULT_COMMITMENT;
    if (!isCommitment(commitment)) {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "commitment" } });
    }
    if (input.fetch !== undefined && typeof input.fetch !== "function") {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "fetch" } });
    }

    const kit = createKitClients({
      solanaRpcUrl: input.solanaRpcUrl,
      ...(input.solanaRpcSubscriptionsUrl === undefined
        ? {}
        : { solanaRpcSubscriptionsUrl: input.solanaRpcSubscriptionsUrl }),
    });
    const indexerUrl = checkedServiceUrl(input.indexerUrl, "indexerUrl");
    const proverUrl = checkedServiceUrl(input.proverUrl, "proverUrl");
    let indexer: ZolanaIndexer;
    try {
      indexer = new ZolanaIndexer(
        new ZolanaApi({
          url: indexerUrl,
          ...(input.apiKey === undefined ? {} : { apiKey: input.apiKey }),
          ...(input.fetch === undefined ? {} : { fetch: input.fetch }),
        }),
      );
    } catch (cause) {
      throw new ClientError("CLIENT_INVALID_CONFIG", {
        details: { field: input.apiKey === undefined ? "indexerUrl" : "apiKey" },
        cause,
      });
    }
    let prover: ProverClient;
    try {
      prover = new ProverClient({
        url: proverUrl,
        ...(input.proverAsyncPoll === undefined ? {} : { asyncPoll: input.proverAsyncPoll }),
        ...(input.fetch === undefined ? {} : { fetch: input.fetch }),
      });
    } catch (cause) {
      throw new ClientError("CLIENT_INVALID_CONFIG", {
        details: { field: input.proverAsyncPoll === undefined ? "proverUrl" : "proverAsyncPoll" },
        cause,
      });
    }

    this.#computeUnitLimit = checkedU32(
      input.computeUnitLimit ?? DEFAULT_TRANSACT_CU_LIMIT,
      "computeUnitLimit",
    );
    if (
      input.computeUnitPriceMicroLamports !== undefined &&
      (input.computeUnitPriceMicroLamports < 0n ||
        input.computeUnitPriceMicroLamports > 0xffff_ffff_ffff_ffffn)
    ) {
      throw new ClientError("CLIENT_INVALID_INTEGER", {
        details: { field: "computeUnitPriceMicroLamports" },
      });
    }
    this.solanaRpc = kit.solanaRpc;
    this.solanaRpcSubscriptions = kit.solanaRpcSubscriptions;
    this.commitment = commitment;
    this.#indexer = indexer;
    this.#prover = prover;
    this.tree = tree;
    this.#computeUnitPrice = input.computeUnitPriceMicroLamports;
    const indexerConfig = input.indexerConfig ?? DEFAULT_INDEXER_RPC_CONFIG;
    validatePollConfig(indexerConfig.poll);
    this.#indexerConfig = indexerConfig;
  }

  /// Mirrors Rust's `ZolanaClient::indexer_config`: the config every indexer
  /// call falls back to and the schedule confirmation polls.
  get indexerConfig(): IndexerRpcConfig {
    return this.#indexerConfig;
  }

  async getAccount(address: Address, context?: RequestContext): Promise<RpcAccount | undefined> {
    checkedAddress(address, "address");
    const { value } = await runKitRpc("getAccountInfo", context, (abortSignal) =>
      this.solanaRpc
        .getAccountInfo(address, { commitment: this.commitment, encoding: "base64" })
        .send({ abortSignal }),
    );
    return value === null ? undefined : decodeRpcAccount(value, "getAccountInfo");
  }

  async getMultipleAccounts(
    addresses: readonly Address[],
    context?: RequestContext,
  ): Promise<readonly (RpcAccount | undefined)[]> {
    addresses.forEach((address) => checkedAddress(address, "address"));
    const { value } = await runKitRpc("getMultipleAccounts", context, (abortSignal) =>
      this.solanaRpc
        .getMultipleAccounts(addresses, {
          commitment: this.commitment,
          encoding: "base64",
        })
        .send({ abortSignal }),
    );
    if (value.length !== addresses.length) {
      throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
        details: {
          method: "getMultipleAccounts",
          expected: addresses.length,
          actual: value.length,
        },
      });
    }
    return Object.freeze(
      value.map((account) =>
        account === null ? undefined : decodeRpcAccount(account, "getMultipleAccounts"),
      ),
    );
  }

  async getBalance(address: Address, context?: RequestContext): Promise<bigint> {
    checkedAddress(address, "address");
    const { value } = await runKitRpc("getBalance", context, (abortSignal) =>
      this.solanaRpc.getBalance(address, { commitment: this.commitment }).send({ abortSignal }),
    );
    return value;
  }

  async getLatestBlockhash(context?: RequestContext): Promise<LatestBlockhash> {
    const { value } = await runKitRpc("getLatestBlockhash", context, (abortSignal) =>
      this.solanaRpc.getLatestBlockhash({ commitment: this.commitment }).send({ abortSignal }),
    );
    return value;
  }

  getEncryptedUtxosByTags(
    request: GetByTagsRequest,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetEncryptedUtxosByTagsResponse> {
    return this.#indexer.getEncryptedUtxosByTags(request, this.#configOr(config), context);
  }

  getShieldedTransactionsByTags(
    request: GetByTagsRequest,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsByTagsResponse> {
    return this.#indexer.getShieldedTransactionsByTags(request, this.#configOr(config), context);
  }

  getShieldedTransactionsByNullifiers(
    request: GetByNullifiersRequest,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsByNullifiersResponse> {
    return this.#indexer.getShieldedTransactionsByNullifiers(
      request,
      this.#configOr(config),
      context,
    );
  }

  getShieldedTransactionsBySignature(
    signature: Signature,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsBySignatureResponse> {
    checkedSignature(signature);
    return this.#indexer.getShieldedTransactionsBySignature(
      signature,
      this.#configOr(config),
      context,
    );
  }

  getMerkleProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetMerkleProofsResponse> {
    return this.#indexer.getMerkleProofs(treeAccount, leaves, this.#configOr(config), context);
  }

  getNonInclusionProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetNonInclusionProofsResponse> {
    return this.#indexer.getNonInclusionProofs(
      treeAccount,
      leaves,
      this.#configOr(config),
      context,
    );
  }

  /// `Some(config.unwrap_or(self.indexer_config))` in Rust: a caller who passes
  /// nothing gets the client's config, not the indexer's own default.
  #configOr(config: IndexerRpcConfig | undefined): IndexerRpcConfig {
    return config ?? this.#indexerConfig;
  }

  async getInputMerkleProofs(
    inputUtxoCommitments: readonly InputUtxoContext[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<readonly SpendProof[]> {
    const inputCandidates: unknown = inputUtxoCommitments;
    if (!Array.isArray(inputCandidates)) {
      throw new ClientError("CLIENT_INVALID_INPUT_CONTEXT");
    }
    const commitments = inputCandidates.map((candidate: unknown, index) => {
      if (typeof candidate !== "object" || candidate === null) {
        throw new ClientError("CLIENT_INVALID_INPUT_CONTEXT", { details: { index } });
      }
      const item = candidate as Record<string, unknown>;
      const itemIndex = item["index"];
      const utxoHash = item["utxoHash"];
      const nullifier = item["nullifier"];
      if (
        typeof itemIndex !== "number" ||
        !Number.isSafeInteger(itemIndex) ||
        itemIndex < 0 ||
        !(utxoHash instanceof Uint8Array) ||
        utxoHash.length !== 32 ||
        !(nullifier instanceof Uint8Array) ||
        nullifier.length !== 32
      ) {
        throw new ClientError("CLIENT_INVALID_INPUT_CONTEXT", { details: { index } });
      }
      return Object.freeze({
        index: itemIndex,
        utxoHash: new Uint8Array(utxoHash) as Bytes32,
        nullifier: new Uint8Array(nullifier) as Bytes32,
      });
    });
    const [state, nullifier] = await Promise.all([
      this.getMerkleProofs(
        this.tree,
        commitments.map((item) => item.utxoHash),
        config,
        context,
      ),
      this.getNonInclusionProofs(
        this.tree,
        commitments.map((item) => item.nullifier),
        config,
        context,
      ),
    ]);
    if (
      state.proofs.length !== commitments.length ||
      nullifier.proofs.length !== commitments.length
    ) {
      throw new ClientError("CLIENT_INCOMPLETE_INPUT_PROOFS", {
        details: {
          expected: commitments.length,
          state: state.proofs.length,
          nullifier: nullifier.proofs.length,
        },
      });
    }
    return Object.freeze(
      commitments.map((commitment, index) => {
        const stateProof = state.proofs[index];
        const nullifierProof = nullifier.proofs[index];
        if (!stateProof || !nullifierProof) {
          throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", {
            details: { index },
          });
        }
        if (!equal(stateProof.leaf, commitment.utxoHash)) {
          throw new ClientError("CLIENT_STATE_PROOF_LEAF_MISMATCH", {
            details: { index },
          });
        }
        // Rust finishes the state proof before starting the nullifier one, so a
        // pair wrong in both ways names the state tree and not the nullifier leaf.
        if (stateProof.merkleContext.tree !== this.tree) {
          throw new ClientError("CLIENT_STATE_PROOF_TREE_MISMATCH", {
            details: { index },
          });
        }
        if (!equal(nullifierProof.leaf, commitment.nullifier)) {
          throw new ClientError("CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH", {
            details: { index },
          });
        }
        if (nullifierProof.merkleContext.tree !== this.tree) {
          throw new ClientError("CLIENT_NULLIFIER_PROOF_TREE_MISMATCH", {
            details: { index },
          });
        }
        return Object.freeze({ state: stateProof, nullifier: nullifierProof });
      }),
    );
  }

  async proveTransact(
    proofInputs: SppProofInputs,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<TransactInstructionData> {
    if (!(proofInputs instanceof SppProofInputs)) {
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    }
    try {
      const dummyNullifiers = proofInputs.dummyNullifiers();
      const [proofs, dummyResponse] = await Promise.all([
        this.getInputMerkleProofs(proofInputs.inputContexts(), config, context),
        dummyNullifiers.length === 0
          ? Promise.resolve(undefined)
          : this.getNonInclusionProofs(this.tree, dummyNullifiers, config, context),
      ]);
      const dummyProofs = dummyResponse?.proofs ?? [];
      if (dummyProofs.length !== dummyNullifiers.length) {
        throw new ClientError("CLIENT_INCOMPLETE_INPUT_PROOFS", {
          details: {
            expected: dummyNullifiers.length,
            state: 0,
            nullifier: dummyProofs.length,
          },
        });
      }
      dummyProofs.forEach((proof, index) => {
        if (proof.merkleContext.tree !== this.tree) {
          throw new ClientError("CLIENT_NULLIFIER_PROOF_TREE_MISMATCH", {
            details: { index },
          });
        }
      });
      const assembled = assemble(proofInputs, proofs, dummyProofs);
      const proof = await this.#prover.prove(assembled.proverInputs, context);
      return assembled.withProof(compressProof(proof).toTransactProof());
    } catch (cause) {
      throw fromClientCause(cause);
    }
  }

  async proveMerge(
    input: Readonly<{
      prepared: PreparedMerge;
      material: MergeMaterialInput;
      indexer?: Pick<ZolanaClient, "getInputMerkleProofs" | "getNonInclusionProofs">;
    }>,
    context?: RequestContext,
  ): Promise<ProvedMerge> {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_MERGE");
    }
    const assembled = await assembleMerge(
      input.prepared,
      input.material,
      input.indexer ?? this,
      this.tree,
      context,
    );
    const compressed = compressProof(
      await this.#prover.proveMerge(assembled.proverInputs, context),
    );
    return Object.freeze({
      data: assembled.instructionData({
        a: compressed.a,
        b: compressed.b,
        c: compressed.c,
      }),
      outputHash: new Uint8Array(assembled.outputHash) as Bytes32,
    });
  }

  /** @internal */
  async assembleAuthorizedMergeTransaction(
    input: Readonly<{
      proved: ProvedMerge;
      feePayer: Address;
      userRecord: Address;
    }>,
    context?: RequestContext,
  ): Promise<Transaction> {
    const candidate: unknown = input;
    const proved =
      typeof candidate === "object" && candidate !== null
        ? (candidate as Record<string, unknown>)["proved"]
        : undefined;
    if (!isProvedMerge(proved)) {
      throw new ClientError("CLIENT_INVALID_MERGE");
    }
    if (!equal(proved.outputHash, proved.data.outputUtxoHash)) {
      throw new ClientError("CLIENT_MERGE_OUTPUT_MISMATCH");
    }
    checkedAddress(input.feePayer, "feePayer");
    checkedAddress(input.userRecord, "userRecord");
    const lifetime = await this.getLatestBlockhash(context);
    return buildUnsignedMergeTransaction({
      tree: this.tree,
      feePayer: input.feePayer,
      userRecord: input.userRecord,
      lifetime,
      data: proved.data,
    });
  }

  /** @internal */
  async assembleAuthorizedPrivateTransaction(
    input: Readonly<{
      authorized: AuthorizedPrivateTransaction;
      feePayer: Address;
      setupInstructions?: readonly Instruction[];
    }>,
    context?: RequestContext,
  ): Promise<Transaction> {
    const data = await this.#proveAuthorizedPrivateTransaction(input, context);
    const lifetime = await this.getLatestBlockhash(context);
    return buildUnsignedTransaction({
      computeUnitLimit: this.#computeUnitLimit,
      ...(this.#computeUnitPrice === undefined
        ? {}
        : { computeUnitPriceMicroLamports: this.#computeUnitPrice }),
      feePayer: input.feePayer,
      inputTree: input.authorized.tree,
      outputTree: this.tree,
      ...(input.setupInstructions === undefined
        ? {}
        : { setupInstructions: input.setupInstructions }),
      ...(input.authorized.withdrawal === undefined
        ? {}
        : { withdrawal: input.authorized.withdrawal }),
      data,
      lifetime,
    });
  }

  async #proveAuthorizedPrivateTransaction(
    input: Readonly<{ authorized: AuthorizedPrivateTransaction; feePayer: Address }>,
    context?: RequestContext,
  ): Promise<TransactInstructionData> {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_TRANSACTION");
    }
    checkedAddress(input.feePayer, "feePayer");
    if (!isAuthorizedPrivateTransaction(input.authorized)) {
      throw new ClientError("CLIENT_INVALID_TRANSACTION");
    }
    const payerHash = bigintToBytes(
      hashField(new Uint8Array(getAddressEncoder().encode(input.feePayer))),
    );
    if (!equal(payerHash, input.authorized.proofInputs.payerPublicKeyHash)) {
      throw new ClientError("CLIENT_FEE_PAYER_MISMATCH");
    }
    if (input.authorized.tree !== this.tree) {
      throw new ClientError("CLIENT_TREE_MISMATCH", {
        details: { transactionTree: input.authorized.tree, clientTree: this.tree },
      });
    }
    return this.proveTransact(input.authorized.proofInputs, undefined, context);
  }
}

export function buildUnsignedTransaction(
  input: Readonly<{
    computeUnitLimit: number;
    computeUnitPriceMicroLamports?: bigint;
    feePayer: Address;
    inputTree: Address;
    outputTree: Address;
    setupInstructions?: readonly Instruction[];
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
    lifetime: LatestBlockhash;
  }>,
): Transaction {
  checkedAddress(input.feePayer, "feePayer");
  checkedAddress(input.inputTree, "inputTree");
  checkedAddress(input.outputTree, "outputTree");
  const instructions = privateTransactionInstructions({ ...input, payer: input.feePayer });
  return checkedTransactionSize(
    compileKitTransaction(input.feePayer, input.lifetime, instructions),
    {
      inputs: input.data.inputs.length,
      outputs: input.data.outputs.length,
    },
  );
}

function privateTransactionInstructions(
  input: Readonly<{
    computeUnitLimit: number;
    computeUnitPriceMicroLamports?: bigint;
    payer: Address;
    inputTree: Address;
    outputTree: Address;
    setupInstructions?: readonly Instruction[];
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
  }>,
): readonly Instruction[] {
  checkedAddress(input.inputTree, "inputTree");
  checkedAddress(input.outputTree, "outputTree");
  checkedU32(input.computeUnitLimit, "computeUnitLimit");
  checkedComputeUnitPrice(input.computeUnitPriceMicroLamports);
  return [
    getSetComputeUnitLimitInstruction({ units: input.computeUnitLimit }),
    ...(input.computeUnitPriceMicroLamports === undefined
      ? []
      : [
          getSetComputeUnitPriceInstruction({
            microLamports: input.computeUnitPriceMicroLamports,
          }),
        ]),
    ...(input.setupInstructions ?? []),
    transactInstruction({
      payer: input.payer,
      inputTree: input.inputTree,
      outputTree: input.outputTree,
      data: input.data,
      ...(input.withdrawal === undefined ? {} : { withdrawal: input.withdrawal }),
    }),
  ];
}

export function buildUnsignedMergeTransaction(
  input: Readonly<{
    tree: Address;
    feePayer: Address;
    userRecord: Address;
    lifetime: LatestBlockhash;
    data: MergeTransactInstructionData;
  }>,
): Transaction {
  checkedAddress(input.tree, "tree");
  checkedAddress(input.feePayer, "feePayer");
  checkedAddress(input.userRecord, "userRecord");
  return checkedTransactionSize(
    compileKitTransaction(input.feePayer, input.lifetime, [
      getSetComputeUnitLimitInstruction({ units: 1_400_000 }),
      mergeTransactInstruction({
        inputTree: input.tree,
        outputTree: input.tree,
        payer: input.feePayer,
        userRecord: input.userRecord,
        data: input.data,
      }),
    ]),
  );
}

function compileKitTransaction(
  feePayer: Address,
  lifetime: LatestBlockhash,
  instructions: readonly Instruction[],
): Transaction {
  try {
    return buildKitUnsignedTransaction({ feePayer, instructions, lifetime });
  } catch (cause) {
    throw new ClientError("CLIENT_TRANSACTION_ASSEMBLY", { cause });
  }
}

function checkedU32(value: number, fieldName: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field: fieldName } });
  }
  return value;
}

function checkedComputeUnitPrice(value: bigint | undefined): void {
  if (value !== undefined && (value < 0n || value > 0xffff_ffff_ffff_ffffn)) {
    throw new ClientError("CLIENT_INVALID_INTEGER", {
      details: { field: "computeUnitPriceMicroLamports" },
    });
  }
}

function checkedAddress(value: Address, field: string): void {
  try {
    assertIsAddress(value);
  } catch {
    throw new ClientError("CLIENT_INVALID_BASE58", { details: { field } });
  }
}

function checkedSignature(value: Signature): void {
  try {
    assertIsSignature(value);
  } catch {
    throw new ClientError("CLIENT_INVALID_BASE58", {
      details: { field: "signature" },
    });
  }
}

function isCommitment(value: unknown): value is Commitment {
  return value === "processed" || value === "confirmed" || value === "finalized";
}

function decodeRpcAccount(
  account: Readonly<{
    owner: Address;
    lamports: bigint;
    data: readonly [string, "base64"];
  }>,
  method: string,
): RpcAccount {
  try {
    return Object.freeze({
      owner: account.owner,
      data: new Uint8Array(getBase64Encoder().encode(account.data[0])),
      lamports: account.lamports,
    });
  } catch (cause) {
    throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
      details: { method, path: "result.value.data" },
      cause,
    });
  }
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function isProvedMerge(value: unknown): value is ProvedMerge {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  const data = candidate["data"];
  const outputHash = candidate["outputHash"];
  const dataOutputHash =
    typeof data === "object" && data !== null
      ? (data as Record<string, unknown>)["outputUtxoHash"]
      : undefined;
  return (
    outputHash instanceof Uint8Array &&
    outputHash.length === 32 &&
    dataOutputHash instanceof Uint8Array &&
    dataOutputHash.length === 32
  );
}

function isAuthorizedPrivateTransaction(value: unknown): value is AuthorizedPrivateTransaction {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    candidate["proofInputs"] instanceof SppProofInputs && typeof candidate["tree"] === "string"
  );
}
