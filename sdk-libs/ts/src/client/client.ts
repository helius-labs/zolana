import {
  assertIsAddress,
  assertIsSignature,
  getBase64Encoder,
  type Address,
  type Commitment,
  type Instruction,
  type Signature,
  type Transaction,
} from "@solana/kit";

import { ZolanaApi } from "../api/index.js";
import { resolveClientEndpoints } from "../endpoint.js";
import {
  mergeTransactInstruction,
  transactInstruction,
  type MergeTransactInstructionData,
} from "../interface/instructions/index.js";
import { DEFAULT_TREE_ADDRESS } from "../interface/program.js";
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

import { compileUnsignedTransaction } from "../flows/compile.js";
import { checkedU32 } from "../flows/internal.js";
import { ClientError, fromClientCause } from "./error.js";
import { checkedServiceUrl } from "./internal.js";
import { ZolanaIndexer } from "./indexer.js";
import {
  createKitClients,
  runKitRpc,
  type LatestBlockhash,
  type SolanaRpc,
  type SolanaRpcSubscriptions,
} from "./kit.js";
import { assemble } from "./prover/assembly.js";
import { ProverClient, type AsyncPollConfig, type ProverHealth } from "./prover/client.js";
import { assembleMerge } from "./prover/merge.js";
import { compressProof } from "./prover/proof.js";
import type { CustomRingProofRequest } from "./prover/types.js";
import {
  DEFAULT_INDEXER_RPC_CONFIG,
  indexerPollTimeout,
  pollUntil,
  validatePollConfig,
} from "./retry.js";
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
  type ProgramAccount,
  type RpcAccount,
  type SpendProof,
} from "./rpc.js";

const DEFAULT_TRANSACT_CU_LIMIT = 300_000;
const DEFAULT_COMMITMENT: Commitment = "confirmed";

export interface ZolanaClientConfig {
  /**
   * Serves the indexer and the prover too, unless either names its own URL.
   * Left out, the whole config falls back to the local validator stack.
   */
  readonly solanaRpcUrl?: string | URL;
  readonly solanaRpcSubscriptionsUrl?: string | URL;
  readonly indexerUrl?: string | URL | undefined;
  readonly proverUrl?: string | URL | undefined;
  /** Sent by the indexer client. A URL that already carries a key needs none. */
  readonly apiKey?: string;
  readonly tree?: Address;
  readonly commitment?: Commitment;
  readonly computeUnitLimit?: number;
  readonly computeUnitPriceMicroLamports?: bigint;
  readonly indexerConfig?: IndexerRpcConfig;
  readonly proverAsyncPoll?: AsyncPollConfig;
  readonly fetch?: typeof globalThis.fetch;
  /**
   * Permit plain http to non-loopback indexer and prover URLs.
   *
   * Off by default: in plaintext the indexer response reveals which UTXOs an
   * identity owns and the prover request carries the witness, so the transport
   * carries the protocol's privacy. Set this only where the network is already
   * private, and never for a public endpoint.
   */
  readonly allowInsecureHttp?: boolean;
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

    const endpoints = resolveClientEndpoints(input);
    const kit = createKitClients({
      solanaRpcUrl: endpoints.solana,
      ...(endpoints.solanaRpcSubscriptions === undefined
        ? {}
        : { solanaRpcSubscriptionsUrl: endpoints.solanaRpcSubscriptions }),
    });
    const allowInsecureHttp = input.allowInsecureHttp ?? false;
    const indexerUrl = checkedServiceUrl(
      endpoints.photon,
      endpoints.photonField,
      allowInsecureHttp,
    );
    const proverUrl = checkedServiceUrl(endpoints.prover, endpoints.proverField, allowInsecureHttp);
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
        details: { field: input.apiKey === undefined ? endpoints.photonField : "apiKey" },
        cause,
      });
    }
    let prover: ProverClient;
    try {
      prover = new ProverClient({
        url: proverUrl,
        allowInsecureHttp,
        ...(input.proverAsyncPoll === undefined ? {} : { asyncPoll: input.proverAsyncPoll }),
        ...(input.fetch === undefined ? {} : { fetch: input.fetch }),
      });
    } catch (cause) {
      throw new ClientError("CLIENT_INVALID_CONFIG", {
        details: {
          field: input.proverAsyncPoll === undefined ? endpoints.proverField : "proverAsyncPoll",
        },
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
    this.tree = tree;
    this.solanaRpc = kit.solanaRpc;
    this.solanaRpcSubscriptions = kit.solanaRpcSubscriptions;
    this.commitment = commitment;
    this.#indexer = indexer;
    this.#prover = prover;
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

  /** Every account of one program, as Rust's `Rpc::get_program_accounts`. */
  async getProgramAccounts(
    programId: Address,
    context?: RequestContext,
  ): Promise<readonly ProgramAccount[]> {
    checkedAddress(programId, "programId");
    const accounts = await runKitRpc("getProgramAccounts", context, (abortSignal) =>
      this.solanaRpc
        .getProgramAccounts(programId, { commitment: this.commitment, encoding: "base64" })
        .send({ abortSignal }),
    );
    return accounts.map((entry) =>
      Object.freeze({
        address: entry.pubkey,
        account: decodeRpcAccount(entry.account, "getProgramAccounts"),
      }),
    );
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

  /**
   * Wait until Solana confirms the transaction and Photon has indexed a Rings
   * event for it.
   *
   * Confirming first turns a transaction that failed on chain into a chain
   * error, instead of an indexer timeout that blames the wrong subsystem.
   */
  async confirmPrivateTransaction(
    signature: Signature,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<void> {
    await this.confirmTransaction(signature, config, context);
    await this.#pollIndexedTransaction(signature, config, context);
  }

  /**
   * Poll the RPC until the signature reaches this client's commitment; returns
   * the slot the transaction landed in, ready for `atSlot` freshness gates.
   */
  async confirmTransaction(
    signature: Signature,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<bigint> {
    checkedSignature(signature);
    const poll = validatePollConfig(this.#configOr(config).poll);
    // Rust's `wait_for_rpc_confirmation` propagates every RPC error with `?` and
    // only retries a signature that is merely not confirmed yet.
    const slot = await pollUntil(
      () => this.#signatureConfirmed(signature, context),
      (landed) => landed !== undefined,
      {
        config: poll,
        ...(context === undefined ? {} : { context }),
        retryErrors: false,
        onTimeout: () =>
          new ClientError("CLIENT_RPC", {
            details: { method: "getSignatureStatuses", reason: "signature not confirmed" },
          }),
      },
    );
    // The accept predicate above guarantees the poll resolved with a slot.
    return slot as bigint;
  }

  /**
   * Photon lags the chain, so an on-chain confirmation alone is not enough for a
   * caller that reads its own outputs back immediately.
   *
   * Every Rings event of one Solana transaction is persisted in a single
   * database transaction, so a single visible event proves the whole transaction
   * is indexed. Matching the event against the transaction's view tags would add
   * no guarantee and would reject legitimate transactions whose events share a
   * tag.
   */
  async #pollIndexedTransaction(
    signature: Signature,
    config: IndexerRpcConfig | undefined,
    context: RequestContext | undefined,
  ): Promise<void> {
    const resolved = this.#configOr(config);
    const poll = validatePollConfig(resolved.poll);
    // The poll below is the wait, so the inner request must not also gate on a slot.
    const request = Object.freeze({ poll: resolved.poll });
    await pollUntil(
      () => this.getShieldedTransactionsBySignature(signature, request, context),
      (response) => response.transactions.length > 0,
      {
        config: poll,
        ...(context === undefined ? {} : { context }),
        onTimeout: (exhausted, lastCause) => indexerPollTimeout(exhausted, lastCause, signature),
      },
    );
  }

  /** Landed slot when the signature reached this client's commitment, else undefined. */
  async #signatureConfirmed(
    signature: Signature,
    context?: RequestContext,
  ): Promise<bigint | undefined> {
    const { value } = await runKitRpc("getSignatureStatuses", context, (abortSignal) =>
      this.solanaRpc.getSignatureStatuses([signature]).send({ abortSignal }),
    );
    const status = value[0];
    if (status === null || status === undefined) return undefined;
    if (status.err !== null) {
      throw new ClientError("CLIENT_RPC", {
        details: { method: "getSignatureStatuses", reason: "transaction failed" },
      });
    }
    return commitmentReached(status.confirmationStatus, this.commitment) ? status.slot : undefined;
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
    return this.#proveTransfer(proofInputs, undefined, config, context);
  }

  async proveRingTransact(
    proofInputs: SppProofInputs,
    ringProgramId: Address,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<TransactInstructionData> {
    checkedAddress(ringProgramId, "ringProgramId");
    return this.#proveTransfer(proofInputs, ringProgramId, config, context);
  }

  async proverHealth(context?: RequestContext): Promise<ProverHealth> {
    try {
      return await this.#prover.health(context);
    } catch (cause) {
      throw fromClientCause(cause);
    }
  }

  async proveCustomRing(
    inputs: CustomRingProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    try {
      const proof = await this.#prover.proveCustomRing(inputs, context);
      return compressProof(proof).toCustomRingProof();
    } catch (cause) {
      throw fromClientCause(cause);
    }
  }

  async #proveTransfer(
    proofInputs: SppProofInputs,
    ring: Address | undefined,
    config: IndexerRpcConfig | undefined,
    context: RequestContext | undefined,
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
      const assembled = assemble(proofInputs, proofs, dummyProofs, ring);
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
      ...(this.#computeUnitPrice === undefined
        ? {}
        : { computeUnitPriceMicroLamports: this.#computeUnitPrice }),
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
    // Compare the address itself, like Rust's `validate_fee_payer_pubkey`. The
    // proof inputs cache a hash of it, but under a different function than any
    // hash derived here would use.
    if (input.feePayer !== input.authorized.proofInputs.payer) {
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

/** Mirrors Rust `MERGE_CU_LIMIT`, the merge verifies one proof over eight inputs. */
export const MERGE_TRANSACT_COMPUTE_UNIT_LIMIT = 1_400_000;

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
  checkedAddress(input.inputTree, "inputTree");
  checkedAddress(input.outputTree, "outputTree");
  return compileUnsignedTransaction({
    feePayer: input.feePayer,
    lifetime: input.lifetime,
    computeUnitLimit: input.computeUnitLimit,
    ...(input.computeUnitPriceMicroLamports === undefined
      ? {}
      : { computeUnitPriceMicroLamports: input.computeUnitPriceMicroLamports }),
    ...(input.setupInstructions === undefined
      ? {}
      : { setupInstructions: input.setupInstructions }),
    instructions: [
      transactInstruction({
        payer: input.feePayer,
        inputTree: input.inputTree,
        outputTree: input.outputTree,
        data: input.data,
        ...(input.withdrawal === undefined ? {} : { withdrawal: input.withdrawal }),
      }),
    ],
    sizeShape: {
      inputs: input.data.inputs.length,
      outputs: input.data.outputs.length,
    },
  });
}

export function buildUnsignedMergeTransaction(
  input: Readonly<{
    tree: Address;
    feePayer: Address;
    userRecord: Address;
    lifetime: LatestBlockhash;
    computeUnitPriceMicroLamports?: bigint;
    data: MergeTransactInstructionData;
  }>,
): Transaction {
  checkedAddress(input.tree, "tree");
  checkedAddress(input.userRecord, "userRecord");
  return compileUnsignedTransaction({
    feePayer: input.feePayer,
    lifetime: input.lifetime,
    computeUnitLimit: MERGE_TRANSACT_COMPUTE_UNIT_LIMIT,
    ...(input.computeUnitPriceMicroLamports === undefined
      ? {}
      : { computeUnitPriceMicroLamports: input.computeUnitPriceMicroLamports }),
    instructions: [
      mergeTransactInstruction({
        inputTree: input.tree,
        outputTree: input.tree,
        payer: input.feePayer,
        userRecord: input.userRecord,
        data: input.data,
      }),
    ],
  });
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

const COMMITMENT_RANK: Readonly<Record<Commitment, number>> = Object.freeze({
  processed: 0,
  confirmed: 1,
  finalized: 2,
});

function commitmentReached(reached: Commitment | null, required: Commitment): boolean {
  if (reached === null) return false;
  return COMMITMENT_RANK[reached] >= COMMITMENT_RANK[required];
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
