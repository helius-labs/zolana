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
import { treeAddress } from "../interface/pda/index.js";
import { DEFAULT_TREE_ID } from "../interface/tree-slot.js";
import type {
  Bytes32,
  RequestContext,
  TransactInstructionData,
  TransactProof,
  TransactWithdrawal,
} from "../interface/types.js";
import { PreparedMerge } from "../transaction/instructions/builders.js";
import { SppProofInputs, type InputUtxoContext } from "../transaction/instructions/transact.js";
import type { ProofInputUtxo } from "../transaction/utxo.js";
import { checkAuthorizedBinding, checkTransactData } from "../transaction/wallet/intent.js";

import { compileUnsignedTransaction } from "../flows/compile.js";
import { checkedComputeUnitLimit, checkedPriorityFee } from "../flows/internal.js";
import { ClientError, fromClientCause } from "./error.js";
import { checkedServiceUrl, hasProofMethods, inputTreeAddress } from "./internal.js";
import { ZolanaIndexer } from "./indexer.js";
import {
  authorizedPrivateTransactionMaterial,
  type AuthorizedPrivateTransaction,
  type AuthorizedPrivateTransactionMaterial,
  type BlockhashProvider,
  type ChainReader,
  type IndexerReader,
  type KitRpcAccess,
  type MergeAssembler,
  type ProofAuthority,
  type ProofReader,
  type ProofService,
  type ProvedMerge,
  type ProvenRingTransact,
  type Prover,
  type TransactionAssembler,
  type TransactionConfirmer,
  type TreeContext,
  type RingProvingConfig,
  type RingMemberProofRequest,
  type RingMemberRequest,
  type RingSpendRecordLookup,
  type RingKeyRegistryEntry,
  type RingKeyRegistryRegisterProof,
} from "./ports.js";
import {
  createKitClients,
  runKitRpc,
  type LatestBlockhash,
  type SolanaRpc,
  type SolanaRpcSubscriptions,
} from "./kit.js";
import { assemble, checkedProverInputs } from "./prover/assembly.js";
import {
  ProverClient,
  type AsyncPollConfig,
  type ProverHealth,
  type ProvingKeyReport,
} from "./prover/client.js";
import { assembleMerge } from "./prover/merge.js";
import { compressProof } from "./prover/proof.js";
import type {
  CustomRingBaseProofRequest,
  CustomRingDepositProofRequest,
  CustomRingPolicyProofRequest,
  CustomRingCompressedPolicyProofRequest,
  CustomRingRegisterKeyProofRequest,
  TransferCircuit,
  TransferInputs,
} from "./prover/types.js";
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
  type MerkleProof,
  type NonInclusionProof,
  type ProgramAccount,
  type RpcAccount,
  type SpendProof,
} from "./rpc.js";

/**
 * Compute-unit ceiling a private transaction is submitted with unless the
 * caller overrides it, matching Rust's `DEFAULT_TRANSACT_CU_LIMIT`. A shielded
 * transact verifies a Groth16 proof on chain, which does not fit inside the
 * budget a legacy transaction received per instruction.
 *
 * Sized from the widest shape this client can send on the rail it sends it on:
 * proving goes through the EdDSA rail, and
 * `program-tests/shielded-pool/CU_BENCHMARK.md` measures "Transfer eddsa 36x2"
 * at 292,473 CU for `process_instruction`. The remaining headroom absorbs the
 * per-input `create_nullifier_pdas` cost, which moves with tree state rather
 * than with the shape. The ring P256 rail is more expensive again, but it
 * carries its own ceiling and does not come through here.
 *
 * Under transaction version 1 this rides in the message header, and requested
 * units rather than consumed ones set the priority fee, so a caller sending
 * only small shapes should pass a lower `computeUnitLimit`.
 */
const DEFAULT_TRANSACT_CU_LIMIT = 450_000;
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
  /**
   * The raw id of the pool tree the client builds against, `DEFAULT_TREE_ID`
   * unless set. Every commitment the client hashes and every proof it requests
   * carries this id.
   */
  readonly treeId?: number;
  /**
   * The pool tree's address. Derived from `treeId` when absent; when both are
   * given they must name the same tree.
   */
  readonly tree?: Address;
  readonly commitment?: Commitment;
  readonly computeUnitLimit?: number;
  /** The whole transaction's fee in lamports, not a price per compute unit. */
  readonly priorityFeeLamports?: bigint;
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

export type {
  AuthorizedPrivateTransaction,
  ProofAuthority,
  ProofService,
  ProvedMerge,
  WalletKeys,
} from "./ports.js";

export class ZolanaClient
  implements
    ChainReader,
    BlockhashProvider,
    IndexerReader,
    ProofReader,
    Prover,
    TransactionConfirmer,
    KitRpcAccess,
    TreeContext,
    TransactionAssembler,
    MergeAssembler
{
  readonly tree: Address;
  readonly treeId: number;
  readonly solanaRpc: SolanaRpc;
  readonly solanaRpcSubscriptions: SolanaRpcSubscriptions;
  readonly commitment: Commitment;
  /** The prover server, for a `LocalKeys` to forward completed inputs to. */
  readonly proofService: ProofService;
  readonly #indexer: ZolanaIndexer;
  readonly #prover: ProverClient;
  readonly #computeUnitLimit: number;
  readonly #priorityFee: bigint | undefined;
  readonly #indexerConfig: IndexerRpcConfig;

  constructor(input: ZolanaClientConfig) {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_CONFIG");
    }

    const treeId = input.treeId ?? DEFAULT_TREE_ID;
    if (!Number.isInteger(treeId) || treeId < 0 || treeId > 0xffff) {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "treeId" } });
    }
    const tree = input.tree ?? treeAddress(treeId);
    checkedAddress(tree, "tree");
    // The id is what every commitment hashes under; an address naming another
    // tree would prove against one tree and submit to another.
    if (tree !== treeAddress(treeId)) {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "tree" } });
    }
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

    this.#computeUnitLimit = checkedComputeUnitLimit(
      input.computeUnitLimit ?? DEFAULT_TRANSACT_CU_LIMIT,
    );
    checkedPriorityFee(input.priorityFeeLamports);
    this.tree = tree;
    this.treeId = treeId;
    this.solanaRpc = kit.solanaRpc;
    this.solanaRpcSubscriptions = kit.solanaRpcSubscriptions;
    this.commitment = commitment;
    this.#indexer = indexer;
    this.#prover = prover;
    this.proofService = prover;
    this.#priorityFee = input.priorityFeeLamports;
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

  async getSlot(context?: RequestContext): Promise<bigint> {
    return runKitRpc("getSlot", context, (abortSignal) =>
      this.solanaRpc.getSlot({ commitment: this.commitment }).send({ abortSignal }),
    );
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

  getRingSpendRecord(
    request: RingMemberRequest,
    context?: RequestContext,
  ): Promise<RingSpendRecordLookup> {
    return this.#indexer.getRingSpendRecord(request, context);
  }

  getRingKeyRegistryEntry(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingKeyRegistryEntry> {
    return this.#indexer.getRingKeyRegistryEntry(request, context);
  }

  getRingKeyRegistryRegisterProof(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingKeyRegistryRegisterProof> {
    return this.#indexer.getRingKeyRegistryRegisterProof(request, context);
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
    return this.#pairSpendProofs(commitments, state.proofs, nullifier.proofs);
  }

  /** One request per proof kind per input tree, padding included, the circuit publishes one root pair per tree slot. */
  async #inputProofs(
    proofInputs: SppProofInputs,
    config: IndexerRpcConfig | undefined,
    context: RequestContext | undefined,
  ): Promise<Readonly<{ proofs: SpendProof[]; dummyProofs: NonInclusionProof[] }>> {
    const commitments = proofInputs.inputContexts();
    const dummyNullifiers = proofInputs.dummyNullifiers();
    const realTrees = proofInputs.inputUtxos.filter((input) => !input.isDummy());
    const dummyTrees = proofInputs.inputUtxos.filter((input) => input.isDummy());
    const at = (inputs: readonly ProofInputUtxo[], treeId: number): number[] =>
      inputs.flatMap((input, index) => (input.treeId === treeId ? [index] : []));
    const spends = new Map<number, SpendProof>();
    const dummies = new Map<number, NonInclusionProof>();
    const treeIds = new Set(proofInputs.inputUtxos.map((input) => input.treeId));
    await Promise.all(
      [...treeIds].map(async (treeId) => {
        const tree = inputTreeAddress(this, treeId);
        const realAt = at(realTrees, treeId);
        const dummyAt = at(dummyTrees, treeId);
        const spent = commitments.filter((_, index) => realAt.includes(index));
        const [state, nullifier] = await Promise.all([
          spent.length === 0
            ? { proofs: [] }
            : this.getMerkleProofs(
                tree,
                spent.map((item) => item.utxoHash),
                config,
                context,
              ),
          this.getNonInclusionProofs(
            tree,
            [
              ...spent.map((item) => item.nullifier),
              ...dummyNullifiers.filter((_, index) => dummyAt.includes(index)),
            ],
            config,
            context,
          ),
        ]);
        const paired = this.#pairSpendProofs(
          spent,
          state.proofs,
          nullifier.proofs.slice(0, spent.length),
          tree,
        );
        const dummyAnswers = nullifier.proofs.slice(spent.length);
        if (dummyAnswers.length !== dummyAt.length) {
          throw new ClientError("CLIENT_INCOMPLETE_INPUT_PROOFS", {
            details: { expected: dummyAt.length, state: 0, nullifier: dummyAnswers.length },
          });
        }
        paired.forEach((proof, position) => spends.set(realAt[position] ?? -1, proof));
        dummyAnswers.forEach((proof, position) => {
          const index = dummyAt[position] ?? -1;
          if (proof.merkleContext.tree !== tree) {
            throw new ClientError("CLIENT_NULLIFIER_PROOF_TREE_MISMATCH", {
              details: { index },
            });
          }
          dummies.set(index, proof);
        });
      }),
    );
    const ordered = <T>(proofs: ReadonlyMap<number, T>, count: number): T[] =>
      Array.from({ length: count }, (_, index) => {
        const proof = proofs.get(index);
        if (proof === undefined) {
          throw new ClientError("CLIENT_MISSING_INPUT_MERKLE_PROOF", { details: { index } });
        }
        return proof;
      });
    return {
      proofs: ordered(spends, commitments.length),
      dummyProofs: ordered(dummies, dummyNullifiers.length),
    };
  }

  /**
   * Zips state and non-inclusion proofs into spend proofs, checking every leaf
   * and tree. Rust finishes the state proof before starting the nullifier one,
   * so a pair wrong in both ways names the state tree and not the nullifier
   * leaf.
   */
  #pairSpendProofs(
    commitments: readonly InputUtxoContext[],
    stateProofs: readonly MerkleProof[],
    nullifierProofs: readonly NonInclusionProof[],
    tree: Address = this.tree,
  ): readonly SpendProof[] {
    if (
      stateProofs.length !== commitments.length ||
      nullifierProofs.length !== commitments.length
    ) {
      throw new ClientError("CLIENT_INCOMPLETE_INPUT_PROOFS", {
        details: {
          expected: commitments.length,
          state: stateProofs.length,
          nullifier: nullifierProofs.length,
        },
      });
    }
    return Object.freeze(
      commitments.map((commitment, index) => {
        const stateProof = stateProofs[index];
        const nullifierProof = nullifierProofs[index];
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
        if (stateProof.merkleContext.tree !== tree) {
          throw new ClientError("CLIENT_STATE_PROOF_TREE_MISMATCH", {
            details: { index },
          });
        }
        if (!equal(nullifierProof.leaf, commitment.nullifier)) {
          throw new ClientError("CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH", {
            details: { index },
          });
        }
        if (nullifierProof.merkleContext.tree !== tree) {
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
    keys: ProofAuthority,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<TransactInstructionData> {
    return (await this.#proveTransfer(proofInputs, { kind: "confidential" }, keys, config, context))
      .data;
  }

  async proveRingTransact(
    proofInputs: SppProofInputs,
    ringProgramId: Address,
    keys: ProofAuthority,
    config?: RingProvingConfig,
    context?: RequestContext,
  ): Promise<ProvenRingTransact> {
    checkedAddress(ringProgramId, "ringProgramId");
    return this.#proveTransfer(
      proofInputs,
      { kind: "ring", ring: ringProgramId },
      keys,
      config?.indexer,
      context,
      config?.outputTree,
    );
  }

  async proverHealth(context?: RequestContext): Promise<ProverHealth> {
    try {
      return await this.#prover.health(context);
    } catch (cause) {
      throw fromClientCause(cause);
    }
  }

  /** See `ProverClient.checkProvingKeys`: run it before the first proof. */
  async checkProverProvingKeys(context?: RequestContext): Promise<ProvingKeyReport> {
    try {
      return await this.#prover.checkProvingKeys(context);
    } catch (cause) {
      throw fromClientCause(cause);
    }
  }

  async proveCustomRingPolicy(
    inputs: CustomRingPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    try {
      const proof = await this.#prover.proveCustomRingPolicy(inputs, context);
      return compressProof(proof).toCustomRingProof();
    } catch (cause) {
      throw fromClientCause(cause);
    }
  }

  async proveCustomRingCompressedPolicy(
    inputs: CustomRingCompressedPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    try {
      return compressProof(
        await this.#prover.proveCustomRingCompressedPolicy(inputs, context),
      ).toCustomRingProof();
    } catch (cause) {
      throw fromClientCause(cause);
    }
  }

  async proveCustomRingRegisterKey(
    inputs: CustomRingRegisterKeyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    try {
      return compressProof(
        await this.#prover.proveCustomRingRegisterKey(inputs, context),
      ).toCustomRingProof();
    } catch (cause) {
      throw fromClientCause(cause);
    }
  }

  async proveCustomRingDelegatePolicy(
    inputs: CustomRingPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    try {
      return compressProof(
        await this.#prover.proveCustomRingDelegatePolicy(inputs, context),
      ).toCustomRingProof();
    } catch (cause) {
      throw fromClientCause(cause);
    }
  }

  async proveRingAuthorityTransact(
    proofInputs: SppProofInputs,
    ringProgramId: Address,
    keys: ProofAuthority,
    context?: RequestContext,
    outputTree?: TreeContext,
  ): Promise<ProvenRingTransact> {
    checkedAddress(ringProgramId, "ringProgramId");
    return this.#proveTransfer(
      proofInputs,
      { kind: "ringAuthority", ring: ringProgramId },
      keys,
      undefined,
      context,
      outputTree,
    );
  }

  async proveCustomRingBase(
    inputs: CustomRingBaseProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    try {
      const proof = await this.#prover.proveCustomRingBase(inputs, context);
      return compressProof(proof).toCustomRingProof();
    } catch (cause) {
      throw fromClientCause(cause);
    }
  }

  async proveCustomRingDeposit(
    inputs: CustomRingDepositProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    try {
      return compressProof(
        await this.#prover.proveCustomRingDeposit(inputs, context),
      ).toCustomRingProof();
    } catch (cause) {
      throw fromClientCause(cause);
    }
  }

  async proveTransferInputs(
    inputs: TransferInputs,
    context?: RequestContext,
  ): Promise<TransactProof> {
    try {
      const proof = await this.#prover.prove(checkedProverInputs(inputs), context);
      return compressProof(proof).toTransactProof();
    } catch (cause) {
      throw fromClientCause(cause);
    }
  }

  async #proveTransfer(
    proofInputs: SppProofInputs,
    circuit: TransferCircuit,
    keys: ProofAuthority,
    config: IndexerRpcConfig | undefined,
    context: RequestContext | undefined,
    outputTree: TreeContext = this,
  ): Promise<ProvenRingTransact> {
    if (!(proofInputs instanceof SppProofInputs)) {
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    }
    checkProofAuthority(keys);
    if (treeAddress(outputTree.treeId) !== outputTree.tree)
      throw new ClientError("CLIENT_TREE_MISMATCH", {
        details: { transactionTree: outputTree.tree, clientTree: treeAddress(outputTree.treeId) },
      });
    // Output commitments bind the destination tree.
    if (proofInputs.outputTreeId !== outputTree.treeId) {
      throw new ClientError("CLIENT_TREE_ID_MISMATCH", {
        details: { expected: outputTree.treeId, actual: proofInputs.outputTreeId },
      });
    }
    try {
      const { proofs, dummyProofs } = await this.#inputProofs(proofInputs, config, context);
      const assembled = assemble(proofInputs, proofs, dummyProofs, circuit);
      const proof = await keys.prove(assembled.proverInputs, context);
      return Object.freeze({
        data: assembled.withProof(compressProof(proof).toTransactProof()),
        roots: assembled.roots,
      });
    } catch (cause) {
      throw fromClientCause(cause);
    }
  }

  async proveMerge(
    input: Readonly<{
      prepared: PreparedMerge;
      keys: ProofAuthority;
      indexer?: Pick<ProofReader, "getInputMerkleProofs" | "getNonInclusionProofs">;
    }>,
    context?: RequestContext,
  ): Promise<ProvedMerge> {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_MERGE");
    }
    checkProofAuthority(input.keys);
    const assembled = await assembleMerge(
      input.prepared,
      input.indexer ?? this,
      this.tree,
      context,
    );
    const compressed = compressProof(await input.keys.proveMerge(assembled.proverInputs, context));
    return Object.freeze({
      data: assembled.instructionData({
        a: compressed.a,
        b: compressed.b,
        c: compressed.c,
      }),
      outputHash: new Uint8Array(assembled.outputHash) as Bytes32,
    });
  }

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
    if (!hasMergeOutputBinding(proved)) {
      throw new ClientError("CLIENT_INVALID_MERGE");
    }
    if (!equal(proved.outputHash, proved.data.outputUtxoHash)) {
      throw new ClientError("CLIENT_MERGE_OUTPUT_MISMATCH");
    }
    checkedAddress(input.feePayer, "feePayer");
    checkedAddress(input.userRecord, "userRecord");
    const lifetime = await this.getLatestBlockhash(context);
    return await buildUnsignedMergeTransaction({
      tree: this.tree,
      feePayer: input.feePayer,
      userRecord: input.userRecord,
      lifetime,
      ...(this.#priorityFee === undefined ? {} : { priorityFeeLamports: this.#priorityFee }),
      data: input.proved.data,
    });
  }

  async assembleAuthorizedPrivateTransaction(
    input: Readonly<{
      authorized: AuthorizedPrivateTransaction;
      feePayer: Address;
      keys: ProofAuthority;
    }>,
    context?: RequestContext,
  ): Promise<Transaction> {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_TRANSACTION");
    }
    const fields = Reflect.ownKeys(candidate);
    if (
      fields.length !== 3 ||
      !Object.hasOwn(candidate, "authorized") ||
      !Object.hasOwn(candidate, "feePayer") ||
      !Object.hasOwn(candidate, "keys") ||
      fields.some((key) => key !== "authorized" && key !== "feePayer" && key !== "keys")
    ) {
      throw new ClientError("CLIENT_INVALID_TRANSACTION");
    }
    const feePayer: unknown = Reflect.get(candidate, "feePayer");
    checkedAddress(feePayer, "feePayer");
    const keys: unknown = Reflect.get(candidate, "keys");
    checkProofAuthority(keys);
    const authorized = authorizedPrivateTransactionMaterial(Reflect.get(candidate, "authorized"));
    if (authorized === undefined) {
      throw new ClientError("CLIENT_INVALID_TRANSACTION");
    }
    const data = await this.#proveAuthorizedPrivateTransaction(authorized, feePayer, keys, context);
    checkTransactData(data, authorized.intent, intentMismatch);
    const lifetime = await this.getLatestBlockhash(context);
    return await buildUnsignedTransaction({
      computeUnitLimit: this.#computeUnitLimit,
      ...(this.#priorityFee === undefined ? {} : { priorityFeeLamports: this.#priorityFee }),
      feePayer,
      inputTree: authorized.tree,
      outputTree: this.tree,
      setupInstructions: authorized.setupInstructions,
      ...(authorized.withdrawal === undefined ? {} : { withdrawal: authorized.withdrawal }),
      data,
      lifetime,
    });
  }

  async #proveAuthorizedPrivateTransaction(
    authorized: AuthorizedPrivateTransactionMaterial,
    feePayer: Address,
    keys: ProofAuthority,
    context?: RequestContext,
  ): Promise<TransactInstructionData> {
    if (feePayer !== authorized.proofInputs.payer) {
      throw new ClientError("CLIENT_FEE_PAYER_MISMATCH");
    }
    if (authorized.tree !== this.tree) {
      throw new ClientError("CLIENT_TREE_MISMATCH", {
        details: { transactionTree: authorized.tree, clientTree: this.tree },
      });
    }
    checkAuthorizedBinding(authorized, intentMismatch);
    return this.proveTransact(authorized.proofInputs, keys, undefined, context);
  }
}

/** A `ProofAuthority` is a structural type; a wrong argument fails here rather than as a missing method later. */
function checkProofAuthority(keys: unknown): asserts keys is ProofAuthority {
  if (!hasProofMethods(keys)) throw new ClientError("CLIENT_INVALID_PROOF_AUTHORITY");
}

/** Mirrors Rust `MERGE_CU_LIMIT`, the merge verifies one proof over eight inputs. */
export const MERGE_TRANSACT_COMPUTE_UNIT_LIMIT = 1_400_000;

export async function buildUnsignedTransaction(
  input: Readonly<{
    computeUnitLimit: number;
    priorityFeeLamports?: bigint;
    feePayer: Address;
    inputTree: Address;
    outputTree: Address;
    setupInstructions?: readonly Instruction[];
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
    lifetime: LatestBlockhash;
  }>,
): Promise<Transaction> {
  checkedAddress(input.inputTree, "inputTree");
  checkedAddress(input.outputTree, "outputTree");
  return compileUnsignedTransaction({
    feePayer: input.feePayer,
    lifetime: input.lifetime,
    computeUnitLimit: input.computeUnitLimit,
    ...(input.priorityFeeLamports === undefined
      ? {}
      : { priorityFeeLamports: input.priorityFeeLamports }),
    ...(input.setupInstructions === undefined
      ? {}
      : { setupInstructions: input.setupInstructions }),
    instructions: [
      await transactInstruction({
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

export async function buildUnsignedMergeTransaction(
  input: Readonly<{
    tree: Address;
    feePayer: Address;
    userRecord: Address;
    lifetime: LatestBlockhash;
    priorityFeeLamports?: bigint;
    data: MergeTransactInstructionData;
  }>,
): Promise<Transaction> {
  checkedAddress(input.tree, "tree");
  checkedAddress(input.userRecord, "userRecord");
  return compileUnsignedTransaction({
    feePayer: input.feePayer,
    lifetime: input.lifetime,
    computeUnitLimit: MERGE_TRANSACT_COMPUTE_UNIT_LIMIT,
    ...(input.priorityFeeLamports === undefined
      ? {}
      : { priorityFeeLamports: input.priorityFeeLamports }),
    instructions: [
      await mergeTransactInstruction({
        inputTree: input.tree,
        outputTree: input.tree,
        payer: input.feePayer,
        userRecord: input.userRecord,
        data: input.data,
      }),
    ],
  });
}

function checkedAddress(value: unknown, field: string): asserts value is Address {
  if (typeof value !== "string") {
    throw new ClientError("CLIENT_INVALID_BASE58", { details: { field } });
  }
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

/** The one field pair the assembler binds, the rest of `ProvedMerge` stays unclaimed. */
interface MergeOutputBinding {
  readonly outputHash: Uint8Array;
  readonly data: Readonly<{ outputUtxoHash: Uint8Array }>;
}

function hasMergeOutputBinding(value: unknown): value is MergeOutputBinding {
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

function intentMismatch(field: string): ClientError {
  return new ClientError("CLIENT_INTENT_MISMATCH", { details: { field } });
}
