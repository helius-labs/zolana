import { ZolanaApi } from "@zolana/api";
import {
  mergeTransactInstruction,
  mergeZoneInstruction,
  transactInstruction,
  type MergeTransactInstructionData,
} from "@zolana/interface/instructions";
import { checkedTransactionSize } from "@zolana/interface";
import type {
  Address,
  Bytes32,
  Instruction,
  RequestContext,
  Shape,
  Signature,
  Transaction,
  TransactionSigner,
  TransactInstructionData,
  TransactWithdrawal,
} from "@zolana/interface";
import type { NullifierKey, P256PublicKey, ShieldedPublicKey } from "@zolana/keypair";
import {
  PreparedMerge,
  PreparedMergeZone,
  SppProofInputs,
  type InputUtxoContext,
} from "@zolana/transaction";

import { ClientError, fromClientCause, isClientError } from "./error.js";
import {
  addressBytes,
  compareBytes,
  decodeBase58,
  sha256Bytes,
  signatureBytes,
} from "./internal.js";
import { ZolanaIndexer } from "./indexer.js";
import { assemble } from "./prover/assembly.js";
import { ProverClient, proveMerge, proveMergeZone } from "./prover/client.js";
import { assembleMerge, assembleMergeZone } from "./prover/merge.js";
import { compressProof } from "./prover/proof.js";
import { DEFAULT_INDEXER_RPC_CONFIG, pollUntil, validatePollConfig } from "./retry.js";
import { compactU16 } from "./wire.js";
import {
  type GetByTagsRequest,
  type GetMerkleProofsResponse,
  type GetNonInclusionProofsResponse,
  type GetShieldedTransactionsByTagsResponse,
  type IndexerRpcConfig,
  type Rpc,
  type RpcAccount,
  type SpendProof,
} from "./rpc.js";

const DEFAULT_TRANSACT_CU_LIMIT = 300_000;
const COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111" as Address;

export interface SignedPrivateTransaction {
  readonly transaction: SppProofInputs;
  readonly withdrawal?: TransactWithdrawal;
  readonly tree: Address;
}

export interface MergeMaterialInput {
  readonly signingPublicKey: ShieldedPublicKey;
  readonly viewingPublicKey: P256PublicKey;
  readonly nullifierKey: NullifierKey;
}

export interface ProvedMerge {
  readonly data: MergeTransactInstructionData;
  readonly outputHash: Bytes32;
}

export interface ProvedMergeZone extends ProvedMerge {
  readonly zoneProgramId: Address;
}

export class ZolanaClient implements Rpc {
  readonly tree: Address;
  readonly rpc: Rpc;
  readonly indexer: ZolanaIndexer;
  readonly #prover: ProverClient;
  readonly #computeUnitLimit: number;
  readonly #computeUnitPrice: bigint | undefined;
  /// `ZolanaClient::indexer_config` in Rust, which `with_indexer_config` and
  /// `with_indexer_poll_config` set. Confirmation polled a hard-coded default
  /// before, and the delegating indexer methods forwarded the caller's
  /// `undefined` straight through, so a configured client behaved like an
  /// unconfigured one on both paths.
  readonly #indexerConfig: IndexerRpcConfig;

  constructor(
    input: Readonly<{
      rpc: Rpc;
      indexer: ZolanaIndexer;
      prover: ProverClient;
      tree: Address;
      computeUnitLimit?: number;
      computeUnitPriceMicroLamports?: bigint;
      indexerConfig?: IndexerRpcConfig;
    }>,
  ) {
    const candidate: unknown = input;
    if (
      typeof candidate !== "object" ||
      candidate === null ||
      typeof input.rpc !== "object" ||
      ![
        "getAccount",
        "getMultipleAccounts",
        "getBalance",
        "getLatestBlockhash",
        "sendTransaction",
        "confirmTransaction",
        "transactOutputViewTags",
      ].every((method) => typeof input.rpc[method as keyof Rpc] === "function") ||
      !(input.indexer instanceof ZolanaIndexer) ||
      !(input.prover instanceof ProverClient)
    ) {
      throw new ClientError("CLIENT_INVALID_CONFIG");
    }
    addressBytes(input.tree);
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
    this.rpc = input.rpc;
    this.indexer = input.indexer;
    this.#prover = input.prover;
    this.tree = input.tree;
    this.#computeUnitPrice = input.computeUnitPriceMicroLamports;
    const indexerConfig = input.indexerConfig ?? DEFAULT_INDEXER_RPC_CONFIG;
    validatePollConfig(indexerConfig.poll);
    this.#indexerConfig = indexerConfig;
  }

  /**
   * Build a client from an RPC plus the indexer and prover URLs, mirroring
   * Rust's `ZolanaClient::from_urls`. The RPC is passed in because a caller may
   * already hold one, or may be supplying their own implementation.
   */
  static fromUrls(
    input: Readonly<{
      rpc: Rpc;
      indexerUrl: URL | string;
      proverUrl: URL | string;
      tree: Address;
      computeUnitLimit?: number;
      computeUnitPriceMicroLamports?: bigint;
      indexerConfig?: IndexerRpcConfig;
    }>,
  ): ZolanaClient {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_CONFIG");
    }
    return new ZolanaClient({
      rpc: input.rpc,
      indexer: new ZolanaIndexer(new ZolanaApi({ url: input.indexerUrl })),
      prover: new ProverClient({ url: input.proverUrl }),
      tree: input.tree,
      ...(input.computeUnitLimit === undefined
        ? {}
        : { computeUnitLimit: input.computeUnitLimit }),
      ...(input.computeUnitPriceMicroLamports === undefined
        ? {}
        : { computeUnitPriceMicroLamports: input.computeUnitPriceMicroLamports }),
      ...(input.indexerConfig === undefined ? {} : { indexerConfig: input.indexerConfig }),
    });
  }

  /// Mirrors Rust's `ZolanaClient::indexer_config`: the config every indexer
  /// call falls back to and the schedule confirmation polls.
  get indexerConfig(): IndexerRpcConfig {
    return this.#indexerConfig;
  }

  getAccount(address: Address, context?: RequestContext): Promise<RpcAccount | undefined> {
    return this.rpc.getAccount(address, context);
  }

  getMultipleAccounts(
    addresses: readonly Address[],
    context?: RequestContext,
  ): Promise<readonly (RpcAccount | undefined)[]> {
    return this.rpc.getMultipleAccounts(addresses, context);
  }

  getBalance(address: Address, context?: RequestContext): Promise<bigint> {
    return this.rpc.getBalance(address, context);
  }

  getLatestBlockhash(
    context?: RequestContext,
  ): Promise<Readonly<{ blockhash: string; lastValidBlockHeight: bigint }>> {
    return this.rpc.getLatestBlockhash(context);
  }

  sendTransaction(transaction: Transaction, context?: RequestContext): Promise<Signature> {
    return this.rpc.sendTransaction(transaction, context);
  }

  confirmTransaction(signature: Signature, context?: RequestContext): Promise<boolean> {
    return this.rpc.confirmTransaction(signature, context);
  }

  transactOutputViewTags(
    signature: Signature,
    context?: RequestContext,
  ): Promise<readonly Bytes32[]> {
    return this.rpc.transactOutputViewTags(signature, context);
  }

  /**
   * Compile, sign, and send `instructions` in one call, mirroring Rust's
   * `Rpc::create_and_send_transaction`. Returns once the cluster accepts the
   * transaction; it does not wait for confirmation or for the indexer to catch
   * up, which `confirmPrivateTransaction` does.
   *
   * `feePayer` signs first and every signer in `signers` after it, so a
   * transaction requiring several signatures is passed along the list. A signer
   * that is not required by the compiled message is an error rather than a
   * silent no-op.
   */
  async createAndSendTransaction(
    input: Readonly<{
      instructions: readonly Instruction[];
      feePayer: TransactionSigner;
      signers?: readonly TransactionSigner[];
    }>,
    context?: RequestContext,
  ): Promise<Signature> {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_TRANSACTION");
    }
    const latest = await this.rpc.getLatestBlockhash(context);
    const unsigned = compileTransaction({
      feePayer: input.feePayer.address,
      recentBlockhash: latest.blockhash,
      instructions: input.instructions,
    });
    let signed = unsigned;
    for (const signer of [input.feePayer, ...(input.signers ?? [])]) {
      signed = await signer.signNativeTransaction(signed);
    }
    // The compiled message reserves one slot per required signer, and the
    // cluster rejects a message with an unfilled slot. Reporting it here names
    // the signer that is missing instead of spending a round trip to be told
    // the signature count is wrong.
    const missing = signed.signatures.findIndex((signature) => signature === undefined);
    if (signed.signatures.length !== unsigned.signatures.length || missing !== -1) {
      throw new ClientError("CLIENT_INCOMPLETE_SIGNATURES", {
        details: {
          required: unsigned.signatures.length,
          provided: signed.signatures.length,
          ...(missing === -1 ? {} : { missingIndex: missing }),
        },
      });
    }
    return await this.rpc.sendTransaction(signed, context);
  }

  /**
   * Mirrors Rust's `ZolanaClient::get_shielded_transactions_by_tags`, which
   * reaches the indexer through the client rather than through a second handle.
   */
  getShieldedTransactionsByTags(
    request: GetByTagsRequest,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsByTagsResponse> {
    return this.indexer.getShieldedTransactionsByTags(request, this.#configOr(config), context);
  }

  getMerkleProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetMerkleProofsResponse> {
    return this.indexer.getMerkleProofs(treeAccount, leaves, this.#configOr(config), context);
  }

  getNonInclusionProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetNonInclusionProofsResponse> {
    return this.indexer.getNonInclusionProofs(treeAccount, leaves, this.#configOr(config), context);
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
      this.indexer.getMerkleProofs(
        this.tree,
        commitments.map((item) => item.utxoHash),
        this.#configOr(config),
        context,
      ),
      this.indexer.getNonInclusionProofs(
        this.tree,
        commitments.map((item) => item.nullifier),
        this.#configOr(config),
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
      const proofs = await this.getInputMerkleProofs(proofInputs.inputUtxoHashes(), config, context);
      const assembled = assemble(proofInputs, proofs);
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
      indexer?: Pick<Rpc, "getInputMerkleProofs">;
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
      await proveMerge(this.#prover, assembled.proverInputs, context),
    );
    const commitment = compressed.commitment;
    if (!commitment) throw new ClientError("CLIENT_MERGE_PROOF_COMMITMENT");
    return Object.freeze({
      data: assembled.instructionData({
        a: compressed.a,
        b: compressed.b,
        c: compressed.c,
        commitment: commitment.commitment,
        commitmentPok: commitment.commitmentPok,
      }),
      outputHash: new Uint8Array(assembled.outputHash) as Bytes32,
    });
  }

  async proveMergeZone(
    input: Readonly<{
      prepared: PreparedMergeZone;
      material: MergeMaterialInput;
      indexer?: Pick<Rpc, "getInputMerkleProofs">;
    }>,
    context?: RequestContext,
  ): Promise<ProvedMergeZone> {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_MERGE");
    }
    const assembled = await assembleMergeZone(
      input.prepared,
      input.material,
      input.indexer ?? this,
      this.tree,
      context,
    );
    const compressed = compressProof(
      await proveMergeZone(this.#prover, assembled.proverInputs, context),
    );
    const commitment = compressed.commitment;
    if (!commitment) throw new ClientError("CLIENT_MERGE_PROOF_COMMITMENT");
    return Object.freeze({
      data: assembled.instructionData({
        a: compressed.a,
        b: compressed.b,
        c: compressed.c,
        commitment: commitment.commitment,
        commitmentPok: commitment.commitmentPok,
      }),
      outputHash: new Uint8Array(assembled.outputHash) as Bytes32,
      zoneProgramId: input.prepared.zoneProgramId,
    });
  }

  finishMergeSubmissionUnsigned(
    input: Readonly<{
      proved: ProvedMerge;
      feePayer: Address;
      userRecord: Address;
      recentBlockhash: string;
    }>,
  ): Transaction {
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
    addressBytes(input.feePayer);
    addressBytes(input.userRecord);
    decodeBase58(input.recentBlockhash, 32, "recentBlockhash");
    return buildUnsignedMergeTransaction({
      tree: this.tree,
      feePayer: input.feePayer,
      userRecord: input.userRecord,
      recentBlockhash: input.recentBlockhash,
      data: proved.data,
    });
  }

  finishMergeZoneSubmissionUnsigned(
    input: Readonly<{
      proved: ProvedMergeZone;
      feePayer: Address;
      zoneProgramId: Address;
      mergeViewTag: Bytes32;
      recentBlockhash: string;
    }>,
  ): Transaction {
    const candidate: unknown = input;
    const proved =
      typeof candidate === "object" && candidate !== null
        ? (candidate as Record<string, unknown>)["proved"]
        : undefined;
    if (!isProvedMergeZone(proved) || proved.zoneProgramId !== input.zoneProgramId) {
      throw new ClientError("CLIENT_INVALID_MERGE");
    }
    if (!equal(proved.outputHash, proved.data.outputUtxoHash)) {
      throw new ClientError("CLIENT_MERGE_OUTPUT_MISMATCH");
    }
    addressBytes(input.feePayer);
    addressBytes(input.zoneProgramId);
    if (!(input.mergeViewTag instanceof Uint8Array) || input.mergeViewTag.length !== 32) {
      throw new ClientError("CLIENT_INVALID_MERGE");
    }
    decodeBase58(input.recentBlockhash, 32, "recentBlockhash");
    return buildUnsignedMergeZoneTransaction({
      tree: this.tree,
      feePayer: input.feePayer,
      zoneProgramId: input.zoneProgramId,
      mergeViewTag: input.mergeViewTag,
      recentBlockhash: input.recentBlockhash,
      data: proved.data,
    });
  }

  async finishSubmissionUnsigned(
    input: Readonly<{
      signed: SignedPrivateTransaction;
      feePayer: Address;
      recentBlockhash: string;
    }>,
    context?: RequestContext,
  ): Promise<Transaction> {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_TRANSACTION");
    }
    decodeBase58(input.recentBlockhash, 32, "recentBlockhash");
    // Rust validates the fee payer before the tree, so a transaction wrong in
    // both ways reports the mismatch the caller controls.
    const payerHash = sha256Bytes(addressBytes(input.feePayer));
    payerHash[0] = 0;
    if (!equal(payerHash, input.signed.transaction.payerPublicKeyHash)) {
      throw new ClientError("CLIENT_FEE_PAYER_MISMATCH");
    }
    if (input.signed.tree !== this.tree) {
      throw new ClientError("CLIENT_TREE_MISMATCH", {
        details: { transactionTree: input.signed.tree, clientTree: this.tree },
      });
    }
    // Rust passes `None` here: the submission path always reads the indexer's tip.
    const data = await this.proveTransact(input.signed.transaction, undefined, context);
    return buildUnsignedTransaction({
      computeUnitLimit: this.#computeUnitLimit,
      ...(this.#computeUnitPrice === undefined
        ? {}
        : { computeUnitPriceMicroLamports: this.#computeUnitPrice }),
      feePayer: input.feePayer,
      tree: input.signed.tree,
      ...(input.signed.withdrawal === undefined ? {} : { withdrawal: input.signed.withdrawal }),
      data,
      recentBlockhash: input.recentBlockhash,
    });
  }

  async confirmPrivateTransaction(signature: Signature, context?: RequestContext): Promise<void> {
    signatureBytes(signature);
    try {
      await pollUntil(
        () => this.rpc.confirmTransaction(signature, context),
        (confirmed) => confirmed,
        {
          config: this.#indexerConfig.poll,
          ...(context === undefined ? {} : { context }),
        },
      );
    } catch (cause) {
      if (!isClientError(cause) || cause.code !== "CLIENT_POLL_TIMED_OUT") throw cause;
      throw new ClientError("CLIENT_CONFIRMATION_TIMEOUT", {
        details: { signature, attempts: this.#indexerConfig.poll.numRetries + 1 },
        cause,
      });
    }
    const tags = await this.rpc.transactOutputViewTags(signature, context);
    if (tags.length === 0) throw new ClientError("CLIENT_MISSING_OUTPUT");
    try {
      await pollUntil(
        // `wait_for_indexed_transaction` sends `Some(50)`; omitting it left the
        // page size to the server, so a busy tag could push the signature off
        // the first page.
        () => this.indexer.getShieldedTransactionsByTags({ tags, limit: 50 }, undefined, context),
        // Rust accepts the signature alone. Re-checking that every requested
        // tag reappears in `outputSlots`/`messages` made this reject records
        // Rust confirms: the indexer answers a tag query with the whole
        // transaction, and which slot carries a tag is the indexer's business,
        // not a confirmation precondition.
        (response) =>
          response.transactions.some((transaction) => transaction.txSignature === signature),
        {
          config: this.#indexerConfig.poll,
          ...(context === undefined ? {} : { context }),
        },
      );
      return;
    } catch (cause) {
      if (!isClientError(cause) || cause.code !== "CLIENT_POLL_TIMED_OUT") throw cause;
      throw new ClientError("CLIENT_INDEXER_TIMEOUT", {
        details: {
          signature,
          expectedTags: tags.length,
          attempts: this.#indexerConfig.poll.numRetries + 1,
        },
        cause,
      });
    }
  }
}

/**
 * Compile `instructions` against a fresh blockhash, hand the unsigned
 * transaction to `sign`, and submit it: Rust's `Rpc::create_and_send_transaction`
 * without the keypairs.
 *
 * Rust takes `&[&Keypair]` and signs in place. No SDK surface here holds key
 * material, so the caller signs, which is also how Light Protocol splits it
 * (`buildAndSignTx` then `sendAndConfirmTx`, both free functions beside `Rpc`
 * rather than methods on it).
 */
export async function createAndSendTransaction(
  input: Readonly<{
    rpc: Rpc;
    feePayer: Address;
    instructions: readonly Instruction[];
    sign: (transaction: Transaction) => Promise<Transaction>;
  }>,
  context?: RequestContext,
): Promise<Signature> {
  const latest = await input.rpc.getLatestBlockhash(context);
  const unsigned = compileLegacyTransaction(input.feePayer, latest.blockhash, input.instructions);
  const signed = await input.sign(unsigned);
  // `Transaction::new` fills every reserved slot by construction, so Rust cannot
  // reach the cluster with one empty. A caller's signer can, and the cluster
  // rejects it, so the round trip is wasted rather than informative.
  const missing = signed.signatures.findIndex((signature) => signature === undefined);
  if (signed.signatures.length !== unsigned.signatures.length || missing !== -1) {
    throw new ClientError("CLIENT_INCOMPLETE_SIGNATURES", {
      details: {
        required: unsigned.signatures.length,
        provided: signed.signatures.length,
        ...(missing === -1 ? {} : { missingIndex: missing }),
      },
    });
  }
  return await input.rpc.sendTransaction(signed, context);
}

export function buildUnsignedTransaction(
  input: Readonly<{
    computeUnitLimit: number;
    computeUnitPriceMicroLamports?: bigint;
    feePayer: Address;
    tree: Address;
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
    recentBlockhash: string;
  }>,
): Transaction {
  const instructions: Instruction[] = [
    computeUnitLimitInstruction(input.computeUnitLimit),
    ...(input.computeUnitPriceMicroLamports === undefined
      ? []
      : [computeUnitPriceInstruction(input.computeUnitPriceMicroLamports)]),
    transactInstruction({
      payer: input.feePayer,
      tree: input.tree,
      data: input.data,
      ...(input.withdrawal === undefined ? {} : { withdrawal: input.withdrawal }),
    }),
  ];
  return compileLegacyTransaction(input.feePayer, input.recentBlockhash, instructions, {
    inputs: input.data.inputs.length,
    outputs: input.data.outputs.length,
  });
}

export function buildUnsignedMergeTransaction(
  input: Readonly<{
    tree: Address;
    feePayer: Address;
    userRecord: Address;
    recentBlockhash: string;
    data: MergeTransactInstructionData;
  }>,
): Transaction {
  return compileLegacyTransaction(input.feePayer, input.recentBlockhash, [
    computeUnitLimitInstruction(1_400_000),
    mergeTransactInstruction({
      tree: input.tree,
      payer: input.feePayer,
      userRecord: input.userRecord,
      data: input.data,
    }),
  ]);
}

export function buildUnsignedMergeZoneTransaction(
  input: Readonly<{
    tree: Address;
    feePayer: Address;
    zoneProgramId: Address;
    mergeViewTag: Bytes32;
    recentBlockhash: string;
    data: MergeTransactInstructionData;
  }>,
): Transaction {
  return compileLegacyTransaction(input.feePayer, input.recentBlockhash, [
    computeUnitLimitInstruction(1_400_000),
    mergeZoneInstruction({
      tree: input.tree,
      zoneProgramId: input.zoneProgramId,
      payer: input.feePayer,
      data: input.data,
      mergeViewTag: input.mergeViewTag,
    }),
  ]);
}

/**
 * Compile instructions into an unsigned legacy transaction whose signature
 * slots are all empty. Callers that only need the shielded `Transact`
 * instruction should prefer `ZolanaClient.finishSubmissionUnsigned`, which
 * also applies the client's compute budget.
 */
export function compileTransaction(
  input: Readonly<{
    feePayer: Address;
    recentBlockhash: string;
    instructions: readonly Instruction[];
  }>,
): Transaction {
  return compileLegacyTransaction(input.feePayer, input.recentBlockhash, input.instructions);
}

function compileLegacyTransaction(
  feePayer: Address,
  recentBlockhash: string,
  instructions: readonly Instruction[],
  shape?: Shape,
): Transaction {
  const accountMap = new Map<
    Address,
    { address: Address; bytes: Uint8Array; isSigner: boolean; isWritable: boolean }
  >();
  accountMap.set(feePayer, {
    address: feePayer,
    bytes: addressBytes(feePayer),
    isSigner: true,
    isWritable: true,
  });
  for (const instruction of instructions) {
    addressBytes(instruction.programAddress);
    for (const account of instruction.accounts) {
      const existing = accountMap.get(account.address);
      accountMap.set(account.address, {
        address: account.address,
        bytes: existing?.bytes ?? addressBytes(account.address),
        isSigner: (existing?.isSigner ?? false) || account.isSigner,
        isWritable: (existing?.isWritable ?? false) || account.isWritable,
      });
    }
    if (!accountMap.has(instruction.programAddress)) {
      accountMap.set(instruction.programAddress, {
        address: instruction.programAddress,
        bytes: addressBytes(instruction.programAddress),
        isSigner: false,
        isWritable: false,
      });
    }
  }
  // `solana_message::Message::new` compiles through `CompiledKeys`, whose
  // `BTreeMap<Address, _>` hands each privilege class back in ascending address
  // order with the fee payer lifted to the front. Ordering by first appearance
  // instead produces a different account list and different compiled indexes
  // for the same instructions.
  const accounts = [...accountMap.values()].sort((left, right) => {
    if (left.address === feePayer) return -1;
    if (right.address === feePayer) return 1;
    if (left.isSigner !== right.isSigner) return left.isSigner ? -1 : 1;
    if (left.isWritable !== right.isWritable) return left.isWritable ? -1 : 1;
    return compareBytes(left.bytes, right.bytes);
  });
  if (accounts.length > 256) throw new ClientError("CLIENT_TOO_MANY_ACCOUNTS");
  const index = new Map(accounts.map((account, itemIndex) => [account.address, itemIndex]));
  const requiredSignatures = accounts.filter((account) => account.isSigner).length;
  const readonlySigners = accounts.filter(
    (account) => account.isSigner && !account.isWritable,
  ).length;
  const readonlyUnsigned = accounts.filter(
    (account) => !account.isSigner && !account.isWritable,
  ).length;
  const parts: Uint8Array[] = [
    Uint8Array.of(requiredSignatures, readonlySigners, readonlyUnsigned),
    compactU16(accounts.length),
    ...accounts.map((account) => addressBytes(account.address)),
    decodeBase58(recentBlockhash, 32, "recentBlockhash"),
    compactU16(instructions.length),
  ];
  for (const instruction of instructions) {
    const programIndex = index.get(instruction.programAddress);
    if (programIndex === undefined) throw new ClientError("CLIENT_TRANSACTION_ASSEMBLY");
    const accountIndexes = instruction.accounts.map((account) => {
      const itemIndex = index.get(account.address);
      if (itemIndex === undefined) throw new ClientError("CLIENT_TRANSACTION_ASSEMBLY");
      return itemIndex;
    });
    parts.push(
      Uint8Array.of(programIndex),
      compactU16(accountIndexes.length),
      Uint8Array.from(accountIndexes),
      compactU16(instruction.data.length),
      new Uint8Array(instruction.data),
    );
  }
  return checkedTransactionSize(
    Object.freeze({
      messageBytes: concat(...parts),
      signatures: Object.freeze(Array.from({ length: requiredSignatures }, () => undefined)),
    }),
    shape,
  );
}

function computeUnitLimitInstruction(limit: number): Instruction {
  const data = new Uint8Array(5);
  data[0] = 2;
  new DataView(data.buffer).setUint32(1, limit, true);
  return Object.freeze({
    programAddress: COMPUTE_BUDGET_PROGRAM,
    accounts: Object.freeze([]),
    data,
  });
}

function computeUnitPriceInstruction(price: bigint): Instruction {
  const data = new Uint8Array(9);
  data[0] = 3;
  new DataView(data.buffer).setBigUint64(1, price, true);
  return Object.freeze({
    programAddress: COMPUTE_BUDGET_PROGRAM,
    accounts: Object.freeze([]),
    data,
  });
}

function concat(...values: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

function checkedU32(value: number, fieldName: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field: fieldName } });
  }
  return value;
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

// Rust keeps plain and zone proved objects apart by type; structural typing
// cannot, so the plain guard requires `zoneProgramId` to be absent.
function hasProvedMergeShape(value: unknown): value is ProvedMerge {
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

function isProvedMerge(value: unknown): value is ProvedMerge {
  return hasProvedMergeShape(value) && !("zoneProgramId" in value);
}

function isProvedMergeZone(value: unknown): value is ProvedMergeZone {
  return (
    hasProvedMergeShape(value) &&
    "zoneProgramId" in value &&
    typeof (value as Record<string, unknown>)["zoneProgramId"] === "string"
  );
}
