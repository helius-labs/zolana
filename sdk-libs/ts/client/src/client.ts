import {
  mergeTransactInstruction,
  transactInstruction,
  type MergeTransactInstructionData,
} from "@zolana/interface/instructions";
import type {
  Address,
  Bytes32,
  Instruction,
  RequestContext,
  Signature,
  Transaction,
  TransactInstructionData,
  TransactWithdrawal,
} from "@zolana/interface";
import type { NullifierKey, P256PublicKey, ShieldedPublicKey } from "@zolana/keypair";
import { PreparedMerge, SppProofInputs, type InputUtxoContext } from "@zolana/transaction";

import { ClientError, fromClientCause } from "./error.js";
import { addressBytes, decodeBase58, sha256Bytes, signatureBytes, sleep } from "./internal.js";
import { ZolanaIndexer } from "./indexer.js";
import { assemble } from "./prover/assembly.js";
import { ProverClient, proveMerge } from "./prover/client.js";
import { assembleMerge } from "./prover/merge.js";
import { compressProof } from "./prover/proof.js";
import {
  DEFAULT_INDEXER_POLL,
  type GetMerkleProofsResponse,
  type GetNonInclusionProofsResponse,
  type IndexerRpcConfig,
  type Rpc,
  type RpcAccount,
  type SpendProof,
  validatePollConfig,
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

export class ZolanaClient implements Rpc {
  readonly tree: Address;
  readonly rpc: Rpc;
  readonly indexer: ZolanaIndexer;
  readonly #prover: ProverClient;
  readonly #computeUnitLimit: number;
  readonly #computeUnitPrice: bigint | undefined;

  constructor(
    input: Readonly<{
      rpc: Rpc;
      indexer: ZolanaIndexer;
      prover: ProverClient;
      tree: Address;
      computeUnitLimit?: number;
      computeUnitPriceMicroLamports?: bigint;
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

  getMerkleProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetMerkleProofsResponse> {
    return this.indexer.getMerkleProofs(treeAccount, leaves, config, context);
  }

  getNonInclusionProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetNonInclusionProofsResponse> {
    return this.indexer.getNonInclusionProofs(treeAccount, leaves, config, context);
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
        config,
        context,
      ),
      this.indexer.getNonInclusionProofs(
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
        if (!equal(nullifierProof.leaf, commitment.nullifier)) {
          throw new ClientError("CLIENT_NULLIFIER_PROOF_LEAF_MISMATCH", {
            details: { index },
          });
        }
        if (stateProof.merkleContext.tree !== this.tree) {
          throw new ClientError("CLIENT_STATE_PROOF_TREE_MISMATCH", {
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
    context?: RequestContext,
  ): Promise<TransactInstructionData> {
    if (!(proofInputs instanceof SppProofInputs)) {
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    }
    try {
      const proofs = await this.getInputMerkleProofs(
        proofInputs.inputContexts(),
        undefined,
        context,
      );
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
    addressBytes(input.feePayer);
    decodeBase58(input.recentBlockhash, 32, "recentBlockhash");
    if (input.signed.tree !== this.tree) {
      throw new ClientError("CLIENT_TREE_MISMATCH", {
        details: { transactionTree: input.signed.tree, clientTree: this.tree },
      });
    }
    const payerHash = sha256Bytes(addressBytes(input.feePayer));
    payerHash[0] = 0;
    if (!equal(payerHash, input.signed.transaction.payerPublicKeyHash)) {
      throw new ClientError("CLIENT_FEE_PAYER_MISMATCH");
    }
    const data = await this.proveTransact(input.signed.transaction, context);
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
    const poll = validatePollConfig(DEFAULT_INDEXER_POLL);
    let delay = poll.delayMs;
    let confirmed = false;
    for (let attempt = 0; attempt <= poll.numRetries; attempt++) {
      if (attempt > 0) {
        await sleep(delay, context);
        delay = delay * 2n < poll.maxDelayMs ? delay * 2n : poll.maxDelayMs;
      }
      try {
        if (await this.rpc.confirmTransaction(signature, context)) {
          confirmed = true;
          break;
        }
      } catch {
        continue;
      }
    }
    if (!confirmed) {
      throw new ClientError("CLIENT_CONFIRMATION_TIMEOUT", {
        details: { signature, attempts: poll.numRetries + 1 },
      });
    }
    const tags = await this.rpc.transactOutputViewTags(signature, context);
    if (tags.length === 0) throw new ClientError("CLIENT_MISSING_OUTPUT");
    delay = poll.delayMs;
    for (let attempt = 0; attempt <= poll.numRetries; attempt++) {
      if (attempt > 0) {
        await sleep(delay, context);
        delay = delay * 2n < poll.maxDelayMs ? delay * 2n : poll.maxDelayMs;
      }
      try {
        const response = await this.indexer.getShieldedTransactionsByTags(
          { tags },
          undefined,
          context,
        );
        const matched = response.transactions.find(
          (transaction) => transaction.txSignature === signature,
        );
        if (matched) {
          const indexed = [
            ...matched.outputSlots.map((slot) => slot.viewTag),
            ...matched.messages.map((message) => message.viewTag),
          ];
          if (tags.every((tag) => indexed.some((item) => equal(item, tag)))) return;
        }
      } catch {
        continue;
      }
    }
    throw new ClientError("CLIENT_INDEXER_TIMEOUT", {
      details: { signature, expectedTags: tags.length, attempts: poll.numRetries + 1 },
    });
  }
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
  return compileLegacyTransaction(input.feePayer, input.recentBlockhash, instructions);
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

function compileLegacyTransaction(
  feePayer: Address,
  recentBlockhash: string,
  instructions: readonly Instruction[],
): Transaction {
  const accountMap = new Map<
    Address,
    { address: Address; isSigner: boolean; isWritable: boolean; order: number }
  >();
  let order = 0;
  accountMap.set(feePayer, {
    address: feePayer,
    isSigner: true,
    isWritable: true,
    order: order++,
  });
  for (const instruction of instructions) {
    addressBytes(instruction.programAddress);
    for (const account of instruction.accounts) {
      addressBytes(account.address);
      const existing = accountMap.get(account.address);
      accountMap.set(account.address, {
        address: account.address,
        isSigner: (existing?.isSigner ?? false) || account.isSigner,
        isWritable: (existing?.isWritable ?? false) || account.isWritable,
        order: existing?.order ?? order++,
      });
    }
    if (!accountMap.has(instruction.programAddress)) {
      accountMap.set(instruction.programAddress, {
        address: instruction.programAddress,
        isSigner: false,
        isWritable: false,
        order: order++,
      });
    }
  }
  const accounts = [...accountMap.values()].sort((left, right) => {
    if (left.address === feePayer) return -1;
    if (right.address === feePayer) return 1;
    if (left.isSigner !== right.isSigner) return left.isSigner ? -1 : 1;
    if (left.isWritable !== right.isWritable) return left.isWritable ? -1 : 1;
    return left.order - right.order;
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
  return Object.freeze({
    messageBytes: concat(...parts),
    signatures: Object.freeze(Array.from({ length: requiredSignatures }, () => undefined)),
  });
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

function compactU16(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
    throw new ClientError("CLIENT_INVALID_INTEGER");
  }
  const result: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining !== 0) byte |= 0x80;
    result.push(byte);
  } while (remaining !== 0);
  return Uint8Array.from(result);
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
