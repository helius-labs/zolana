import type { Address, Bytes32, RequestContext, Signature, Transaction } from "@zolana/interface";
import type {
  GetMerkleProofsResponse,
  GetNonInclusionProofsResponse,
  IndexerRpcConfig,
  Rpc,
  SpendProof,
} from "@zolana/client";
import type { InputUtxoContext } from "@zolana/transaction";

import { TestKitError } from "./error.js";

interface RpcAccount {
  readonly owner: Address;
  readonly data: Uint8Array;
  readonly lamports: bigint;
}

function copyAccount(account: RpcAccount): RpcAccount {
  return Object.freeze({ ...account, data: new Uint8Array(account.data) });
}

function contextFailure(context?: RequestContext): Promise<never> | undefined {
  if (context?.signal?.aborted) {
    return Promise.reject(new TestKitError("TEST_KIT_ABORTED"));
  }
  if (context?.timeoutMs !== undefined && context.timeoutMs <= 0) {
    return Promise.reject(
      new TestKitError("TEST_KIT_TIMEOUT", {
        details: { timeoutMs: context.timeoutMs },
      }),
    );
  }
  return undefined;
}

export class TestRpc implements Rpc {
  readonly #accounts = new Map<Address, RpcAccount>();
  readonly #balances = new Map<Address, bigint>();
  readonly #confirmations = new Map<Signature, boolean>();
  readonly #viewTags = new Map<Signature, readonly Bytes32[]>();
  readonly #merkle = new Map<string, GetMerkleProofsResponse>();
  readonly #nonInclusion = new Map<string, GetNonInclusionProofsResponse>();
  readonly #spendProofs = new Map<string, SpendProof>();
  readonly sent: Transaction[] = [];
  blockhash = Object.freeze({
    blockhash: "11111111111111111111111111111111",
    lastValidBlockHeight: 1n,
  });
  nextSignature = "1111111111111111111111111111111111111111111111111111111111111111" as Signature;

  setAccount(address: Address, account: RpcAccount | undefined): void {
    if (account === undefined) this.#accounts.delete(address);
    else this.#accounts.set(address, copyAccount(account));
  }

  setBalance(address: Address, lamports: bigint): void {
    this.#balances.set(address, lamports);
  }

  setConfirmation(signature: Signature, confirmed: boolean): void {
    this.#confirmations.set(signature, confirmed);
  }

  setOutputViewTags(signature: Signature, tags: readonly Bytes32[]): void {
    this.#viewTags.set(
      signature,
      tags.map((tag) => new Uint8Array(tag) as Bytes32),
    );
  }

  setMerkleProofs(tree: Address, leaf: Bytes32, response: GetMerkleProofsResponse): void {
    this.#merkle.set(key(tree, leaf), response);
  }

  setNonInclusionProofs(
    tree: Address,
    leaf: Bytes32,
    response: GetNonInclusionProofsResponse,
  ): void {
    this.#nonInclusion.set(key(tree, leaf), response);
  }

  setSpendProof(utxoHash: Bytes32, proof: SpendProof): void {
    this.#spendProofs.set(hex(utxoHash), proof);
  }

  getAccount(address: Address, context?: RequestContext): Promise<RpcAccount | undefined> {
    const failure = contextFailure(context);
    if (failure) return failure;
    const account = this.#accounts.get(address);
    return Promise.resolve(account && copyAccount(account));
  }

  getMultipleAccounts(
    addresses: readonly Address[],
    context?: RequestContext,
  ): Promise<readonly (RpcAccount | undefined)[]> {
    const failure = contextFailure(context);
    if (failure) return failure;
    return Promise.resolve(
      addresses.map((address) => {
        const account = this.#accounts.get(address);
        return account && copyAccount(account);
      }),
    );
  }

  getBalance(address: Address, context?: RequestContext): Promise<bigint> {
    const failure = contextFailure(context);
    if (failure) return failure;
    return Promise.resolve(this.#balances.get(address) ?? 0n);
  }

  getLatestBlockhash(
    context?: RequestContext,
  ): Promise<Readonly<{ blockhash: string; lastValidBlockHeight: bigint }>> {
    const failure = contextFailure(context);
    if (failure) return failure;
    return Promise.resolve(Object.freeze({ ...this.blockhash }));
  }

  sendTransaction(transaction: Transaction, context?: RequestContext): Promise<Signature> {
    const failure = contextFailure(context);
    if (failure) return failure;
    this.sent.push({
      messageBytes: new Uint8Array(transaction.messageBytes),
      signatures: [...transaction.signatures],
    });
    return Promise.resolve(this.nextSignature);
  }

  confirmTransaction(signature: Signature, context?: RequestContext): Promise<boolean> {
    const failure = contextFailure(context);
    if (failure) return failure;
    return Promise.resolve(this.#confirmations.get(signature) ?? false);
  }

  transactOutputViewTags(
    signature: Signature,
    context?: RequestContext,
  ): Promise<readonly Bytes32[]> {
    const failure = contextFailure(context);
    if (failure) return failure;
    return Promise.resolve(
      (this.#viewTags.get(signature) ?? []).map((tag) => new Uint8Array(tag) as Bytes32),
    );
  }

  getMerkleProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    _config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetMerkleProofsResponse> {
    const failure = contextFailure(context);
    if (failure) return failure;
    return Promise.resolve(
      combineMerkle(leaves.map((leaf) => this.#merkle.get(key(treeAccount, leaf)))),
    );
  }

  getNonInclusionProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    _config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetNonInclusionProofsResponse> {
    const failure = contextFailure(context);
    if (failure) return failure;
    return Promise.resolve(
      combineNonInclusion(leaves.map((leaf) => this.#nonInclusion.get(key(treeAccount, leaf)))),
    );
  }

  getInputMerkleProofs(
    inputs: readonly InputUtxoContext[],
    _config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<readonly SpendProof[]> {
    const failure = contextFailure(context);
    if (failure) return failure;
    return Promise.resolve(
      inputs.map((input) => {
        const proof = this.#spendProofs.get(hex(input.utxoHash));
        if (proof === undefined) {
          throw new TestKitError("TEST_KIT_FIXTURE", {
            details: { reason: "missingSpendProof", inputIndex: input.index },
          });
        }
        return proof;
      }),
    );
  }
}

function combineMerkle(
  responses: readonly (GetMerkleProofsResponse | undefined)[],
): GetMerkleProofsResponse {
  return Object.freeze({
    context: Object.freeze({ blockTime: responses.at(-1)?.context.blockTime ?? 0n }),
    proofs: responses.flatMap((response) => response?.proofs ?? []),
  });
}

function combineNonInclusion(
  responses: readonly (GetNonInclusionProofsResponse | undefined)[],
): GetNonInclusionProofsResponse {
  return Object.freeze({
    context: Object.freeze({ blockTime: responses.at(-1)?.context.blockTime ?? 0n }),
    proofs: responses.flatMap((response) => response?.proofs ?? []),
  });
}

function key(tree: Address, leaf: Bytes32): string {
  return `${tree}:${hex(leaf)}`;
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
