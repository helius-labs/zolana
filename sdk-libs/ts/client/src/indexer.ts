import { ZolanaApi } from "@zolana/api";
import { hash, hashBytes } from "@zolana/indexer-api";
import type {
  GetEncryptedUtxosByTagsResponse,
  GetRingsByTagsRequest,
  GetShieldedTransactionsByTagsResponse,
  MerkleProof as WireMerkleProof,
  NonInclusionProof as WireNonInclusionProof,
} from "@zolana/indexer-api";
import type { Address, Bytes32, RequestContext } from "@zolana/interface";

import { ClientError } from "./error.js";
import { sleep } from "./internal.js";
import {
  DEFAULT_INDEXER_POLL,
  type GetMerkleProofsResponse,
  type GetNonInclusionProofsResponse,
  type IndexerPollConfig,
  type IndexerRpcConfig,
  type MerkleProof,
  type NonInclusionProof,
  validatePollConfig,
} from "./rpc.js";

const DEFAULT_PROOF_POLL = Object.freeze({
  numRetries: 120,
  delayMs: 500n,
  maxDelayMs: 500n,
});

export class ZolanaIndexer {
  readonly #api: ZolanaApi;

  constructor(api: ZolanaApi) {
    if (!(api instanceof ZolanaApi)) {
      throw new ClientError("CLIENT_INVALID_INDEXER", {
        details: { field: "api" },
      });
    }
    this.#api = api;
  }

  getEncryptedUtxosByTags(
    request: GetRingsByTagsRequest,
    context?: RequestContext,
  ): Promise<GetEncryptedUtxosByTagsResponse> {
    return this.#api.getEncryptedUtxosByTags(request, context);
  }

  getShieldedTransactionsByTags(
    request: GetRingsByTagsRequest,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsByTagsResponse> {
    return this.#api.getShieldedTransactionsByTags(request, context);
  }

  getMerkleProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetMerkleProofsResponse> {
    const requested = copyLeaves(leaves);
    return pollIndexer(
      config,
      context,
      async () => {
        try {
          const response = await this.#api.getMerkleProofs(
            { treeAccount, leaves: requested.map((leaf) => hash(leaf)) },
            context,
          );
          return Object.freeze({
            context: Object.freeze({ blockTime: response.context.blockTime }),
            proofs: Object.freeze(response.proofs.map(convertMerkleProof)),
          });
        } catch (cause) {
          throw wrapIndexer(cause, "getMerkleProofs");
        }
      },
      (response) => response.proofs.length >= requested.length,
      DEFAULT_PROOF_POLL,
    );
  }

  getNonInclusionProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetNonInclusionProofsResponse> {
    const requested = copyLeaves(leaves);
    return pollIndexer(
      config,
      context,
      async () => {
        try {
          const response = await this.#api.getNonInclusionProofs(
            { treeAccount, leaves: requested.map((leaf) => hash(leaf)) },
            context,
          );
          return Object.freeze({
            context: Object.freeze({ blockTime: response.context.blockTime }),
            proofs: Object.freeze(response.proofs.map(convertNonInclusionProof)),
          });
        } catch (cause) {
          throw wrapIndexer(cause, "getNonInclusionProofs");
        }
      },
      (response) => response.proofs.length >= requested.length,
      DEFAULT_PROOF_POLL,
    );
  }
}

function copyLeaves(leaves: readonly Bytes32[]): readonly Bytes32[] {
  return Object.freeze(
    leaves.map((leaf, index) => {
      if (!(leaf instanceof Uint8Array) || leaf.length !== 32) {
        throw new ClientError("CLIENT_INVALID_LENGTH", {
          details: {
            field: `leaves[${String(index)}]`,
            expected: 32,
            actual: leaf instanceof Uint8Array ? leaf.length : -1,
          },
        });
      }
      return new Uint8Array(leaf) as Bytes32;
    }),
  );
}

function convertMerkleProof(proof: WireMerkleProof): MerkleProof {
  return Object.freeze({
    leaf: copyHash(proof.leaf),
    merkleContext: Object.freeze({ ...proof.merkleContext }),
    path: Object.freeze(proof.path.map(copyHash)),
    leafIndex: proof.leafIndex,
    root: copyHash(proof.root),
    rootSeq: proof.rootSeq,
    rootIndex: proof.rootIndex,
  });
}

function convertNonInclusionProof(proof: WireNonInclusionProof): NonInclusionProof {
  return Object.freeze({
    leaf: copyHash(proof.leaf),
    merkleContext: Object.freeze({ ...proof.merkleContext }),
    path: Object.freeze(proof.path.map(copyHash)),
    lowElement: copyHash(proof.lowElement),
    lowElementIndex: proof.lowElementIndex,
    highElement: copyHash(proof.highElement),
    highElementIndex: proof.highElementIndex,
    root: copyHash(proof.root),
    rootSeq: proof.rootSeq,
    rootIndex: proof.rootIndex,
  });
}

function copyHash(value: Parameters<typeof hashBytes>[0]): Bytes32 {
  return new Uint8Array(hashBytes(value)) as Bytes32;
}

async function pollIndexer<T extends Readonly<{ context: Readonly<{ blockTime: bigint }> }>>(
  config: IndexerRpcConfig | undefined,
  context: RequestContext | undefined,
  request: () => Promise<T>,
  complete: (response: T) => boolean,
  defaultPoll: IndexerPollConfig = DEFAULT_INDEXER_POLL,
): Promise<T> {
  const rawConfig: unknown = config;
  if (
    rawConfig !== undefined &&
    (typeof rawConfig !== "object" ||
      rawConfig === null ||
      typeof (rawConfig as Record<string, unknown>)["waitForIndexer"] !== "boolean")
  ) {
    throw new ClientError("CLIENT_INVALID_POLL_CONFIG", {
      details: { field: "waitForIndexer" },
    });
  }
  const waitForIndexer = config?.waitForIndexer ?? false;
  const poll = validatePollConfig(config?.poll ?? defaultPoll);
  const target = BigInt(Math.floor(Date.now() / 1000));
  let latest = -(1n << 63n);
  let lastError: unknown;
  let delay = poll.delayMs;
  for (let attempt = 0; attempt <= poll.numRetries; attempt++) {
    if (attempt > 0) {
      await sleep(delay, context);
      delay = delay * 2n < poll.maxDelayMs ? delay * 2n : poll.maxDelayMs;
    }
    try {
      const response = await request();
      latest = response.context.blockTime;
      if (waitForIndexer ? latest >= target : complete(response)) return response;
    } catch (error) {
      if (waitForIndexer) throw error;
      lastError = error;
    }
  }
  if (waitForIndexer) {
    throw new ClientError("CLIENT_INDEXER_NOT_CAUGHT_UP", {
      details: {
        target: target.toString(),
        latest: latest.toString(),
        attempts: poll.numRetries + 1,
      },
      cause: safeCause(lastError),
    });
  }
  throw new ClientError("CLIENT_INDEXER_TIMEOUT", {
    details: { attempts: poll.numRetries + 1 },
    cause: safeCause(lastError),
  });
}

function wrapIndexer(cause: unknown, method: string): ClientError {
  if (cause instanceof ClientError) return cause;
  return new ClientError("CLIENT_INDEXER", {
    details: { method },
    cause: safeCause(cause),
  });
}

function safeCause(cause: unknown): unknown {
  if (
    typeof cause === "object" &&
    cause !== null &&
    "code" in cause &&
    typeof cause.code === "string"
  ) {
    return Object.freeze({ code: cause.code });
  }
  return undefined;
}
