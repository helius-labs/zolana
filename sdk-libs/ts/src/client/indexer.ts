import { ZolanaApi } from "../api/index.js";
import { base64String, hash, hashBytes, limit } from "../indexer/scalars.js";
import type {
  EncryptedUtxoMatch as WireEncryptedUtxoMatch,
  GetEncryptedUtxosByTagsResponse as WireGetEncryptedUtxosByTagsResponse,
  GetShieldedTransactionsByNullifiersResponse as WireGetShieldedTransactionsByNullifiersResponse,
  GetShieldedTransactionsBySignatureResponse as WireGetShieldedTransactionsBySignatureResponse,
  GetShieldedTransactionsByTagsResponse as WireGetShieldedTransactionsByTagsResponse,
  IndexedShieldedTransaction as WireShieldedTransaction,
  MerkleProof as WireMerkleProof,
  NonInclusionProof as WireNonInclusionProof,
  RingsOutputSlot as WireOutputSlot,
} from "../indexer/types.js";
import type {
  Address,
  Bytes16,
  Bytes32,
  Bytes33,
  RequestContext,
  Signature,
} from "../interface/types.js";
import { P256PublicKey } from "../keypair/public-key.js";
import type { IndexedShieldedTransaction } from "../transaction/instructions/transact.js";

import { ClientError, isClientError } from "./error.js";
import { decodeBase64 } from "./internal.js";
import {
  DEFAULT_INDEXER_POLL_CONFIG,
  pollUntil,
  validatePollConfig,
  type IndexerRpcConfig,
} from "./retry.js";
import {
  type EncryptedUtxoMatch,
  type GetByNullifiersRequest,
  type GetByTagsRequest,
  type GetEncryptedUtxosByTagsResponse,
  type GetMerkleProofsResponse,
  type GetNonInclusionProofsResponse,
  type GetShieldedTransactionsByNullifiersResponse,
  type GetShieldedTransactionsBySignatureResponse,
  type GetShieldedTransactionsByTagsResponse,
  type MerkleProof,
  type NonInclusionProof,
} from "./rpc.js";

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
    request: GetByTagsRequest,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetEncryptedUtxosByTagsResponse> {
    const owned = copyTagRequest(request);
    return pollIndexer(config, context, async () => {
      const method = "getEncryptedUtxosByTags";
      try {
        const response = await this.#api.getEncryptedUtxosByTags(
          {
            tags: owned.tags.map((tag) => hash(tag)),
            ...(owned.cursor === undefined ? {} : { cursor: base64String(owned.cursor) }),
            ...(owned.limit === undefined ? {} : { limit: limit(BigInt(owned.limit)) }),
          },
          context,
        );
        return convertEncryptedUtxosResponse(response, method);
      } catch (cause) {
        throw wrapIndexer(cause, method);
      }
    });
  }

  getShieldedTransactionsByTags(
    request: GetByTagsRequest,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsByTagsResponse> {
    const owned = copyTagRequest(request);
    return pollIndexer(config, context, async () => {
      const method = "getShieldedTransactionsByTags";
      try {
        const response = await this.#api.getShieldedTransactionsByTags(
          {
            tags: owned.tags.map((tag) => hash(tag)),
            ...(owned.cursor === undefined ? {} : { cursor: base64String(owned.cursor) }),
            ...(owned.limit === undefined ? {} : { limit: limit(BigInt(owned.limit)) }),
          },
          context,
        );
        return convertShieldedTransactionsResponse(response, method);
      } catch (cause) {
        throw wrapIndexer(cause, method);
      }
    });
  }

  getShieldedTransactionsByNullifiers(
    request: GetByNullifiersRequest,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsByNullifiersResponse> {
    const owned = copyNullifierRequest(request);
    return pollIndexer(config, context, async () => {
      const method = "getShieldedTransactionsByNullifiers";
      try {
        const response = await this.#api.getShieldedTransactionsByNullifiers(
          {
            nullifiers: owned.nullifiers.map((nullifier) => hash(nullifier)),
            ...(owned.cursor === undefined ? {} : { cursor: base64String(owned.cursor) }),
            ...(owned.limit === undefined ? {} : { limit: limit(BigInt(owned.limit)) }),
          },
          context,
        );
        return convertShieldedTransactionsByNullifiersResponse(response, method);
      } catch (cause) {
        throw wrapIndexer(cause, method);
      }
    });
  }

  getShieldedTransactionsBySignature(
    signature: Signature,
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetShieldedTransactionsBySignatureResponse> {
    return pollIndexer(config, context, async () => {
      const method = "getShieldedTransactionsBySignature";
      try {
        const response = await this.#api.getShieldedTransactionsBySignature(
          { txSignature: signature },
          context,
        );
        return convertShieldedTransactionsBySignatureResponse(response, method);
      } catch (cause) {
        throw wrapIndexer(cause, method);
      }
    });
  }

  getMerkleProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetMerkleProofsResponse> {
    const requested = copyLeaves(leaves);
    return pollIndexer(config, context, async () => {
      const method = "getMerkleProofs";
      try {
        const response = await this.#api.getMerkleProofs(
          { treeAccount, leaves: requested.map((leaf) => hash(leaf)) },
          context,
        );
        return Object.freeze({
          context: Object.freeze({
            blockTime: response.context.blockTime,
            slot: response.context.slot,
          }),
          proofs: Object.freeze(response.proofs.map(convertMerkleProof)),
        });
      } catch (cause) {
        throw wrapIndexer(cause, method);
      }
    });
  }

  getNonInclusionProofs(
    treeAccount: Address,
    leaves: readonly Bytes32[],
    config?: IndexerRpcConfig,
    context?: RequestContext,
  ): Promise<GetNonInclusionProofsResponse> {
    const requested = copyLeaves(leaves);
    return pollIndexer(config, context, async () => {
      const method = "getNonInclusionProofs";
      try {
        const response = await this.#api.getNonInclusionProofs(
          { treeAccount, leaves: requested.map((leaf) => hash(leaf)) },
          context,
        );
        return Object.freeze({
          context: Object.freeze({
            blockTime: response.context.blockTime,
            slot: response.context.slot,
          }),
          proofs: Object.freeze(response.proofs.map(convertNonInclusionProof)),
        });
      } catch (cause) {
        throw wrapIndexer(cause, method);
      }
    });
  }
}

function copyTagRequest(request: GetByTagsRequest): GetByTagsRequest {
  if (request.cursor !== undefined && !(request.cursor instanceof Uint8Array)) {
    throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "cursor" } });
  }
  return Object.freeze({
    tags: copyFixedBytes(request.tags, 32, "tags") as readonly Bytes32[],
    ...(request.cursor === undefined ? {} : { cursor: new Uint8Array(request.cursor) }),
    ...(request.limit === undefined ? {} : { limit: checkedPageLimit(request.limit) }),
  });
}

function copyNullifierRequest(request: GetByNullifiersRequest): GetByNullifiersRequest {
  if (request.cursor !== undefined && !(request.cursor instanceof Uint8Array)) {
    throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "cursor" } });
  }
  return Object.freeze({
    nullifiers: copyFixedBytes(request.nullifiers, 32, "nullifiers") as readonly Bytes32[],
    ...(request.cursor === undefined ? {} : { cursor: new Uint8Array(request.cursor) }),
    ...(request.limit === undefined ? {} : { limit: checkedPageLimit(request.limit) }),
  });
}

function checkedPageLimit(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 1000) {
    throw new ClientError("CLIENT_INVALID_INTEGER", {
      details: { field: "limit", value: String(value) },
    });
  }
  return value;
}

function copyLeaves(leaves: readonly Bytes32[]): readonly Bytes32[] {
  return copyFixedBytes(leaves, 32, "leaves") as readonly Bytes32[];
}

function copyFixedBytes(
  values: readonly Uint8Array[],
  expected: number,
  field: string,
): readonly Uint8Array[] {
  return Object.freeze(
    values.map((value, index) => {
      if (!(value instanceof Uint8Array) || value.length !== expected) {
        throw new ClientError("CLIENT_INVALID_LENGTH", {
          details: {
            field: `${field}[${String(index)}]`,
            expected,
            actual: value instanceof Uint8Array ? value.length : -1,
          },
        });
      }
      return new Uint8Array(value);
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

function convertEncryptedUtxosResponse(
  response: WireGetEncryptedUtxosByTagsResponse,
  method: string,
): GetEncryptedUtxosByTagsResponse {
  return Object.freeze({
    context: Object.freeze({ blockTime: response.context.blockTime, slot: response.context.slot }),
    matches: Object.freeze(
      response.matches.map((item, index) =>
        convertEncryptedUtxoMatch(item, method, `$.matches[${String(index)}]`),
      ),
    ),
    ...(response.nextCursor === undefined
      ? {}
      : { nextCursor: decodeBase64(response.nextCursor, "next_cursor") }),
  });
}

function convertEncryptedUtxoMatch(
  item: WireEncryptedUtxoMatch,
  method: string,
  path: string,
): EncryptedUtxoMatch {
  return Object.freeze({
    slot: item.slot,
    txSignature: item.txSignature,
    outputSlot: convertOutputSlot(item.outputSlot),
    ...(item.txViewingPk === undefined
      ? {}
      : { txViewingPk: decodeP256(item.txViewingPk, method, `${path}.tx_viewing_pk`) }),
    ...(item.salt === undefined ? {} : { salt: decodeSalt(item.salt, method, `${path}.salt`) }),
  });
}

function convertShieldedTransactionsResponse(
  response: WireGetShieldedTransactionsByTagsResponse,
  method: string,
): GetShieldedTransactionsByTagsResponse {
  return Object.freeze({
    context: Object.freeze({ blockTime: response.context.blockTime, slot: response.context.slot }),
    transactions: Object.freeze(
      response.transactions.map((item, index) =>
        convertShieldedTransaction(item, method, `$.transactions[${String(index)}]`),
      ),
    ),
    ...(response.nextCursor === undefined
      ? {}
      : { nextCursor: decodeBase64(response.nextCursor, "next_cursor") }),
  });
}

function convertShieldedTransactionsByNullifiersResponse(
  response: WireGetShieldedTransactionsByNullifiersResponse,
  method: string,
): GetShieldedTransactionsByNullifiersResponse {
  // Delegating alone would silently drop how far the scan reached, leaving sync to
  // restart from zero every time with nothing to show it had been told
  // otherwise.
  return Object.freeze({
    ...convertShieldedTransactionsResponse(response, method),
    ...(response.scannedThrough === undefined
      ? {}
      : { scannedThrough: decodeBase64(response.scannedThrough, "scanned_through") }),
  });
}

function convertShieldedTransactionsBySignatureResponse(
  response: WireGetShieldedTransactionsBySignatureResponse,
  method: string,
): GetShieldedTransactionsBySignatureResponse {
  return Object.freeze({
    context: Object.freeze({ blockTime: response.context.blockTime, slot: response.context.slot }),
    transactions: Object.freeze(
      response.transactions.map((item, index) =>
        Object.freeze({
          eventIndex: item.eventIndex,
          transaction: convertShieldedTransaction(
            item.transaction,
            method,
            `$.transactions[${String(index)}].transaction`,
          ),
        }),
      ),
    ),
  });
}

function convertShieldedTransaction(
  item: WireShieldedTransaction,
  method: string,
  path: string,
): IndexedShieldedTransaction {
  return Object.freeze({
    slot: item.slot,
    txSignature: item.txSignature,
    ...(item.txViewingPk === undefined
      ? {}
      : {
          txViewingPublicKey: decodeP256(item.txViewingPk, method, `${path}.tx_viewing_pk`),
        }),
    ...(item.salt === undefined ? {} : { salt: decodeSalt(item.salt, method, `${path}.salt`) }),
    outputSlots: Object.freeze(item.outputSlots.map(convertOutputSlot)),
    messages: Object.freeze(
      item.messages.map((message) =>
        Object.freeze({
          viewTag: copyHash(message.viewTag),
          data: decodeBase64(message.payload, "message.payload"),
        }),
      ),
    ),
    nullifiers: Object.freeze(item.nullifiers.map(copyHash)),
    proofless: item.proofless,
  });
}

function convertOutputSlot(
  slot: WireOutputSlot,
): IndexedShieldedTransaction["outputSlots"][number] {
  return Object.freeze({
    viewTag: copyHash(slot.viewTag),
    outputContext: Object.freeze({
      hash: copyHash(slot.outputContext.hash),
      tree: slot.outputContext.tree,
      leafIndex: slot.outputContext.leafIndex,
    }),
    payload: decodeBase64(slot.payload, "output_slot.payload"),
  });
}

function decodeP256(value: string, method: string, path: string): P256PublicKey {
  const bytes = decodeBase64(value, path);
  if (bytes.length !== 33) throw invalidResponse(method, path, 33, bytes.length);
  try {
    return P256PublicKey.fromBytes(bytes as Bytes33);
  } catch {
    throw invalidResponse(method, path);
  }
}

function decodeSalt(value: string, method: string, path: string): Bytes16 {
  const bytes = decodeBase64(value, path);
  if (bytes.length !== 16) throw invalidResponse(method, path, 16, bytes.length);
  return bytes as Bytes16;
}

async function pollIndexer<T extends Readonly<{ context: Readonly<{ slot: bigint }> }>>(
  config: IndexerRpcConfig | undefined,
  context: RequestContext | undefined,
  request: () => Promise<T>,
): Promise<T> {
  const rawConfig: unknown = config;
  if (
    rawConfig !== undefined &&
    (typeof rawConfig !== "object" ||
      rawConfig === null ||
      (((rawConfig as Record<string, unknown>)["requireSlot"] ?? undefined) !== undefined &&
        typeof (rawConfig as Record<string, unknown>)["requireSlot"] !== "bigint"))
  ) {
    throw new ClientError("CLIENT_INVALID_POLL_CONFIG", {
      details: { field: "requireSlot" },
    });
  }
  const target = config?.requireSlot;
  if (target === undefined) return request();
  const poll = validatePollConfig(config?.poll ?? DEFAULT_INDEXER_POLL_CONFIG);
  const attempts = poll.numRetries + 1;
  let latest: bigint | undefined;
  let responses = 0;
  try {
    return await pollUntil(
      request,
      (response) => {
        responses++;
        latest = response.context.slot;
        return latest >= target;
      },
      { config: poll, ...(context === undefined ? {} : { context }) },
    );
  } catch (cause) {
    // Fewer responses than attempts means the schedule ended on a failure, so
    // `cause` already carries the precise reason and its structured cause.
    if (latest === undefined || responses !== attempts) throw cause;
    if (!isClientError(cause) || cause.code !== "CLIENT_POLL_TIMED_OUT") throw cause;
    throw new ClientError("CLIENT_INDEXER_NOT_CAUGHT_UP", {
      details: {
        target: target.toString(),
        latest: latest.toString(),
        attempts,
      },
    });
  }
}

function wrapIndexer(cause: unknown, method: string): ClientError {
  if (isClientError(cause)) return cause;
  const code = externalCode(cause);
  if (code === "API_ABORTED") return new ClientError("CLIENT_ABORTED", { details: { method } });
  if (code === "API_TIMEOUT") {
    return new ClientError("CLIENT_TIMEOUT", {
      details: { method, retryable: true },
      cause,
    });
  }
  if (code === "API_REQUEST") {
    return new ClientError("CLIENT_REQUEST", {
      details: { method, retryable: true },
      cause,
    });
  }
  if (code === "API_INVALID_RESULT") {
    return new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
      details: { method, ...safePath(cause) },
      cause,
    });
  }
  return new ClientError("CLIENT_INDEXER", {
    details: { method, retryable: apiRetryable(cause) },
    cause,
  });
}

// The API layer already classified the failure. An unrecognized shape counts as
// fatal so a rejected request cannot consume the whole polling schedule.
function apiRetryable(cause: unknown): boolean {
  if (typeof cause !== "object" || cause === null || !("details" in cause)) return false;
  const details: unknown = cause.details;
  return (
    typeof details === "object" &&
    details !== null &&
    "retryable" in details &&
    details.retryable === true
  );
}

function externalCode(cause: unknown): string | undefined {
  if (
    typeof cause === "object" &&
    cause !== null &&
    "code" in cause &&
    typeof cause.code === "string"
  ) {
    return cause.code;
  }
  return undefined;
}

function safePath(cause: unknown): Readonly<{ path?: string }> {
  if (typeof cause !== "object" || cause === null || !("details" in cause)) return {};
  const details = cause.details;
  if (typeof details !== "object" || details === null || !("path" in details)) return {};
  return typeof details.path === "string" ? { path: details.path } : {};
}

function invalidResponse(
  method: string,
  path: string,
  expected?: number,
  actual?: number,
): ClientError {
  return new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
    details: {
      method,
      path,
      ...(expected === undefined ? {} : { expected }),
      ...(actual === undefined ? {} : { actual }),
    },
  });
}
