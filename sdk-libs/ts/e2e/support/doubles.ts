import { ZolanaApi } from "@zolana/api";
import { ZolanaIndexer, type Rpc, type ZolanaClient } from "@zolana/client";
import { base64String, hash, hashBytes } from "@zolana/indexer-api";
import type {
  EncryptedUtxoMatch,
  Hash,
  IndexedShieldedTransaction,
  RingsOutputSlot,
} from "@zolana/indexer-api";
import {
  getEncryptedUtxosByTagsMethod,
  getShieldedTransactionsByTagsMethod,
} from "@zolana/indexer-api/methods";
import type { Signature } from "@zolana/interface";
import type { IndexedOutput, TestIndexer } from "@zolana/test-kit/node";

const INDEXER_URL = "https://indexer.test";
const BLOCK_TIME = 1n;
const BASE58_DIGITS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

interface JsonRpcRequest {
  readonly id: unknown;
  readonly method: string;
  readonly params: unknown;
}

/**
 * The signature of the transaction that created the deposit at `leafIndex`.
 * Sixty-three zero bytes then the leaf index, which stays a canonical base58
 * signature and stays distinct per deposit.
 */
export function depositSignature(leafIndex: bigint): Signature {
  const digit = BASE58_DIGITS[Number(leafIndex)];
  if (digit === undefined) {
    throw new Error(`no distinct deposit signature for leaf ${String(leafIndex)}`);
  }
  return `${"1".repeat(63)}${digit}` as Signature;
}

/**
 * A real `ZolanaIndexer` answering from `source` over an in-process JSON-RPC
 * transport. Rows are built as indexer wire values and reach the wallet through
 * the client's own decoding, so this double cannot serve a shape the deployed
 * indexer never produces.
 */
export function fixtureIndexer(source: TestIndexer): ZolanaIndexer {
  return new ZolanaIndexer(new ZolanaApi({ url: INDEXER_URL, fetch: serve(source) }));
}

/**
 * Checks a hand-written indexer against the real methods. Every method the
 * double declares is typed by `ZolanaIndexer`, so a parameter list or a
 * response that disagrees with the client fails to compile.
 */
export function indexerDouble(methods: Partial<ZolanaIndexer>): ZolanaIndexer {
  return methods as ZolanaIndexer;
}

/** Checks a hand-written client against the real `ZolanaClient` members. */
export function clientDouble(methods: Partial<ZolanaClient>): ZolanaClient {
  return methods as ZolanaClient;
}

/** Checks a hand-written RPC against the real `Rpc` methods. */
export function rpcDouble(methods: Partial<Rpc>): Rpc {
  return methods as Rpc;
}

function serve(source: TestIndexer): typeof globalThis.fetch {
  return (_input, init) => {
    const body = init?.body;
    if (typeof body !== "string") {
      throw new Error("the fixture indexer answers JSON-RPC requests only");
    }
    const request = JSON.parse(body) as JsonRpcRequest;
    return Promise.resolve(
      Response.json({ id: request.id, jsonrpc: "2.0", result: result(source, request) }),
    );
  };
}

function result(source: TestIndexer, request: JsonRpcRequest): Readonly<Record<string, unknown>> {
  if (request.method === getEncryptedUtxosByTagsMethod.name) {
    const { tags } = getEncryptedUtxosByTagsMethod.decodeRequest(request.params);
    return getEncryptedUtxosByTagsMethod.encodeResponse({
      context: { blockTime: BLOCK_TIME },
      matches: tagged(source, tags).map(depositMatch),
    });
  }
  if (request.method === getShieldedTransactionsByTagsMethod.name) {
    const { tags } = getShieldedTransactionsByTagsMethod.decodeRequest(request.params);
    return getShieldedTransactionsByTagsMethod.encodeResponse({
      context: { blockTime: BLOCK_TIME },
      transactions: tagged(source, tags).map(depositTransaction),
    });
  }
  throw new Error(`the fixture indexer does not serve ${request.method}`);
}

function tagged(source: TestIndexer, tags: readonly Hash[]): readonly IndexedOutput[] {
  return tags.flatMap((tag) => source.byViewTag(hashBytes(tag)));
}

function depositSlot(output: IndexedOutput): RingsOutputSlot {
  return {
    viewTag: hash(output.viewTag),
    outputContext: {
      hash: hash(output.utxoHash),
      tree: output.tree,
      leafIndex: output.leafIndex,
    },
    payload: base64String(output.data),
  };
}

function depositMatch(output: IndexedOutput): EncryptedUtxoMatch {
  return {
    slot: output.leafIndex + 1n,
    txSignature: depositSignature(output.leafIndex),
    outputSlot: depositSlot(output),
  };
}

// Photon lists a deposit on both endpoints. It is spendable only through the
// encrypted-utxo one, so sync must take it there and skip the copy here.
function depositTransaction(output: IndexedOutput): IndexedShieldedTransaction {
  return {
    slot: output.leafIndex + 1n,
    txSignature: depositSignature(output.leafIndex),
    outputSlots: [depositSlot(output)],
    messages: [],
    nullifiers: [],
    proofless: true,
  };
}
