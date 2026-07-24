import type {
  EncryptedUtxoMatch,
  GetEncryptedUtxosByTagsResponse,
  GetMerkleProofsRequest,
  GetMerkleProofsResponse,
  GetNonInclusionProofsRequest,
  GetNonInclusionProofsResponse,
  GetNullifierQueueElementsRequest,
  GetNullifierQueueElementsResponse,
  GetRingsByTagsRequest,
  GetShieldedTransactionsByTagsResponse,
  IndexedShieldedTransaction,
  IndexerContext,
  MerkleProof,
  NonInclusionProof,
  NullifierQueueElement,
  RingsMessage,
  RingsOutputContext,
  RingsOutputSlot,
} from "./types.js";
import {
  checkedAddress,
  checkedBase64,
  checkedHash,
  checkedSignature,
  limit,
  schemaFailure,
} from "./scalars.js";

type WireObject = Record<string, unknown>;

const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;
const U64_MAX = (1n << 64n) - 1n;
const U16_MAX = 65_535;

function object(value: unknown, path: string, fields: readonly string[]): WireObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", path, "an object", value);
  }
  const record = value as WireObject;
  for (const key of Object.keys(record)) {
    if (!fields.includes(key)) {
      schemaFailure("INDEXER_SCHEMA_UNKNOWN_FIELD", `${path}.${key}`, "a known field", key);
    }
  }
  return record;
}

function array<T>(
  value: unknown,
  path: string,
  decode: (item: unknown, itemPath: string) => T,
): readonly T[] {
  if (!Array.isArray(value)) {
    return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", path, "an array", value);
  }
  return value.map((item, index) => decode(item, `${path}[${String(index)}]`));
}

function boolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") {
    return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", path, "a boolean", value);
  }
  return value;
}

function wireInteger(value: unknown, path: string, minimum: bigint, maximum: bigint): bigint {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    return schemaFailure("INDEXER_SCHEMA_INVALID_INTEGER", path, "a safe JSON integer", value);
  }
  const integer = BigInt(value);
  if (integer < minimum || integer > maximum) {
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_INTEGER",
      path,
      `an integer from ${minimum.toString()} through ${maximum.toString()}`,
      value,
    );
  }
  return integer;
}

function u64(value: unknown, path: string): bigint {
  return wireInteger(value, path, 0n, U64_MAX);
}

function i64(value: unknown, path: string): bigint {
  return wireInteger(value, path, I64_MIN, I64_MAX);
}

function u16(value: unknown, path: string): number {
  const integer = wireInteger(value, path, 0n, BigInt(U16_MAX));
  return Number(integer);
}

function checkedPageLimit(value: unknown, path: string) {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_LIMIT",
      path,
      "an integer from 1 through 1000",
      value,
    );
  }
  const integer = BigInt(value);
  if (integer < 1n || integer > 1000n) {
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_LIMIT",
      path,
      "an integer from 1 through 1000",
      value,
    );
  }
  return limit(integer);
}

function toWireInteger(value: bigint, path: string, minimum: bigint, maximum: bigint): number {
  if (value < minimum || value > maximum) {
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_INTEGER",
      path,
      `an integer from ${minimum.toString()} through ${maximum.toString()}`,
      value,
    );
  }
  const number = Number(value);
  if (!Number.isSafeInteger(number)) {
    return schemaFailure(
      "INDEXER_SCHEMA_UNSAFE_INTEGER",
      path,
      "an integer exactly representable in JSON",
      value,
    );
  }
  return number;
}

function toU64(value: bigint, path: string): number {
  return toWireInteger(value, path, 0n, U64_MAX);
}

function toI64(value: bigint, path: string): number {
  return toWireInteger(value, path, I64_MIN, I64_MAX);
}

function optional<T>(
  value: unknown,
  path: string,
  decode: (item: unknown, itemPath: string) => T,
): T | undefined {
  return value === undefined || value === null ? undefined : decode(value, path);
}

function context(value: unknown, path: string): IndexerContext {
  const record = object(value, path, ["block_time"]);
  return { blockTime: i64(record["block_time"], `${path}.block_time`) };
}

function outputContext(value: unknown, path: string): RingsOutputContext {
  const record = object(value, path, ["hash", "tree", "leaf_index"]);
  return {
    hash: checkedHash(record["hash"], `${path}.hash`),
    tree: checkedAddress(record["tree"], `${path}.tree`),
    leafIndex: u64(record["leaf_index"], `${path}.leaf_index`),
  };
}

function outputSlot(value: unknown, path: string): RingsOutputSlot {
  const record = object(value, path, ["view_tag", "output_context", "payload"]);
  return {
    viewTag: checkedHash(record["view_tag"], `${path}.view_tag`),
    outputContext: outputContext(record["output_context"], `${path}.output_context`),
    payload: checkedBase64(record["payload"], `${path}.payload`),
  };
}

function message(value: unknown, path: string): RingsMessage {
  const record = object(value, path, ["view_tag", "payload"]);
  return {
    viewTag: checkedHash(record["view_tag"], `${path}.view_tag`),
    payload: checkedBase64(record["payload"], `${path}.payload`),
  };
}

function encryptedUtxoMatch(value: unknown, path: string): EncryptedUtxoMatch {
  const record = object(value, path, [
    "slot",
    "tx_signature",
    "output_slot",
    "tx_viewing_pk",
    "salt",
  ]);
  const txViewingPk = optional(record["tx_viewing_pk"], `${path}.tx_viewing_pk`, checkedBase64);
  const salt = optional(record["salt"], `${path}.salt`, checkedBase64);
  return {
    slot: u64(record["slot"], `${path}.slot`),
    txSignature: checkedSignature(record["tx_signature"], `${path}.tx_signature`),
    outputSlot: outputSlot(record["output_slot"], `${path}.output_slot`),
    ...(txViewingPk === undefined ? {} : { txViewingPk }),
    ...(salt === undefined ? {} : { salt }),
  };
}

function indexedTransaction(value: unknown, path: string): IndexedShieldedTransaction {
  const record = object(value, path, [
    "slot",
    "tx_signature",
    "tx_viewing_pk",
    "salt",
    "output_slots",
    "messages",
    "nullifiers",
    "proofless",
  ]);
  const txViewingPk = optional(record["tx_viewing_pk"], `${path}.tx_viewing_pk`, checkedBase64);
  const salt = optional(record["salt"], `${path}.salt`, checkedBase64);
  return {
    slot: u64(record["slot"], `${path}.slot`),
    txSignature: checkedSignature(record["tx_signature"], `${path}.tx_signature`),
    ...(txViewingPk === undefined ? {} : { txViewingPk }),
    ...(salt === undefined ? {} : { salt }),
    outputSlots: array(record["output_slots"], `${path}.output_slots`, outputSlot),
    messages: array(record["messages"], `${path}.messages`, message),
    nullifiers: array(record["nullifiers"], `${path}.nullifiers`, checkedHash),
    proofless: boolean(record["proofless"], `${path}.proofless`),
  };
}

function merkleContext(value: unknown, path: string): MerkleProof["merkleContext"] {
  const record = object(value, path, ["tree_type", "tree"]);
  return {
    treeType: u16(record["tree_type"], `${path}.tree_type`),
    tree: checkedAddress(record["tree"], `${path}.tree`),
  };
}

function merkleProof(value: unknown, path: string): MerkleProof {
  const record = object(value, path, [
    "leaf",
    "merkle_context",
    "path",
    "leaf_index",
    "root",
    "root_seq",
    "root_index",
  ]);
  return {
    leaf: checkedHash(record["leaf"], `${path}.leaf`),
    merkleContext: merkleContext(record["merkle_context"], `${path}.merkle_context`),
    path: array(record["path"], `${path}.path`, checkedHash),
    leafIndex: u64(record["leaf_index"], `${path}.leaf_index`),
    root: checkedHash(record["root"], `${path}.root`),
    rootSeq: u64(record["root_seq"], `${path}.root_seq`),
    rootIndex: u16(record["root_index"], `${path}.root_index`),
  };
}

function nonInclusionProof(value: unknown, path: string): NonInclusionProof {
  const record = object(value, path, [
    "leaf",
    "merkle_context",
    "path",
    "low_element",
    "low_element_index",
    "high_element",
    "high_element_index",
    "root",
    "root_seq",
    "root_index",
  ]);
  return {
    leaf: checkedHash(record["leaf"], `${path}.leaf`),
    merkleContext: merkleContext(record["merkle_context"], `${path}.merkle_context`),
    path: array(record["path"], `${path}.path`, checkedHash),
    lowElement: checkedHash(record["low_element"], `${path}.low_element`),
    lowElementIndex: u64(record["low_element_index"], `${path}.low_element_index`),
    highElement: checkedHash(record["high_element"], `${path}.high_element`),
    highElementIndex: u64(record["high_element_index"], `${path}.high_element_index`),
    root: checkedHash(record["root"], `${path}.root`),
    rootSeq: u64(record["root_seq"], `${path}.root_seq`),
    rootIndex: u16(record["root_index"], `${path}.root_index`),
  };
}

function queueElement(value: unknown, path: string): NullifierQueueElement {
  const record = object(value, path, ["seq", "value"]);
  return {
    seq: u64(record["seq"], `${path}.seq`),
    value: checkedHash(record["value"], `${path}.value`),
  };
}

export function decodeRingsByTagsRequest(value: unknown): GetRingsByTagsRequest {
  const record = object(value, "$", ["tags", "cursor", "limit"]);
  const cursor = optional(record["cursor"], "$.cursor", checkedBase64);
  const pageLimit =
    record["limit"] === undefined || record["limit"] === null
      ? undefined
      : checkedPageLimit(record["limit"], "$.limit");
  return {
    tags: array(record["tags"], "$.tags", checkedHash),
    ...(cursor === undefined ? {} : { cursor }),
    ...(pageLimit === undefined ? {} : { limit: pageLimit }),
  };
}

export function encodeRingsByTagsRequest(value: GetRingsByTagsRequest): WireObject {
  const decoded = decodeRingsByTagsRequest({
    tags: value.tags,
    ...(value.cursor === undefined ? {} : { cursor: value.cursor }),
    ...(value.limit === undefined ? {} : { limit: toU64(value.limit, "$.limit") }),
  });
  return {
    tags: [...decoded.tags],
    ...(decoded.cursor === undefined ? {} : { cursor: decoded.cursor }),
    ...(decoded.limit === undefined ? {} : { limit: Number(decoded.limit) }),
  };
}

export function decodeEncryptedUtxosResponse(value: unknown): GetEncryptedUtxosByTagsResponse {
  const record = object(value, "$", ["context", "matches", "next_cursor"]);
  const nextCursor = optional(record["next_cursor"], "$.next_cursor", checkedBase64);
  return {
    context: context(record["context"], "$.context"),
    matches: array(record["matches"], "$.matches", encryptedUtxoMatch),
    ...(nextCursor === undefined ? {} : { nextCursor }),
  };
}

export function decodeShieldedTransactionsResponse(
  value: unknown,
): GetShieldedTransactionsByTagsResponse {
  const record = object(value, "$", ["context", "transactions", "next_cursor"]);
  const nextCursor = optional(record["next_cursor"], "$.next_cursor", checkedBase64);
  return {
    context: context(record["context"], "$.context"),
    transactions: array(record["transactions"], "$.transactions", indexedTransaction),
    ...(nextCursor === undefined ? {} : { nextCursor }),
  };
}

function decodeLeavesRequest(value: unknown): GetMerkleProofsRequest {
  const record = object(value, "$", ["tree_account", "leaves"]);
  return {
    treeAccount: checkedAddress(record["tree_account"], "$.tree_account"),
    leaves: array(record["leaves"], "$.leaves", checkedHash),
  };
}

function encodeLeavesRequest(
  value: GetMerkleProofsRequest | GetNonInclusionProofsRequest,
): WireObject {
  decodeLeavesRequest({
    tree_account: value.treeAccount,
    leaves: value.leaves,
  });
  return { tree_account: value.treeAccount, leaves: [...value.leaves] };
}

export function decodeMerkleProofsRequest(value: unknown): GetMerkleProofsRequest {
  return decodeLeavesRequest(value);
}

export function encodeMerkleProofsRequest(value: GetMerkleProofsRequest): WireObject {
  return encodeLeavesRequest(value);
}

export function decodeMerkleProofsResponse(value: unknown): GetMerkleProofsResponse {
  const record = object(value, "$", ["context", "proofs"]);
  return {
    context: context(record["context"], "$.context"),
    proofs: array(record["proofs"], "$.proofs", merkleProof),
  };
}

export function decodeNonInclusionProofsRequest(value: unknown): GetNonInclusionProofsRequest {
  return decodeLeavesRequest(value);
}

export function encodeNonInclusionProofsRequest(value: GetNonInclusionProofsRequest): WireObject {
  return encodeLeavesRequest(value);
}

export function decodeNonInclusionProofsResponse(value: unknown): GetNonInclusionProofsResponse {
  const record = object(value, "$", ["context", "proofs"]);
  return {
    context: context(record["context"], "$.context"),
    proofs: array(record["proofs"], "$.proofs", nonInclusionProof),
  };
}

export function decodeNullifierQueueRequest(value: unknown): GetNullifierQueueElementsRequest {
  const record = object(value, "$", ["tree_account", "start_seq", "limit"]);
  const startSeq = record["start_seq"] === undefined ? 0n : u64(record["start_seq"], "$.start_seq");
  return {
    treeAccount: checkedAddress(record["tree_account"], "$.tree_account"),
    startSeq,
    limit: checkedPageLimit(record["limit"], "$.limit"),
  };
}

export function encodeNullifierQueueRequest(value: GetNullifierQueueElementsRequest): WireObject {
  const wire = {
    tree_account: value.treeAccount,
    start_seq: toU64(value.startSeq ?? 0n, "$.start_seq"),
    limit: toU64(value.limit, "$.limit"),
  };
  decodeNullifierQueueRequest(wire);
  return wire;
}

export function decodeNullifierQueueResponse(value: unknown): GetNullifierQueueElementsResponse {
  const record = object(value, "$", ["context", "elements"]);
  return {
    context: context(record["context"], "$.context"),
    elements: array(record["elements"], "$.elements", queueElement),
  };
}

function wireContext(value: IndexerContext): WireObject {
  return { block_time: toI64(value.blockTime, "$.context.blockTime") };
}

function wireOutputContext(value: RingsOutputContext): WireObject {
  return {
    hash: value.hash,
    tree: value.tree,
    leaf_index: toU64(value.leafIndex, "$.outputContext.leafIndex"),
  };
}

function wireOutputSlot(value: RingsOutputSlot): WireObject {
  return {
    view_tag: value.viewTag,
    output_context: wireOutputContext(value.outputContext),
    payload: value.payload,
  };
}

function wireMerkleContext(value: MerkleProof["merkleContext"]): WireObject {
  return {
    tree_type: value.treeType,
    tree: value.tree,
  };
}

function wireMerkleProof(value: MerkleProof): WireObject {
  return {
    leaf: value.leaf,
    merkle_context: wireMerkleContext(value.merkleContext),
    path: [...value.path],
    leaf_index: toU64(value.leafIndex, "$.proof.leafIndex"),
    root: value.root,
    root_seq: toU64(value.rootSeq, "$.proof.rootSeq"),
    root_index: value.rootIndex,
  };
}

export function encodeEncryptedUtxosResponse(value: GetEncryptedUtxosByTagsResponse): WireObject {
  const wire = {
    context: wireContext(value.context),
    matches: value.matches.map((match) => ({
      slot: toU64(match.slot, "$.matches.slot"),
      tx_signature: match.txSignature,
      output_slot: wireOutputSlot(match.outputSlot),
      tx_viewing_pk: match.txViewingPk ?? null,
      salt: match.salt ?? null,
    })),
    next_cursor: value.nextCursor ?? null,
  };
  decodeEncryptedUtxosResponse(wire);
  return wire;
}

export function encodeShieldedTransactionsResponse(
  value: GetShieldedTransactionsByTagsResponse,
): WireObject {
  const wire = {
    context: wireContext(value.context),
    transactions: value.transactions.map((transaction) => ({
      slot: toU64(transaction.slot, "$.transactions.slot"),
      tx_signature: transaction.txSignature,
      tx_viewing_pk: transaction.txViewingPk ?? null,
      salt: transaction.salt ?? null,
      output_slots: transaction.outputSlots.map(wireOutputSlot),
      messages: transaction.messages.map((item) => ({
        view_tag: item.viewTag,
        payload: item.payload,
      })),
      nullifiers: [...transaction.nullifiers],
      proofless: transaction.proofless,
    })),
    next_cursor: value.nextCursor ?? null,
  };
  decodeShieldedTransactionsResponse(wire);
  return wire;
}

export function encodeMerkleProofsResponse(value: GetMerkleProofsResponse): WireObject {
  const wire = {
    context: wireContext(value.context),
    proofs: value.proofs.map(wireMerkleProof),
  };
  decodeMerkleProofsResponse(wire);
  return wire;
}

export function encodeNonInclusionProofsResponse(value: GetNonInclusionProofsResponse): WireObject {
  const wire = {
    context: wireContext(value.context),
    proofs: value.proofs.map((proof) => ({
      leaf: proof.leaf,
      merkle_context: wireMerkleContext(proof.merkleContext),
      path: [...proof.path],
      low_element: proof.lowElement,
      low_element_index: toU64(proof.lowElementIndex, "$.proof.lowElementIndex"),
      high_element: proof.highElement,
      high_element_index: toU64(proof.highElementIndex, "$.proof.highElementIndex"),
      root: proof.root,
      root_seq: toU64(proof.rootSeq, "$.proof.rootSeq"),
      root_index: proof.rootIndex,
    })),
  };
  decodeNonInclusionProofsResponse(wire);
  return wire;
}

export function encodeNullifierQueueResponse(value: GetNullifierQueueElementsResponse): WireObject {
  const wire = {
    context: wireContext(value.context),
    elements: value.elements.map((element) => ({
      seq: toU64(element.seq, "$.elements.seq"),
      value: element.value,
    })),
  };
  decodeNullifierQueueResponse(wire);
  return wire;
}
