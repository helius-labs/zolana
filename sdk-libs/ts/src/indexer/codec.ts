import type {
  EncryptedUtxoMatch,
  GetEncryptedUtxosByTagsResponse,
  GetMerkleProofsRequest,
  GetMerkleProofsResponse,
  GetNonInclusionProofsRequest,
  GetNonInclusionProofsResponse,
  GetRingsByNullifiersRequest,
  GetRingsByTagsRequest,
  GetShieldedTransactionsByNullifiersResponse,
  GetShieldedTransactionsBySignatureRequest,
  GetShieldedTransactionsBySignatureResponse,
  GetShieldedTransactionsByTagsResponse,
  IndexedShieldedTransaction,
  IndexerContext,
  MerkleProof,
  NonInclusionProof,
  RingsMessage,
  RingsOutputContext,
  RingsOutputSlot,
  SignatureIndexedShieldedTransaction,
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

/** No leading zero, no sign on zero, no exponent: one spelling per value. */
const DECIMAL_INTEGER = /^(?:0|-?[1-9][0-9]*)$/;

function inRange(
  integer: bigint,
  value: unknown,
  path: string,
  minimum: bigint,
  maximum: bigint,
): bigint {
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

function wireInteger(value: unknown, path: string, minimum: bigint, maximum: bigint): bigint {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    return schemaFailure("INDEXER_SCHEMA_INVALID_INTEGER", path, "a safe JSON integer", value);
  }
  return inRange(BigInt(value), value, path, minimum, maximum);
}

/**
 * Wire form of a field whose value nothing in the protocol caps below
 * `Number.MAX_SAFE_INTEGER`: a Solana slot or block time, or a monotonic tree
 * sequence.
 *
 * Photon writes a JSON number, which stays valid. A JSON number that has
 * already lost precision is refused rather than silently truncated, so an
 * indexer with a value past the double-precision range has to send the decimal
 * string instead. The two forms are the union Light Protocol accepts
 * (`js/stateless.js/src/rpc-interface.ts:316-328`).
 */
function unboundedWireInteger(
  value: unknown,
  path: string,
  minimum: bigint,
  maximum: bigint,
): bigint {
  if (typeof value !== "string") {
    return wireInteger(value, path, minimum, maximum);
  }
  if (!DECIMAL_INTEGER.test(value)) {
    return schemaFailure("INDEXER_SCHEMA_INVALID_INTEGER", path, "a decimal integer string", value);
  }
  return inRange(BigInt(value), value, path, minimum, maximum);
}

/** For a tree index, which the tree height caps well below `2^53`. */
function u64(value: unknown, path: string): bigint {
  return wireInteger(value, path, 0n, U64_MAX);
}

function unboundedU64(value: unknown, path: string): bigint {
  return unboundedWireInteger(value, path, 0n, U64_MAX);
}

function unboundedI64(value: unknown, path: string): bigint {
  return unboundedWireInteger(value, path, I64_MIN, I64_MAX);
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

/**
 * Every integer this package writes is a JSON number, including the fields
 * `unboundedWireInteger` will read as a decimal string. `zolana-indexer-api`
 * serializes with plain serde and installs no string acceptor on its `u64` and
 * `i64` fields, so a quoted integer is a body the Rust side refuses, and
 * `encodeRequest` feeds the body Photon parses. The string form is a reader's
 * tolerance, not a shape we emit, which is why a value past the safe-integer
 * bound is reported here rather than encoded.
 */
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

function optional<T>(
  value: unknown,
  path: string,
  decode: (item: unknown, itemPath: string) => T,
): T | undefined {
  return value === undefined || value === null ? undefined : decode(value, path);
}

function context(value: unknown, path: string): IndexerContext {
  // `object` rejects any key not listed here, so a new wire field must be added
  // in the same release that starts sending it.
  const record = object(value, path, ["blockTime", "slot"]);
  return {
    blockTime: unboundedI64(record["blockTime"], `${path}.blockTime`),
    slot: u64(record["slot"], `${path}.slot`),
  };
}

function outputContext(value: unknown, path: string): RingsOutputContext {
  const record = object(value, path, ["hash", "tree", "leafIndex"]);
  return {
    hash: checkedHash(record["hash"], `${path}.hash`),
    tree: checkedAddress(record["tree"], `${path}.tree`),
    leafIndex: u64(record["leafIndex"], `${path}.leafIndex`),
  };
}

function outputSlot(value: unknown, path: string): RingsOutputSlot {
  const record = object(value, path, ["viewTag", "outputContext", "payload"]);
  return {
    viewTag: checkedHash(record["viewTag"], `${path}.viewTag`),
    outputContext: outputContext(record["outputContext"], `${path}.outputContext`),
    payload: checkedBase64(record["payload"], `${path}.payload`),
  };
}

function message(value: unknown, path: string): RingsMessage {
  const record = object(value, path, ["viewTag", "payload"]);
  return {
    viewTag: checkedHash(record["viewTag"], `${path}.viewTag`),
    payload: checkedBase64(record["payload"], `${path}.payload`),
  };
}

function encryptedUtxoMatch(value: unknown, path: string): EncryptedUtxoMatch {
  const record = object(value, path, ["slot", "txSignature", "outputSlot", "txViewingPk", "salt"]);
  const txViewingPk = optional(record["txViewingPk"], `${path}.txViewingPk`, checkedBase64);
  const salt = optional(record["salt"], `${path}.salt`, checkedBase64);
  return {
    slot: unboundedU64(record["slot"], `${path}.slot`),
    txSignature: checkedSignature(record["txSignature"], `${path}.txSignature`),
    outputSlot: outputSlot(record["outputSlot"], `${path}.outputSlot`),
    ...(txViewingPk === undefined ? {} : { txViewingPk }),
    ...(salt === undefined ? {} : { salt }),
  };
}

function indexedTransaction(value: unknown, path: string): IndexedShieldedTransaction {
  const record = object(value, path, [
    "slot",
    "txSignature",
    "txViewingPk",
    "salt",
    "outputSlots",
    "messages",
    "nullifiers",
    "proofless",
    "ringConfig",
    "ringProgramId",
  ]);
  const txViewingPk = optional(record["txViewingPk"], `${path}.txViewingPk`, checkedBase64);
  const salt = optional(record["salt"], `${path}.salt`, checkedBase64);
  const ringConfig = optional(record["ringConfig"], `${path}.ringConfig`, checkedAddress);
  const ringProgramId = optional(record["ringProgramId"], `${path}.ringProgramId`, checkedAddress);
  return {
    slot: unboundedU64(record["slot"], `${path}.slot`),
    txSignature: checkedSignature(record["txSignature"], `${path}.txSignature`),
    ...(txViewingPk === undefined ? {} : { txViewingPk }),
    ...(salt === undefined ? {} : { salt }),
    outputSlots: array(record["outputSlots"], `${path}.outputSlots`, outputSlot),
    messages: array(record["messages"], `${path}.messages`, message),
    nullifiers: array(record["nullifiers"], `${path}.nullifiers`, checkedHash),
    proofless: boolean(record["proofless"], `${path}.proofless`),
    ...(ringConfig === undefined ? {} : { ringConfig }),
    ...(ringProgramId === undefined ? {} : { ringProgramId }),
  };
}

function signatureIndexedTransaction(
  value: unknown,
  path: string,
): SignatureIndexedShieldedTransaction {
  const record = object(value, path, ["eventIndex", "transaction"]);
  return {
    eventIndex: u16(record["eventIndex"], `${path}.eventIndex`),
    transaction: indexedTransaction(record["transaction"], `${path}.transaction`),
  };
}

function merkleContext(value: unknown, path: string): MerkleProof["merkleContext"] {
  const record = object(value, path, ["treeType", "tree"]);
  return {
    treeType: u16(record["treeType"], `${path}.treeType`),
    tree: checkedAddress(record["tree"], `${path}.tree`),
  };
}

function merkleProof(value: unknown, path: string): MerkleProof {
  const record = object(value, path, [
    "leaf",
    "merkleContext",
    "path",
    "leafIndex",
    "root",
    "rootSeq",
    "rootIndex",
  ]);
  return {
    leaf: checkedHash(record["leaf"], `${path}.leaf`),
    merkleContext: merkleContext(record["merkleContext"], `${path}.merkleContext`),
    path: array(record["path"], `${path}.path`, checkedHash),
    leafIndex: u64(record["leafIndex"], `${path}.leafIndex`),
    root: checkedHash(record["root"], `${path}.root`),
    rootSeq: unboundedU64(record["rootSeq"], `${path}.rootSeq`),
    rootIndex: u16(record["rootIndex"], `${path}.rootIndex`),
  };
}

function nonInclusionProof(value: unknown, path: string): NonInclusionProof {
  const record = object(value, path, [
    "leaf",
    "merkleContext",
    "path",
    "lowElement",
    "lowElementIndex",
    "highElement",
    "highElementIndex",
    "root",
    "rootSeq",
    "rootIndex",
  ]);
  return {
    leaf: checkedHash(record["leaf"], `${path}.leaf`),
    merkleContext: merkleContext(record["merkleContext"], `${path}.merkleContext`),
    path: array(record["path"], `${path}.path`, checkedHash),
    lowElement: checkedHash(record["lowElement"], `${path}.lowElement`),
    lowElementIndex: u64(record["lowElementIndex"], `${path}.lowElementIndex`),
    highElement: checkedHash(record["highElement"], `${path}.highElement`),
    highElementIndex: u64(record["highElementIndex"], `${path}.highElementIndex`),
    root: checkedHash(record["root"], `${path}.root`),
    rootSeq: unboundedU64(record["rootSeq"], `${path}.rootSeq`),
    rootIndex: u16(record["rootIndex"], `${path}.rootIndex`),
  };
}

function decodeRingsByTagsRequest(value: unknown): GetRingsByTagsRequest {
  const record = object(value, "$", ["tags", "cursor", "limit", "ringProgramId"]);
  const cursor = optional(record["cursor"], "$.cursor", checkedBase64);
  const pageLimit =
    record["limit"] === undefined || record["limit"] === null
      ? undefined
      : checkedPageLimit(record["limit"], "$.limit");
  const ringProgramId = optional(record["ringProgramId"], "$.ringProgramId", checkedAddress);
  return {
    tags: array(record["tags"], "$.tags", checkedHash),
    ...(cursor === undefined ? {} : { cursor }),
    ...(pageLimit === undefined ? {} : { limit: pageLimit }),
    ...(ringProgramId === undefined ? {} : { ringProgramId }),
  };
}

export function encodeRingsByTagsRequest(value: GetRingsByTagsRequest): WireObject {
  const decoded = decodeRingsByTagsRequest({
    tags: value.tags,
    ...(value.cursor === undefined ? {} : { cursor: value.cursor }),
    ...(value.limit === undefined ? {} : { limit: toU64(value.limit, "$.limit") }),
    ...(value.ringProgramId === undefined ? {} : { ringProgramId: value.ringProgramId }),
  });
  return {
    tags: [...decoded.tags],
    ...(decoded.cursor === undefined ? {} : { cursor: decoded.cursor }),
    ...(decoded.limit === undefined ? {} : { limit: Number(decoded.limit) }),
    ...(decoded.ringProgramId === undefined ? {} : { ringProgramId: decoded.ringProgramId }),
  };
}

function decodeRingsByNullifiersRequest(value: unknown): GetRingsByNullifiersRequest {
  const record = object(value, "$", ["nullifiers", "cursor", "limit"]);
  const cursor = optional(record["cursor"], "$.cursor", checkedBase64);
  const pageLimit =
    record["limit"] === undefined || record["limit"] === null
      ? undefined
      : checkedPageLimit(record["limit"], "$.limit");
  return {
    nullifiers: array(record["nullifiers"], "$.nullifiers", checkedHash),
    ...(cursor === undefined ? {} : { cursor }),
    ...(pageLimit === undefined ? {} : { limit: pageLimit }),
  };
}

export function encodeRingsByNullifiersRequest(value: GetRingsByNullifiersRequest): WireObject {
  const decoded = decodeRingsByNullifiersRequest({
    nullifiers: value.nullifiers,
    ...(value.cursor === undefined ? {} : { cursor: value.cursor }),
    ...(value.limit === undefined ? {} : { limit: toU64(value.limit, "$.limit") }),
  });
  return {
    nullifiers: [...decoded.nullifiers],
    ...(decoded.cursor === undefined ? {} : { cursor: decoded.cursor }),
    ...(decoded.limit === undefined ? {} : { limit: Number(decoded.limit) }),
  };
}

export function encodeShieldedTransactionsBySignatureRequest(
  value: GetShieldedTransactionsBySignatureRequest,
): WireObject {
  return {
    txSignature: checkedSignature(value.txSignature, "$.txSignature"),
  };
}

export function decodeEncryptedUtxosResponse(value: unknown): GetEncryptedUtxosByTagsResponse {
  const record = object(value, "$", ["context", "matches", "nextCursor", "scannedThrough"]);
  const nextCursor = optional(record["nextCursor"], "$.nextCursor", checkedBase64);
  const scannedThrough = optional(record["scannedThrough"], "$.scannedThrough", checkedBase64);
  return {
    context: context(record["context"], "$.context"),
    matches: array(record["matches"], "$.matches", encryptedUtxoMatch),
    ...(nextCursor === undefined ? {} : { nextCursor }),
    ...(scannedThrough === undefined ? {} : { scannedThrough }),
  };
}

export function decodeShieldedTransactionsResponse(
  value: unknown,
): GetShieldedTransactionsByTagsResponse {
  const record = object(value, "$", ["context", "transactions", "nextCursor", "scannedThrough"]);
  const nextCursor = optional(record["nextCursor"], "$.nextCursor", checkedBase64);
  const scannedThrough = optional(record["scannedThrough"], "$.scannedThrough", checkedBase64);
  return {
    context: context(record["context"], "$.context"),
    transactions: array(record["transactions"], "$.transactions", indexedTransaction),
    ...(nextCursor === undefined ? {} : { nextCursor }),
    ...(scannedThrough === undefined ? {} : { scannedThrough }),
  };
}

export function decodeShieldedTransactionsByNullifiersResponse(
  value: unknown,
): GetShieldedTransactionsByNullifiersResponse {
  // Not `decodeShieldedTransactionsResponse`: `object` rejects any key it was
  // not told about, and this response carries one more.
  const record = object(value, "$", ["context", "transactions", "nextCursor", "scannedThrough"]);
  const nextCursor = optional(record["nextCursor"], "$.nextCursor", checkedBase64);
  const scannedThrough = optional(record["scannedThrough"], "$.scannedThrough", checkedBase64);
  return {
    context: context(record["context"], "$.context"),
    transactions: array(record["transactions"], "$.transactions", indexedTransaction),
    ...(nextCursor === undefined ? {} : { nextCursor }),
    ...(scannedThrough === undefined ? {} : { scannedThrough }),
  };
}

export function decodeShieldedTransactionsBySignatureResponse(
  value: unknown,
): GetShieldedTransactionsBySignatureResponse {
  const record = object(value, "$", ["context", "transactions"]);
  return {
    context: context(record["context"], "$.context"),
    transactions: array(record["transactions"], "$.transactions", signatureIndexedTransaction),
  };
}

function decodeLeavesRequest(value: unknown): GetMerkleProofsRequest {
  const record = object(value, "$", ["treeAccount", "leaves"]);
  return {
    treeAccount: checkedAddress(record["treeAccount"], "$.treeAccount"),
    leaves: array(record["leaves"], "$.leaves", checkedHash),
  };
}

function encodeLeavesRequest(
  value: GetMerkleProofsRequest | GetNonInclusionProofsRequest,
): WireObject {
  decodeLeavesRequest({
    treeAccount: value.treeAccount,
    leaves: value.leaves,
  });
  return { treeAccount: value.treeAccount, leaves: [...value.leaves] };
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
