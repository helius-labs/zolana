import { SLOT_BOUNDS, checkedHistoryFilters, validatePage } from "../interface/page.js";
import { checkedPaginationToken } from "../interface/pagination-token.js";
import { treeAddress } from "../interface/pda/index.js";
import type {
  EncryptedUtxoMatch,
  GetEncryptedUtxosByTagsResponse,
  GetMerkleProofsRequest,
  GetMerkleProofsResponse,
  GetNonInclusionProofsRequest,
  GetNonInclusionProofsResponse,
  GetRingsByNullifiersRequest,
  GetRingsByTagsRequest,
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
  GetUserRecordsRequest,
  GetUserRecordsResponse,
  HistoryFilters,
  PaginationToken,
  SlotFilter,
  UserRecord,
} from "./types.js";
import { jsonInteger } from "../interface/decode.js";
import { MAX_USER_RECORD_OWNERS } from "../interface/indexer-limits.js";
import { isMergeEncryptionScheme, type MergeEncryptionScheme } from "../interface/state.js";
import {
  checkedAddress,
  checkedBase64,
  checkedHash,
  checkedSignature,
  limit,
  schemaFailure,
} from "./scalars.js";

type WireObject = Record<string, unknown>;

const PAGE_CONTROLS = ["paginationToken", "limit", "filters", "minContextSlot"] as const;

/**
 * Every field of the wire contract, per object. A decoder reads only the fields
 * its entry lists (`object` types the record that way), and error paths name
 * only these fields.
 */
const FIELDS = {
  userRecordsResponse: ["context", "records"],
  userRecord: ["owner", "nullifierPubkey", "viewingPubkey", "mergeEncryption"],
  userRecordsRequest: ["owners"],
  historyFilters: ["slot"],
  slotFilter: SLOT_BOUNDS,
  context: ["blockTime", "slot"],
  outputContext: ["hash", "treeId", "leafIndex"],
  outputSlot: ["viewTag", "outputContext", "payload"],
  message: ["viewTag", "payload"],
  encryptedUtxoMatch: ["slot", "txSignature", "outputSlot", "txViewingPk", "salt"],
  indexedTransaction: [
    "slot",
    "txSignature",
    "eventIndex",
    "txViewingPk",
    "salt",
    "outputSlots",
    "messages",
    "nullifiers",
    "proofless",
    "ringConfig",
    "ringProgramId",
  ],
  signatureIndexedTransaction: ["eventIndex", "transaction"],
  merkleContext: ["treeType", "tree"],
  merkleProof: ["leaf", "merkleContext", "path", "leafIndex", "root", "rootSeq", "rootIndex"],
  nonInclusionProof: [
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
  ],
  ringsByTagsRequest: ["tags", "ringProgramId", ...PAGE_CONTROLS],
  ringsByNullifiersRequest: ["nullifiers", ...PAGE_CONTROLS],
  page: ["context", "data", "paginationToken", "outputTreeId"],
  transactionEvents: ["slot", "signature", "events"],
  transactionOutputs: ["slot", "signature", "outputs"],
  bySignatureResponse: ["context", "transactions", "outputTreeId"],
  leavesRequest: ["treeAccount", "leaves"],
  proofsResponse: ["context", "proofs"],
} as const satisfies Record<string, readonly string[]>;

const FIELD_NAMES: ReadonlySet<string> = new Set(Object.values(FIELDS).flat());
const SCHEMA_PATH = /^\$(?:\.[A-Za-z]+|\[\d+\])*$/u;

/**
 * `path` when it names only fields of this contract and array indexes, so an
 * error detail never echoes a key the caller or the indexer chose.
 */
export function knownSchemaPath(path: string): string | undefined {
  if (path.length > 256 || !SCHEMA_PATH.test(path)) return undefined;
  const names = path.match(/[A-Za-z]+/gu) ?? [];
  return names.every((name) => FIELD_NAMES.has(name)) ? path : undefined;
}

export function encodeUserRecordsRequest(value: GetUserRecordsRequest): WireObject {
  const owners: unknown = value.owners;
  if (!Array.isArray(owners) || owners.length < 1 || owners.length > MAX_USER_RECORD_OWNERS) {
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_TYPE",
      "$.owners",
      `1 to ${String(MAX_USER_RECORD_OWNERS)} owners`,
      owners,
    );
  }
  return {
    owners: owners.map((owner, index) => checkedAddress(owner, `$.owners[${String(index)}]`)),
  };
}

export function decodeUserRecordsResponse(value: unknown): GetUserRecordsResponse {
  const row = object(value, "$", FIELDS.userRecordsResponse);
  return {
    context: context(row["context"], "$.context"),
    records: array(row["records"], "$.records", (item, path) =>
      item === null ? null : userRecord(item, path),
    ),
  };
}

function userRecord(value: unknown, path: string): UserRecord {
  const record = object(value, path, FIELDS.userRecord);
  return {
    owner: checkedAddress(record["owner"], `${path}.owner`),
    nullifierPubkey: checkedHash(record["nullifierPubkey"], `${path}.nullifierPubkey`),
    viewingPubkey: checkedBase64(record["viewingPubkey"], `${path}.viewingPubkey`),
    mergeEncryption: mergeEncryptionScheme(record["mergeEncryption"], `${path}.mergeEncryption`),
  };
}

const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;
const U64_MAX = (1n << 64n) - 1n;
const U16_MAX = 65_535;

/**
 * A response object. A field this release does not know is ignored, as serde
 * does in `spr-indexer-api`, so Photon can add one without breaking deployed
 * clients; every known field is still validated in full.
 */
export function object<F extends string>(
  value: unknown,
  path: string,
  _fields: readonly F[],
): Readonly<Record<F, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", path, "an object", value);
  }
  return value as Readonly<Record<F, unknown>>;
}

/**
 * A request object. An unknown field is refused: a misspelled parameter would
 * otherwise answer a different question.
 */
function exactObject<F extends string>(
  value: unknown,
  path: string,
  fields: readonly F[],
): Readonly<Record<F, unknown>> {
  const record = object(value, path, fields);
  for (const key of Object.keys(record)) {
    if (!(fields as readonly string[]).includes(key)) {
      schemaFailure("INDEXER_SCHEMA_UNKNOWN_FIELD", `${path}.${key}`, "a known field", key);
    }
  }
  return record;
}

export function array<T>(
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

/** A `jsonInteger` in the field's range, for every integer field of the contract. */
export function wireInteger(
  value: unknown,
  path: string,
  minimum: bigint,
  maximum: bigint,
): bigint {
  const integer = jsonInteger(value);
  if (integer === undefined) {
    return schemaFailure("INDEXER_SCHEMA_INVALID_INTEGER", path, "a JSON integer", value);
  }
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

function mergeEncryptionScheme(value: unknown, path: string): MergeEncryptionScheme {
  const integer = Number(wireInteger(value, path, 0n, 255n));
  if (!isMergeEncryptionScheme(integer)) {
    return schemaFailure(
      "INDEXER_SCHEMA_INVALID_INTEGER",
      path,
      "a merge encryption scheme",
      value,
    );
  }
  return integer;
}

export function u16(value: unknown, path: string): number {
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
 * A request integer, written as a JSON number. `JSON.stringify` has no exact
 * form past `Number.MAX_SAFE_INTEGER`, so such a value is refused, not rounded.
 */
export function toWireInteger(
  value: bigint,
  path: string,
  minimum: bigint,
  maximum: bigint,
): number {
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

function paginationToken(value: unknown, path: string): PaginationToken {
  try {
    return checkedPaginationToken(value);
  } catch {
    return schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", path, "a pagination token");
  }
}

function historyFilters(value: unknown, path: string): HistoryFilters {
  const record = exactObject(value, path, FIELDS.historyFilters);
  const slot = optional(record["slot"], `${path}.slot`, slotFilter);
  return slot === undefined ? {} : { slot };
}

function slotFilter(value: unknown, path: string): SlotFilter {
  const record = exactObject(value, path, FIELDS.slotFilter);
  const filter: { -readonly [K in keyof SlotFilter]: SlotFilter[K] } = {};
  for (const bound of SLOT_BOUNDS) {
    const slot = optional(record[bound], `${path}.${bound}`, u64);
    if (slot !== undefined) filter[bound] = slot;
  }
  return filter;
}

/** Unknown keys are refused, a filter must never be dropped in silence. */
function encodeHistoryFilters(value: unknown, path: string): WireObject | undefined {
  const slot = checkedHistoryFilters(value, (field) =>
    schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", `$.${field}`, "known slot bounds"),
  )?.slot;
  if (slot === undefined) return undefined;
  const bounds: WireObject = {};
  for (const bound of SLOT_BOUNDS) {
    const bigint = slot[bound];
    if (bigint !== undefined) bounds[bound] = toU64(bigint, `${path}.slot.${bound}`);
  }
  return Object.keys(bounds).length === 0 ? undefined : { slot: bounds };
}

function pageControls(
  record: WireObject,
): Pick<GetRingsByTagsRequest, "paginationToken" | "limit" | "filters" | "minContextSlot"> {
  const token = optional(record["paginationToken"], "$.paginationToken", paginationToken);
  const filters = optional(record["filters"], "$.filters", historyFilters);
  const minContextSlot = optional(record["minContextSlot"], "$.minContextSlot", u64);
  const pageLimit =
    record["limit"] === undefined || record["limit"] === null
      ? undefined
      : checkedPageLimit(record["limit"], "$.limit");
  return {
    ...(token === undefined ? {} : { paginationToken: token }),
    ...(pageLimit === undefined ? {} : { limit: pageLimit }),
    ...(filters?.slot === undefined ? {} : { filters }),
    ...(minContextSlot === undefined ? {} : { minContextSlot }),
  };
}

function encodePageControls(
  value: Pick<GetRingsByTagsRequest, "paginationToken" | "limit" | "filters" | "minContextSlot">,
): WireObject {
  const filters = encodeHistoryFilters(value.filters, "$.filters");
  return {
    ...(value.paginationToken === undefined
      ? {}
      : { paginationToken: paginationToken(value.paginationToken, "$.paginationToken") }),
    ...(value.limit === undefined ? {} : { limit: toU64(value.limit, "$.limit") }),
    ...(filters === undefined ? {} : { filters }),
    ...(value.minContextSlot === undefined
      ? {}
      : { minContextSlot: toU64(value.minContextSlot, "$.minContextSlot") }),
  };
}

export function context(value: unknown, path: string): IndexerContext {
  const record = object(value, path, FIELDS.context);
  return {
    blockTime: i64(record["blockTime"], `${path}.blockTime`),
    slot: u64(record["slot"], `${path}.slot`),
  };
}

/** The tree account is derived from `treeId`; a `tree` field on the wire is not read. */
function outputContext(value: unknown, path: string): RingsOutputContext {
  const record = object(value, path, FIELDS.outputContext);
  const treeId = u16(record["treeId"], `${path}.treeId`);
  return {
    treeId,
    hash: checkedHash(record["hash"], `${path}.hash`),
    tree: treeAddress(treeId),
    leafIndex: u64(record["leafIndex"], `${path}.leafIndex`),
  };
}

function outputSlot(value: unknown, path: string): RingsOutputSlot {
  const record = object(value, path, FIELDS.outputSlot);
  return {
    viewTag: checkedHash(record["viewTag"], `${path}.viewTag`),
    outputContext: outputContext(record["outputContext"], `${path}.outputContext`),
    payload: checkedBase64(record["payload"], `${path}.payload`),
  };
}

function message(value: unknown, path: string): RingsMessage {
  const record = object(value, path, FIELDS.message);
  return {
    viewTag: checkedHash(record["viewTag"], `${path}.viewTag`),
    payload: checkedBase64(record["payload"], `${path}.payload`),
  };
}

function encryptedUtxoMatch(value: unknown, path: string): EncryptedUtxoMatch {
  const record = object(value, path, FIELDS.encryptedUtxoMatch);
  const txViewingPk = optional(record["txViewingPk"], `${path}.txViewingPk`, checkedBase64);
  const salt = optional(record["salt"], `${path}.salt`, checkedBase64);
  return {
    slot: u64(record["slot"], `${path}.slot`),
    txSignature: checkedSignature(record["txSignature"], `${path}.txSignature`),
    outputSlot: outputSlot(record["outputSlot"], `${path}.outputSlot`),
    ...(txViewingPk === undefined ? {} : { txViewingPk }),
    ...(salt === undefined ? {} : { salt }),
  };
}

export function indexedTransaction(value: unknown, path: string): IndexedShieldedTransaction {
  const record = object(value, path, FIELDS.indexedTransaction);
  const txViewingPk = optional(record["txViewingPk"], `${path}.txViewingPk`, checkedBase64);
  const salt = optional(record["salt"], `${path}.salt`, checkedBase64);
  const ringConfig = optional(record["ringConfig"], `${path}.ringConfig`, checkedAddress);
  const ringProgramId = optional(record["ringProgramId"], `${path}.ringProgramId`, checkedAddress);
  const eventIndex = optional(record["eventIndex"], `${path}.eventIndex`, u16);
  return {
    slot: u64(record["slot"], `${path}.slot`),
    txSignature: checkedSignature(record["txSignature"], `${path}.txSignature`),
    ...(eventIndex === undefined ? {} : { eventIndex }),
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
  const record = object(value, path, FIELDS.signatureIndexedTransaction);
  return {
    eventIndex: u16(record["eventIndex"], `${path}.eventIndex`),
    transaction: indexedTransaction(record["transaction"], `${path}.transaction`),
  };
}

function merkleContext(value: unknown, path: string): MerkleProof["merkleContext"] {
  const record = object(value, path, FIELDS.merkleContext);
  return {
    treeType: u16(record["treeType"], `${path}.treeType`),
    tree: checkedAddress(record["tree"], `${path}.tree`),
  };
}

function merkleProof(value: unknown, path: string): MerkleProof {
  const record = object(value, path, FIELDS.merkleProof);
  return {
    leaf: checkedHash(record["leaf"], `${path}.leaf`),
    merkleContext: merkleContext(record["merkleContext"], `${path}.merkleContext`),
    path: array(record["path"], `${path}.path`, checkedHash),
    leafIndex: u64(record["leafIndex"], `${path}.leafIndex`),
    root: checkedHash(record["root"], `${path}.root`),
    rootSeq: u64(record["rootSeq"], `${path}.rootSeq`),
    rootIndex: u16(record["rootIndex"], `${path}.rootIndex`),
  };
}

function nonInclusionProof(value: unknown, path: string): NonInclusionProof {
  const record = object(value, path, FIELDS.nonInclusionProof);
  return {
    leaf: checkedHash(record["leaf"], `${path}.leaf`),
    merkleContext: merkleContext(record["merkleContext"], `${path}.merkleContext`),
    path: array(record["path"], `${path}.path`, checkedHash),
    lowElement: checkedHash(record["lowElement"], `${path}.lowElement`),
    lowElementIndex: u64(record["lowElementIndex"], `${path}.lowElementIndex`),
    highElement: checkedHash(record["highElement"], `${path}.highElement`),
    highElementIndex: u64(record["highElementIndex"], `${path}.highElementIndex`),
    root: checkedHash(record["root"], `${path}.root`),
    rootSeq: u64(record["rootSeq"], `${path}.rootSeq`),
    rootIndex: u16(record["rootIndex"], `${path}.rootIndex`),
  };
}

function decodeRingsByTagsRequest(value: unknown): GetRingsByTagsRequest {
  const record = exactObject(value, "$", FIELDS.ringsByTagsRequest);
  const controls = pageControls(record);
  const ringProgramId = optional(record["ringProgramId"], "$.ringProgramId", checkedAddress);
  const tags = array(record["tags"], "$.tags", checkedHash);
  if (tags.length === 0 && ringProgramId === undefined)
    schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", "$.tags", "nonempty tags or ringProgramId");
  return {
    tags,
    ...controls,
    ...(ringProgramId === undefined ? {} : { ringProgramId }),
  };
}

export function encodeRingsByTagsRequest(value: GetRingsByTagsRequest): WireObject {
  const decoded = decodeRingsByTagsRequest({
    tags: value.tags,
    ...encodePageControls(value),
    ...(value.ringProgramId === undefined ? {} : { ringProgramId: value.ringProgramId }),
  });
  return {
    tags: [...decoded.tags],
    ...encodePageControls(decoded),
    ...(decoded.ringProgramId === undefined ? {} : { ringProgramId: decoded.ringProgramId }),
  };
}

function decodeRingsByNullifiersRequest(value: unknown): GetRingsByNullifiersRequest {
  const record = exactObject(value, "$", FIELDS.ringsByNullifiersRequest);
  return {
    nullifiers: array(record["nullifiers"], "$.nullifiers", checkedHash),
    ...pageControls(record),
  };
}

export function encodeRingsByNullifiersRequest(value: GetRingsByNullifiersRequest): WireObject {
  const decoded = decodeRingsByNullifiersRequest({
    nullifiers: value.nullifiers,
    ...encodePageControls(value),
  });
  return {
    nullifiers: [...decoded.nullifiers],
    ...encodePageControls(decoded),
  };
}

export function encodeShieldedTransactionsBySignatureRequest(
  value: GetShieldedTransactionsBySignatureRequest,
): WireObject {
  return {
    txSignature: checkedSignature(value.txSignature, "$.txSignature"),
  };
}

function decodePage<T>(
  value: unknown,
  rowFields: typeof FIELDS.transactionEvents | typeof FIELDS.transactionOutputs,
  decode: (v: unknown, p: string) => T,
) {
  const child = rowFields[2];
  const record = object(value, "$", FIELDS.page);
  const outputTreeId = optional(record["outputTreeId"], "$.outputTreeId", u16);
  const pageContext = context(record["context"], "$.context");
  const token =
    record["paginationToken"] === null
      ? null
      : paginationToken(record["paginationToken"], "$.paginationToken");
  const data = array(record["data"], "$.data", (v, p) => {
    const row = object(v, p, rowFields);
    const slot = u64(row["slot"], `${p}.slot`);
    const signature = checkedSignature(row["signature"], `${p}.signature`);
    const entries = array(row[child], `${p}.${child}`, decode);
    if (entries.length === 0)
      schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", p, "a nonempty transaction");
    return { slot, signature, entries };
  });
  try {
    validatePage({ context: pageContext, data, paginationToken: token });
  } catch {
    schemaFailure(
      "INDEXER_SCHEMA_INVALID_TYPE",
      "$.paginationToken",
      "a consistent pagination token",
    );
  }
  return {
    ...(outputTreeId === undefined ? {} : { outputTreeId }),
    context: pageContext,
    data,
    paginationToken: token,
  };
}

export function decodeEncryptedUtxosResponse(value: unknown): GetEncryptedUtxosByTagsResponse {
  const page = decodePage(value, FIELDS.transactionOutputs, encryptedUtxoMatch);
  return {
    ...page,
    data: page.data.map(({ entries: outputs, ...header }) => {
      if (
        outputs.some(
          (output) => output.slot !== header.slot || output.txSignature !== header.signature,
        )
      )
        schemaFailure("INDEXER_SCHEMA_INVALID_TYPE", "$.data", "matching transaction headers");
      return { ...header, outputs };
    }),
  };
}

export function decodeShieldedTransactionsResponse(
  value: unknown,
): GetShieldedTransactionsByTagsResponse {
  const page = decodePage(value, FIELDS.transactionEvents, indexedTransaction);
  return {
    ...page,
    data: page.data.map(({ entries: events, ...header }) => {
      let previous = -1;
      for (const event of events) {
        if (
          event.slot !== header.slot ||
          event.txSignature !== header.signature ||
          event.eventIndex === undefined ||
          event.eventIndex <= previous
        )
          schemaFailure(
            "INDEXER_SCHEMA_INVALID_TYPE",
            "$.data",
            "ordered events matching the transaction header",
          );
        previous = event.eventIndex;
      }
      return { ...header, events };
    }),
  };
}

export function decodeShieldedTransactionsBySignatureResponse(
  value: unknown,
): GetShieldedTransactionsBySignatureResponse {
  const record = object(value, "$", FIELDS.bySignatureResponse);
  const outputTreeId = optional(record["outputTreeId"], "$.outputTreeId", u16);
  return {
    ...(outputTreeId === undefined ? {} : { outputTreeId }),
    context: context(record["context"], "$.context"),
    transactions: array(record["transactions"], "$.transactions", signatureIndexedTransaction),
  };
}

/**
 * Correlates a by-signature answer with its request: every event belongs to
 * the requested transaction, in its one slot no later than `context.slot`,
 * and carries its own `eventIndex`, strictly ascending.
 */
export function validateShieldedTransactionsBySignatureResponse(
  response: GetShieldedTransactionsBySignatureResponse,
  request: GetShieldedTransactionsBySignatureRequest,
): void {
  const slot = response.transactions[0]?.transaction.slot;
  let previous = -1;
  response.transactions.forEach(({ eventIndex, transaction }, index) => {
    const path = `$.transactions[${String(index)}]`;
    if (transaction.txSignature !== request.txSignature)
      schemaFailure(
        "INDEXER_SCHEMA_INVALID_TYPE",
        `${path}.transaction.txSignature`,
        "the requested signature",
      );
    if (transaction.eventIndex !== eventIndex || eventIndex <= previous)
      schemaFailure(
        "INDEXER_SCHEMA_INVALID_TYPE",
        `${path}.eventIndex`,
        "the event's own index, ascending",
      );
    if (transaction.slot !== slot || transaction.slot > response.context.slot)
      schemaFailure(
        "INDEXER_SCHEMA_INVALID_TYPE",
        `${path}.transaction.slot`,
        "the transaction's slot, no later than the context",
      );
    previous = eventIndex;
  });
}

function decodeLeavesRequest(value: unknown): GetMerkleProofsRequest {
  const record = exactObject(value, "$", FIELDS.leavesRequest);
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
  const record = object(value, "$", FIELDS.proofsResponse);
  return {
    context: context(record["context"], "$.context"),
    proofs: array(record["proofs"], "$.proofs", merkleProof),
  };
}

export function encodeNonInclusionProofsRequest(value: GetNonInclusionProofsRequest): WireObject {
  return encodeLeavesRequest(value);
}

export function decodeNonInclusionProofsResponse(value: unknown): GetNonInclusionProofsResponse {
  const record = object(value, "$", FIELDS.proofsResponse);
  return {
    context: context(record["context"], "$.context"),
    proofs: array(record["proofs"], "$.proofs", nonInclusionProof),
  };
}
