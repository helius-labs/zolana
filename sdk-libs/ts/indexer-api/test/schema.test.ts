import { describe, expect, it } from "vitest";

import {
  GET_ENCRYPTED_UTXOS_BY_TAGS,
  GET_MERKLE_PROOFS,
  GET_NON_INCLUSION_PROOFS,
  GET_NULLIFIER_QUEUE_ELEMENTS,
  GET_SHIELDED_TRANSACTIONS_BY_TAGS,
  IndexerSchemaError,
  base64String,
  hash,
  hashBytes,
  limit,
} from "../src/index.js";
import {
  getEncryptedUtxosByTagsMethod,
  getMerkleProofsMethod,
  getNonInclusionProofsMethod,
  getNullifierQueueElementsMethod,
  getShieldedTransactionsByTagsMethod,
} from "../src/methods/index.js";

const HASH = "11111111111111111111111111111111";
const SIGNATURE = "1".repeat(64);
const CONTEXT = { block_time: 0 };
const MERKLE_CONTEXT = { tree_type: 0, tree: HASH };
const PROOF = {
  leaf: HASH,
  merkle_context: MERKLE_CONTEXT,
  path: [HASH],
  leaf_index: 0,
  root: HASH,
  root_seq: 0,
  root_index: 0,
};
const NON_INCLUSION_PROOF = {
  leaf: HASH,
  merkle_context: MERKLE_CONTEXT,
  path: [HASH],
  low_element: HASH,
  low_element_index: 0,
  high_element: HASH,
  high_element_index: 1,
  root: HASH,
  root_seq: 0,
  root_index: 0,
};

function expectSchemaError(action: () => unknown, code: string, path: string): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(IndexerSchemaError);
    expect((error as IndexerSchemaError).code).toBe(code);
    expect((error as IndexerSchemaError).details?.["path"]).toBe(path);
    return;
  }
  throw new Error("expected schema validation to fail");
}

describe("indexer schema", () => {
  it("exports the exact method names", () => {
    expect([
      GET_ENCRYPTED_UTXOS_BY_TAGS,
      GET_SHIELDED_TRANSACTIONS_BY_TAGS,
      GET_MERKLE_PROOFS,
      GET_NON_INCLUSION_PROOFS,
      GET_NULLIFIER_QUEUE_ELEMENTS,
    ]).toEqual([
      "get_encrypted_utxos_by_tags",
      "get_shielded_transactions_by_tags",
      "get_merkle_proofs",
      "get_non_inclusion_proofs",
      "get_nullifier_queue_elements",
    ]);
  });

  it("constructs canonical encoded scalars and returns copied hash bytes", () => {
    expect(base64String(new Uint8Array([1, 2, 3]))).toBe("AQID");
    expect(base64String("AQID")).toBe("AQID");
    const bytes = new Uint8Array(32);
    const encoded = hash(bytes as never);
    bytes[0] = 9;
    expect(encoded).toBe(HASH);
    const first = hashBytes(encoded);
    first[0] = 7;
    expect(hashBytes(encoded)).toEqual(new Uint8Array(32));
    expect(limit(1n)).toBe(1n);
    expect(limit(1000n)).toBe(1000n);
  });

  it("rejects malformed scalar values and limit boundaries", () => {
    expectSchemaError(() => base64String("A==="), "INDEXER_SCHEMA_INVALID_BASE64", "$");
    expectSchemaError(() => hash("short"), "INDEXER_SCHEMA_HASH_WRONG_SIZE", "$");
    expectSchemaError(
      () => hash(new Uint8Array(31) as never),
      "INDEXER_SCHEMA_HASH_WRONG_SIZE",
      "$",
    );
    expectSchemaError(() => limit(0n), "INDEXER_SCHEMA_INVALID_LIMIT", "$");
    expectSchemaError(() => limit(1001n), "INDEXER_SCHEMA_INVALID_LIMIT", "$");
  });

  it("does not retain rejected wire strings in errors", () => {
    const secret = `not-base64-${"sensitive".repeat(32)}`;
    try {
      base64String(secret);
    } catch (error) {
      expect(JSON.stringify(error)).not.toContain(secret);
      expect((error as IndexerSchemaError).details?.["actual"]).toEqual({
        type: "string",
        length: secret.length,
      });
      return;
    }
    throw new Error("expected schema validation to fail");
  });

  it("rejects malformed encrypted UTXO fields", () => {
    const response = {
      context: CONTEXT,
      matches: [
        {
          slot: 0,
          tx_signature: SIGNATURE,
          output_slot: {
            view_tag: HASH,
            output_context: { hash: HASH, tree: HASH, leaf_index: 0 },
            payload: "AA==",
          },
          tx_viewing_pk: null,
          salt: null,
        },
      ],
      next_cursor: null,
    };
    expectSchemaError(
      () =>
        getEncryptedUtxosByTagsMethod.decodeResponse({
          ...response,
          matches: [{ ...response.matches[0], tx_signature: HASH }],
        }),
      "INDEXER_SCHEMA_INVALID_SIGNATURE",
      "$.matches[0].tx_signature",
    );
    expectSchemaError(
      () => getEncryptedUtxosByTagsMethod.decodeResponse({ ...response, extra: true }),
      "INDEXER_SCHEMA_UNKNOWN_FIELD",
      "$.extra",
    );
  });

  it("rejects malformed transaction payloads and nested unknown fields", () => {
    const transaction = {
      slot: 0,
      tx_signature: SIGNATURE,
      tx_viewing_pk: null,
      salt: null,
      output_slots: [],
      messages: [{ view_tag: HASH, payload: "AA==", extra: 1 }],
      nullifiers: [],
      proofless: false,
    };
    expectSchemaError(
      () =>
        getShieldedTransactionsByTagsMethod.decodeResponse({
          context: CONTEXT,
          transactions: [transaction],
          next_cursor: null,
        }),
      "INDEXER_SCHEMA_UNKNOWN_FIELD",
      "$.transactions[0].messages[0].extra",
    );
  });

  it("rejects Merkle path, index, and context boundaries", () => {
    expectSchemaError(
      () =>
        getMerkleProofsMethod.decodeResponse({
          context: CONTEXT,
          proofs: [{ ...PROOF, path: [HASH, "short"] }],
        }),
      "INDEXER_SCHEMA_HASH_WRONG_SIZE",
      "$.proofs[0].path[1]",
    );
    expectSchemaError(
      () =>
        getMerkleProofsMethod.decodeResponse({
          context: CONTEXT,
          proofs: [{ ...PROOF, leaf_index: -1 }],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.proofs[0].leaf_index",
    );
    expectSchemaError(
      () =>
        getMerkleProofsMethod.decodeResponse({
          context: CONTEXT,
          proofs: [{ ...PROOF, root_index: 65_536 }],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.proofs[0].root_index",
    );
    expectSchemaError(
      () =>
        getMerkleProofsMethod.decodeResponse({
          context: CONTEXT,
          proofs: [{ ...PROOF, merkle_context: { ...MERKLE_CONTEXT, tree_type: 65_536 } }],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.proofs[0].merkle_context.tree_type",
    );
  });

  it("decodes a u64 above the safe-integer bound carried as a decimal string", () => {
    const rootSeq = (1n << 60n) + 7n;
    const leafIndex = (1n << 53n) + 1n;
    const decoded = getMerkleProofsMethod.decodeResponse({
      context: CONTEXT,
      proofs: [
        {
          ...PROOF,
          leaf_index: leafIndex.toString(),
          root_seq: rootSeq.toString(),
        },
      ],
    });

    expect(decoded.proofs[0]?.leafIndex).toBe(leafIndex);
    expect(decoded.proofs[0]?.rootSeq).toBe(rootSeq);
  });

  it("rejects a decimal string outside the field's range or in a non-canonical form", () => {
    for (const [seq, path] of [
      [(1n << 64n).toString(), "$.proofs[0].root_seq"],
      ["-1", "$.proofs[0].root_seq"],
      ["007", "$.proofs[0].root_seq"],
      ["1.0", "$.proofs[0].root_seq"],
      [" 1", "$.proofs[0].root_seq"],
      ["", "$.proofs[0].root_seq"],
    ] as const) {
      expectSchemaError(
        () =>
          getMerkleProofsMethod.decodeResponse({
            context: CONTEXT,
            proofs: [{ ...PROOF, root_seq: seq }],
          }),
        "INDEXER_SCHEMA_INVALID_INTEGER",
        path,
      );
    }
  });

  it("rejects a JSON number that lost precision before it reached the decoder", () => {
    expectSchemaError(
      () =>
        getMerkleProofsMethod.decodeResponse({
          context: CONTEXT,
          proofs: [{ ...PROOF, root_seq: 2 ** 53 }],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.proofs[0].root_seq",
    );
  });

  it("rejects malformed non-inclusion neighbors", () => {
    expectSchemaError(
      () =>
        getNonInclusionProofsMethod.decodeResponse({
          context: CONTEXT,
          proofs: [
            {
              ...NON_INCLUSION_PROOF,
              high_element_index: -1,
            },
          ],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.proofs[0].high_element_index",
    );
  });

  it("rejects inclusion-only leaf indexes in non-inclusion proofs", () => {
    expectSchemaError(
      () =>
        getNonInclusionProofsMethod.decodeResponse({
          context: CONTEXT,
          proofs: [{ ...NON_INCLUSION_PROOF, leaf_index: 0 }],
        }),
      "INDEXER_SCHEMA_UNKNOWN_FIELD",
      "$.proofs[0].leaf_index",
    );
  });

  it("rejects queue sequence, limit, and unknown fields", () => {
    expectSchemaError(
      () =>
        getNullifierQueueElementsMethod.decodeResponse({
          context: CONTEXT,
          elements: [{ seq: -1, value: HASH }],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.elements[0].seq",
    );
    expectSchemaError(
      () =>
        getNullifierQueueElementsMethod.decodeRequest({
          tree_account: HASH,
          limit: 1001,
        }),
      "INDEXER_SCHEMA_INVALID_LIMIT",
      "$.limit",
    );
    expectSchemaError(
      () =>
        getNullifierQueueElementsMethod.decodeRequest({
          tree_account: HASH,
          limit: 1,
          cursor: "AA==",
        }),
      "INDEXER_SCHEMA_UNKNOWN_FIELD",
      "$.cursor",
    );
  });

  it("rejects malformed request cursor, address, leaves, and fields", () => {
    expectSchemaError(
      () =>
        getEncryptedUtxosByTagsMethod.decodeRequest({
          tags: [HASH],
          cursor: "not-base64",
        }),
      "INDEXER_SCHEMA_INVALID_BASE64",
      "$.cursor",
    );
    expectSchemaError(
      () => getMerkleProofsMethod.decodeRequest({ tree_account: "short", leaves: [HASH] }),
      "INDEXER_SCHEMA_INVALID_ADDRESS",
      "$.tree_account",
    );
    expectSchemaError(
      () => getMerkleProofsMethod.decodeRequest({ tree_account: "0".repeat(32), leaves: [HASH] }),
      "INDEXER_SCHEMA_INVALID_ADDRESS",
      "$.tree_account",
    );
    expectSchemaError(
      () => getNonInclusionProofsMethod.decodeRequest({ tree_account: HASH, leaves: "bad" }),
      "INDEXER_SCHEMA_INVALID_TYPE",
      "$.leaves",
    );
  });

  it("maps nullable request pagination to omitted camel-case fields", () => {
    expect(
      getEncryptedUtxosByTagsMethod.decodeRequest({
        tags: [HASH],
        cursor: null,
        limit: null,
      }),
    ).toEqual({ tags: [HASH] });
  });

  it("rejects unknown fields in every response family", () => {
    const cases: readonly [() => unknown, string][] = [
      [
        () =>
          getEncryptedUtxosByTagsMethod.decodeResponse({
            context: CONTEXT,
            matches: [],
            next_cursor: null,
            unknown: true,
          }),
        "$.unknown",
      ],
      [
        () =>
          getShieldedTransactionsByTagsMethod.decodeResponse({
            context: CONTEXT,
            transactions: [],
            next_cursor: null,
            unknown: true,
          }),
        "$.unknown",
      ],
      [
        () =>
          getMerkleProofsMethod.decodeResponse({
            context: CONTEXT,
            proofs: [],
            unknown: true,
          }),
        "$.unknown",
      ],
      [
        () =>
          getNonInclusionProofsMethod.decodeResponse({
            context: CONTEXT,
            proofs: [],
            unknown: true,
          }),
        "$.unknown",
      ],
      [
        () =>
          getNullifierQueueElementsMethod.decodeResponse({
            context: CONTEXT,
            elements: [],
            unknown: true,
          }),
        "$.unknown",
      ],
    ];

    for (const [action, path] of cases) {
      expectSchemaError(action, "INDEXER_SCHEMA_UNKNOWN_FIELD", path);
    }
  });
});
