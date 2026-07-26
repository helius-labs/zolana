import { describe, expect, it } from "vitest";

import { IndexerSchemaError } from "../src/index.js";
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
const OUTPUT_SLOT = {
  view_tag: HASH,
  output_context: { hash: HASH, tree: HASH, leaf_index: 0 },
  payload: "AA==",
};
const MATCH = {
  slot: 0,
  tx_signature: SIGNATURE,
  output_slot: OUTPUT_SLOT,
  tx_viewing_pk: null,
  salt: null,
};
const TRANSACTION = {
  slot: 0,
  tx_signature: SIGNATURE,
  tx_viewing_pk: null,
  salt: null,
  output_slots: [OUTPUT_SLOT],
  messages: [],
  nullifiers: [],
  proofless: false,
};
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

// One past `Number.MAX_SAFE_INTEGER`, the first value a JSON number cannot carry.
const PAST_SAFE = "9007199254740992";
const PAST_SAFE_VALUE = 9_007_199_254_740_992n;
const U64_MAX = "18446744073709551615";

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

describe("indexer integer domain", () => {
  it("reads a decimal string on every field no protocol invariant caps", () => {
    expect(
      getEncryptedUtxosByTagsMethod.decodeResponse({
        context: { block_time: PAST_SAFE },
        matches: [{ ...MATCH, slot: PAST_SAFE }],
        next_cursor: null,
      }),
    ).toMatchObject({
      context: { blockTime: PAST_SAFE_VALUE },
      matches: [{ slot: PAST_SAFE_VALUE }],
    });

    expect(
      getShieldedTransactionsByTagsMethod.decodeResponse({
        context: CONTEXT,
        transactions: [{ ...TRANSACTION, slot: U64_MAX }],
        next_cursor: null,
      }).transactions[0]?.slot,
    ).toBe(18_446_744_073_709_551_615n);

    expect(
      getMerkleProofsMethod.decodeResponse({
        context: CONTEXT,
        proofs: [{ ...PROOF, root_seq: PAST_SAFE }],
      }).proofs[0]?.rootSeq,
    ).toBe(PAST_SAFE_VALUE);

    expect(
      getNonInclusionProofsMethod.decodeResponse({
        context: CONTEXT,
        proofs: [{ ...NON_INCLUSION_PROOF, root_seq: PAST_SAFE }],
      }).proofs[0]?.rootSeq,
    ).toBe(PAST_SAFE_VALUE);

    expect(
      getNullifierQueueElementsMethod.decodeResponse({
        context: CONTEXT,
        elements: [{ seq: PAST_SAFE, value: HASH }],
      }).elements[0]?.seq,
    ).toBe(PAST_SAFE_VALUE);

    expect(
      getNullifierQueueElementsMethod.decodeRequest({
        tree_account: HASH,
        start_seq: PAST_SAFE,
        limit: 1,
      }).startSeq,
    ).toBe(PAST_SAFE_VALUE);
  });

  it("reads a negative decimal string for the signed block time", () => {
    expect(
      getMerkleProofsMethod.decodeResponse({
        context: { block_time: "-1700000000" },
        proofs: [],
      }).context.blockTime,
    ).toBe(-1_700_000_000n);
  });

  it("leaves a JSON number payload decoding exactly as before", () => {
    expect(
      getEncryptedUtxosByTagsMethod.decodeResponse({
        context: { block_time: 1_700_000_000 },
        matches: [{ ...MATCH, slot: 42 }],
        next_cursor: null,
      }),
    ).toMatchObject({
      context: { blockTime: 1_700_000_000n },
      matches: [{ slot: 42n }],
    });

    expect(
      getNullifierQueueElementsMethod.decodeResponse({
        context: CONTEXT,
        elements: [{ seq: 7, value: HASH }],
      }).elements[0]?.seq,
    ).toBe(7n);
  });

  it("still refuses a JSON number that has already lost precision", () => {
    expectSchemaError(
      () =>
        getNullifierQueueElementsMethod.decodeResponse({
          context: CONTEXT,
          elements: [{ seq: Number.MAX_SAFE_INTEGER + 1, value: HASH }],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.elements[0].seq",
    );
    expectSchemaError(
      () =>
        getMerkleProofsMethod.decodeResponse({
          context: { block_time: 1.5 },
          proofs: [],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.context.block_time",
    );
  });

  it("refuses a string that is not a canonical decimal integer", () => {
    for (const malformed of ["", " 1", "01", "1.0", "1e3", "0x10", "+1", "-0"]) {
      expectSchemaError(
        () =>
          getNullifierQueueElementsMethod.decodeResponse({
            context: CONTEXT,
            elements: [{ seq: malformed, value: HASH }],
          }),
        "INDEXER_SCHEMA_INVALID_INTEGER",
        "$.elements[0].seq",
      );
    }
  });

  it("range checks a decimal string against the declared width", () => {
    expectSchemaError(
      () =>
        getNullifierQueueElementsMethod.decodeResponse({
          context: CONTEXT,
          elements: [{ seq: "18446744073709551616", value: HASH }],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.elements[0].seq",
    );
    expectSchemaError(
      () =>
        getNullifierQueueElementsMethod.decodeResponse({
          context: CONTEXT,
          elements: [{ seq: "-1", value: HASH }],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.elements[0].seq",
    );
  });

  it("keeps the string form off fields a tree height or a width already caps", () => {
    expectSchemaError(
      () =>
        getMerkleProofsMethod.decodeResponse({
          context: CONTEXT,
          proofs: [{ ...PROOF, leaf_index: "12" }],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.proofs[0].leaf_index",
    );
    expectSchemaError(
      () =>
        getMerkleProofsMethod.decodeResponse({
          context: CONTEXT,
          proofs: [{ ...PROOF, root_index: "12" }],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.proofs[0].root_index",
    );
    expectSchemaError(
      () =>
        getMerkleProofsMethod.decodeResponse({
          context: CONTEXT,
          proofs: [{ ...PROOF, merkle_context: { ...MERKLE_CONTEXT, tree_type: "0" } }],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.proofs[0].merkle_context.tree_type",
    );
    expectSchemaError(
      () =>
        getNonInclusionProofsMethod.decodeResponse({
          context: CONTEXT,
          proofs: [{ ...NON_INCLUSION_PROOF, high_element_index: "2" }],
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.proofs[0].high_element_index",
    );
    expectSchemaError(
      () =>
        getEncryptedUtxosByTagsMethod.decodeResponse({
          context: CONTEXT,
          matches: [
            {
              ...MATCH,
              output_slot: {
                ...OUTPUT_SLOT,
                output_context: { hash: HASH, tree: HASH, leaf_index: "3" },
              },
            },
          ],
          next_cursor: null,
        }),
      "INDEXER_SCHEMA_INVALID_INTEGER",
      "$.matches[0].output_slot.output_context.leaf_index",
    );
    expectSchemaError(
      () =>
        getNullifierQueueElementsMethod.decodeRequest({
          tree_account: HASH,
          limit: "10",
        }),
      "INDEXER_SCHEMA_INVALID_LIMIT",
      "$.limit",
    );
  });
});
