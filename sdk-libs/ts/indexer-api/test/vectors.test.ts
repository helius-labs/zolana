import { describe, expect, it } from "vitest";

import {
  getEncryptedUtxosByTagsMethod,
  getMerkleProofsMethod,
  getNonInclusionProofsMethod,
  getNullifierQueueElementsMethod,
  getShieldedTransactionsByTagsMethod,
} from "../src/methods/index.js";

const HASH = "11111111111111111111111111111111";
const ADDRESS = HASH;
const SIGNATURE = "1".repeat(64);
const CONTEXT = { block_time: 1234 };
const OUTPUT_CONTEXT = { hash: HASH, tree: ADDRESS, leaf_index: 7 };
const OUTPUT_SLOT = {
  view_tag: HASH,
  output_context: OUTPUT_CONTEXT,
  payload: "AQID",
};
const MERKLE_PROOF = {
  leaf: HASH,
  merkle_context: { tree_type: 1, tree: ADDRESS },
  path: [HASH, HASH],
  leaf_index: 7,
  root: HASH,
  root_seq: 8,
  root_index: 9,
};

describe("frozen indexer wire vectors", () => {
  it("decodes and re-encodes encrypted UTXO matches", () => {
    const wire = {
      context: CONTEXT,
      matches: [
        {
          slot: 5,
          tx_signature: SIGNATURE,
          output_slot: OUTPUT_SLOT,
          tx_viewing_pk: "AQID",
          salt: null,
        },
      ],
      next_cursor: "BA==",
    };

    const value = getEncryptedUtxosByTagsMethod.decodeResponse(wire);

    expect(value).toEqual({
      context: { blockTime: 1234n },
      matches: [
        {
          slot: 5n,
          txSignature: SIGNATURE,
          outputSlot: {
            viewTag: HASH,
            outputContext: { hash: HASH, tree: ADDRESS, leafIndex: 7n },
            payload: "AQID",
          },
          txViewingPk: "AQID",
        },
      ],
      nextCursor: "BA==",
    });
    expect(getEncryptedUtxosByTagsMethod.encodeResponse(value)).toEqual(wire);
  });

  it("decodes and re-encodes shielded transactions", () => {
    const wire = {
      context: CONTEXT,
      transactions: [
        {
          slot: 6,
          tx_signature: SIGNATURE,
          tx_viewing_pk: null,
          salt: "AA==",
          output_slots: [OUTPUT_SLOT],
          messages: [{ view_tag: HASH, payload: "BQY=" }],
          nullifiers: [HASH],
          proofless: true,
        },
      ],
      next_cursor: null,
    };

    const value = getShieldedTransactionsByTagsMethod.decodeResponse(wire);

    expect(value).toEqual({
      context: { blockTime: 1234n },
      transactions: [
        {
          slot: 6n,
          txSignature: SIGNATURE,
          salt: "AA==",
          outputSlots: [
            {
              viewTag: HASH,
              outputContext: { hash: HASH, tree: ADDRESS, leafIndex: 7n },
              payload: "AQID",
            },
          ],
          messages: [{ viewTag: HASH, payload: "BQY=" }],
          nullifiers: [HASH],
          proofless: true,
        },
      ],
    });
    expect(getShieldedTransactionsByTagsMethod.encodeResponse(value)).toEqual(wire);
  });

  it("decodes and re-encodes Merkle proofs", () => {
    const wire = { context: CONTEXT, proofs: [MERKLE_PROOF] };

    const value = getMerkleProofsMethod.decodeResponse(wire);

    expect(value.proofs[0]).toEqual({
      leaf: HASH,
      merkleContext: { treeType: 1, tree: ADDRESS },
      path: [HASH, HASH],
      leafIndex: 7n,
      root: HASH,
      rootSeq: 8n,
      rootIndex: 9,
    });
    expect(getMerkleProofsMethod.encodeResponse(value)).toEqual(wire);
  });

  it("decodes and re-encodes non-inclusion proofs", () => {
    const proof = {
      leaf: HASH,
      merkle_context: { tree_type: 1, tree: ADDRESS },
      path: [HASH, HASH],
      low_element: HASH,
      low_element_index: 2,
      high_element: HASH,
      high_element_index: 3,
      root: HASH,
      root_seq: 8,
      root_index: 9,
    };
    const wire = { context: CONTEXT, proofs: [proof] };

    const value = getNonInclusionProofsMethod.decodeResponse(wire);

    expect(value.proofs[0]).toEqual({
      leaf: HASH,
      merkleContext: { treeType: 1, tree: ADDRESS },
      path: [HASH, HASH],
      lowElement: HASH,
      lowElementIndex: 2n,
      highElement: HASH,
      highElementIndex: 3n,
      root: HASH,
      rootSeq: 8n,
      rootIndex: 9,
    });
    expect(getNonInclusionProofsMethod.encodeResponse(value)).toEqual(wire);
  });

  it("decodes and re-encodes nullifier queue elements", () => {
    const wire = {
      context: CONTEXT,
      elements: [
        { seq: 0, value: HASH },
        { seq: 10, value: HASH },
      ],
    };

    const value = getNullifierQueueElementsMethod.decodeResponse(wire);

    expect(value).toEqual({
      context: { blockTime: 1234n },
      elements: [
        { seq: 0n, value: HASH },
        { seq: 10n, value: HASH },
      ],
    });
    expect(getNullifierQueueElementsMethod.encodeResponse(value)).toEqual(wire);
  });

  it("encodes every request with exact snake-case keys", () => {
    expect(
      getEncryptedUtxosByTagsMethod.encodeRequest({
        tags: [HASH],
        cursor: "AQ==",
        limit: 1000n,
      } as never),
    ).toEqual({ tags: [HASH], cursor: "AQ==", limit: 1000 });
    expect(
      getMerkleProofsMethod.encodeRequest({
        treeAccount: ADDRESS,
        leaves: [HASH],
      } as never),
    ).toEqual({ tree_account: ADDRESS, leaves: [HASH] });
    expect(
      getNonInclusionProofsMethod.encodeRequest({
        treeAccount: ADDRESS,
        leaves: [HASH],
      } as never),
    ).toEqual({ tree_account: ADDRESS, leaves: [HASH] });
    expect(
      getNullifierQueueElementsMethod.encodeRequest({
        treeAccount: ADDRESS,
        limit: 1n,
      } as never),
    ).toEqual({ tree_account: ADDRESS, start_seq: 0, limit: 1 });
  });
});
