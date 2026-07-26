import { describe, expect, it } from "vitest";

import * as root from "../src/index.js";
import * as methods from "../src/methods/index.js";

describe("public exports", () => {
  it("pins the package root", () => {
    expect(Object.keys(root).sort()).toEqual([
      "GET_ENCRYPTED_UTXOS_BY_TAGS",
      "GET_MERKLE_PROOFS",
      "GET_NON_INCLUSION_PROOFS",
      "GET_NULLIFIER_QUEUE_ELEMENTS",
      "GET_SHIELDED_TRANSACTIONS_BY_TAGS",
      "IndexerSchemaError",
      "MIN_PAGE_LIMIT",
      "PAGE_LIMIT",
      "base64Bytes",
      "base64String",
      "hash",
      "hashBytes",
      "limit",
    ]);
  });

  it("pins the methods entry point to the five Photon method descriptors", () => {
    expect(Object.keys(methods).sort()).toEqual([
      "getEncryptedUtxosByTagsMethod",
      "getMerkleProofsMethod",
      "getNonInclusionProofsMethod",
      "getNullifierQueueElementsMethod",
      "getShieldedTransactionsByTagsMethod",
    ]);
  });
});
