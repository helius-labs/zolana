import { describe, expect, it } from "vitest";

import { base64String, hash, hashBytes, limit } from "../src/index.js";
import {
  getEncryptedUtxosByTagsMethod,
  getNonInclusionProofsMethod,
  getNullifierQueueElementsMethod,
} from "../src/methods/index.js";

function bytes(length: number, seed: number): Uint8Array {
  const value = new Uint8Array(length);
  let state = seed >>> 0;
  for (let index = 0; index < value.length; index += 1) {
    state = (state * 1_664_525 + 1_013_904_223) >>> 0;
    value[index] = state & 0xff;
  }
  return value;
}

describe("schema properties", () => {
  it("round-trips deterministic 32-byte hashes", () => {
    for (let seed = 0; seed < 256; seed += 1) {
      const input = bytes(32, seed);
      expect(hashBytes(hash(input as never))).toEqual(input);
    }
  });

  it("emits canonical base64 for arbitrary byte lengths", () => {
    for (let length = 0; length < 128; length += 1) {
      const encoded = base64String(bytes(length, length));
      expect(base64String(encoded)).toBe(encoded);
      expect(encoded.length % 4).toBe(0);
    }
  });

  it("accepts exactly the shared page-limit interval", () => {
    for (let value = 1n; value <= 1000n; value += 1n) {
      expect(limit(value)).toBe(value);
    }
    for (const value of [-1000n, -1n, 0n, 1001n, 10_000n]) {
      expect(() => limit(value)).toThrow();
    }
  });

  it("preserves request order and optional pagination fields", () => {
    const tags = Array.from({ length: 32 }, (_, index) => hash(bytes(32, index) as never));
    const wire = getEncryptedUtxosByTagsMethod.encodeRequest({
      tags,
      cursor: base64String(new Uint8Array([9, 8, 7])),
      limit: limit(32n),
    });

    expect(getEncryptedUtxosByTagsMethod.decodeRequest(wire)).toEqual({
      tags,
      cursor: "CQgH",
      limit: 32n,
    });
  });

  it("defaults only the queue start sequence on the wire", () => {
    const treeAccount = hash(new Uint8Array(32) as never);
    const wire = getNullifierQueueElementsMethod.encodeRequest({
      treeAccount,
      limit: limit(1n),
    } as never);

    expect(wire).toEqual({
      tree_account: treeAccount,
      start_seq: 0,
      limit: 1,
    });
    expect(getNullifierQueueElementsMethod.decodeRequest(wire)).toEqual({
      treeAccount,
      startSeq: 0n,
      limit: 1n,
    });
  });

  it("round-trips standalone non-inclusion proofs without leaf indexes", () => {
    for (let pathLength = 0; pathLength <= 40; pathLength += 1) {
      const leaf = hash(bytes(32, pathLength * 64) as never);
      const lowElement = hash(bytes(32, pathLength * 64 + 1) as never);
      const highElement = hash(bytes(32, pathLength * 64 + 2) as never);
      const path = Array.from({ length: pathLength }, (_, index) =>
        hash(bytes(32, pathLength * 64 + index + 3) as never),
      );
      const wire = {
        context: { block_time: pathLength },
        proofs: [
          {
            leaf,
            merkle_context: { tree_type: pathLength, tree: lowElement },
            path,
            low_element: lowElement,
            low_element_index: pathLength,
            high_element: highElement,
            high_element_index: pathLength + 1,
            root: leaf,
            root_seq: pathLength + 2,
            root_index: pathLength,
          },
        ],
      };

      const value = getNonInclusionProofsMethod.decodeResponse(wire);
      expect(getNonInclusionProofsMethod.encodeResponse(value)).toEqual(wire);
      expect(value.proofs[0]).not.toHaveProperty("leafIndex");
    }
  });
});
