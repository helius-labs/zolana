import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";
import type { Bytes32 } from "../src/interface/types.js";
import {
  HEAD_MAP_CAPACITY,
  HEAD_MAP_EMPTY_ROOT,
  HEAD_MAP_FIELD_MAX,
  HEAD_MAP_HEIGHT,
  headMapLeaf,
  headMapRootFromProof,
  headMapZeroBytes,
  verifyHeadMapInsert,
} from "../src/ring/head-map.js";
import { bigIntBytes } from "../src/transaction/internal.js";

const ZERO = new Uint8Array(32) as Bytes32;
const member = (value: number): Bytes32 => bigIntBytes(BigInt(value)) as Bytes32;

beforeAll(async () => {
  await initializePoseidon();
});

describe("ring head map", () => {
  it("rejects negative and aliased forty-bit proof indexes", () => {
    const path = headMapZeroBytes().slice(0, HEAD_MAP_HEIGHT);
    for (const index of [-1n, HEAD_MAP_CAPACITY, HEAD_MAP_CAPACITY + 1n]) {
      expect(() => headMapRootFromProof({ leaf: ZERO, index, proof: path })).toThrow(
        "RING_HEAD_MAP_INVALID",
      );
    }
  });

  it("returns owned zero bytes without exposing the private empty leaf", () => {
    const first = headMapZeroBytes();
    first[0]?.fill(255);
    expect(headMapZeroBytes()[0]).toEqual(ZERO);
  });

  it("rejects noncanonical field values before hashing", () => {
    const invalid = new Uint8Array(32).fill(255) as Bytes32;
    expect(() =>
      headMapLeaf({ member: ZERO, next: HEAD_MAP_FIELD_MAX, nullifier: invalid }),
    ).toThrow("RING_HEAD_MAP_INVALID");
  });
  // The pinned empty root proves the TS leaf, zero-bytes and reduction match the
  // Rust reference and the Go circuit element for element.
  it("reduces the sentinel-only tree to the pinned empty root", () => {
    const zeros = headMapZeroBytes();
    const sentinel = headMapLeaf({ member: ZERO, next: HEAD_MAP_FIELD_MAX, nullifier: ZERO });
    const root = headMapRootFromProof({
      leaf: sentinel,
      index: 0n,
      proof: zeros.slice(0, HEAD_MAP_HEIGHT),
    });
    expect(root).toEqual(HEAD_MAP_EMPTY_ROOT);
  });

  it("verifies a first-member insertion", () => {
    const zeros = headMapZeroBytes();
    const newMember = member(0x1234);
    const genesis = member(0x5e);

    const splicedLow = headMapLeaf({ member: ZERO, next: newMember, nullifier: ZERO });
    const newProof = [splicedLow, ...zeros.slice(1, HEAD_MAP_HEIGHT)];

    const registeredRoot = verifyHeadMapInsert({
      root: HEAD_MAP_EMPTY_ROOT,
      appendIndex: 1n,
      member: newMember,
      genesis,
      lowMember: ZERO,
      lowNext: HEAD_MAP_FIELD_MAX,
      lowNullifier: ZERO,
      lowIndex: 0n,
      lowProof: zeros.slice(0, HEAD_MAP_HEIGHT),
      newProof,
    });
    expect(registeredRoot).not.toEqual(HEAD_MAP_EMPTY_ROOT);
  });

  it("rejects a member outside the low element's range", () => {
    const zeros = headMapZeroBytes();
    expect(() =>
      verifyHeadMapInsert({
        root: HEAD_MAP_EMPTY_ROOT,
        appendIndex: 1n,
        member: ZERO,
        genesis: member(0x5e),
        lowMember: ZERO,
        lowNext: HEAD_MAP_FIELD_MAX,
        lowNullifier: ZERO,
        lowIndex: 0n,
        lowProof: zeros.slice(0, HEAD_MAP_HEIGHT),
        newProof: zeros.slice(0, HEAD_MAP_HEIGHT),
      }),
    ).toThrow("RING_HEAD_MAP_INVALID");
  });

  it("rejects a stale root and a wrong proof length", () => {
    const zeros = headMapZeroBytes();
    const lowProof = zeros.slice(0, HEAD_MAP_HEIGHT);
    const insert = {
      root: HEAD_MAP_EMPTY_ROOT,
      appendIndex: 1n,
      member: member(0x1234),
      genesis: member(0x5e),
      lowMember: ZERO,
      lowNext: HEAD_MAP_FIELD_MAX,
      lowNullifier: ZERO,
      lowIndex: 0n,
      lowProof,
      newProof: [
        headMapLeaf({ member: ZERO, next: member(0x1234), nullifier: ZERO }),
        ...zeros.slice(1, HEAD_MAP_HEIGHT),
      ],
    };
    expect(() => verifyHeadMapInsert({ ...insert, root: member(9) })).toThrow(
      "RING_HEAD_MAP_INVALID",
    );
    expect(() => verifyHeadMapInsert({ ...insert, lowProof: lowProof.slice(1) })).toThrow(
      "RING_HEAD_MAP_INVALID",
    );
  });
});
