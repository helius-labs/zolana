import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";
import type { Bytes32 } from "../src/interface/types.js";
import {
  HEAD_MAP_EMPTY_ROOT,
  HEAD_MAP_FIELD_MAX,
  HEAD_MAP_HEIGHT,
  headMapLeaf,
  headMapRootFromProof,
  headMapZeroBytes,
  verifyHeadMapInsert,
  verifyHeadMapTransfer,
} from "../src/ring/head-map.js";
import { bigIntBytes } from "../src/transaction/internal.js";

const ZERO = new Uint8Array(32) as Bytes32;
const member = (value: number): Bytes32 => bigIntBytes(BigInt(value)) as Bytes32;

beforeAll(async () => {
  await initializePoseidon();
});

describe("ring head map", () => {
  // The pinned empty root proves the TS leaf, zero-bytes and reduction match the
  // Rust reference and the Go circuit element for element.
  it("reduces the sentinel-only tree to the pinned empty root", () => {
    const zeros = headMapZeroBytes();
    const sentinel = headMapLeaf(ZERO, HEAD_MAP_FIELD_MAX, ZERO);
    const root = headMapRootFromProof(sentinel, 0n, zeros.slice(0, HEAD_MAP_HEIGHT));
    expect(root).toEqual(HEAD_MAP_EMPTY_ROOT);
  });

  it("verifies a first-member insertion and then a transfer", () => {
    const zeros = headMapZeroBytes();
    const newMember = member(0x1234);
    const genesis = member(0x5e);
    const successor = member(0x77);

    const splicedLow = headMapLeaf(ZERO, newMember, ZERO);
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

    // The member keeps the sentinel's successor pointer, only its nullifier moves.
    const transferredRoot = verifyHeadMapTransfer({
      root: registeredRoot,
      member: newMember,
      next: HEAD_MAP_FIELD_MAX,
      spent: genesis,
      successor,
      index: 1n,
      proof: newProof,
    });
    expect(transferredRoot).not.toEqual(registeredRoot);
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
    ).toThrow("out of range");
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
      newProof: [headMapLeaf(ZERO, member(0x1234), ZERO), ...zeros.slice(1, HEAD_MAP_HEIGHT)],
    };
    expect(() => verifyHeadMapInsert({ ...insert, root: member(9) })).toThrow("root mismatch");
    expect(() => verifyHeadMapInsert({ ...insert, lowProof: lowProof.slice(1) })).toThrow(
      "proof length",
    );

    const transferProof = insert.newProof;
    expect(() =>
      verifyHeadMapTransfer({
        root: member(9),
        member: member(0x1234),
        next: HEAD_MAP_FIELD_MAX,
        spent: member(0x5e),
        successor: member(0x77),
        index: 1n,
        proof: transferProof,
      }),
    ).toThrow("root mismatch");
  });
});
