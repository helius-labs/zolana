import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";
import type { Bytes32 } from "../src/interface/types.js";
import {
  MEMBER_REGISTRY_CAPACITY,
  MEMBER_REGISTRY_EMPTY_ROOT,
  MEMBER_REGISTRY_FIELD_MAX,
  MEMBER_REGISTRY_HEIGHT,
  memberRegistryLeaf,
  memberRegistryRootFromProof,
  memberRegistryZeroBytes,
  verifyMemberRegistryInsert,
} from "../src/ring/member-registry-tree.js";
import { bigIntBytes } from "../src/transaction/internal.js";

const ZERO = new Uint8Array(32) as Bytes32;
const member = (value: number): Bytes32 => bigIntBytes(BigInt(value)) as Bytes32;

beforeAll(async () => {
  await initializePoseidon();
});

describe("ring key registry tree", () => {
  it("rejects negative and aliased forty-bit proof indexes", () => {
    const path = memberRegistryZeroBytes().slice(0, MEMBER_REGISTRY_HEIGHT);
    for (const index of [-1n, MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_CAPACITY + 1n]) {
      expect(() => memberRegistryRootFromProof({ leaf: ZERO, index, proof: path })).toThrow(
        "RING_MEMBER_REGISTRY_INVALID",
      );
    }
  });

  it("returns owned zero bytes without exposing the private empty leaf", () => {
    const first = memberRegistryZeroBytes();
    first[0]?.fill(255);
    expect(memberRegistryZeroBytes()[0]).toEqual(ZERO);
  });

  it("rejects noncanonical field values before hashing", () => {
    const invalid = new Uint8Array(32).fill(255) as Bytes32;
    expect(() =>
      memberRegistryLeaf({
        member: ZERO,
        next: MEMBER_REGISTRY_FIELD_MAX,
        lists: 0n,
        escrowKey: invalid,
      }),
    ).toThrow("RING_MEMBER_REGISTRY_INVALID");
  });
  // The pinned empty root proves the TS leaf, zero-bytes and reduction match the
  // Rust reference and the Go circuit element for element.
  it("reduces the sentinel-only tree to the pinned empty root", () => {
    const zeros = memberRegistryZeroBytes();
    const sentinel = memberRegistryLeaf({
      member: ZERO,
      next: MEMBER_REGISTRY_FIELD_MAX,
      lists: 0n,
      escrowKey: ZERO,
    });
    const root = memberRegistryRootFromProof({
      leaf: sentinel,
      index: 0n,
      proof: zeros.slice(0, MEMBER_REGISTRY_HEIGHT),
    });
    expect(root).toEqual(MEMBER_REGISTRY_EMPTY_ROOT);
  });

  it("verifies a first-member insertion", () => {
    const zeros = memberRegistryZeroBytes();
    const newMember = member(0x1234);
    const key = member(0x5e);

    const splicedLow = memberRegistryLeaf({
      member: ZERO,
      next: newMember,
      lists: 0n,
      escrowKey: ZERO,
    });
    const newProof = [splicedLow, ...zeros.slice(1, MEMBER_REGISTRY_HEIGHT)];

    const registeredRoot = verifyMemberRegistryInsert({
      root: MEMBER_REGISTRY_EMPTY_ROOT,
      appendIndex: 1n,
      member: newMember,
      lists: 0n,
      escrowKey: key,
      lowMember: ZERO,
      lowNext: MEMBER_REGISTRY_FIELD_MAX,
      lowLists: 0n,
      lowEscrowKey: ZERO,
      lowIndex: 0n,
      lowProof: zeros.slice(0, MEMBER_REGISTRY_HEIGHT),
      newProof,
    });
    expect(registeredRoot).not.toEqual(MEMBER_REGISTRY_EMPTY_ROOT);
  });

  it("rejects a member outside the low element's range", () => {
    const zeros = memberRegistryZeroBytes();
    expect(() =>
      verifyMemberRegistryInsert({
        root: MEMBER_REGISTRY_EMPTY_ROOT,
        appendIndex: 1n,
        member: ZERO,
        lists: 0n,
        escrowKey: member(0x5e),
        lowMember: ZERO,
        lowNext: MEMBER_REGISTRY_FIELD_MAX,
        lowLists: 0n,
        lowEscrowKey: ZERO,
        lowIndex: 0n,
        lowProof: zeros.slice(0, MEMBER_REGISTRY_HEIGHT),
        newProof: zeros.slice(0, MEMBER_REGISTRY_HEIGHT),
      }),
    ).toThrow("RING_MEMBER_REGISTRY_INVALID");
  });

  it("rejects a stale root and a wrong proof length", () => {
    const zeros = memberRegistryZeroBytes();
    const lowProof = zeros.slice(0, MEMBER_REGISTRY_HEIGHT);
    const insert = {
      root: MEMBER_REGISTRY_EMPTY_ROOT,
      appendIndex: 1n,
      member: member(0x1234),
      lists: 0n,
      escrowKey: member(0x5e),
      lowMember: ZERO,
      lowNext: MEMBER_REGISTRY_FIELD_MAX,
      lowLists: 0n,
      lowEscrowKey: ZERO,
      lowIndex: 0n,
      lowProof,
      newProof: [
        memberRegistryLeaf({ member: ZERO, next: member(0x1234), lists: 0n, escrowKey: ZERO }),
        ...zeros.slice(1, MEMBER_REGISTRY_HEIGHT),
      ],
    };
    expect(() => verifyMemberRegistryInsert({ ...insert, root: member(9) })).toThrow(
      "RING_MEMBER_REGISTRY_INVALID",
    );
    expect(() => verifyMemberRegistryInsert({ ...insert, lowProof: lowProof.slice(1) })).toThrow(
      "RING_MEMBER_REGISTRY_INVALID",
    );
  });
});
