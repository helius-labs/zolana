import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";
import type { Bytes32 } from "../src/interface/types.js";
import {
  KEY_REGISTRY_CAPACITY,
  KEY_REGISTRY_EMPTY_ROOT,
  KEY_REGISTRY_FIELD_MAX,
  KEY_REGISTRY_HEIGHT,
  keyRegistryLeaf,
  keyRegistryRootFromProof,
  keyRegistryZeroBytes,
  verifyKeyRegistryInsert,
} from "../src/ring/key-registry-tree.js";
import { bigIntBytes } from "../src/transaction/internal.js";

const ZERO = new Uint8Array(32) as Bytes32;
const member = (value: number): Bytes32 => bigIntBytes(BigInt(value)) as Bytes32;

beforeAll(async () => {
  await initializePoseidon();
});

describe("ring key registry tree", () => {
  it("rejects negative and aliased forty-bit proof indexes", () => {
    const path = keyRegistryZeroBytes().slice(0, KEY_REGISTRY_HEIGHT);
    for (const index of [-1n, KEY_REGISTRY_CAPACITY, KEY_REGISTRY_CAPACITY + 1n]) {
      expect(() => keyRegistryRootFromProof({ leaf: ZERO, index, proof: path })).toThrow(
        "RING_KEY_REGISTRY_INVALID",
      );
    }
  });

  it("returns owned zero bytes without exposing the private empty leaf", () => {
    const first = keyRegistryZeroBytes();
    first[0]?.fill(255);
    expect(keyRegistryZeroBytes()[0]).toEqual(ZERO);
  });

  it("rejects noncanonical field values before hashing", () => {
    const invalid = new Uint8Array(32).fill(255) as Bytes32;
    expect(() =>
      keyRegistryLeaf({ member: ZERO, next: KEY_REGISTRY_FIELD_MAX, key: invalid }),
    ).toThrow("RING_KEY_REGISTRY_INVALID");
  });
  // The pinned empty root proves the TS leaf, zero-bytes and reduction match the
  // Rust reference and the Go circuit element for element.
  it("reduces the sentinel-only tree to the pinned empty root", () => {
    const zeros = keyRegistryZeroBytes();
    const sentinel = keyRegistryLeaf({ member: ZERO, next: KEY_REGISTRY_FIELD_MAX, key: ZERO });
    const root = keyRegistryRootFromProof({
      leaf: sentinel,
      index: 0n,
      proof: zeros.slice(0, KEY_REGISTRY_HEIGHT),
    });
    expect(root).toEqual(KEY_REGISTRY_EMPTY_ROOT);
  });

  it("verifies a first-member insertion", () => {
    const zeros = keyRegistryZeroBytes();
    const newMember = member(0x1234);
    const key = member(0x5e);

    const splicedLow = keyRegistryLeaf({ member: ZERO, next: newMember, key: ZERO });
    const newProof = [splicedLow, ...zeros.slice(1, KEY_REGISTRY_HEIGHT)];

    const registeredRoot = verifyKeyRegistryInsert({
      root: KEY_REGISTRY_EMPTY_ROOT,
      appendIndex: 1n,
      member: newMember,
      key,
      lowMember: ZERO,
      lowNext: KEY_REGISTRY_FIELD_MAX,
      lowKey: ZERO,
      lowIndex: 0n,
      lowProof: zeros.slice(0, KEY_REGISTRY_HEIGHT),
      newProof,
    });
    expect(registeredRoot).not.toEqual(KEY_REGISTRY_EMPTY_ROOT);
  });

  it("rejects a member outside the low element's range", () => {
    const zeros = keyRegistryZeroBytes();
    expect(() =>
      verifyKeyRegistryInsert({
        root: KEY_REGISTRY_EMPTY_ROOT,
        appendIndex: 1n,
        member: ZERO,
        key: member(0x5e),
        lowMember: ZERO,
        lowNext: KEY_REGISTRY_FIELD_MAX,
        lowKey: ZERO,
        lowIndex: 0n,
        lowProof: zeros.slice(0, KEY_REGISTRY_HEIGHT),
        newProof: zeros.slice(0, KEY_REGISTRY_HEIGHT),
      }),
    ).toThrow("RING_KEY_REGISTRY_INVALID");
  });

  it("rejects a stale root and a wrong proof length", () => {
    const zeros = keyRegistryZeroBytes();
    const lowProof = zeros.slice(0, KEY_REGISTRY_HEIGHT);
    const insert = {
      root: KEY_REGISTRY_EMPTY_ROOT,
      appendIndex: 1n,
      member: member(0x1234),
      key: member(0x5e),
      lowMember: ZERO,
      lowNext: KEY_REGISTRY_FIELD_MAX,
      lowKey: ZERO,
      lowIndex: 0n,
      lowProof,
      newProof: [
        keyRegistryLeaf({ member: ZERO, next: member(0x1234), key: ZERO }),
        ...zeros.slice(1, KEY_REGISTRY_HEIGHT),
      ],
    };
    expect(() => verifyKeyRegistryInsert({ ...insert, root: member(9) })).toThrow(
      "RING_KEY_REGISTRY_INVALID",
    );
    expect(() => verifyKeyRegistryInsert({ ...insert, lowProof: lowProof.slice(1) })).toThrow(
      "RING_KEY_REGISTRY_INVALID",
    );
  });
});
