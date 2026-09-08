import { describe, expect, it } from "vitest";

import {
  NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET,
  NULLIFIER_ROOT_HISTORY_OFFSET,
  NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
  STATE_ROOT_HISTORY_CAPACITY,
  TREE_ACCOUNT_SIZE,
  StateDiscriminator,
  UTXO_ROOT_HISTORY_CAPACITY,
  UTXO_ROOT_HISTORY_CAPACITY_OFFSET,
  UTXO_ROOT_HISTORY_CURSOR_OFFSET,
  UTXO_ROOT_HISTORY_LEN_OFFSET,
  UTXO_ROOT_HISTORY_OFFSET,
  UTXO_SUBTREES_LEN_OFFSET,
  decodeTreeHeadRoots,
} from "../src/interface/index.js";

import { filled, treeAccount } from "./helpers/tree-account.js";

describe("tree head roots", () => {
  it("pins the Rust root history offsets", () => {
    expect(TREE_ACCOUNT_SIZE).toBe(39_952);
    expect(STATE_ROOT_HISTORY_CAPACITY).toBe(500);
    expect(UTXO_ROOT_HISTORY_CAPACITY).toBe(STATE_ROOT_HISTORY_CAPACITY);
    expect(UTXO_ROOT_HISTORY_CURSOR_OFFSET).toBe(112);
    expect(UTXO_ROOT_HISTORY_LEN_OFFSET).toBe(114);
    expect(UTXO_ROOT_HISTORY_CAPACITY_OFFSET).toBe(116);
    expect(UTXO_SUBTREES_LEN_OFFSET).toBe(118);
    expect(UTXO_ROOT_HISTORY_OFFSET).toBe(1_152);
    expect(NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET).toBe(17_224);
    expect(NULLIFIER_ROOT_HISTORY_OFFSET).toBe(17_232);
  });

  it("reads the Rust account layout", () => {
    const account = new Uint8Array(39_952);
    const header = new DataView(account.buffer);
    account[0] = StateDiscriminator.treeAccount;
    header.setUint16(112, 2, true);
    header.setUint16(114, 3, true);
    header.setUint16(116, 500, true);
    account[118] = 32;
    header.setBigUint64(120, 123_456_789n, true);
    account.set(filled(0x12), 80);
    account.set(filled(0x12), 1_152 + 2 * 32);
    header.setBigUint64(17_224, 5n, true);
    account.set(filled(0x24), 17_232 + 4 * 32);

    expect(decodeTreeHeadRoots(account)).toEqual({
      stateRoot: filled(0x12),
      stateRootIndex: 2,
      nullifierRoot: filled(0x24),
      nullifierRootIndex: 4,
    });
  });

  it("reads the utxo cursor slot and the nullifier slot before the write cursor", () => {
    expect(UTXO_ROOT_HISTORY_CAPACITY).toBe(500);
    expect(NULLIFIER_TREE_ROOT_HISTORY_CAPACITY).toBe(100);
    const account = treeAccount({ stateCursor: 2, written: 3, nullifierCursor: 5n });
    expect(decodeTreeHeadRoots(account)).toEqual({
      stateRoot: filled(0x12),
      stateRootIndex: 2,
      nullifierRoot: filled(0x24),
      nullifierRootIndex: 4,
    });
  });

  it("wraps the nullifier index below zero to the last slot and refuses a cursor at capacity", () => {
    const account = treeAccount({ stateCursor: 0, written: 1, nullifierCursor: 0n });
    expect(decodeTreeHeadRoots(account)).toMatchObject({
      nullifierRoot: filled(0x20 + (99 % 16)),
      nullifierRootIndex: 99,
    });
    expect(() =>
      decodeTreeHeadRoots(treeAccount({ stateCursor: 0, written: 1, nullifierCursor: 100n })),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }));
  });

  it("refuses a cursor outside the head position and an empty history", () => {
    expect(() =>
      decodeTreeHeadRoots(treeAccount({ stateCursor: 3, written: 3, nullifierCursor: 1n })),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }));
    expect(() =>
      decodeTreeHeadRoots(treeAccount({ stateCursor: 1, written: 3, nullifierCursor: 1n })),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }));
    expect(() =>
      decodeTreeHeadRoots(treeAccount({ stateCursor: 0, written: 0, nullifierCursor: 1n })),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }));
    const wrapped = treeAccount({
      stateCursor: 0,
      written: UTXO_ROOT_HISTORY_CAPACITY,
      nullifierCursor: 1n,
    });
    new DataView(wrapped.buffer).setUint16(
      UTXO_ROOT_HISTORY_CURSOR_OFFSET,
      UTXO_ROOT_HISTORY_CAPACITY,
      true,
    );
    expect(() => decodeTreeHeadRoots(wrapped)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
  });

  it.each([
    [0, 500],
    [7, 500],
    [240, 241],
    [299, 300],
    [499, 500],
  ])("reads state cursor %i with history length %i", (stateCursor, written) => {
    const account = treeAccount({ stateCursor, written, nullifierCursor: 1n });
    expect(decodeTreeHeadRoots(account)).toMatchObject({
      stateRoot: filled(0x10 + (stateCursor % 16)),
      stateRootIndex: stateCursor,
    });
  });

  it.each([501, 65_535])("refuses history length %i above capacity", (written) => {
    const account = treeAccount({ stateCursor: 2, written: 3, nullifierCursor: 1n });
    new DataView(account.buffer).setUint16(UTXO_ROOT_HISTORY_LEN_OFFSET, written, true);
    expect(() => decodeTreeHeadRoots(account)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
  });

  it.each([0, 200, 499, 501])("refuses stored history capacity %i", (capacity) => {
    const account = treeAccount({ stateCursor: 2, written: 3, nullifierCursor: 1n });
    new DataView(account.buffer).setUint16(UTXO_ROOT_HISTORY_CAPACITY_OFFSET, capacity, true);
    expect(() => decodeTreeHeadRoots(account)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
  });

  it.each([0, 31, 33])("refuses subtree count %i", (height) => {
    const account = treeAccount({ stateCursor: 2, written: 3, nullifierCursor: 1n });
    account[UTXO_SUBTREES_LEN_OFFSET] = height;
    expect(() => decodeTreeHeadRoots(account)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
  });

  it("refuses a zero root in either history", () => {
    const account = treeAccount({ stateCursor: 1, written: 2, nullifierCursor: 1n });
    account.fill(0, NULLIFIER_ROOT_HISTORY_OFFSET, NULLIFIER_ROOT_HISTORY_OFFSET + 32);
    expect(() => decodeTreeHeadRoots(account)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
    const zeroState = treeAccount({ stateCursor: 1, written: 2, nullifierCursor: 1n });
    zeroState.fill(0, UTXO_ROOT_HISTORY_OFFSET + 32, UTXO_ROOT_HISTORY_OFFSET + 64);
    expect(() => decodeTreeHeadRoots(zeroState)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
  });

  it("refuses a foreign discriminator and a truncated account", () => {
    const account = treeAccount({ stateCursor: 0, written: 1, nullifierCursor: 1n });
    account[0] = StateDiscriminator.protocolConfig;
    expect(() => decodeTreeHeadRoots(account)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_DISCRIMINATOR" }),
    );
    expect(() => decodeTreeHeadRoots(account.subarray(0, 8_000))).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
  });

  it("refuses the previous account size", () => {
    const account = new Uint8Array(30_344);
    account[0] = StateDiscriminator.treeAccount;
    expect(() => decodeTreeHeadRoots(account)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
  });
});
