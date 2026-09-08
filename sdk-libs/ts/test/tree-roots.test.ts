import { describe, expect, it } from "vitest";

import {
  NULLIFIER_ROOT_HISTORY_OFFSET,
  NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
  StateDiscriminator,
  UTXO_ROOT_HISTORY_CAPACITY,
  UTXO_ROOT_HISTORY_CURSOR_OFFSET,
  UTXO_ROOT_HISTORY_OFFSET,
  decodeTreeHeadRoots,
} from "../src/interface/index.js";

import { filled, treeAccount } from "./helpers/tree-account.js";

describe("tree head roots", () => {
  it("reads the utxo cursor slot and the nullifier slot before the write cursor", () => {
    expect(UTXO_ROOT_HISTORY_CAPACITY).toBe(200);
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

  it("refuses a cursor past the written window and an empty history", () => {
    expect(() =>
      decodeTreeHeadRoots(treeAccount({ stateCursor: 3, written: 3, nullifierCursor: 1n })),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }));
    expect(() =>
      decodeTreeHeadRoots(treeAccount({ stateCursor: 0, written: 0, nullifierCursor: 1n })),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }));
    const wrapped = treeAccount({
      stateCursor: 0,
      written: UTXO_ROOT_HISTORY_CAPACITY,
      nullifierCursor: 1n,
    });
    wrapped.set(Uint8Array.of(250 & 0xff, 250 >> 8), UTXO_ROOT_HISTORY_CURSOR_OFFSET);
    expect(() => decodeTreeHeadRoots(wrapped)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
  });

  it("reads any slot once the history wrapped", () => {
    const account = treeAccount({
      stateCursor: 7,
      written: UTXO_ROOT_HISTORY_CAPACITY,
      nullifierCursor: 1n,
    });
    expect(decodeTreeHeadRoots(account).stateRootIndex).toBe(7);
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
});
