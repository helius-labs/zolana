import { describe, expect, it, vi } from "vitest";
import type { Bytes16, Bytes32 } from "../src/interface/types.js";
import { ShieldedKeypair, ViewingKey } from "../src/keypair/index.js";
import { TransactionError } from "../src/transaction/error.js";
import { checked } from "../src/transaction/internal.js";
import { KeyMemo } from "../src/transaction/wallet/key-memo.js";
import { LocalShieldedKeys } from "../src/transaction/wallet/keys.js";
import { withTransactionKey } from "../src/wallet/private-transaction.js";

const firstNullifier = checked<Bytes32>(new Uint8Array(32), 32, "nullifier");
const sparse: unknown[] = [];
sparse.length = 1;
const malformed = [
  { name: "null", answer: null },
  { name: "undefined", answer: undefined },
  { name: "object", answer: {} },
  { name: "array-like object", answer: { length: 1, 0: new Uint8Array(32) } },
  { name: "short array", answer: [] },
  { name: "sparse array", answer: sparse },
  { name: "wrong entry", answer: ["invalid"] },
];

describe("key holder batches", () => {
  for (const method of ["decrypt", "derive", "transactionKeys"] as const) {
    it.each(malformed)(`${method} rejects $name without caching it`, async ({ answer }) => {
      const owner = ShieldedKeypair.generate();
      const keys = LocalShieldedKeys.fromKeypair(owner);
      // A JavaScript holder can violate its declared return type at runtime.
      Object.defineProperty(keys, method, { value: async () => answer });
      const memo = new KeyMemo(keys);
      const request = { viewingPublicKey: keys.address().viewingPublicKey, firstNullifier };
      const lookup = () => {
        switch (method) {
          case "decrypt":
            return memo.decrypt({
              ...request,
              txViewingPublicKey: request.viewingPublicKey,
              ciphertext: new Uint8Array(1),
              salt: checked<Bytes16>(new Uint8Array(16), 16, "salt"),
              slotIndex: 0,
              label: "transfer",
            });
          case "derive":
            return memo.derive({
              kind: "nullifier",
              utxoHash: firstNullifier,
              blinding: firstNullifier,
            });
          case "transactionKeys":
            return memo.transactionKey(request);
        }
      };
      try {
        expect(lookup()).toBeUndefined();
        await expect(memo.resolve()).rejects.toMatchObject({
          code: "TRANSACTION_KEYS_BATCH_MISMATCH",
        });
        expect(lookup()).toBeUndefined();
      } finally {
        memo.destroy();
        keys.destroy();
        owner.destroy();
      }
    });
  }

  it.each(["invalid", "sparse"])(
    "memo destroys a live key after a %s entry in a matching-length batch",
    async (shape) => {
      const owner = ShieldedKeypair.generate();
      const keys = LocalShieldedKeys.fromKeypair(owner);
      const fresh = ViewingKey.generate();
      const returned: unknown[] = ["invalid", fresh];
      if (shape === "sparse") delete returned[0];
      const transactionKeys = vi.fn(async () => returned);
      Object.defineProperty(keys, "transactionKeys", { value: transactionKeys });
      const memo = new KeyMemo(keys);
      const viewingPublicKey = keys.address().viewingPublicKey;
      // Distinct requests survive memo deduplication, so validation reaches
      // the bad entry rather than rejecting the batch's count first.
      const requests = [
        { viewingPublicKey, firstNullifier },
        {
          viewingPublicKey,
          firstNullifier: checked<Bytes32>(new Uint8Array(32).fill(1), 32, "nullifier"),
        },
      ];
      try {
        for (const request of requests) expect(memo.transactionKey(request)).toBeUndefined();
        await expect(memo.resolve()).rejects.toMatchObject({
          code: "TRANSACTION_KEYS_BATCH_MISMATCH",
        });
        expect(transactionKeys).toHaveBeenCalledExactlyOnceWith(requests, undefined);
        expect(returned).toHaveLength(requests.length);
        expect(() => fresh.publicKey()).toThrow(
          expect.objectContaining({ code: "KEYPAIR_INVALID_SECRET_KEY" }),
        );
        for (const request of requests) expect(memo.transactionKey(request)).toBeUndefined();
      } finally {
        memo.destroy();
        fresh.destroy();
        keys.destroy();
        owner.destroy();
      }
    },
  );

  it("sealing destroys returned keys when an overlong batch is rejected", async () => {
    const owner = ShieldedKeypair.generate();
    const keys = LocalShieldedKeys.fromKeypair(owner);
    const fresh = ViewingKey.generate();
    const transactionKeys = vi.fn(async () => ["invalid", fresh]);
    Object.defineProperty(keys, "transactionKeys", { value: transactionKeys });
    const use = vi.fn();
    try {
      await expect(withTransactionKey(keys, firstNullifier, use)).rejects.toMatchObject({
        code: "TRANSACTION_KEYS_BATCH_MISMATCH",
      });
      expect(transactionKeys).toHaveBeenCalledExactlyOnceWith(
        [{ viewingPublicKey: keys.address().viewingPublicKey, firstNullifier }],
        undefined,
      );
      expect(() => fresh.publicKey()).toThrow(
        expect.objectContaining({ code: "KEYPAIR_INVALID_SECRET_KEY" }),
      );
      expect(use).not.toHaveBeenCalled();
    } finally {
      fresh.destroy();
      keys.destroy();
      owner.destroy();
    }
  });

  it("preserves a rejected derivation while destroying keys from a malformed sibling batch", async () => {
    const owner = ShieldedKeypair.generate();
    const keys = LocalShieldedKeys.fromKeypair(owner);
    const fresh = ViewingKey.generate();
    const cause = new TransactionError("TRANSACTION_KEYS_IDENTITY_MISMATCH");
    Object.defineProperty(keys, "transactionKeys", { value: async () => [undefined, fresh] });
    vi.spyOn(keys, "derive").mockRejectedValue(cause);
    const memo = new KeyMemo(keys);
    try {
      memo.transactionKey({ viewingPublicKey: keys.address().viewingPublicKey, firstNullifier });
      memo.derive({ kind: "nullifier", utxoHash: firstNullifier, blinding: firstNullifier });
      await expect(memo.resolve()).rejects.toBe(cause);
      expect(() => fresh.publicKey()).toThrow(
        expect.objectContaining({ code: "KEYPAIR_INVALID_SECRET_KEY" }),
      );
    } finally {
      memo.destroy();
      fresh.destroy();
      keys.destroy();
      owner.destroy();
    }
  });
  it.each([
    "success",
    "malformed derivation",
    "rejected decrypt",
    "malformed transaction keys",
    "synchronous key failure",
  ])("wipes derivations after %s", async (outcome) => {
    const owner = ShieldedKeypair.generate();
    const keys = LocalShieldedKeys.fromKeypair(owner);
    const fresh = checked<Bytes32>(new Uint8Array(32).fill(7), 32, "key");
    const malformedBytes = new Uint8Array(31).fill(8);
    Object.defineProperty(keys, "derive", {
      value: async () => (outcome === "malformed derivation" ? [fresh, malformedBytes] : [fresh]),
    });
    const memo = new KeyMemo(keys);
    const publicKey = keys.address().viewingPublicKey;
    const request = { kind: "mergeOutputKey" as const, firstNullifier };
    try {
      expect(memo.derive(request)).toBeUndefined();
      if (outcome === "malformed derivation") {
        memo.derive({ kind: "mergeOutputBlinding", firstNullifier });
      } else if (outcome === "rejected decrypt") {
        vi.spyOn(keys, "decrypt").mockRejectedValue(
          new TransactionError("TRANSACTION_DESERIALIZE"),
        );
        memo.decrypt({
          viewingPublicKey: publicKey,
          txViewingPublicKey: publicKey,
          ciphertext: new Uint8Array(),
          salt: checked<Bytes16>(new Uint8Array(16), 16, "salt"),
          slotIndex: 0,
          label: "transfer",
        });
      } else if (outcome === "synchronous key failure") {
        vi.spyOn(keys, "transactionKeys").mockImplementation(() => {
          throw new TransactionError("TRANSACTION_KEYS_IDENTITY_MISMATCH");
        });
        memo.transactionKey({ viewingPublicKey: publicKey, firstNullifier });
      } else if (outcome === "malformed transaction keys") {
        vi.spyOn(keys, "transactionKeys").mockResolvedValue([]);
        memo.transactionKey({ viewingPublicKey: publicKey, firstNullifier });
      }
      if (outcome === "success") {
        await memo.resolve();
        const copy = memo.derive(request);
        expect(copy).toEqual(fresh);
        expect(copy).not.toBe(fresh);
        copy?.fill(0);
        expect(fresh.some((byte) => byte !== 0)).toBe(true);
        memo.destroy();
      } else {
        await expect(memo.resolve()).rejects.toBeInstanceOf(TransactionError);
      }
      expect(fresh).toEqual(new Uint8Array(32));
      if (outcome === "malformed derivation") expect(malformedBytes).toEqual(new Uint8Array(31));
    } finally {
      memo.destroy();
      keys.destroy();
      owner.destroy();
    }
  });
});
