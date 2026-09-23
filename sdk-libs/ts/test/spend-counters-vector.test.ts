import { describe, expect, it } from "vitest";
import vector from "../../../test-vectors/spend-counters.json" with { type: "json" };
import { initializePoseidon } from "../src/hasher/index.js";
import { checkedBytes, bigIntToBytes } from "../src/keypair/bytes.js";
import type { Bytes16, Bytes32 } from "../src/interface/types.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { encodeSpendCounters, spendCountersCommitment } from "../src/ring/policy.js";
import { spendCountersDisclosureHash, openSpendCountersWithKey } from "../src/ring/counters.js";

await initializePoseidon();
describe("counter disclosure wire", () => {
  it("matches the circuit and Rust counter encryption", () => {
    const secret = checkedBytes<Bytes32>(Buffer.from(vector.secret, "hex"), 32, "field");
    const salt = checkedBytes<Bytes16>(Buffer.from(vector.transactionSalt, "hex"), 16, "salt");
    const counters = {
      salt: checkedBytes<Bytes32>(bigIntToBytes(BigInt(`0x${vector.counterSalt}`)), 32, "field"),
      assets: Array.from({ length: 8 }, (_, index) =>
        checkedBytes<Bytes32>(bigIntToBytes(BigInt(vector.assets[index] ?? "0")), 32, "field"),
      ),
      spent: Array.from({ length: 8 }, (_, index) => BigInt(vector.spent[index] ?? "0")),
    };
    const tx = ViewingKey.fromBytes(secret);
    try {
      const body = new Uint8Array([
        ...tx.publicKey().toBytes(),
        ...tx.encryptSlot(tx.publicKey(), encodeSpendCounters(counters), salt, 0xffff_ffff),
      ]);
      expect(Buffer.from(body).toString("hex")).toBe(vector.body);
      const foreign = ViewingKey.generate();
      try {
        const foreignBody = new Uint8Array([
          ...foreign.publicKey().toBytes(),
          ...tx.encryptSlot(foreign.publicKey(), encodeSpendCounters(counters), salt, 0xffff_ffff),
        ]);
        expect(() =>
          openSpendCountersWithKey(tx, {
            salt,
            data: foreignBody,
            commitment: spendCountersCommitment(counters),
          }),
        ).toThrow("RING_SPEND_COUNTERS_UNKNOWN");
        expect(
          openSpendCountersWithKey(tx, {
            salt,
            data: body,
            commitment: spendCountersCommitment(counters),
          }),
        ).toEqual(counters);
      } finally {
        foreign.destroy();
      }
      expect(Buffer.from(spendCountersDisclosureHash(salt, body)).toString("hex")).toBe(
        vector.hash.padStart(64, "0"),
      );
    } finally {
      tx.destroy();
    }
  });
});
