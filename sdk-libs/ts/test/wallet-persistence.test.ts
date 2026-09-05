import { address, type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  Data,
  SOL_MINT,
  ShieldedKeypair,
  Utxo,
  Wallet,
  deserializeWallet,
  serializeWallet,
  type Bytes32,
} from "../src/index.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const SIGNATURE = "1".repeat(64) as Signature;

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

describe("wallet persistence", () => {
  it("round-trips resumable wallet state without secret keys", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    wallet._replace({
      utxos: [
        {
          utxo: new Utxo({
            owner: keypair.signingPublicKey(),
            asset: SOL_MINT,
            amount: 42n,
            blinding: new Uint8Array(32).fill(3) as Bytes32,
            data: new Data([{ kind: "memo", bytes: Uint8Array.of(4, 5) }]),
          }),
          outputContext: { hash: bytes(6), tree: TREE, leafIndex: 7n },
          nullifier: bytes(8),
          spent: false,
        },
      ],
      transactions: [
        {
          id: { signature: SIGNATURE, slot: 9n, index: 7n },
          kind: "deposit",
          direction: "inbound",
          status: "confirmed",
          asset: SOL_MINT,
          amount: 42n,
        },
      ],
      nullifiers: new Set(["09".repeat(32)]),
      lastSynced: 123n,
    });

    const serialized = serializeWallet(wallet);
    const restored = deserializeWallet(serialized);

    expect(restored.balance(SOL_MINT).amount).toBe(42n);
    expect(restored.lastSynced).toBe(123n);
    expect(restored.privateTransactions()).toEqual(wallet.privateTransactions());
    expect(restored._state().nullifiers).toEqual(wallet._state().nullifiers);
    expect(serializeWallet(restored)).toBe(serialized);
    expect(serialized).not.toContain("secret");
    expect(serialized).not.toMatch(/txCount|requestCount|knownSenders|knownRecipients/u);
  });

  it("round-trips sync cursors on every stream", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    wallet._setSyncCursor("transactions", "aa".repeat(32), { slot: 1n, signature: SIGNATURE });
    wallet._setSyncCursor("proofless", "bb".repeat(32), { slot: 2n, signature: SIGNATURE });
    wallet._setSyncCursor("nullifiers", "cc".repeat(32), { slot: 3n, signature: SIGNATURE });

    const serialized = serializeWallet(wallet);
    const restored = deserializeWallet(serialized);

    expect(restored._syncCursor("transactions", "aa".repeat(32))).toEqual({
      slot: 1n,
      signature: SIGNATURE,
    });
    expect(restored._syncCursor("proofless", "bb".repeat(32))).toEqual({
      slot: 2n,
      signature: SIGNATURE,
    });
    expect(restored._syncCursor("nullifiers", "cc".repeat(32))).toEqual({
      slot: 3n,
      signature: SIGNATURE,
    });
    expect(serializeWallet(restored)).toBe(serialized);
  });

  it("accepts version 2 state with empty cursors", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    wallet._setSyncCursor("transactions", "aa".repeat(32), { slot: 1n, signature: SIGNATURE });
    const snapshot = JSON.parse(serializeWallet(wallet)) as Record<string, unknown>;
    snapshot["version"] = 2;
    delete snapshot["syncCursors"];

    const restored = deserializeWallet(JSON.stringify(snapshot));

    expect(restored._syncCursor("transactions", "aa".repeat(32))).toBeUndefined();
  });

  it("accepts version 3 state and drops its byte cursors", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const snapshot = JSON.parse(serializeWallet(wallet)) as Record<string, unknown>;
    snapshot["version"] = 3;
    // Version 3 stored opaque cursor bytes, positions in a retired encoding.
    snapshot["syncCursors"] = {
      transactions: [{ key: "aa".repeat(32), cursor: "AQI=" }],
      proofless: [],
      nullifiers: [],
    };

    const restored = deserializeWallet(JSON.stringify(snapshot));

    expect(restored._syncCursor("transactions", "aa".repeat(32))).toBeUndefined();
  });

  it("drops a persisted cursor for a nullifier already spent", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    wallet._replace({
      utxos: [],
      transactions: [],
      nullifiers: new Set(["dd".repeat(32)]),
    });
    const snapshot = JSON.parse(serializeWallet(wallet)) as {
      syncCursors: { nullifiers: { key: string; slot: string; signature: string }[] };
    };
    snapshot.syncCursors.nullifiers.push({
      key: "dd".repeat(32),
      slot: "1",
      signature: SIGNATURE,
    });

    const restored = deserializeWallet(JSON.stringify(snapshot));

    expect(restored._syncCursor("nullifiers", "dd".repeat(32))).toBeUndefined();
  });

  it("rejects unsupported or malformed persisted state", () => {
    expect(() => deserializeWallet('{"version":1}')).toThrow("TRANSACTION_DESERIALIZE");
    expect(() => deserializeWallet("not json")).toThrow("TRANSACTION_DESERIALIZE");
    const withBadCursor = (key: string) =>
      JSON.stringify({
        ...(JSON.parse(
          serializeWallet(new Wallet({ identity: ShieldedKeypair.generate().shieldedAddress() })),
        ) as Record<string, unknown>),
        syncCursors: { transactions: [{ key, cursor: "AQI=" }], proofless: [], nullifiers: [] },
      });
    expect(() => deserializeWallet(withBadCursor("zz"))).toThrow("TRANSACTION_DESERIALIZE");

    const wallet = new Wallet({ identity: ShieldedKeypair.generate().shieldedAddress() });
    const legacy = JSON.parse(serializeWallet(wallet)) as {
      viewingKeyHistory: Record<string, unknown>[];
    };
    legacy.viewingKeyHistory[0]!["txCount"] = "0";
    expect(() => deserializeWallet(JSON.stringify(legacy))).toThrow("TRANSACTION_DESERIALIZE");
  });
});
