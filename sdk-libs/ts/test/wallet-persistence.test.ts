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

  it("round-trips sync checkpoints on every stream, the full u64 slot range included", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    wallet._setSyncCheckpoint("transactions", "aa".repeat(32), 1n);
    wallet._setSyncCheckpoint("proofless", "bb".repeat(32), 2n);
    wallet._setSyncCheckpoint("nullifiers", "cc".repeat(32), 0xffff_ffff_ffff_ffffn);

    const serialized = serializeWallet(wallet);
    const restored = deserializeWallet(serialized);

    expect(restored._syncCheckpoint("transactions", "aa".repeat(32))).toBe(1n);
    expect(restored._syncCheckpoint("proofless", "bb".repeat(32))).toBe(2n);
    expect(restored._syncCheckpoint("nullifiers", "cc".repeat(32))).toBe(0xffff_ffff_ffff_ffffn);
    expect(JSON.parse(serialized).syncCheckpoints.transactions).toEqual([
      { key: "aa".repeat(32), slot: "1" },
    ]);
    expect(serializeWallet(restored)).toBe(serialized);
  });

  it("accepts version 2 state with no checkpoints", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    wallet._setSyncCheckpoint("transactions", "aa".repeat(32), 1n);
    const snapshot = JSON.parse(serializeWallet(wallet)) as Record<string, unknown>;
    snapshot["version"] = 2;
    delete snapshot["syncCheckpoints"];

    const restored = deserializeWallet(JSON.stringify(snapshot));

    expect(restored._syncCheckpoint("transactions", "aa".repeat(32))).toBeUndefined();
  });

  it.each([3, 4, 5])("accepts version %s state and drops its byte cursors", (version) => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const snapshot = JSON.parse(serializeWallet(wallet)) as Record<string, unknown>;
    snapshot["version"] = version;
    // Versions 3 through 5 stored opaque cursor bytes.
    snapshot["syncCursors"] = {
      transactions: [{ key: "aa".repeat(32), cursor: "AQI=" }],
      proofless: [],
      nullifiers: [],
    };

    const restored = deserializeWallet(JSON.stringify(snapshot));

    expect(restored._syncCheckpoint("transactions", "aa".repeat(32))).toBeUndefined();
  });

  it("drops a persisted checkpoint for a nullifier already spent", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    wallet._replace({
      utxos: [],
      transactions: [],
      nullifiers: new Set(["dd".repeat(32)]),
    });
    const snapshot = JSON.parse(serializeWallet(wallet)) as {
      syncCheckpoints: { nullifiers: { key: string; slot: string }[] };
    };
    snapshot.syncCheckpoints.nullifiers.push({ key: "dd".repeat(32), slot: "1" });

    const restored = deserializeWallet(JSON.stringify(snapshot));

    expect(restored._syncCheckpoint("nullifiers", "dd".repeat(32))).toBeUndefined();
  });

  it("rejects unsupported or malformed persisted state", () => {
    expect(() => deserializeWallet('{"version":1}')).toThrow("TRANSACTION_DESERIALIZE");
    expect(() => deserializeWallet("not json")).toThrow("TRANSACTION_DESERIALIZE");
    const withCheckpoint = (entry: Record<string, unknown>) =>
      JSON.stringify({
        ...(JSON.parse(
          serializeWallet(new Wallet({ identity: ShieldedKeypair.generate().shieldedAddress() })),
        ) as Record<string, unknown>),
        syncCheckpoints: { transactions: [entry], proofless: [], nullifiers: [] },
      });
    for (const entry of [
      { key: "zz", slot: "1" },
      { key: "aa".repeat(32), slot: "-1" },
      { key: "aa".repeat(32), slot: "18446744073709551616" },
      { key: "aa".repeat(32), slot: 1 },
      { key: "aa".repeat(32), cursor: `1:1:${SIGNATURE}` },
    ]) {
      expect(() => deserializeWallet(withCheckpoint(entry))).toThrow("TRANSACTION_DESERIALIZE");
    }

    const wallet = new Wallet({ identity: ShieldedKeypair.generate().shieldedAddress() });
    const legacy = JSON.parse(serializeWallet(wallet)) as {
      viewingKeyHistory: Record<string, unknown>[];
    };
    legacy.viewingKeyHistory[0]!["txCount"] = "0";
    expect(() => deserializeWallet(JSON.stringify(legacy))).toThrow("TRANSACTION_DESERIALIZE");
  });

  it("rejects a P-256 viewing snapshot", () => {
    const wallet = new Wallet({ identity: ShieldedKeypair.generate().shieldedAddress() });
    const snapshot = JSON.parse(serializeWallet(wallet)) as {
      identity: { viewingPublicKey: string };
      viewingKeyHistory: { viewingPublicKey: string }[];
    };
    const oldViewingKey = Buffer.from(
      "03170ee9cf7a6f1ad811bd2019d386f67ce337458e0bf585c3cad7ddac85373e32",
      "hex",
    ).toString("base64");
    snapshot.identity.viewingPublicKey = oldViewingKey;
    snapshot.viewingKeyHistory[0]!.viewingPublicKey = oldViewingKey;

    expect(() => deserializeWallet(JSON.stringify(snapshot))).toThrow("TRANSACTION_DESERIALIZE");
  });
});
