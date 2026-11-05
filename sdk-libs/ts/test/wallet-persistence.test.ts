import { type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { treeAddress } from "../src/interface/pda/index.js";
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

const TREE = treeAddress(0);
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
          outputContext: { hash: bytes(6), tree: TREE, treeId: 0, leafIndex: 7n },
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

  it.each([1, 2, 3, 4, 5, 7])("refuses a version %s snapshot", (version) => {
    const wallet = new Wallet({ identity: ShieldedKeypair.generate().shieldedAddress() });
    const snapshot = JSON.parse(serializeWallet(wallet)) as Record<string, unknown>;
    expect(snapshot["version"]).toBe(6);
    snapshot["version"] = version;

    expect(() => deserializeWallet(JSON.stringify(snapshot))).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_DESERIALIZE",
        details: { field: "version" },
      }),
    );
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

  it("restores each UTXO's tree id and refuses one its tree account disagrees with", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    wallet._replace({
      utxos: [
        {
          utxo: new Utxo({
            owner: keypair.signingPublicKey(),
            asset: SOL_MINT,
            amount: 42n,
            blinding: bytes(3),
          }),
          outputContext: { hash: bytes(6), tree: treeAddress(1), treeId: 1, leafIndex: 7n },
          nullifier: bytes(8),
          spent: false,
        },
      ],
      transactions: [],
      nullifiers: new Set(),
    });
    const serialized = serializeWallet(wallet);
    expect(deserializeWallet(serialized).utxos()[0]?.outputContext).toEqual(
      wallet.utxos()[0]?.outputContext,
    );

    type Snapshot = {
      utxos: { outputContext: { tree: string; treeId?: number | undefined } }[];
    };
    const edited = (edit: (snapshot: Snapshot) => void): string => {
      const snapshot = JSON.parse(serialized) as Snapshot;
      edit(snapshot);
      return JSON.stringify(snapshot);
    };
    for (const treeId of [undefined, 2, -1, 65_536, 1.5]) {
      expect(() =>
        deserializeWallet(
          edited((snapshot) => {
            snapshot.utxos[0]!.outputContext.treeId = treeId;
          }),
        ),
      ).toThrow("TRANSACTION_DESERIALIZE");
    }
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
