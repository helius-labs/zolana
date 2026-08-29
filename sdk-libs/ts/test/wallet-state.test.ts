import { address, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import { Data, Utxo, Wallet } from "../src/transaction/index.js";
import { AssetRegistry } from "../src/transaction/wallet/asset.js";
import type { SyncDelta } from "../src/transaction/wallet/state.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const MINT = address("So11111111111111111111111111111111111111112");

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function walletWith(keypair: ShieldedKeypair, amounts: readonly bigint[]): Wallet {
  const wallet = new Wallet({ identity: keypair.shieldedAddress(), registry: new AssetRegistry() });
  wallet._replace({
    utxos: amounts.map((amount, index) => noteEntry(keypair, amount, index)),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

function noteEntry(keypair: ShieldedKeypair, amount: bigint, index: number) {
  return {
    utxo: new Utxo({
      owner: keypair.signingPublicKey(),
      asset: address("11111111111111111111111111111111"),
      amount,
      blinding: filled(index + 1),
      data: new Data(),
    }),
    outputContext: { hash: filled(index + 1), tree: TREE, leafIndex: BigInt(index) },
    nullifier: filled(index + 20),
    spent: false,
  };
}

function deltaFrom(
  wallet: Wallet,
  overrides: Partial<SyncDelta> = {},
  additions: readonly Readonly<{ assetId: bigint; mint: Address }>[] = [],
): SyncDelta {
  return {
    ...wallet._state(),
    lastSynced: 7n,
    cursors: {
      transactions: new Map(),
      proofless: new Map(),
      nullifiers: new Map(),
    },
    registryAdditions: additions,
    ...overrides,
  };
}

describe("wallet commit machinery", () => {
  it("commits rows, cursors, and registry additions in one step", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = walletWith(keypair, []);
    const revision = wallet._revision;
    const staged = walletWith(keypair, [10n, 20n]);

    wallet._commitSync(
      deltaFrom(
        staged,
        {
          cursors: {
            transactions: new Map([["aa", filled(9)]]),
            proofless: new Map(),
            nullifiers: new Map(),
          },
        },
        [{ assetId: 2n, mint: MINT }],
      ),
      revision,
    );

    expect(wallet.utxos()).toHaveLength(2);
    expect(wallet.lastSynced).toBe(7n);
    expect(wallet._syncCursor("transactions", "aa")).toEqual(filled(9));
    expect(wallet.registry.assetId(MINT)).toBe(2n);
    expect(wallet._revision).toBe(revision + 1);
  });

  it("refuses a stale revision and leaves state and cursors untouched", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = walletWith(keypair, [10n]);
    const staged = walletWith(keypair, [10n, 20n]);

    expect(() =>
      wallet._commitSync(
        deltaFrom(staged, {
          cursors: {
            transactions: new Map([["aa", filled(9)]]),
            proofless: new Map(),
            nullifiers: new Map(),
          },
        }),
        wallet._revision - 1,
      ),
    ).toThrow("TRANSACTION_WALLET_STATE_STALE");
    expect(wallet.utxos()).toHaveLength(1);
    expect(wallet._syncCursor("transactions", "aa")).toBeUndefined();
  });

  it("refuses a duplicate output before touching registry or cursors", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = walletWith(keypair, []);
    const entry = noteEntry(keypair, 10n, 0);

    expect(() =>
      wallet._commitSync(
        deltaFrom(
          wallet,
          {
            utxos: [entry, entry],
            cursors: {
              transactions: new Map([["aa", filled(9)]]),
              proofless: new Map(),
              nullifiers: new Map(),
            },
          },
          [{ assetId: 2n, mint: MINT }],
        ),
        wallet._revision,
      ),
    ).toThrow("TRANSACTION_DUPLICATE_OUTPUT");
    expect(() => wallet.registry.assetId(MINT)).toThrow("TRANSACTION_UNKNOWN_MINT");
    expect(wallet._syncCursor("transactions", "aa")).toBeUndefined();
  });

  it("refuses a conflicting registry addition without applying earlier ones", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = walletWith(keypair, []);
    const other = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");

    expect(() =>
      wallet._commitSync(
        deltaFrom(wallet, {}, [
          { assetId: 2n, mint: MINT },
          { assetId: 2n, mint: other },
        ]),
        wallet._revision,
      ),
    ).toThrow("TRANSACTION_DUPLICATE_ASSET_ID");
    expect(() => wallet.registry.assetId(MINT)).toThrow("TRANSACTION_UNKNOWN_MINT");
  });

  it("trips the stale guard on a registry write between snapshot and commit", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = walletWith(keypair, []);
    const revision = wallet._revision;
    wallet.ensureAsset(2n, MINT);

    expect(() => wallet._commitSync(deltaFrom(wallet), revision)).toThrow(
      "TRANSACTION_WALLET_STATE_STALE",
    );
  });

  it("clones independently, cursors included", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = walletWith(keypair, [10n]);
    wallet._setSyncCursor("transactions", "aa", filled(3));

    const clone = wallet._clone();
    clone._setSyncCursor("transactions", "aa", filled(4));
    clone._replace({ utxos: [], transactions: [], nullifiers: new Set() });

    expect(wallet.utxos()).toHaveLength(1);
    expect(wallet._syncCursor("transactions", "aa")).toEqual(filled(3));
    expect(clone.utxos()).toHaveLength(0);
    expect(clone._syncCursor("transactions", "aa")).toEqual(filled(4));
  });

  it("serializes locked spans and survives a failing one", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = walletWith(keypair, []);
    const order: string[] = [];
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });

    const first = wallet._withSyncLock(async () => {
      order.push("first-start");
      await gate;
      order.push("first-end");
      throw new Error("first fails");
    });
    const second = wallet._withSyncLock(async () => {
      order.push("second");
    });

    release?.();
    await expect(first).rejects.toThrow("first fails");
    await second;
    expect(order).toEqual(["first-start", "first-end", "second"]);
  });
});
