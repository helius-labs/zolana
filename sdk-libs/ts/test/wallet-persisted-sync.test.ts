import { address, type Signature } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import type { Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import {
  Data,
  KeypairWalletAuthority,
  SOL_MINT,
  Utxo,
  Wallet,
  deserializeWallet,
  serializeWallet,
} from "../src/transaction/index.js";
import {
  loadPersistedWallet,
  syncPersistedWallet,
  walletSnapshotCipher,
  type WalletStateStore,
} from "../src/wallet/index.js";
import { syncWallet } from "../src/wallet/sync.js";
import { syncReads, plainCipher } from "./helpers/clients.js";
import { forged } from "./helpers/forged.js";

const OWNER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const SIGNATURE = "1".repeat(64) as Signature;

const TAG_CURSOR = Uint8Array.of(1, 1);
const PROOFLESS_CURSOR = Uint8Array.of(2, 2);
const NULLIFIER_CURSOR = Uint8Array.of(3, 3);

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

interface RequestWithCursor {
  readonly cursor?: Uint8Array;
}

function firstCursor(fake: ReturnType<typeof vi.fn>): Uint8Array | undefined {
  return forged<[RequestWithCursor][]>(fake.mock.calls)[0]?.[0]?.cursor;
}

/** Terminal pages carrying one distinct resume position per stream. */
function cursorPages() {
  return {
    getShieldedTransactionsByTags: vi.fn(async () => ({
      context: { blockTime: 1_700_000_000n, slot: 0n },
      transactions: [],
      scannedThrough: TAG_CURSOR,
    })),
    getEncryptedUtxosByTags: vi.fn(async () => ({
      context: { blockTime: 1_700_000_000n, slot: 0n },
      matches: [],
      scannedThrough: PROOFLESS_CURSOR,
    })),
    getShieldedTransactionsByNullifiers: vi.fn(async () => ({
      context: { blockTime: 1_700_000_000n, slot: 0n },
      transactions: [],
      scannedThrough: NULLIFIER_CURSOR,
    })),
  };
}

function memoryStore(initial?: string): WalletStateStore & {
  saved: string | undefined;
  save: ReturnType<typeof vi.fn>;
} {
  const store = {
    saved: initial,
    save: vi.fn(async (snapshot: string) => {
      store.saved = snapshot;
    }),
    load: async () => store.saved,
  };
  return store;
}

function newWallet() {
  const keypair = ShieldedKeypair.generate();
  const wallet = new Wallet({ identity: keypair.shieldedAddress() });
  const authority = new KeypairWalletAuthority({ solanaPublicKey: OWNER, keypair });
  return { keypair, wallet, authority };
}

/** One unspent note gives the nullifier stream something to scan. */
function seedNote(wallet: Wallet, keypair: ShieldedKeypair): void {
  wallet._replace({
    utxos: [
      {
        utxo: new Utxo({
          owner: keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: 42n,
          blinding: bytes(3),
          data: new Data([]),
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
    nullifiers: new Set(),
    lastSynced: 0n,
  });
}

describe("persisted wallet sync", () => {
  it("saves one snapshot after the sync commits", async () => {
    const { wallet, authority } = newWallet();
    const client = syncReads(cursorPages());
    const store = memoryStore();

    const { report, snapshot } = await syncPersistedWallet({
      wallet,
      authority,
      client,
      store,
      cipher: plainCipher,
    });

    expect(store.save).toHaveBeenCalledTimes(1);
    expect(store.saved).toBe(snapshot);
    expect(snapshot).toBe(serializeWallet(wallet));
    expect((JSON.parse(snapshot) as { version: number }).version).toBe(3);
    expect(wallet.lastSynced).toBeGreaterThan(0n);
    expect(report.storedUtxos).toBe(0);
  });

  it("resumes every cursor stream from the saved snapshot", async () => {
    const { keypair, wallet, authority } = newWallet();
    seedNote(wallet, keypair);
    const store = memoryStore();
    await syncPersistedWallet({
      wallet,
      authority,
      client: syncReads(cursorPages()),
      store,
      cipher: plainCipher,
    });

    const restored = deserializeWallet(store.saved ?? "");
    const reads = cursorPages();
    await syncWallet({ wallet: restored, authority, client: syncReads(reads) });

    expect(firstCursor(reads.getShieldedTransactionsByTags)).toEqual(TAG_CURSOR);
    expect(firstCursor(reads.getEncryptedUtxosByTags)).toEqual(PROOFLESS_CURSOR);
    expect(firstCursor(reads.getShieldedTransactionsByNullifiers)).toEqual(NULLIFIER_CURSOR);
  });

  it("saves nothing when the indexer fails", async () => {
    const { wallet, authority } = newWallet();
    const reads = cursorPages();
    reads.getShieldedTransactionsByTags.mockRejectedValue(new Error("indexer down"));
    const store = memoryStore();

    await expect(
      syncPersistedWallet({
        wallet,
        authority,
        client: syncReads(reads),
        store,
        cipher: plainCipher,
      }),
    ).rejects.toMatchObject({ code: "WALLET_SYNC" });
    expect(store.save).not.toHaveBeenCalled();
    expect(store.saved).toBeUndefined();
  });

  it("saves nothing when the sync fails after cursors advanced", async () => {
    const { keypair, wallet, authority } = newWallet();
    seedNote(wallet, keypair);
    const reads = cursorPages();
    // The nullifier scan runs after both tag streams staged their cursors.
    reads.getShieldedTransactionsByNullifiers.mockRejectedValueOnce(new Error("indexer down"));
    const store = memoryStore();

    await expect(
      syncPersistedWallet({
        wallet,
        authority,
        client: syncReads(reads),
        store,
        cipher: plainCipher,
      }),
    ).rejects.toMatchObject({ code: "WALLET_SYNC" });
    expect(store.save).not.toHaveBeenCalled();

    reads.getShieldedTransactionsByTags.mockClear();
    await syncPersistedWallet({
      wallet,
      authority,
      client: syncReads(reads),
      store,
      cipher: plainCipher,
    });
    expect(firstCursor(reads.getShieldedTransactionsByTags)).toBeUndefined();
    const saved = JSON.parse(store.saved ?? "") as {
      syncCursors: Record<string, readonly unknown[]>;
    };
    expect(saved.syncCursors["transactions"]).not.toHaveLength(0);
    expect(saved.syncCursors["nullifiers"]).not.toHaveLength(0);
  });

  it("orders overlapping persisted syncs, an older save cannot land last", async () => {
    const { wallet, authority } = newWallet();
    const pending: Array<() => void> = [];
    const store = {
      saved: undefined as string | undefined,
      save: vi.fn(
        (snapshot: string) =>
          new Promise<void>((resolve) => {
            pending.push(() => {
              store.saved = snapshot;
              resolve();
            });
          }),
      ),
    };
    const readsA = cursorPages();
    const readsB = cursorPages();
    readsB.getShieldedTransactionsByTags.mockResolvedValue({
      context: { blockTime: 1_700_000_000n, slot: 0n },
      transactions: [],
      scannedThrough: Uint8Array.of(9, 9),
    });

    const first = syncPersistedWallet({
      wallet,
      authority,
      client: syncReads(readsA),
      store,
      cipher: plainCipher,
    });
    const second = syncPersistedWallet({
      wallet,
      authority,
      client: syncReads(readsB),
      store,
      cipher: plainCipher,
    });

    await vi.waitFor(() => expect(store.save).toHaveBeenCalledTimes(1));
    // The second sync waits behind the first sync's pending save.
    expect(readsB.getShieldedTransactionsByTags).not.toHaveBeenCalled();

    pending.shift()?.();
    const a = await first;
    await vi.waitFor(() => expect(store.save).toHaveBeenCalledTimes(2));
    pending.shift()?.();
    const b = await second;

    expect(a.snapshot).not.toBe(b.snapshot);
    expect(store.saved).toBe(b.snapshot);
    expect(b.snapshot).toBe(serializeWallet(wallet));
  });

  it("reports a failed save and keeps the previous snapshot", async () => {
    const { wallet, authority } = newWallet();
    const previous = serializeWallet(wallet);
    const store = memoryStore(previous);
    store.save.mockRejectedValueOnce(new Error("disk full"));

    await expect(
      syncPersistedWallet({
        wallet,
        authority,
        client: syncReads(cursorPages()),
        store,
        cipher: plainCipher,
      }),
    ).rejects.toMatchObject({ code: "WALLET_PERSIST" });
    expect(store.saved).toBe(previous);
    expect(wallet.lastSynced).toBeGreaterThan(0n);
    expect(() => deserializeWallet(store.saved ?? "")).not.toThrow();
  });

  it("persists the advanced wallet when retried after a failed save", async () => {
    const { wallet, authority } = newWallet();
    const store = memoryStore();
    store.save.mockRejectedValueOnce(new Error("disk full"));
    const firstReads = cursorPages();
    await expect(
      syncPersistedWallet({
        wallet,
        authority,
        client: syncReads(firstReads),
        store,
        cipher: plainCipher,
      }),
    ).rejects.toMatchObject({ code: "WALLET_PERSIST" });

    const retryReads = cursorPages();
    const { snapshot } = await syncPersistedWallet({
      wallet,
      authority,
      client: syncReads(retryReads),
      store,
      cipher: plainCipher,
    });

    expect(firstCursor(retryReads.getShieldedTransactionsByTags)).toEqual(TAG_CURSOR);
    expect(store.saved).toBe(snapshot);
    const saved = JSON.parse(snapshot) as { syncCursors: { transactions: readonly unknown[] } };
    expect(saved.syncCursors.transactions).not.toHaveLength(0);
  });

  it("upgrades a version 2 snapshot on its first persisted sync", async () => {
    const { wallet, authority } = newWallet();
    const v2 = JSON.parse(serializeWallet(wallet)) as Record<string, unknown>;
    v2["version"] = 2;
    delete v2["syncCursors"];
    const restored = deserializeWallet(JSON.stringify(v2));
    const store = memoryStore();

    await syncPersistedWallet({
      wallet: restored,
      authority,
      client: syncReads(cursorPages()),
      store,
      cipher: plainCipher,
    });

    const saved = JSON.parse(store.saved ?? "") as {
      version: number;
      syncCursors: { transactions: readonly unknown[] };
    };
    expect(saved.version).toBe(3);
    expect(saved.syncCursors.transactions).not.toHaveLength(0);
  });
});

describe("sealed wallet snapshots", () => {
  async function sealedStore(): Promise<
    Readonly<{
      keypair: ShieldedKeypair;
      cipher: ReturnType<typeof walletSnapshotCipher>;
      store: ReturnType<typeof memoryStore>;
      snapshot: string;
    }>
  > {
    const { keypair, wallet, authority } = newWallet();
    const cipher = walletSnapshotCipher(keypair);
    const store = memoryStore();
    const { snapshot } = await syncPersistedWallet({
      wallet,
      authority,
      client: syncReads(cursorPages()),
      store,
      cipher,
    });
    return { keypair, cipher, store, snapshot };
  }

  it("stores ciphertext and restores through the cipher", async () => {
    const { cipher, store, snapshot } = await sealedStore();
    expect(store.saved).not.toContain("syncCursors");
    expect((JSON.parse(store.saved ?? "") as { v: number }).v).toBe(1);
    const restored = await loadPersistedWallet({ store, cipher });
    expect(restored).toBeDefined();
    expect(serializeWallet(restored!)).toBe(snapshot);
  });

  it("refuses a tampered snapshot", async () => {
    const { cipher, store } = await sealedStore();
    const envelope = JSON.parse(store.saved ?? "") as { data: string };
    const bytes = Buffer.from(envelope.data, "base64");
    const index = bytes.length - 20;
    bytes[index] = (bytes[index] ?? 0) ^ 1;
    store.saved = JSON.stringify({ ...envelope, data: bytes.toString("base64") });
    await expect(loadPersistedWallet({ store, cipher })).rejects.toMatchObject({
      code: "WALLET_SNAPSHOT",
    });
  });

  it("refuses a snapshot sealed for another wallet", async () => {
    const { store } = await sealedStore();
    const other = walletSnapshotCipher(ShieldedKeypair.generate());
    await expect(loadPersistedWallet({ store, cipher: other })).rejects.toMatchObject({
      code: "WALLET_SNAPSHOT",
    });
  });
});
