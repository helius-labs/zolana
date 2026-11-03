import { transactionItems, outputItems } from "../../../test/helpers/pages.js";
import { describe, expect, it, vi } from "vitest";

import type { Bytes32 } from "../../../src/interface/index.js";
import {
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  type X25519PublicKey,
} from "../../../src/keypair/index.js";
import {
  AssetRegistry,
  LocalShieldedKeys,
  Wallet,
  type ShieldedKeys,
} from "../../../src/transaction/index.js";
import { ClientError } from "../../../src/client/error.js";
import { syncWallet, type SyncClient } from "../../../src/wallet/index.js";
import fixture from "../../../vectors/wallet-sync-tags-v1.json" with { type: "json" };

interface Case {
  readonly id: string;
  readonly viewingKeys: readonly string[];
  readonly queryChunk: number;
  readonly tags: readonly string[];
  readonly shieldedChunkSizes: readonly number[];
  readonly depositChunkSizes: readonly number[];
}

function bytes(hex: string): Uint8Array {
  return Uint8Array.from({ length: hex.length / 2 }, (_, index) =>
    Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16),
  );
}

function hex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function secret(name: string): Bytes32 {
  const value = (fixture.secrets as Readonly<Record<string, string | undefined>>)[name];
  if (value === undefined) throw new Error(`the fixture has no secret named ${name}`);
  return bytes(value) as Bytes32;
}

function viewingKey(name: string): ViewingKey {
  return ViewingKey.fromBytes(secret(name));
}

function keypair(identity: "self" | "other" = "self"): ShieldedKeypair {
  const signing = secret(identity === "self" ? "signing" : "otherSigning");
  return ShieldedKeypair.withViewingKey(
    SigningKey.fromEd25519Bytes(signing),
    viewingKey(identity === "self" ? "current" : "rotated"),
  );
}

function recorder(): Readonly<{
  client: SyncClient;
  shielded: { tags: string[]; limit: number | undefined }[];
  deposits: { tags: string[]; limit: number | undefined }[];
  nullifiers: ReturnType<typeof vi.fn>;
}> {
  const shielded: { tags: string[]; limit: number | undefined }[] = [];
  const deposits: { tags: string[]; limit: number | undefined }[] = [];
  const nullifiers = vi.fn(async () => ({
    context: { blockTime: 0n, slot: 1n },
    data: transactionItems([]),
    paginationToken: null,
  }));
  const client = {
    getShieldedTransactionsByTags: (
      request: Readonly<{ tags: readonly Bytes32[]; limit?: number }>,
    ) => {
      shielded.push({ tags: request.tags.map(hex), limit: request.limit });
      return Promise.resolve({
        context: { blockTime: 0n, slot: 1n },
        data: transactionItems([]),
        paginationToken: null,
      });
    },
    getEncryptedUtxosByTags: (request: Readonly<{ tags: readonly Bytes32[]; limit?: number }>) => {
      deposits.push({ tags: request.tags.map(hex), limit: request.limit });
      return Promise.resolve({
        context: { blockTime: 0n, slot: 1n },
        data: outputItems([]),
        paginationToken: null,
      });
    },
    getShieldedTransactionsByNullifiers: nullifiers,
  };
  return { client, shielded, deposits, nullifiers };
}

function keysFor(owner: ShieldedKeypair, viewingKeys: readonly ViewingKey[]): LocalShieldedKeys {
  return LocalShieldedKeys.fromKeys({
    address: owner.shieldedAddress(),
    viewingKeys,
    nullifierKey: owner.nullifierKey(),
  });
}

/** The sender view tags a first sync sweeps for each held key: indices 0 through 99. */
function senderTags(viewingKeys: readonly ViewingKey[]): readonly string[] {
  return viewingKeys.flatMap((key) =>
    Array.from({ length: 100 }, (_, index) => hex(key.senderViewTag(BigInt(index)))),
  );
}

/** Splits recorded transaction-tag requests into the stable chunks and the sender sweep's. */
function split(
  requests: readonly { tags: string[]; limit: number | undefined }[],
  viewingKeys: readonly ViewingKey[],
): Readonly<{
  stable: { tags: string[]; limit: number | undefined }[];
  sender: { tags: string[]; limit: number | undefined }[];
}> {
  const sender = new Set(senderTags(viewingKeys));
  return {
    stable: requests.filter((request) => !request.tags.every((tag) => sender.has(tag))),
    sender: requests.filter((request) => request.tags.every((tag) => sender.has(tag))),
  };
}

/** Keys that answer as `inner` but report a different address or key set. */
function misreporting(
  inner: ShieldedKeys,
  overrides: Partial<Pick<ShieldedKeys, "address" | "viewingPublicKeys">>,
): ShieldedKeys {
  return {
    address: () => inner.address(),
    viewingPublicKeys: () => inner.viewingPublicKeys(),
    decrypt: (requests) => inner.decrypt(requests),
    derive: (requests) => inner.derive(requests),
    transactionKeys: (requests) => inner.transactionKeys(requests),
    ...overrides,
  };
}

describe("wallet sync stable-tag vectors", () => {
  it("derives the fixed signing identity used by the vectors", () => {
    expect(hex(keypair().signingPublicKey().toBytes())).toBe(fixture.signingPublicKey);
  });

  it("uses the bounded stable-query defaults", async () => {
    const owner = keypair();
    const recorded = recorder();
    await syncWallet({
      wallet: new Wallet({ identity: owner.shieldedAddress() }),
      keys: keysFor(owner, [owner.viewingKey()]),
      client: recorded.client,
    });

    expect(fixture.defaults).toEqual({
      pageLimit: 1000,
      queryChunk: 64,
      waitForIndexer: false,
    });
    const { stable, sender } = split(recorded.shielded, [owner.viewingKey()]);
    expect(stable).toHaveLength(1);
    expect(sender.map((request) => request.tags.length)).toEqual([64, 36]);
    expect(recorded.deposits).toHaveLength(1);
    expect(recorded.shielded.map((request) => request.limit)).toEqual([1000, 1000, 1000]);
    expect(recorded.deposits[0]?.limit).toBe(1000);
    expect(recorded.nullifiers).not.toHaveBeenCalled();
  });

  /** Syncs a fresh wallet against an indexer whose tag pages above `fits` transactions are too large. */
  function syncTooLargeAbove(fits: number, pageLimit: number) {
    const owner = keypair();
    const recorded = recorder();
    const client: SyncClient = {
      ...recorded.client,
      getShieldedTransactionsByTags: async (request) => {
        const page = await recorded.client.getShieldedTransactionsByTags(request);
        if ((request.limit ?? 0) <= fits) return page;
        throw new ClientError("CLIENT_INDEXER_RESPONSE_TOO_LARGE", {
          details: { method: "getShieldedTransactionsByTags" },
        });
      },
    };
    const sync = syncWallet({
      wallet: new Wallet({ identity: owner.shieldedAddress() }),
      keys: keysFor(owner, [owner.viewingKey()]),
      client,
      config: { pageLimit },
    });
    return { sync, recorded };
  }

  it("halves pageLimit until a page fits and keeps it for the rest of the sync", async () => {
    const { sync, recorded } = syncTooLargeAbove(50, 200);
    await sync;
    // The halved limit carries over to the two sender view tag chunks.
    expect(recorded.shielded.map(({ limit }) => limit)).toEqual([200, 100, 50, 50, 50]);
    expect(recorded.deposits.map(({ limit }) => limit)).toEqual([50]);
  });

  it("fails the sync when a one-transaction page is still too large", async () => {
    const { sync, recorded } = syncTooLargeAbove(0, 4);
    await expect(sync).rejects.toMatchObject({
      code: "WALLET_SYNC",
      causeCode: "CLIENT_INDEXER_RESPONSE_TOO_LARGE",
    });
    expect(recorded.shielded.map(({ limit }) => limit)).toEqual([4, 2, 1]);
  });

  for (const item of fixture.cases as readonly Case[]) {
    it(`queries signing and bootstrap tags, then sender view tags: ${item.id}`, async () => {
      const owner = keypair();
      const retained = item.viewingKeys.map(viewingKey);
      const recorded = recorder();
      const wallet = new Wallet({
        identity: owner.shieldedAddress(),
        registry: new AssetRegistry(),
      });

      await syncWallet({
        wallet,
        keys: keysFor(owner, retained),
        client: recorded.client,
        config: { queryChunk: item.queryChunk },
      });

      const { stable, sender } = split(recorded.shielded, retained);
      expect(stable.flatMap((request) => request.tags)).toEqual(item.tags);
      expect(recorded.deposits.flatMap((request) => request.tags)).toEqual(item.tags);
      expect(stable.map((request) => request.tags.length)).toEqual(item.shieldedChunkSizes);
      // Sender view tags read the transaction stream only, every held key's.
      expect(sender.flatMap((request) => request.tags)).toEqual(senderTags(retained));
      expect(recorded.deposits.map((request) => request.tags.length)).toEqual(
        item.depositChunkSizes,
      );
      expect(wallet.viewingKeyHistory).toHaveLength(item.viewingKeys.length);
      expect(wallet.viewingKeyHistory.map((entry) => Object.keys(entry).sort())).toEqual(
        item.viewingKeys.map(() => ["createdAt", "viewingPublicKey"]),
      );
    });
  }

  it("rejects mismatched keys before issuing discovery queries", async () => {
    const owner = keypair();
    const other = keypair("other");
    const ownerKeys = keysFor(owner, [owner.viewingKey()]);
    const rotatedOnly: readonly X25519PublicKey[] = [viewingKey("rotated").publicKey()];
    for (const [keys, causeCode] of [
      // Another wallet's keys.
      [keysFor(other, [other.viewingKey()]), "TRANSACTION_KEYS_IDENTITY_MISMATCH"],
      // The right address, but the identity's viewing key is not among those held.
      [
        misreporting(ownerKeys, { viewingPublicKeys: () => rotatedOnly }),
        "TRANSACTION_MISSING_CURRENT_VIEWING_KEY",
      ],
    ] as const) {
      const recorded = recorder();
      await expect(
        syncWallet({
          wallet: new Wallet({ identity: owner.shieldedAddress() }),
          keys,
          client: recorded.client,
        }),
      ).rejects.toMatchObject({ code: "WALLET_SYNC", causeCode });
      expect(recorded.shielded).toHaveLength(0);
      expect(recorded.deposits).toHaveLength(0);
      expect(recorded.nullifiers).not.toHaveBeenCalled();
    }
  });
});
