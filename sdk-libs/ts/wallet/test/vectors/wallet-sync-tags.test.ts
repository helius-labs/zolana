import { describe, expect, it, vi } from "vitest";

import type { ZolanaClient } from "../../../src/client/index.js";
import type { Bytes32 } from "../../../src/interface/index.js";
import { ShieldedKeypair, SigningKey, ViewingKey } from "../../../src/keypair/index.js";
import { AssetRegistry, Wallet, type WalletSyncMaterial } from "../../../src/transaction/index.js";
import { syncWallet, type SyncAuthority } from "../../../src/wallet/index.js";
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
  client: Pick<
    ZolanaClient,
    | "getEncryptedUtxosByTags"
    | "getShieldedTransactionsByNullifiers"
    | "getShieldedTransactionsByTags"
  >;
  shielded: { tags: string[]; limit: number | undefined }[];
  deposits: { tags: string[]; limit: number | undefined }[];
  nullifiers: ReturnType<typeof vi.fn>;
}> {
  const shielded: { tags: string[]; limit: number | undefined }[] = [];
  const deposits: { tags: string[]; limit: number | undefined }[] = [];
  const nullifiers = vi.fn(async () => ({
    context: { blockTime: 0n, slot: 1n },
    transactions: [],
  }));
  const client = {
    getShieldedTransactionsByTags: (
      request: Readonly<{ tags: readonly Bytes32[]; limit?: number }>,
    ) => {
      shielded.push({ tags: request.tags.map(hex), limit: request.limit });
      return Promise.resolve({ context: { blockTime: 0n, slot: 1n }, transactions: [] });
    },
    getEncryptedUtxosByTags: (request: Readonly<{ tags: readonly Bytes32[]; limit?: number }>) => {
      deposits.push({ tags: request.tags.map(hex), limit: request.limit });
      return Promise.resolve({ context: { blockTime: 0n, slot: 1n }, matches: [] });
    },
    getShieldedTransactionsByNullifiers: nullifiers,
  };
  return { client, shielded, deposits, nullifiers };
}

function authority(material: WalletSyncMaterial): SyncAuthority {
  return {
    withSyncSession: (run) => run({ syncMaterial: () => Promise.resolve(material) }),
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
      authority: authority({
        identity: owner.shieldedAddress(),
        viewingKeys: [owner.viewingKey()],
        nullifierKey: owner.nullifierKey(),
      }),
      client: recorded.client as ZolanaClient,
    });

    expect(fixture.defaults).toEqual({
      pageLimit: 1000,
      queryChunk: 64,
      waitForIndexer: false,
    });
    expect(recorded.shielded).toHaveLength(1);
    expect(recorded.deposits).toHaveLength(1);
    expect(recorded.shielded[0]?.limit).toBe(1000);
    expect(recorded.deposits[0]?.limit).toBe(1000);
    expect(recorded.nullifiers).not.toHaveBeenCalled();
  });

  for (const item of fixture.cases as readonly Case[]) {
    it(`queries only signing and bootstrap tags: ${item.id}`, async () => {
      const owner = keypair();
      const retained = item.viewingKeys.map(viewingKey);
      const recorded = recorder();
      const wallet = new Wallet({
        identity: owner.shieldedAddress(),
        registry: new AssetRegistry(),
      });

      await syncWallet({
        wallet,
        authority: authority({
          identity: owner.shieldedAddress(),
          viewingKeys: retained,
          nullifierKey: owner.nullifierKey(),
        }),
        client: recorded.client as ZolanaClient,
        config: { queryChunk: item.queryChunk },
      });

      expect(recorded.shielded.flatMap((request) => request.tags)).toEqual(item.tags);
      expect(recorded.deposits.flatMap((request) => request.tags)).toEqual(item.tags);
      expect(recorded.shielded.map((request) => request.tags.length)).toEqual(
        item.shieldedChunkSizes,
      );
      expect(recorded.deposits.map((request) => request.tags.length)).toEqual(
        item.depositChunkSizes,
      );
      expect(wallet.viewingKeyHistory).toHaveLength(item.viewingKeys.length);
      expect(wallet.viewingKeyHistory.map((entry) => Object.keys(entry).sort())).toEqual(
        item.viewingKeys.map(() => ["createdAt", "viewingPublicKey"]),
      );
    });
  }

  it("does not retain anonymous counter-tag runtime methods", async () => {
    const owner = keypair();
    const key = owner.viewingKey();

    await syncWallet({
      wallet: new Wallet({ identity: owner.shieldedAddress() }),
      authority: authority({
        identity: owner.shieldedAddress(),
        viewingKeys: [key],
        nullifierKey: owner.nullifierKey(),
      }),
      client: recorder().client as ZolanaClient,
    });

    expect(key).not.toHaveProperty("senderViewTag");
    expect(key).not.toHaveProperty("recipientRequestViewTag");
    expect(key).not.toHaveProperty("sendSharedViewTag");
    expect(key).not.toHaveProperty("recipientSharedViewTag");
  });

  it("rejects mismatched material before issuing discovery queries", async () => {
    const owner = keypair();
    const other = keypair("other");
    for (const material of [
      {
        identity: other.shieldedAddress(),
        viewingKeys: [owner.viewingKey()],
        nullifierKey: other.nullifierKey(),
      },
      {
        identity: owner.shieldedAddress(),
        viewingKeys: [viewingKey("rotated")],
        nullifierKey: owner.nullifierKey(),
      },
    ] satisfies readonly WalletSyncMaterial[]) {
      const recorded = recorder();
      await expect(
        syncWallet({
          wallet: new Wallet({ identity: owner.shieldedAddress() }),
          authority: authority(material),
          client: recorded.client as ZolanaClient,
        }),
      ).rejects.toMatchObject({ code: "WALLET_SYNC" });
      expect(recorded.shielded).toHaveLength(0);
      expect(recorded.deposits).toHaveLength(0);
      expect(recorded.nullifiers).not.toHaveBeenCalled();
    }
  });
});
