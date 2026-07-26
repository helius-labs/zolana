import type { Bytes32 } from "../../../src/interface/index.js";
import type { ZolanaClient } from "../../../src/client/index.js";
import {
  NullifierKey,
  P256PublicKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
} from "../../../src/keypair/index.js";
import type { WalletSyncMaterial } from "../../../src/transaction/index.js";
import { AssetRegistry, Wallet } from "../../../src/transaction/index.js";
import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/wallet-sync-tags-v1.json" with { type: "json" };
import type { WalletAuthority } from "../../../src/wallet/index.js";
import { syncWallet } from "../../../src/wallet/index.js";

interface HistoryCase {
  readonly key: string;
  readonly txCount: string;
  readonly requestCount: string;
  readonly knownSenders: Readonly<Record<string, string>>;
  readonly knownRecipients: Readonly<Record<string, string>>;
}

interface Case {
  readonly id: string;
  readonly history: readonly HistoryCase[];
  readonly viewingKeys: readonly string[];
  readonly identity: string;
  readonly tagWindow: string;
  readonly tagQueryChunk: number;
  readonly outcome: Readonly<{ arm: string; error?: string }>;
  readonly tags: readonly string[];
  readonly shieldedChunkSizes: readonly number[];
  readonly depositChunkSizes: readonly number[];
}

// Rust wraps a sync failure as `ClientError::Transaction(TransactionError::X)`,
// and the port wraps it as `WALLET_SYNC` carrying the same inner code. These are
// the inner codes; an unmapped variant fails rather than passing quietly.
const REJECTIONS: Readonly<Record<string, string>> = {
  "Transaction(InvalidTagWindow)": "TRANSACTION_INVALID_TAG_WINDOW",
  "Transaction(WalletAuthorityMismatch)": "TRANSACTION_WALLET_AUTHORITY_MISMATCH",
  "Transaction(MissingCurrentViewingKey)": "TRANSACTION_MISSING_CURRENT_VIEWING_KEY",
};

function bytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function hex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function secret(name: string): Uint8Array {
  const secrets: Readonly<Record<string, string | undefined>> = fixture.secrets;
  const value = secrets[name];
  if (value === undefined) throw new Error(`the fixture has no secret named ${name}`);
  return bytes(value);
}

function viewingKey(name: string): ViewingKey {
  return ViewingKey.fromBytes(secret(name) as Bytes32);
}

function counterpartyHex(name: string): string {
  const value = (fixture.counterparties as Readonly<Record<string, string | undefined>>)[name];
  if (value === undefined) throw new Error(`the fixture has no counterparty named ${name}`);
  return value;
}

function counterparty(name: string): P256PublicKey {
  return P256PublicKey.fromBytes(bytes(counterpartyHex(name)) as never);
}

/// Rebuilds the Rust `ShieldedKeypair::from_ed25519(secret, viewing_key)`, whose
/// TypeScript twin takes an account index instead of a key and so cannot pair a
/// chosen viewing key with a chosen signing secret.
function keypair(identity: string): ShieldedKeypair {
  const signing = secret(identity === "self" ? "signing" : "otherSigning") as Bytes32;
  return ShieldedKeypair.fromKeys(
    SigningKey.fromEd25519Bytes(signing),
    NullifierKey.fromSigningSecret(signing),
    viewingKey(identity === "self" ? "current" : "rotated"),
  );
}

function counters(entry: HistoryCase): Readonly<Record<string, unknown>> {
  return {
    viewingPublicKey: viewingKey(entry.key).publicKey(),
    createdAt: 0n,
    txCount: BigInt(entry.txCount),
    requestCount: BigInt(entry.requestCount),
    knownSenders: Object.entries(entry.knownSenders).map(([name, count]) => ({
      counterparty: counterparty(name),
      count: BigInt(count),
    })),
    knownRecipients: Object.entries(entry.knownRecipients).map(([name, count]) => ({
      counterparty: counterparty(name),
      count: BigInt(count),
    })),
  };
}

/// Answers every tag query with an empty page and records what it was asked, so
/// a case can compare the tag set and the chunking against the Rust run.
function recorder(): Readonly<{
  client: Pick<ZolanaClient, "getEncryptedUtxosByTags" | "getShieldedTransactionsByTags">;
  tags: Set<string>;
  shielded: number[];
  deposits: number[];
}> {
  const tags = new Set<string>();
  const shielded: number[] = [];
  const deposits: number[] = [];
  const client = {
    getShieldedTransactionsByTags: (request: Readonly<{ tags: readonly Bytes32[] }>) => {
      shielded.push(request.tags.length);
      for (const tag of request.tags) tags.add(hex(tag));
      return Promise.resolve({ context: { blockTime: 0n }, transactions: [] });
    },
    getEncryptedUtxosByTags: (request: Readonly<{ tags: readonly Bytes32[] }>) => {
      deposits.push(request.tags.length);
      return Promise.resolve({ context: { blockTime: 0n }, matches: [] });
    },
  };
  return { client, tags, shielded, deposits };
}

describe("wallet sync tag vectors", () => {
  it("derives the identity the Rust run used", () => {
    expect(hex(keypair("self").signingPublicKey().toBytes())).toBe(fixture.signingPublicKey);
    for (const name of ["alice", "bob"]) {
      expect(hex(counterparty(name).toBytes())).toBe(counterpartyHex(name));
    }
  });

  it("defaults the sync config to the Rust values", () => {
    // The blocking Rust entry point waits for the indexer and the async one does
    // not; the port has a single async entry, so it matches the async default.
    expect(fixture.defaults.waitForIndexerDefault).toBe(false);
    expect(fixture.defaults.tagWindow).toBe("64");
    expect(fixture.defaults.tagQueryChunk).toBe(64);
    expect(fixture.defaults.pageLimit).toBe(1000);
    expect(fixture.defaults.rounds).toBe(6);
  });

  it("orders deposit trees the way Rust orders an address", () => {
    const trees = fixture.depositTreeOrder;
    const byBytes = [...trees].sort((left, right) => {
      const leftBytes = bytes(left.bytes);
      const rightBytes = bytes(right.bytes);
      for (let index = 0; index < leftBytes.length; index++) {
        const difference = (leftBytes[index] ?? 0) - (rightBytes[index] ?? 0);
        if (difference !== 0) return difference;
      }
      return 0;
    });
    expect(byBytes.map((tree) => tree.address)).toEqual(trees.map((tree) => tree.address));

    // The premise of comparing decoded bytes: on this triple the encoded strings
    // sort differently, so a comparator reading the base58 form would hand the
    // decrypt pass a different deposit order than Rust does.
    const byString = [...trees].map((tree) => tree.address).sort();
    expect(byString).not.toEqual(trees.map((tree) => tree.address));
  });

  for (const item of fixture.cases as readonly Case[]) {
    it(`asks for the same tags as Rust: ${item.id}`, async () => {
      const owner = keypair(item.identity);
      const wallet = new Wallet({
        identity: keypair("self").shieldedAddress(),
        registry: new AssetRegistry([]),
      });
      wallet._replace({
        utxos: [],
        transactions: [],
        nullifiers: new Set(),
        viewingKeyHistory: item.history.map(counters) as never,
      });
      const material: WalletSyncMaterial = {
        identity: owner.shieldedAddress(),
        viewingKeys: item.viewingKeys.map(viewingKey),
        nullifierKey: owner.nullifierKey(),
      };
      const authority = {
        syncMaterial: () => Promise.resolve(material),
      } as unknown as WalletAuthority;
      const { client, tags, shielded, deposits } = recorder();

      const outcome = await syncWallet({
        wallet,
        authority,
        client: client as ZolanaClient,
        config: { tagWindow: BigInt(item.tagWindow), tagQueryChunk: item.tagQueryChunk },
      }).then(
        () => undefined,
        (error: unknown) => error as { code?: string; causeCode?: string },
      );

      if (item.outcome.arm === "ok") {
        expect(outcome).toBeUndefined();
      } else {
        const expected = REJECTIONS[item.outcome.error ?? ""];
        if (expected === undefined) {
          throw new Error(`no code is mapped for Rust ${item.outcome.error ?? "?"}`);
        }
        expect(outcome?.code).toBe("WALLET_SYNC");
        expect(outcome?.causeCode).toBe(expected);
      }

      expect([...tags].sort()).toEqual([...item.tags]);
      // Rust collects the tags through a `HashSet`, so which tag lands in which
      // chunk is not part of the contract; how many queries a chunk size costs
      // is, because that is what a sync pays for.
      expect([...shielded].sort((left, right) => right - left)).toEqual([
        ...item.shieldedChunkSizes,
      ]);
      expect([...deposits].sort((left, right) => right - left)).toEqual([
        ...item.depositChunkSizes,
      ]);
    });
  }
});
