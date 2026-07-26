import { address, getBase64Decoder, type Signature } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ZolanaClient } from "../src/client/index.js";
import { ShieldedKeypair, ViewingKey } from "../src/keypair/index.js";
import { splAssetRegistryAccountCodec } from "../src/interface/codecs/index.js";
import {
  SHIELDED_POOL_PROGRAM_ID,
  type Bytes16,
  type Bytes31,
  type Bytes32,
} from "../src/interface/index.js";
import {
  Data,
  LocalWalletAuthority,
  SOL_MINT,
  Utxo,
  Wallet,
  assetField,
  decryptTransactions,
} from "../src/transaction/index.js";
import { newViewingKeyEntry } from "../src/transaction/wallet/state.js";
import {
  EncryptedScheme,
  encodeOutputData,
  encryptMerge,
} from "../src/transaction/serialization/index.js";
import { backfillAssetRegistry, syncWallet } from "../src/wallet/sync.js";

const OWNER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const SIGNATURE = "1".repeat(64) as Signature;
const SPL_MINT = address("So11111111111111111111111111111111111111112");

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("wallet sync", () => {
  it("records the completed sync time instead of resetting it to zero", async () => {
    vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const client = {
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1_700_000_000n },
        transactions: [],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1_700_000_000n },
        matches: [],
      })),
    } as unknown as ZolanaClient;

    const report = await syncWallet({
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
      client,
      config: { tagWindow: 1n, rounds: 1 },
    });

    expect(wallet.lastSynced).toBe(1_700_000_000n);
    expect(report).toMatchObject({ complete: true, rounds: 1 });
  });

  it("filters registry backfill before downloading program accounts", async () => {
    const keypair = ShieldedKeypair.generate();
    const send = vi.fn(async () => []);
    const getProgramAccounts = vi.fn(() => ({ send }));
    const client = {
      commitment: "confirmed",
      rpc: { getProgramAccounts },
    } as unknown as ZolanaClient;

    await expect(
      backfillAssetRegistry(new Wallet({ identity: keypair.shieldedAddress() }), client),
    ).resolves.toBe(0);

    expect(getProgramAccounts).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        filters: [
          { dataSize: 48n },
          {
            memcmp: expect.objectContaining({
              offset: 0n,
              encoding: "base64",
            }),
          },
        ],
      }),
    );
  });

  it("backfills an SPL mint already present in the wallet", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const blinding = new Uint8Array(31).fill(3) as Bytes31;
    const utxo = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SPL_MINT,
      amount: 42n,
      blinding,
      data: new Data(),
    });
    const hash = utxo.hash(keypair.nullifierPublicKey());
    wallet._replace({
      ...wallet._state(),
      utxos: [
        {
          utxo,
          outputContext: { hash, tree: TREE, leafIndex: 0n },
          nullifier: keypair.nullifier(hash, blinding),
          spent: false,
        },
      ],
    });
    expect(() => wallet.balance(SPL_MINT)).toThrowError("TRANSACTION_UNKNOWN_MINT");

    const accountData = splAssetRegistryAccountCodec.encode({ mint: SPL_MINT, assetId: 2n });
    const send = vi.fn(async () => [
      {
        account: {
          owner: SHIELDED_POOL_PROGRAM_ID,
          data: [getBase64Decoder().decode(accountData), "base64"],
        },
      },
    ]);
    const client = {
      commitment: "confirmed",
      rpc: { getProgramAccounts: () => ({ send }) },
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        transactions: [],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        matches: [],
      })),
    } as unknown as ZolanaClient;

    const report = await syncWallet({
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
      client,
      config: { tagWindow: 1n, rounds: 1 },
    });

    expect(report.complete).toBe(false);
    expect(send).toHaveBeenCalledOnce();
    expect(wallet.registry.entries()).toContainEqual([2n, SPL_MINT]);
    expect(wallet.balance(SPL_MINT)).toMatchObject({ assetId: 2n, amount: 42n });
  });

  it("reports an unresolved merge asset field explicitly", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const assetField = bytes(77);
    const ciphertext = encryptMerge(keypair, keypair.viewingPublicKey(), {
      amount: 42n,
      assetField,
      blinding: new Uint8Array(31).fill(4) as Bytes31,
    });

    const report = await decryptTransactions({
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
      transactions: [
        {
          slot: 1n,
          txSignature: SIGNATURE,
          outputSlots: [
            {
              viewTag: keypair.signingPublicKey().confidentialViewTag(),
              outputContext: { hash: bytes(78), tree: TREE, leafIndex: 0n },
              payload: encodeOutputData(EncryptedScheme.merge, ciphertext, "verifiable"),
            },
          ],
          messages: [],
          nullifiers: [],
          proofless: false,
        },
      ],
    });

    expect(report.unknownAssetFields).toEqual([assetField]);
  });

  it("does not backfill for a merge another viewing key cannot decrypt", async () => {
    const keypair = ShieldedKeypair.generate();
    const oldViewingKey = ViewingKey.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    wallet._replace({
      ...wallet._state(),
      viewingKeyHistory: [
        newViewingKeyEntry(oldViewingKey.publicKey(), 0n),
        newViewingKeyEntry(keypair.viewingPublicKey(), 0n),
      ],
    });
    const blinding = new Uint8Array(31).fill(5) as Bytes31;
    const mergedUtxo = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 42n,
      blinding,
    });
    const ciphertext = encryptMerge(keypair, keypair.viewingPublicKey(), {
      amount: 42n,
      assetField: assetField(SOL_MINT),
      blinding,
    });
    const transaction = {
      slot: 1n,
      txSignature: SIGNATURE,
      outputSlots: [
        {
          viewTag: keypair.signingPublicKey().confidentialViewTag(),
          outputContext: {
            hash: mergedUtxo.hash(keypair.nullifierPublicKey()),
            tree: TREE,
            leafIndex: 0n,
          },
          payload: encodeOutputData(EncryptedScheme.merge, ciphertext, "verifiable"),
        },
      ],
      messages: [],
      nullifiers: [],
      proofless: false,
    } as const;
    const client = {
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        transactions: [transaction],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        matches: [],
      })),
    } as unknown as ZolanaClient;
    const authority = {
      syncMaterial: async () => ({
        identity: keypair.shieldedAddress(),
        viewingKeys: [oldViewingKey, keypair.viewingKey()],
        nullifierKey: keypair.nullifierKey(),
      }),
    } as never;

    const report = await syncWallet({
      wallet,
      authority,
      client,
      config: { tagWindow: 1n, rounds: 2 },
    });

    expect(report).toMatchObject({
      complete: true,
      unknownAssetFields: [],
      unknownAssetIds: [],
    });
    expect(report.undecryptableCandidates).toBeGreaterThan(0);
    expect(wallet.balance(SOL_MINT).amount).toBe(42n);
  });

  it("reports when its round bound stops an advancing scan", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const client = {
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        transactions: [
          {
            slot: 1n,
            txSignature: SIGNATURE,
            txViewingPublicKey: keypair.viewingPublicKey(),
            salt: new Uint8Array(16) as Bytes16,
            outputSlots: [],
            messages: [],
            nullifiers: [],
            proofless: false,
          },
        ],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        matches: [],
      })),
    } as unknown as ZolanaClient;

    const report = await syncWallet({
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
      client,
      config: { tagWindow: 1n, rounds: 1 },
    });

    expect(report).toMatchObject({ complete: false, rounds: 1 });
  });

  it("rejects a non-advancing indexer cursor", async () => {
    const keypair = ShieldedKeypair.generate();
    const cursor = Uint8Array.of(9);
    const getShieldedTransactionsByTags = vi.fn(async () => ({
      context: { blockTime: 1n },
      transactions: [],
      nextCursor: cursor,
    }));
    const client = {
      getShieldedTransactionsByTags,
      getEncryptedUtxosByTags: vi.fn(),
    } as unknown as ZolanaClient;

    await expect(
      syncWallet({
        wallet: new Wallet({ identity: keypair.shieldedAddress() }),
        authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
        client,
        config: { tagWindow: 1n, rounds: 1 },
      }),
    ).rejects.toMatchObject({
      code: "WALLET_SYNC",
      causeCode: "CLIENT_INVALID_RPC_RESPONSE",
    });
    expect(getShieldedTransactionsByTags).toHaveBeenCalledTimes(2);
  });

  it("retains multiple shielded events from one Solana signature", async () => {
    const keypair = ShieldedKeypair.generate();
    const transaction = (value: number) => ({
      slot: 1n,
      txSignature: SIGNATURE,
      txViewingPublicKey: keypair.viewingPublicKey(),
      salt: new Uint8Array(16) as Bytes16,
      outputSlots: [
        {
          viewTag: bytes(value),
          outputContext: {
            hash: bytes(value + 10),
            tree: TREE,
            leafIndex: BigInt(value),
          },
          payload: Uint8Array.of(255),
        },
      ],
      messages: [],
      nullifiers: [],
      proofless: false,
    });
    const client = {
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        transactions: [transaction(1), transaction(2)],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        matches: [],
      })),
    } as unknown as ZolanaClient;

    const report = await syncWallet({
      wallet: new Wallet({ identity: keypair.shieldedAddress() }),
      authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
      client,
      config: { tagWindow: 1n, rounds: 2 },
    });

    expect(report.unparsedTransactions).toBe(2);
    expect(report.complete).toBe(true);
  });
});
