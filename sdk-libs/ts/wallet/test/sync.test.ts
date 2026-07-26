import type { ZolanaIndexer } from "@zolana/client";
import { SHIELDED_POOL_PROGRAM_ID, type Address, type Bytes32 } from "@zolana/interface";
import { splAssetRegistryAccountCodec } from "@zolana/interface/codecs";
import { randomBlinding, ShieldedKeypair } from "@zolana/keypair";
import {
  AssetRegistry,
  OutputData,
  EncryptedScheme,
  SOL_ASSET_ID,
  SOL_MINT,
  Utxo,
  Wallet,
} from "@zolana/transaction";
import { encodeOutputData, encodeProofless } from "@zolana/transaction/serialization";
import { describe, expect, it, vi } from "vitest";

import { LocalWalletAuthority, WalletError, syncWallet } from "../src/index.js";
import { backfillAssetRegistry, type ViewingKeyCounters } from "../src/sync.js";
import { hex, walletFixture } from "./helpers/fixtures.js";

const OWNER = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi" as Address;
const TREE = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR" as Address;
const bytes32 = (value: number): Bytes32 => new Uint8Array(32).fill(value) as Bytes32;

function state(): Readonly<{
  wallet: Wallet;
  authority: LocalWalletAuthority;
  keypair: ShieldedKeypair;
}> {
  const keypair = ShieldedKeypair.generate();
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry(),
  });
  wallet._replace({
    utxos: [2n, 38n].map((amount, index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: randomBlinding(),
        data: new OutputData(),
      }),
      outputContext: { hash: bytes32(index + 1), tree: TREE, leafIndex: BigInt(index) },
      nullifier: bytes32(index + 10),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return {
    wallet,
    authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
    keypair,
  };
}

const DEPOSIT_AMOUNT = 21n;

function depositMatch(
  keypair: ShieldedKeypair,
  viewTag: Bytes32,
): Readonly<{
  slot: bigint;
  txSignature: string;
  outputSlot: {
    viewTag: Bytes32;
    outputContext: { hash: Bytes32; tree: Address; leafIndex: bigint };
    payload: Uint8Array;
  };
}> {
  const blinding = randomBlinding();
  const utxo = new Utxo({
    owner: keypair.signingPublicKey(),
    asset: SOL_MINT,
    amount: DEPOSIT_AMOUNT,
    blinding,
    data: new OutputData(),
  });
  return {
    slot: 5n,
    txSignature: "3QnHBSdd4LEV3B9vCPgqmMKtaLQupsnEsBz3JqnHhBWQ",
    outputSlot: {
      viewTag,
      outputContext: {
        hash: utxo.hash(keypair.nullifierKey().publicKey()),
        tree: TREE,
        leafIndex: 7n,
      },
      payload: encodeOutputData(
        EncryptedScheme.proofless,
        encodeProofless({ owner: bytes32(0), blinding, asset: SOL_MINT, amount: DEPOSIT_AMOUNT }),
      ),
    },
  };
}

describe("wallet sync", () => {
  it("backfills valid registry accounts once and skips malformed rows", async () => {
    const { wallet } = state();
    const registryData = splAssetRegistryAccountCodec.encode({ mint: OWNER, assetId: 2n });
    const getProgramAccounts = vi.fn(() =>
      Promise.resolve([
        {
          address: TREE,
          account: { owner: SHIELDED_POOL_PROGRAM_ID, lamports: 1n, data: registryData },
        },
        {
          address: OWNER,
          account: {
            owner: SHIELDED_POOL_PROGRAM_ID,
            lamports: 1n,
            data: Uint8Array.of(5),
          },
        },
      ]),
    );

    await expect(backfillAssetRegistry(wallet, { getProgramAccounts })).resolves.toBe(1);
    expect(wallet.registry.resolve(2n)).toBe(OWNER);
    await expect(backfillAssetRegistry(wallet, { getProgramAccounts })).resolves.toBe(0);
  });

  it("pages configured tag chunks and leaves repeated empty sync atomic", async () => {
    const fixture = await walletFixture<{
      inputs: {
        config: {
          tagWindow: string;
          tagQueryChunk: string;
          pageLimit: string;
          rounds: string;
          waitForIndexer: boolean;
        };
      };
      expected: {
        idempotentEmptySync: { durableUtxoCount: string; historyCount: string };
        balances: { amount: string }[];
      };
    }>("wallet_sync");
    const { wallet, authority } = state();
    const getShieldedTransactionsByTags = vi.fn(() =>
      Promise.resolve({ context: { blockTime: 100n }, transactions: [] }),
    );
    const getEncryptedUtxosByTags = vi.fn(() =>
      Promise.resolve({ context: { blockTime: 100n }, matches: [] }),
    );
    const indexer = {
      getShieldedTransactionsByTags,
      getEncryptedUtxosByTags,
    } as unknown as ZolanaIndexer;
    const config = {
      tagWindow: BigInt(fixture.inputs.config.tagWindow),
      tagQueryChunk: Number(fixture.inputs.config.tagQueryChunk),
      pageLimit: Number(fixture.inputs.config.pageLimit),
      rounds: Number(fixture.inputs.config.rounds),
      waitForIndexer: fixture.inputs.config.waitForIndexer,
    };
    await syncWallet({ wallet, authority, indexer, config });
    await syncWallet({ wallet, authority, indexer, config });
    expect(wallet.utxos()).toHaveLength(
      Number(fixture.expected.idempotentEmptySync.durableUtxoCount),
    );
    expect(wallet.privateTransactions()).toHaveLength(
      Number(fixture.expected.idempotentEmptySync.historyCount),
    );
    const balance = fixture.expected.balances[0];
    if (balance === undefined) throw new Error("missing balance fixture");
    expect(wallet.balance(SOL_MINT).amount).toBe(BigInt(balance.amount));
    expect(getShieldedTransactionsByTags).toHaveBeenCalledTimes(8);
    expect(getEncryptedUtxosByTags).toHaveBeenCalledTimes(8);
  });

  it("preserves wallet state across indexer timeout and abort failures", async () => {
    const fixture = await walletFixture<{
      expected: {
        atomicFailure: { walletUnchanged: boolean };
        indexerOutcomes: { timeout: { code: string }; abort: { code: string } };
      };
    }>("wallet_sync");
    const { wallet, authority } = state();
    const before = wallet.utxos();
    const timeout = new Error(fixture.expected.indexerOutcomes.timeout.code);
    let chunk = 0;
    const indexer = {
      getShieldedTransactionsByTags: () => {
        chunk++;
        if (chunk > 2) return Promise.reject(timeout);
        return Promise.resolve({ context: { blockTime: 0n }, transactions: [] });
      },
      getEncryptedUtxosByTags: () => Promise.resolve({ context: { blockTime: 0n }, matches: [] }),
    } as unknown as ZolanaIndexer;
    await expect(syncWallet({ wallet, authority, indexer })).rejects.toEqual(
      expect.objectContaining({ code: "WALLET_SYNC", cause: timeout }),
    );
    expect(wallet.utxos()).toEqual(before);
    expect(fixture.expected.atomicFailure.walletUnchanged).toBe(true);

    const controller = new AbortController();
    controller.abort();
    const aborted = new Error(fixture.expected.indexerOutcomes.abort.code);
    const aborting = {
      getShieldedTransactionsByTags: () => Promise.reject(aborted),
      getEncryptedUtxosByTags: () => Promise.resolve({ context: { blockTime: 0n }, matches: [] }),
    } as unknown as ZolanaIndexer;
    await expect(
      syncWallet({ wallet, authority, indexer: aborting }, { signal: controller.signal }),
    ).rejects.toBeInstanceOf(WalletError);
    expect(wallet.utxos()).toEqual(before);
  });

  it("queries both shared tag families past the counter offsets", async () => {
    const window = 2n;
    for (const family of ["recipientShared", "sendShared"] as const) {
      const { wallet, authority, keypair } = state();
      const viewingKey = keypair.viewingKey();
      const counterparty = ShieldedKeypair.generate().viewingKey().publicKey();
      const counters: ViewingKeyCounters = {
        viewingPublicKey: viewingKey.publicKey(),
        createdAt: 0n,
        txCount: 3n,
        requestCount: 1n,
        knownSenders: [{ counterparty, count: 1n }],
        knownRecipients: [{ counterparty, count: 1n }],
      };
      wallet._replace({ ...wallet._state(), viewingKeyHistory: [counters] });
      const target =
        family === "recipientShared"
          ? viewingKey.recipientSharedViewTag(counterparty, 1n)
          : viewingKey.sendSharedViewTag(counterparty, 1n);
      const deposit = depositMatch(keypair, target);
      const requested = new Set<string>();
      const indexer = {
        getShieldedTransactionsByTags: () =>
          Promise.resolve({ context: { blockTime: 0n }, transactions: [] }),
        getEncryptedUtxosByTags: (request: Readonly<{ tags: readonly Bytes32[] }>) => {
          for (const tag of request.tags) requested.add(hex(tag));
          const matched = request.tags.some((tag) => hex(tag) === hex(target));
          return Promise.resolve({
            context: { blockTime: 0n },
            matches: matched ? [deposit] : [],
          });
        },
      } as unknown as ZolanaIndexer;

      await syncWallet({
        wallet,
        authority,
        indexer,
        config: { tagWindow: window, tagQueryChunk: 1 },
      });

      expect(requested.has(hex(target))).toBe(true);
      // The last index each counter reaches sits beyond the bare window, so it
      // is only queried when the counter offsets the range.
      expect(requested.has(hex(viewingKey.senderViewTag(counters.txCount + window - 1n)))).toBe(
        true,
      );
      expect(
        requested.has(hex(viewingKey.recipientRequestViewTag(counters.requestCount + window - 1n))),
      ).toBe(true);
      // Only the recipient-shared family opens what it finds. A wallet derives
      // its send-shared tags for the notes it pays out, so a note addressed to
      // it never lands under one: that scan advances the counter and decodes
      // nothing, exactly as `Wallet::sync` does.
      const stored = family === "recipientShared";
      expect(wallet.utxos()).toHaveLength(stored ? 3 : 2);
      expect(wallet.balance(SOL_MINT).amount).toBe(stored ? 40n + DEPOSIT_AMOUNT : 40n);
    }
  });

  it("queries a discovered sender's shared family on the next round", async () => {
    const { wallet, authority, keypair } = state();
    const sender = ShieldedKeypair.generate();
    const senderViewingPublicKey = sender.viewingKey().publicKey();
    const blinding = randomBlinding();
    const note = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 7n,
      blinding,
      data: new OutputData(),
    });
    const envelope = await new LocalWalletAuthority({
      solanaPublicKey: OWNER,
      keypair: sender,
    }).encryptAnonymousTransfer({
      firstNullifier: bytes32(1),
      senderViewTag: bytes32(3),
      sender: {
        ownerPublicKey: sender.signingPublicKey(),
        splAssetId: SOL_ASSET_ID,
        splAmount: 0n,
        solAmount: 1n,
        blindingSeed: randomBlinding(),
        recipientViewingPublicKeys: [keypair.viewingKey().publicKey()],
        splData: new OutputData(),
        solData: new OutputData(),
      },
      recipients: [
        {
          viewTag: keypair.viewingKey().recipientRequestViewTag(0n),
          recipientPublicKey: keypair.viewingKey().publicKey(),
          plaintext: {
            ownerPublicKey: keypair.signingPublicKey(),
            senderPublicKey: senderViewingPublicKey,
            assetId: SOL_ASSET_ID,
            amount: 7n,
            blinding,
            data: new OutputData(),
          },
        },
      ],
    });
    const requestTag = keypair.viewingKey().recipientRequestViewTag(0n);
    const transaction = {
      slot: 1n,
      txSignature: "3QnHBSdd4LEV3B9vCPgqmMKtaLQupsnEsBz3JqnHhBWQ",
      txViewingPublicKey: envelope.txViewingPublicKey,
      salt: envelope.salt,
      outputSlots: envelope.payload.flatMap((message, index) =>
        message === undefined
          ? []
          : [
              {
                viewTag: message.viewTag,
                outputContext: {
                  hash: index === 1 ? note.hash(keypair.nullifierKey().publicKey()) : bytes32(0),
                  tree: TREE,
                  leafIndex: BigInt(index),
                },
                payload: message.data,
              },
            ],
      ),
      messages: [],
      nullifiers: [],
      proofless: false,
    };
    const requested = new Set<string>();
    const indexer = {
      getShieldedTransactionsByTags: (request: Readonly<{ tags: readonly Bytes32[] }>) => {
        for (const tag of request.tags) requested.add(hex(tag));
        const matched = request.tags.some((tag) => hex(tag) === hex(requestTag));
        return Promise.resolve({
          context: { blockTime: 0n },
          transactions: matched ? [transaction] : [],
        });
      },
      getEncryptedUtxosByTags: () => Promise.resolve({ context: { blockTime: 0n }, matches: [] }),
    } as unknown as ZolanaIndexer;

    await syncWallet({ wallet, authority, indexer, config: { tagWindow: 1n } });

    expect(wallet.utxos()).toHaveLength(3);
    // The sender is only known once the note decoded, so its shared tags can
    // only have been asked for on a later round.
    expect(
      requested.has(hex(keypair.viewingKey().recipientSharedViewTag(senderViewingPublicKey, 0n))),
    ).toBe(true);
  });

  it("rejects encrypted and non-proofless plaintext payloads during deposit sync", async () => {
    const { wallet, authority, keypair } = state();
    const viewTag = keypair.viewingKey().recipientRequestViewTag(0n);
    const before = wallet.utxos().length;
    const bogus = [
      encodeOutputData(EncryptedScheme.plaintextTransfer, Uint8Array.of(0), "plaintext"),
      encodeOutputData(EncryptedScheme.confidential, new Uint8Array(48).fill(9), "encrypted"),
      encodeOutputData(EncryptedScheme.proofless, Uint8Array.of(1, 2, 3), "plaintext"),
    ];
    let index = 0;
    const indexer = {
      getShieldedTransactionsByTags: () =>
        Promise.resolve({ context: { blockTime: 0n }, transactions: [] }),
      getEncryptedUtxosByTags: () => {
        const payload = bogus.at(index) ?? bogus.at(0);
        if (payload === undefined) {
          throw new Error("missing deposit sync payload");
        }
        index += 1;
        return Promise.resolve({
          context: { blockTime: 0n },
          matches: [
            {
              slot: 5n,
              txSignature: `sig-${String(index)}`,
              outputSlot: {
                viewTag,
                outputContext: { hash: bytes32(index), tree: TREE, leafIndex: BigInt(index) },
                payload,
              },
            },
          ],
        });
      },
    } as unknown as ZolanaIndexer;

    await syncWallet({
      wallet,
      authority,
      indexer,
      config: { tagWindow: 1n, tagQueryChunk: 1, rounds: 3 },
    });
    expect(wallet.utxos()).toHaveLength(before);
  });

  it("forwards the indexer poll configuration", async () => {
    const { wallet, authority } = state();
    const retry = { numRetries: 3, delayMs: 5n, maxDelayMs: 9n };
    const getShieldedTransactionsByTags = vi.fn(() =>
      Promise.resolve({ context: { blockTime: 0n }, transactions: [] }),
    );
    const indexer = {
      getShieldedTransactionsByTags,
      getEncryptedUtxosByTags: () => Promise.resolve({ context: { blockTime: 0n }, matches: [] }),
    } as unknown as ZolanaIndexer;

    await syncWallet({
      wallet,
      authority,
      indexer,
      config: { tagWindow: 1n, waitForIndexer: true, retry },
    });

    expect(getShieldedTransactionsByTags.mock.calls[0]?.[1]).toEqual({
      waitForIndexer: true,
      poll: retry,
    });
  });
});
