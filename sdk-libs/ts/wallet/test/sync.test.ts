import type { ZolanaIndexer } from "@zolana/client";
import type { Address, Bytes32 } from "@zolana/interface";
import { randomBlinding, ShieldedKeypair } from "@zolana/keypair";
import { AssetRegistry, Data, SOL_MINT, Utxo, Wallet } from "@zolana/transaction";
import { describe, expect, it, vi } from "vitest";

import { LocalWalletAuthority, WalletError, syncWallet } from "../src/index.js";
import { walletFixture } from "./helpers/fixtures.js";

const OWNER = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi" as Address;
const TREE = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR" as Address;
const bytes32 = (value: number): Bytes32 => new Uint8Array(32).fill(value) as Bytes32;

function state(): Readonly<{
  wallet: Wallet;
  authority: LocalWalletAuthority;
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
        data: new Data(),
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
  };
}

describe("wallet sync", () => {
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
    expect(wallet.balance(SOL_MINT)?.amount).toBe(BigInt(balance.amount));
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
    let round = 0;
    const indexer = {
      getShieldedTransactionsByTags: () => {
        round++;
        if (round > 4) return Promise.reject(timeout);
        return Promise.resolve({
          context: { blockTime: 0n },
          transactions:
            round === 1
              ? [
                  {
                    slot: 1n,
                    txSignature: "indexed-first-round",
                    outputSlots: [],
                    messages: [],
                    nullifiers: [],
                    proofless: false,
                  },
                ]
              : [],
        });
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
});
