import { address, type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { bytesKey } from "../src/interface/bytes.js";
import type { Bytes32, HistoryFilters } from "../src/interface/index.js";
import { randomBlinding } from "../src/keypair/bytes.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import {
  AssetRegistry,
  ConfidentialTransfer,
  LocalShieldedKeys,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  Wallet,
  type IndexedShieldedTransaction,
} from "../src/transaction/index.js";
import { syncWallet } from "../src/wallet/sync.js";
import { outputItems, transactionItems } from "./helpers/pages.js";
import { syncReads } from "./helpers/clients.js";

const RING = address("Ring111111111111111111111111111111111111111");
const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");

/**
 * A policy-ring transfer from `sender` that keeps 6 lamports of change in the
 * ring under its sender view tag of index `txCount`, as the indexer returns it.
 */
function ringTransfer(
  sender: ShieldedKeypair,
  txCount: bigint,
  slot: bigint,
): IndexedShieldedTransaction {
  const input = ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: sender.signingPublicKey(),
      asset: SOL_MINT,
      amount: 10n,
      blinding: randomBlinding(),
    }),
    sender,
  );
  const viewingKey = sender.viewingKey();
  const tag = viewingKey.senderViewTag(txCount);
  viewingKey.destroy();
  const transfer = new ConfidentialTransfer(
    sender.shieldedAddress(),
    [input],
    sender.shieldedAddress().solanaAddress(),
  )
    .withRingProgramId(RING)
    .withSenderViewTag(tag);
  transfer.send(ShieldedKeypair.generate().shieldedAddress(), SOL_MINT, 4n);
  const signed = transfer.sign(sender, new AssetRegistry());
  const external = signed.externalData;
  return {
    slot,
    txSignature: String(slot).padStart(64, "1") as Signature,
    txViewingPublicKey: external.txViewingPublicKey,
    salt: external.salt,
    outputSlots: external.outputs.map((output, index) => ({
      viewTag: external.resolvedOwnerTags[index]!,
      outputContext: { hash: output.utxoHash, tree: TREE, leafIndex: slot * 16n + BigInt(index) },
      payload: output.data ?? new Uint8Array(),
    })),
    messages: [],
    nullifiers: signed.inputContexts().map((context) => context.nullifier),
    proofless: false,
  };
}

/** An indexer over `history` at `tip`, recording every tag the sync asks about. */
function indexer(history: IndexedShieldedTransaction[], tip: { slot: bigint }) {
  const asked: { tags: readonly Bytes32[]; filters?: HistoryFilters }[] = [];
  const page = <T>(data: T) => ({
    context: { blockTime: 1_700_000_000n, slot: tip.slot },
    data,
    paginationToken: null,
  });
  const client = syncReads({
    getShieldedTransactionsByTags: async (request) => {
      asked.push(request);
      const wanted = new Set(request.tags.map(bytesKey));
      const above = request.filters?.slot?.gt ?? -1n;
      return page(
        transactionItems(
          history.filter(
            (transaction) =>
              transaction.slot > above &&
              [...transaction.outputSlots, ...transaction.messages].some((slot) =>
                wanted.has(bytesKey(slot.viewTag)),
              ),
          ),
        ),
      );
    },
    getEncryptedUtxosByTags: async () => page(outputItems([])),
    getShieldedTransactionsByNullifiers: async () => page(transactionItems([])),
  });
  return { client, asked };
}

/** The sender view tag indices of `keypair` the sync asked about, ascending. */
function askedIndices(
  keypair: ShieldedKeypair,
  asked: readonly { tags: readonly Bytes32[] }[],
): readonly number[] {
  const viewingKey = keypair.viewingKey();
  const byTag = new Map(
    Array.from({ length: 1_000 }, (_, index) => [
      bytesKey(viewingKey.senderViewTag(BigInt(index))),
      index,
    ]),
  );
  viewingKey.destroy();
  return [
    ...new Set(
      asked.flatMap((request) =>
        request.tags.flatMap((tag) => {
          const index = byTag.get(bytesKey(tag));
          return index === undefined ? [] : [index];
        }),
      ),
    ),
  ].sort((left, right) => left - right);
}

function range(end: number): readonly number[] {
  return Array.from({ length: end }, (_, index) => index);
}

function ringChange(wallet: Wallet): readonly bigint[] {
  return wallet
    .utxos()
    .filter((entry) => entry.utxo.ringProgramId === RING)
    .map((entry) => entry.utxo.amount);
}

describe("sender view tag sweep", () => {
  it("finds change under the sender view tag and reports the next unused index", async () => {
    const sender = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: sender.shieldedAddress() });
    const keys = LocalShieldedKeys.fromKeypair(sender);
    const history = [ringTransfer(sender, 7n, 3n)];
    const { client, asked } = indexer(history, { slot: 5n });

    const report = await syncWallet({ wallet, keys, client });

    expect(report.nextSenderTxCount).toBe(8n);
    expect(ringChange(wallet)).toEqual([6n]);
    // Index 7 moves the end of the sweep to 108.
    expect(askedIndices(sender, asked)).toEqual(range(108));
  });

  it("reports index 0 and sweeps one gap for a wallet that never sent", async () => {
    const sender = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: sender.shieldedAddress() });
    const { client, asked } = indexer([], { slot: 5n });

    const report = await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(sender),
      client,
    });

    expect(report.nextSenderTxCount).toBe(0n);
    expect(askedIndices(sender, asked)).toEqual(range(100));
  });

  it("extends the sweep past 100 once a match moves the window", async () => {
    const sender = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: sender.shieldedAddress() });
    const keys = LocalShieldedKeys.fromKeypair(sender);
    const history = [ringTransfer(sender, 60n, 3n), ringTransfer(sender, 150n, 4n)];
    const { client, asked } = indexer(history, { slot: 5n });

    const report = await syncWallet({ wallet, keys, client });

    expect(report.nextSenderTxCount).toBe(151n);
    expect(ringChange(wallet)).toEqual([6n, 6n]);
    expect(askedIndices(sender, asked)).toEqual(range(251));
  });

  it("leaves an index past a run of 100 unused indices undiscovered", async () => {
    const sender = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: sender.shieldedAddress() });
    const { client } = indexer([ringTransfer(sender, 100n, 3n)], { slot: 5n });

    const report = await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(sender),
      client,
    });

    expect(report.nextSenderTxCount).toBe(0n);
    expect(ringChange(wallet)).toEqual([]);
  });

  // Each tag resumes above its checkpoint, so a resumed sync no longer sees
  // the earlier matches; the run of checkpointed tags restores them.
  it("resumes the sweep where the previous sync ended", async () => {
    const sender = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: sender.shieldedAddress() });
    const keys = LocalShieldedKeys.fromKeypair(sender);
    const history = [ringTransfer(sender, 60n, 3n), ringTransfer(sender, 150n, 4n)];
    const tip = { slot: 5n };
    const { client, asked } = indexer(history, tip);
    expect((await syncWallet({ wallet, keys, client })).nextSenderTxCount).toBe(151n);

    asked.length = 0;
    tip.slot = 9n;
    const resumed = await syncWallet({ wallet, keys, client });
    expect(resumed.nextSenderTxCount).toBe(151n);
    expect(askedIndices(sender, asked)).toEqual(range(251));
    const senderRequests = asked.filter((request) => askedIndices(sender, [request]).length > 0);
    expect(senderRequests.every((request) => request.filters?.slot?.gt === 5n)).toBe(true);

    // The next transfer takes the reported index, inside the swept window.
    history.push(ringTransfer(sender, 151n, 11n), ringTransfer(sender, 240n, 12n));
    asked.length = 0;
    tip.slot = 13n;
    const next = await syncWallet({ wallet, keys, client });
    expect(next.nextSenderTxCount).toBe(241n);
    expect(ringChange(wallet)).toEqual([6n, 6n, 6n, 6n]);
    expect(askedIndices(sender, asked)).toEqual(range(341));
  });
});
