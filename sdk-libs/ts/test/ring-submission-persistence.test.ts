import { address, generateKeyPairSigner, signTransactionWithSigners } from "@solana/kit";
import { afterEach, expect, it, vi } from "vitest";

import { LocalKeys } from "../src/client/keys.js";
import { compileUnsignedTransaction } from "../src/flows/compile.js";
import { reserveEntries, DEFAULT_RESERVATION_TTL_MS } from "../src/flows/reserve.js";
import { ringConfigPda, treeAddress } from "../src/interface/pda/index.js";
import type { Bytes32 } from "../src/interface/types.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { buildRingTransferTransaction } from "../src/ring/transfer.js";
import { RingTransactionSubmission, reconcileRingSubmissions } from "../src/ring/submission.js";
import { SOL_MINT, AssetRegistry } from "../src/transaction/asset.js";
import { Utxo, ProofInputUtxo } from "../src/transaction/utxo.js";
import { Wallet } from "../src/transaction/wallet/state.js";
import { deserializeWallet, serializeWallet } from "../src/transaction/wallet/persistence.js";
import { loadPersistedWallet, savePersistedWallet } from "../src/wallet/persisted.js";
import { walletSnapshotCipher } from "../src/wallet/snapshot-cipher.js";
import { BLOCKHASH, ringTransferClient } from "./helpers/clients.js";
import { ringProgramConfigData, ownedAccount } from "./helpers/ring-accounts.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const MEMO = address("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
function field(value: number): Bytes32 {
  const bytes = new Uint8Array(32);
  bytes[31] = value;
  return bytes as Bytes32;
}
function funded(treeId: number) {
  const owner = ShieldedKeypair.generate();
  const wallet = new Wallet({ identity: owner.shieldedAddress(), registry: new AssetRegistry() });
  const utxo = new Utxo({
    owner: owner.signingPublicKey(),
    asset: SOL_MINT,
    amount: 10n,
    blinding: field(6),
    ringProgramId: RING,
  });
  const proof = ProofInputUtxo.fromKeypair(utxo, owner, undefined, treeId);
  const entry = {
    utxo,
    outputContext: {
      hash: utxo.hash(owner.shieldedAddress().nullifierPublicKey, treeId),
      tree: treeAddress(treeId),
      leafIndex: 0n,
    },
    nullifier: proof.nullifier(),
    spent: false,
  };
  wallet._replace({ utxos: [entry], transactions: [], nullifiers: new Set() });
  return { owner, wallet, entry };
}
afterEach(() => vi.restoreAllMocks());

it("binds high level ring transfers to the configured nonzero tree", async () => {
  const f = funded(7);
  const [config, bump] = await ringConfigPda(RING);
  let outputTreeId: number | undefined;
  const client = ringTransferClient({
    tree: treeAddress(7),
    treeId: 7,
    getAccount: async (key) =>
      key === config
        ? ownedAccount(
            RING,
            ringProgramConfigData({
              authority: f.owner.shieldedAddress().solanaAddress(),
              auditorPublicKey: f.owner.viewingPublicKey().toBytes(),
              bump,
              hasPolicy: false,
            }),
          )
        : undefined,
    proveRingTransact: async (inputs) => {
      outputTreeId = inputs.outputTreeId;
      throw new Error("prover boundary reached");
    },
  });
  const keys = LocalKeys.fromKeypair(f.owner, {
    prove: async () => {
      throw new Error("unreachable");
    },
    proveMerge: async () => {
      throw new Error("unreachable");
    },
  });
  await expect(
    buildRingTransferTransaction({
      client,
      ringProgramId: RING,
      wallet: f.wallet,
      keys,
      feePayer: f.owner.shieldedAddress().solanaAddress(),
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 1n,
    }),
  ).rejects.toMatchObject({ code: "RING_BUILD_TRANSFER" });
  expect(outputTreeId).toBe(7);
  expect(f.wallet._activeReservations(BigInt(Date.now()))).toHaveLength(0);
});

it("retains unknown submissions after the lease interval and confirmation until sync", async () => {
  const f = funded(0);
  const payer = await generateKeyPairSigner();
  let now = 1_000;
  vi.spyOn(Date, "now").mockImplementation(() => now);
  const submission = await RingTransactionSubmission.fromBuilder({
    wallet: f.wallet,
    windowChanged: async () => false,
    build: async (retry) => {
      retry.entries = [f.entry];
      retry.reservation = reserveEntries(f.wallet, retry.entries, retry.lifetime);
      return {
        transaction: compileUnsignedTransaction({
          feePayer: payer.address,
          lifetime: BLOCKHASH,
          instructions: [{ programAddress: MEMO }],
          computeUnitLimit: 1_000,
        }),
        lastValidBlockHeight: 100n,
        intentHash: field(1),
        ringInstructionIndex: 0,
      };
    },
  });
  const send = vi.fn(async () => undefined);
  const transport = {
    sign: async (transaction: Parameters<typeof signTransactionWithSigners>[1]) =>
      signTransactionWithSigners([payer], transaction),
    send,
    status: async () => ({ kind: "unknown" as const }),
  };
  const pending = await submission.send(transport);
  expect(pending.kind).toBe("unknown");
  now += Number(DEFAULT_RESERVATION_TTL_MS) + 1;
  expect(() => reserveEntries(f.wallet, [f.entry])).toThrow("TRANSACTION_NOTE_RESERVED");
  await submission.send(transport);
  expect(f.wallet._activeReservations(BigInt(now))).toHaveLength(1);
  expect(send).toHaveBeenCalledTimes(1);
  expect(() => submission.cancel()).toThrow("RING_SUBMISSION_PENDING");
  await submission.send({ ...transport, status: async () => ({ kind: "confirmed", slot: 9n }) });
  expect(() => reserveEntries(f.wallet, [f.entry])).toThrow("TRANSACTION_NOTE_RESERVED");
  f.wallet._replace({
    utxos: [{ ...f.entry, spent: true }],
    transactions: [],
    nullifiers: new Set(),
  });
  expect(f.wallet._activeReservations(BigInt(now))).toHaveLength(0);
});

async function persistedFixture(count = 1) {
  const f = funded(0);
  if (count > 1) {
    const utxo = new Utxo({
      owner: f.owner.signingPublicKey(),
      asset: SOL_MINT,
      amount: 15n,
      blinding: field(15),
      ringProgramId: RING,
    });
    const proof = ProofInputUtxo.fromKeypair(utxo, f.owner, undefined, 0);
    f.wallet._replace({
      utxos: [
        f.entry,
        {
          utxo,
          outputContext: { hash: proof.hash(), tree: treeAddress(0), leafIndex: 1n },
          nullifier: proof.nullifier(),
          spent: false,
        },
      ],
      transactions: [],
      nullifiers: new Set(),
    });
  }
  const payer = await generateKeyPairSigner();
  const submission = await RingTransactionSubmission.fromBuilder({
    wallet: f.wallet,
    windowChanged: async () => false,
    build: async (retry) => {
      retry.entries = f.wallet.utxos();
      retry.reservation ??= reserveEntries(f.wallet, retry.entries, retry.lifetime);
      return {
        transaction: compileUnsignedTransaction({
          feePayer: payer.address,
          lifetime: BLOCKHASH,
          instructions: [{ programAddress: MEMO }],
          computeUnitLimit: 1_000,
        }),
        lastValidBlockHeight: 100n,
        intentHash: field(1),
        ringInstructionIndex: 0,
      };
    },
  });
  let stored: string | undefined;
  const store = {
    load: async () => stored,
    save: vi.fn(async (snapshot: string) => {
      stored = snapshot;
    }),
  };
  const cipher = walletSnapshotCipher(f.owner);
  const transport = {
    sign: async (transaction: Parameters<typeof signTransactionWithSigners>[1]) =>
      signTransactionWithSigners([payer], transaction),
    send: vi.fn(async () => undefined),
    status: vi.fn(async () => ({ kind: "unknown" as const })),
  };
  return { ...f, store, cipher, submission, transport };
}

it("saves the signed checkpoint before broadcast and restores held notes after restart", async () => {
  const f = await persistedFixture();
  f.transport.send.mockImplementation(async () => {
    const loaded = await loadPersistedWallet(f);
    expect(loaded?.pendingSubmissions()).toHaveLength(1);
    expect(loaded?._activeReservations(BigInt(Date.now()) + 999_999n)).toHaveLength(1);
    return undefined;
  });
  const result = await f.submission.sendPersisted(f);
  const loaded = await loadPersistedWallet(f);
  if (loaded === undefined) throw new Error("missing wallet");
  const pending = loaded.pendingSubmissions()[0];
  expect(pending).toMatchObject({
    signature: result.signature,
    attempts: 1,
    lastValidBlockHeight: 100n,
  });
  expect(() => reserveEntries(loaded, loaded.utxos())).toThrow("TRANSACTION_NOTE_RESERVED");
  expect(await reconcileRingSubmissions({ ...f, wallet: loaded })).toEqual([result]);
  expect(f.transport.send).toHaveBeenCalledTimes(1);
  expect(f.transport.status).toHaveBeenLastCalledWith(pending, undefined);
  await reconcileRingSubmissions({
    ...f,
    wallet: loaded,
    transport: { status: async () => ({ kind: "confirmed", slot: 5n }) },
  });
  expect(() => reserveEntries(loaded, loaded.utxos())).toThrow("TRANSACTION_NOTE_RESERVED");
  loaded._replace({
    utxos: [{ ...f.entry, spent: true }],
    transactions: [],
    nullifiers: new Set(),
  });
  await reconcileRingSubmissions({
    ...f,
    wallet: loaded,
    transport: { status: async () => ({ kind: "confirmed", slot: 5n }) },
  });
  expect(loaded.pendingSubmissions()).toEqual([]);
  expect((await loadPersistedWallet(f))?.pendingSubmissions()).toEqual([]);
});

it("does not broadcast after a failed checkpoint save", async () => {
  const f = await persistedFixture();
  f.store.save.mockRejectedValueOnce(new Error("disk unavailable"));
  await expect(f.submission.sendPersisted(f)).rejects.toMatchObject({ code: "WALLET_PERSIST" });
  expect(f.transport.send).not.toHaveBeenCalled();
  expect(f.wallet.pendingSubmissions()).toEqual([]);
  expect(() => reserveEntries(f.wallet, [f.entry])).not.toThrow();
});

it("keeps a broadcast pending when the caller aborts", async () => {
  const f = await persistedFixture();
  f.transport.send.mockRejectedValueOnce(new Error("lost response"));
  await f.submission.sendPersisted(f);
  const wallet = await loadPersistedWallet(f);
  if (wallet === undefined) throw new Error("missing wallet");
  await expect(
    reconcileRingSubmissions({
      ...f,
      wallet,
      transport: {
        status: async () => {
          throw new Error("offline");
        },
      },
    }),
  ).rejects.toThrow("offline");
  expect(() => reserveEntries(wallet, wallet.utxos())).toThrow("TRANSACTION_NOTE_RESERVED");
});

it("settles a restored expiry without building or broadcasting another payment", async () => {
  const f = await persistedFixture();
  await f.submission.sendPersisted(f);
  const wallet = await loadPersistedWallet(f);
  if (wallet === undefined) throw new Error("missing wallet");
  const results = await reconcileRingSubmissions({
    ...f,
    wallet,
    transport: { status: async () => ({ kind: "expired" }) },
  });
  expect(results).toMatchObject([{ kind: "failed", attempts: 1 }]);
  expect(wallet.pendingSubmissions()).toEqual([]);
  expect(() => reserveEntries(wallet, wallet.utxos())).not.toThrow();
  expect(f.transport.send).toHaveBeenCalledTimes(1);
});

it("serializes saves with sync and leaves the newest checkpoint in the store", async () => {
  const f = await persistedFixture();
  let release: () => void = () => {};
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  const seal = vi.fn(async (snapshot: string) => {
    await blocked;
    return f.cipher.seal(snapshot);
  });
  const persistence = { ...f, cipher: { ...f.cipher, seal } };
  const saving = savePersistedWallet(persistence);
  await vi.waitFor(() => expect(seal).toHaveBeenCalledTimes(1));
  const sending = f.submission.sendPersisted(persistence);
  await vi.waitFor(() => expect(f.wallet.pendingSubmissions()).toHaveLength(1));
  expect(f.transport.send).not.toHaveBeenCalled();
  release();
  await saving;
  await sending;
  expect((await loadPersistedWallet(f))?.pendingSubmissions()).toHaveLength(1);
});

it.each([2, 3])("upgrades version %s without losing notes or history", (version) => {
  const f = funded(0);
  const old = JSON.parse(serializeWallet(f.wallet)) as Record<string, unknown>;
  old["version"] = version;
  delete old["pendingSubmissions"];
  const loaded = deserializeWallet(JSON.stringify(old));
  expect(loaded.utxos()).toEqual(f.wallet.utxos());
  expect(loaded.pendingSubmissions()).toEqual([]);
  expect(JSON.parse(serializeWallet(loaded))).toMatchObject({ version: 4 });
});

it("saves an existing unknown signature when persistence is attached", async () => {
  const f = await persistedFixture();
  const pending = await f.submission.send(f.transport);
  expect(f.store.save).not.toHaveBeenCalled();
  expect(await f.submission.sendPersisted(f)).toEqual(pending);
  expect((await loadPersistedWallet(f))?.pendingSubmissions()).toMatchObject([
    { signature: pending.signature },
  ]);
  expect(f.transport.send).toHaveBeenCalledTimes(1);
});

it("restores a pending transaction after sync observes a competing spend of one input", async () => {
  const f = await persistedFixture(2);
  await f.submission.sendPersisted(f);
  f.wallet._replace({
    utxos: f.wallet.utxos().map((entry, index) => ({ ...entry, spent: index === 0 })),
    transactions: [],
    nullifiers: new Set(),
  });
  await savePersistedWallet(f);
  const wallet = await loadPersistedWallet(f);
  if (wallet === undefined) throw new Error("missing wallet");
  expect(wallet.pendingSubmissions()).toHaveLength(1);
  const remaining = wallet.utxos().filter((entry) => !entry.spent);
  expect(remaining).toHaveLength(1);
  expect(() => reserveEntries(wallet, remaining)).toThrow("TRANSACTION_NOTE_RESERVED");
});
