import {
  address,
  getAddressEncoder,
  getBase64Decoder,
  SolanaError,
  SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND,
  type Signature,
} from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ShieldedKeypair, SigningKey, ViewingKey } from "../src/keypair/index.js";
import { mergeDummyNullifier, mergeOutputBlinding } from "../src/keypair/merge/index.js";
import { SHIELDED_POOL_PROGRAM_ID, type Bytes16, type Bytes32 } from "../src/interface/index.js";
import { StateDiscriminator } from "../src/interface/state.js";
import {
  AssetRegistry,
  ConfidentialTransfer,
  Data,
  LocalShieldedKeys,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  Wallet,
  createProofOutput,
  decryptTransactions,
  deriveBlinding,
  deserializeWallet,
  encodeConfidentialSlots,
  encryptAnonymousTransfer,
  serializeWallet,
  splitBundleFromUtxos,
  type ShieldedKeys,
} from "../src/transaction/index.js";
import {
  EncryptedScheme,
  encodeOutputData,
  encodeProofless,
  encodeSplitBundle,
  encryptConfidential,
  encryptSplit,
  readOutputData,
} from "../src/transaction/serialization/codecs.js";
import { encodeRingDepositPlaintext } from "../src/transaction/serialization/ring-deposit.js";
import { SOL_ASSET_ID } from "../src/transaction/asset.js";
import {
  anonymousRecipientUtxo,
  anonymousSenderFromUtxos,
  anonymousSenderUtxos,
} from "../src/transaction/serialization/codecs.js";
import { backfillAssetRegistry, syncWallet } from "../src/wallet/sync.js";
import { syncPersistedWallet } from "../src/wallet/persisted.js";
import { kitReads, solanaRpcReads, syncReads, plainCipher } from "./helpers/clients.js";

const OWNER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const SIGNATURE = "1".repeat(64) as Signature;
const SPL_MINT = address("So11111111111111111111111111111111111111112");

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

interface RequestWithCursor {
  readonly cursor?: Uint8Array;
}

function mergeAfterSplit() {
  const keypair = ShieldedKeypair.generate();
  const identityTag = keypair.signingPublicKey().confidentialViewTag();
  const blindingSeed = bytes(7);
  const outputs = [0, 1].map(
    (index) =>
      new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 21n,
        blinding: deriveBlinding(blindingSeed, index),
      }),
  );
  const contexts = outputs.map((utxo, index) => ({
    hash: utxo.hash(keypair.nullifierPublicKey()),
    tree: TREE,
    leafIndex: BigInt(index),
  }));
  const salt = new Uint8Array(16).fill(5) as Bytes16;
  const txKey = keypair.viewingKey().transactionViewingKey(bytes(9));
  const bundle = encodeSplitBundle(
    splitBundleFromUtxos(
      outputs,
      { owner: keypair.signingPublicKey(), assets: new AssetRegistry() },
      { blindingSeed },
    ),
  );
  const split = {
    slot: 1n,
    txSignature: SIGNATURE,
    txViewingPublicKey: txKey.publicKey(),
    salt,
    outputSlots: contexts.map((outputContext, index) => ({
      viewTag: identityTag,
      outputContext,
      payload:
        index === 0
          ? encodeOutputData(
              EncryptedScheme.split,
              encryptSplit(txKey, keypair.viewingPublicKey(), bundle, salt, 0),
              "encrypted",
            )
          : new Uint8Array(),
    })),
    messages: [],
    nullifiers: [bytes(90)],
    proofless: false,
  };

  const spent = outputs.map((utxo, index) =>
    utxo.nullifier(contexts[index]!.hash, keypair.nullifierKey()),
  );
  const firstNullifier = spent[0]!;
  const merged = new Utxo({
    owner: keypair.signingPublicKey(),
    asset: SOL_MINT,
    amount: 42n,
    blinding: mergeOutputBlinding(keypair.nullifierKey(), firstNullifier),
  });
  const merge = {
    slot: 2n,
    txSignature: "2".repeat(64) as Signature,
    outputSlots: [
      {
        viewTag: identityTag,
        outputContext: {
          hash: merged.hash(keypair.nullifierPublicKey()),
          tree: TREE,
          leafIndex: 2n,
        },
        payload: new Uint8Array(),
      },
    ],
    messages: [],
    nullifiers: [
      ...spent,
      ...Array.from({ length: 6 }, (_, offset) =>
        mergeDummyNullifier(keypair.nullifierKey(), firstNullifier, offset + 2),
      ),
    ],
    proofless: false,
  };
  const mergeContext = merge.outputSlots[0]!.outputContext;
  const chainedNullifier = merged.nullifier(mergeContext.hash, keypair.nullifierKey());
  const chained = new Utxo({
    owner: keypair.signingPublicKey(),
    asset: SOL_MINT,
    amount: 42n,
    blinding: mergeOutputBlinding(keypair.nullifierKey(), chainedNullifier),
  });
  const chainedMerge = {
    slot: 3n,
    txSignature: "3".repeat(64) as Signature,
    outputSlots: [
      {
        viewTag: identityTag,
        outputContext: {
          hash: chained.hash(keypair.nullifierPublicKey()),
          tree: TREE,
          leafIndex: 3n,
        },
        payload: new Uint8Array(),
      },
    ],
    messages: [],
    nullifiers: [
      chainedNullifier,
      ...Array.from({ length: 7 }, (_, offset) =>
        mergeDummyNullifier(keypair.nullifierKey(), chainedNullifier, offset + 1),
      ),
    ],
    proofless: false,
  };

  return {
    keypair,
    keys: LocalShieldedKeys.fromKeypair(keypair),
    split,
    merge,
    chainedMerge,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

/** A holder that forwards to `keys`; tests override one method to misbehave. */
function remoteOver(keys: ShieldedKeys): ShieldedKeys {
  return {
    address: () => keys.address(),
    viewingPublicKeys: () => keys.viewingPublicKeys(),
    decrypt: (requests) => keys.decrypt(requests),
    derive: (requests) => keys.derive(requests),
    transactionKeys: (requests) => keys.transactionKeys(requests),
  };
}

function decryptWithKeys(
  keys: ShieldedKeys,
  input: Omit<Parameters<typeof decryptTransactions>[0], "keys">,
): Promise<ReturnType<typeof decryptTransactions> extends Promise<infer R> ? R : never> {
  return decryptTransactions({ ...input, keys });
}

describe("wallet sync atomicity", () => {
  function emptyTagPages() {
    return {
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1_700_000_000n, slot: 0n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers: vi.fn(),
    };
  }

  it("commits no cursor from a sync that failed partway", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const keys = LocalShieldedKeys.fromKeypair(keypair);
    const cursor = Uint8Array.of(1, 2, 3);
    // Chunk size 1 splits the wallet's two tags into two calls, the first
    // returns a cursor, the second dies.
    let served = 0;
    const getShieldedTransactionsByTags = vi.fn(async (_request: RequestWithCursor) => {
      served += 1;
      if (served === 2) throw new Error("indexer down");
      return {
        context: { blockTime: 1_700_000_000n, slot: 0n },
        transactions: [],
        scannedThrough: cursor,
      };
    });
    const client = syncReads({
      getShieldedTransactionsByTags,
      ...emptyTagPages(),
    });

    await expect(
      syncWallet({ wallet, keys, client, config: { queryChunk: 1 } }),
    ).rejects.toMatchObject({ code: "WALLET_SYNC" });
    expect(wallet.lastSynced).toBe(0n);

    served = 10;
    getShieldedTransactionsByTags.mockClear();
    await syncWallet({ wallet, keys, client, config: { queryChunk: 1 } });
    for (const call of getShieldedTransactionsByTags.mock.calls) {
      expect(call[0]?.cursor).toBeUndefined();
    }
  });

  it("runs concurrent syncs one after the other over the committed cursor", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const keys = LocalShieldedKeys.fromKeypair(keypair);
    const cursor = Uint8Array.of(7, 7);
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let firstCall = true;
    const getShieldedTransactionsByTags = vi.fn(async (request: { cursor?: Uint8Array }) => {
      if (firstCall) {
        firstCall = false;
        await gate;
      }
      return {
        context: { blockTime: 1_700_000_000n, slot: 0n },
        transactions: [],
        ...(request.cursor === undefined ? { scannedThrough: cursor } : {}),
      };
    });
    const client = syncReads({
      getShieldedTransactionsByTags,
      ...emptyTagPages(),
    });

    const first = syncWallet({ wallet, keys, client });
    const second = syncWallet({ wallet, keys, client });
    release?.();
    await first;
    await second;

    const calls = getShieldedTransactionsByTags.mock.calls;
    expect(calls[0]?.[0]?.cursor).toBeUndefined();
    expect(calls.at(-1)?.[0]?.cursor).toEqual(cursor);
  });

  it("fails a sync overtaken by another writer and keeps the newer state", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const keys = LocalShieldedKeys.fromKeypair(keypair);
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let firstCall = true;
    const getShieldedTransactionsByTags = vi.fn(async (_request: RequestWithCursor) => {
      if (firstCall) {
        firstCall = false;
        await gate;
      }
      return { context: { blockTime: 1_700_000_000n, slot: 0n }, transactions: [] };
    });
    const client = syncReads({
      getShieldedTransactionsByTags,
      ...emptyTagPages(),
    });

    const sync = syncWallet({ wallet, keys, client });
    await vi.waitFor(() => expect(getShieldedTransactionsByTags).toHaveBeenCalled());
    // An out-of-band writer lands between the sync's snapshot and its commit.
    wallet._replace({ utxos: [], transactions: [], nullifiers: new Set(), lastSynced: 42n });
    release?.();

    await expect(sync).rejects.toMatchObject({
      code: "WALLET_SYNC",
      causeCode: "TRANSACTION_WALLET_STATE_STALE",
    });
    expect(wallet.lastSynced).toBe(42n);
  });

  it("resumes from persisted cursors after a restart", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const keys = LocalShieldedKeys.fromKeypair(keypair);
    const cursor = Uint8Array.of(5, 5, 5);
    let served = 0;
    const getShieldedTransactionsByTags = vi.fn(async (_request: RequestWithCursor) => {
      served += 1;
      return {
        context: { blockTime: 1_700_000_000n, slot: 0n },
        transactions: [],
        ...(served === 1 ? { scannedThrough: cursor } : {}),
      };
    });
    const client = syncReads({
      getShieldedTransactionsByTags,
      ...emptyTagPages(),
    });

    await syncWallet({ wallet, keys, client });
    const restored = deserializeWallet(serializeWallet(wallet));
    getShieldedTransactionsByTags.mockClear();
    await syncWallet({ wallet: restored, keys, client });

    const call = getShieldedTransactionsByTags.mock.calls[0]?.[0];
    expect(call?.cursor).toEqual(cursor);
  });

  it("refuses keys that describe another wallet before querying any tag", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const getShieldedTransactionsByTags = vi.fn(async () => ({
      context: { blockTime: 1_700_000_000n, slot: 0n },
      transactions: [],
    }));
    const client = syncReads({ getShieldedTransactionsByTags, ...emptyTagPages() });

    await expect(
      syncWallet({
        wallet,
        keys: LocalShieldedKeys.fromKeypair(ShieldedKeypair.generate()),
        client,
      }),
    ).rejects.toMatchObject({ code: "WALLET_SYNC" });
    expect(getShieldedTransactionsByTags).not.toHaveBeenCalled();
  });
});

describe("wallet sync", () => {
  it("records the completed sync time instead of resetting it to zero", async () => {
    vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const client = syncReads({
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1_700_000_000n, slot: 0n },
        transactions: [],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1_700_000_000n, slot: 0n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers: vi.fn(),
    });

    const report = await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(keypair),
      client,
    });

    expect(wallet.lastSynced).toBe(1_700_000_000n);
    expect(report).toMatchObject({ storedUtxos: 0, unparsedTransactions: 0 });
  });

  it("resumes each tag stream from where it was read to", async () => {
    // Without this every sync re-reads the wallet's whole history: 569 ECDH
    // operations for a wallet holding a handful of UTXOs, growing forever.
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const cursor = Uint8Array.of(1, 2, 3);
    // One page carrying a cursor, then the end. Repeating a cursor would trip
    // the SDK's loop guard, which is a different behaviour under test.
    let served = 0;
    const getShieldedTransactionsByTags = vi.fn(async (_request: RequestWithCursor) => {
      served += 1;
      return {
        context: { blockTime: 1_700_000_000n, slot: 0n },
        transactions: [],
        ...(served === 1 ? { nextCursor: cursor } : {}),
      };
    });
    const client = syncReads({
      getShieldedTransactionsByTags,
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1_700_000_000n, slot: 0n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers: vi.fn(),
    });
    const keys = LocalShieldedKeys.fromKeypair(keypair);

    await syncWallet({ wallet, keys, client });
    const calls = () => getShieldedTransactionsByTags.mock.calls;
    const firstCall = calls()[0]?.[0];
    expect(firstCall?.cursor).toBeUndefined();

    getShieldedTransactionsByTags.mockClear();
    await syncWallet({ wallet, keys, client });
    const secondCall = calls()[0]?.[0];
    expect(secondCall?.cursor).toEqual(cursor);
  });

  it("does not resume a newly learned tag from another tag's position", async () => {
    // The trap the per-tag watermarks exist for. Tags come from a counter plus a
    // window, so one can be learned after others have advanced far past the
    // slots it needs. Sharing a cursor would skip its history permanently.
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    wallet._setSyncCursor("transactions", "deadbeef", Uint8Array.of(9, 9, 9));

    const getShieldedTransactionsByTags = vi.fn(async (_request: RequestWithCursor) => ({
      context: { blockTime: 1_700_000_000n, slot: 0n },
      transactions: [],
    }));
    const client = syncReads({
      getShieldedTransactionsByTags,
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1_700_000_000n, slot: 0n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers: vi.fn(),
    });

    await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(keypair),
      client,
    });

    // The wallet's real tags have no watermark, so every query starts at the
    // beginning -- the unrelated tag's cursor must not leak into them.
    for (const call of getShieldedTransactionsByTags.mock.calls) {
      expect(call[0]?.cursor).toBeUndefined();
    }
  });

  it("filters registry backfill before downloading program accounts", async () => {
    const keypair = ShieldedKeypair.generate();
    const send = vi.fn(async () => []);
    const getProgramAccounts = vi.fn(() => ({ send }));
    const client = kitReads({
      commitment: "confirmed",
      solanaRpc: { getProgramAccounts },
    });

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

  function unknownMintWallet(keypair: ShieldedKeypair): Wallet {
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const blinding = new Uint8Array(32).fill(3) as Bytes32;
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
    return wallet;
  }

  it("refuses an unknown-mint sync on a client without kit access", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = unknownMintWallet(keypair);
    const emptyPage = vi.fn(async () => ({
      context: { blockTime: 1n, slot: 0n },
      transactions: [],
    }));
    const client = syncReads({
      getShieldedTransactionsByTags: emptyPage,
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers: emptyPage,
    });
    await expect(
      syncWallet({
        wallet,
        keys: LocalShieldedKeys.fromKeypair(keypair),
        client,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_SYNC",
      causeCode: "WALLET_INVALID_SYNC_CONFIG",
    });
  });

  it("backfills an SPL mint already present in the wallet", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = unknownMintWallet(keypair);
    expect(() => wallet.balance(SPL_MINT)).toThrowError("TRANSACTION_UNKNOWN_MINT");

    const accountData = new Uint8Array(48);
    accountData[0] = StateDiscriminator.splAssetRegistry;
    accountData.set(getAddressEncoder().encode(SPL_MINT), 8);
    new DataView(accountData.buffer).setBigUint64(40, 2n, true);
    const send = vi.fn(async () => [
      {
        account: {
          owner: SHIELDED_POOL_PROGRAM_ID,
          data: [getBase64Decoder().decode(accountData), "base64"],
        },
      },
    ]);
    const client = syncReads({
      commitment: "confirmed",
      solanaRpc: solanaRpcReads({ getProgramAccounts: () => ({ send }) }),
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        transactions: [],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        transactions: [],
      })),
    });

    const report = await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(keypair),
      client,
    });

    expect(report.unknownAssetIds).toEqual([]);
    expect(send).toHaveBeenCalledOnce();
    expect(wallet.registry.entries()).toContainEqual([2n, SPL_MINT]);
    expect(wallet.balance(SPL_MINT)).toMatchObject({ assetId: 2n, amount: 42n });
  });

  it("holds the cursors until the registry resolves every held mint", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = unknownMintWallet(keypair);
    const keys = LocalShieldedKeys.fromKeypair(keypair);
    const requestCursors: (Uint8Array | undefined)[] = [];
    const tagPage = vi.fn(async (request: { cursor?: Uint8Array }) => {
      requestCursors.push(request.cursor);
      return {
        context: { blockTime: 1n, slot: 0n },
        transactions: [],
        scannedThrough: Uint8Array.of(6, 6),
      };
    });
    const accountData = new Uint8Array(48);
    accountData[0] = StateDiscriminator.splAssetRegistry;
    accountData.set(getAddressEncoder().encode(SPL_MINT), 8);
    new DataView(accountData.buffer).setBigUint64(40, 2n, true);
    const registration = {
      account: {
        owner: SHIELDED_POOL_PROGRAM_ID,
        data: [getBase64Decoder().decode(accountData), "base64"],
      },
    };
    let scan: () => unknown = () => {
      throw new SolanaError(SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND, {
        __serverMessage: "method not found",
      });
    };
    const client = syncReads({
      commitment: "confirmed",
      solanaRpc: solanaRpcReads({
        getProgramAccounts: () => ({ send: vi.fn(async () => scan()) }),
      }),
      getShieldedTransactionsByTags: tagPage,
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        transactions: [],
      })),
    });
    const store = {
      saved: undefined as string | undefined,
      save: vi.fn(async (snapshot: string) => {
        store.saved = snapshot;
      }),
    };
    await expect(
      syncPersistedWallet({ wallet, keys, client, store, cipher: plainCipher }),
    ).rejects.toMatchObject({
      code: "WALLET_SYNC",
      causeCode: "CLIENT_UNSUPPORTED_RPC_METHOD",
    });
    scan = () => [];
    await expect(
      syncPersistedWallet({ wallet, keys, client, store, cipher: plainCipher }),
    ).rejects.toMatchObject({
      code: "WALLET_SYNC",
      causeCode: "WALLET_UNRESOLVED_ASSET",
    });
    expect(store.save).not.toHaveBeenCalled();
    expect(wallet.lastSynced).toBe(0n);

    scan = () => [registration];
    await syncPersistedWallet({ wallet, keys, client, store, cipher: plainCipher });
    expect(requestCursors.every((cursor) => cursor === undefined)).toBe(true);
    expect(wallet.balance(SPL_MINT).amount).toBe(42n);
    expect(store.save).toHaveBeenCalledTimes(1);
  });

  it("reconstructs a ciphertext-free merge from owned spent inputs", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const inputUtxos = [20n, 22n].map((amount, index) => {
      const blinding = bytes(index + 3);
      const utxo = new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding,
      });
      const hash = utxo.hash(keypair.nullifierPublicKey());
      return {
        utxo,
        outputContext: { hash, tree: TREE, leafIndex: BigInt(index) },
        nullifier: keypair.nullifier(hash, blinding),
        spent: false,
      };
    });
    wallet._replace({ ...wallet._state(), utxos: inputUtxos });
    const firstNullifier = inputUtxos[0]!.nullifier;
    const nullifiers = [
      ...inputUtxos.map((entry) => entry.nullifier),
      ...Array.from({ length: 6 }, (_, offset) =>
        mergeDummyNullifier(keypair.nullifierKey(), firstNullifier, offset + 2),
      ),
    ];
    const merged = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 42n,
      blinding: mergeOutputBlinding(keypair.nullifierKey(), firstNullifier),
    });

    const report = await decryptWithKeys(LocalShieldedKeys.fromKeypair(keypair), {
      wallet,
      transactions: [
        {
          slot: 1n,
          txSignature: SIGNATURE,
          outputSlots: [
            {
              viewTag: keypair.signingPublicKey().confidentialViewTag(),
              outputContext: {
                hash: merged.hash(keypair.nullifierPublicKey()),
                tree: TREE,
                leafIndex: 2n,
              },
              payload: new Uint8Array(),
            },
          ],
          messages: [],
          nullifiers,
          proofless: false,
        },
      ],
    });

    expect(report).toMatchObject({ storedUtxos: 1, undecryptableCandidates: 0 });
    expect(wallet.balance(SOL_MINT).amount).toBe(42n);
  });

  it("reconstructs a merge whose inputs arrive in the same batch", async () => {
    const { keypair, keys, split, merge } = mergeAfterSplit();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });

    const report = await decryptWithKeys(keys, {
      wallet,
      transactions: [split, merge],
    });

    expect(report).toMatchObject({ storedUtxos: 3, undecryptableCandidates: 0 });
    expect(wallet.balance(SOL_MINT).amount).toBe(42n);
  });

  it("reaches the same state whether the merge replays fresh or incrementally", async () => {
    const { keypair, keys, split, merge } = mergeAfterSplit();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });

    await decryptWithKeys(keys, { wallet, transactions: [split] });
    const report = await decryptWithKeys(keys, { wallet, transactions: [merge] });

    expect(report).toMatchObject({ storedUtxos: 1, undecryptableCandidates: 0 });
    expect(wallet.balance(SOL_MINT).amount).toBe(42n);

    const fresh = new Wallet({ identity: keypair.shieldedAddress() });
    await decryptWithKeys(keys, { wallet: fresh, transactions: [split, merge] });
    expect(fresh.balance(SOL_MINT).amount).toBe(wallet.balance(SOL_MINT).amount);
    expect(fresh.utxos()).toEqual(wallet.utxos());
  });

  it("resolves merge chains when a dependent merge arrives first", async () => {
    const { keypair, keys, split, merge, chainedMerge } = mergeAfterSplit();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });

    const report = await decryptWithKeys(keys, {
      wallet,
      transactions: [split, chainedMerge, merge],
    });

    expect(report).toMatchObject({ storedUtxos: 4, undecryptableCandidates: 0 });
    expect(wallet.balance(SOL_MINT).amount).toBe(42n);
  });

  it("asks a remote key holder once per dependency level, not once per output", async () => {
    // A key holder behind a network answers in batches: the pass records every
    // request it cannot answer, resolves them together, and runs again. The
    // result must be the one in-process keys produce, and the call count must
    // follow the dependency chain (ciphertext, nullifier, merge derivations),
    // not the number of outputs.
    const { keypair, keys, split, merge, chainedMerge } = mergeAfterSplit();
    const calls = { decrypt: 0, derive: 0, transactionKeys: 0, items: 0 };
    const remote: ShieldedKeys = {
      address: () => keys.address(),
      viewingPublicKeys: () => keys.viewingPublicKeys(),
      decrypt: (requests) => {
        calls.decrypt++;
        calls.items += requests.length;
        return keys.decrypt(requests);
      },
      derive: (requests) => {
        calls.derive++;
        calls.items += requests.length;
        return keys.derive(requests);
      },
      transactionKeys: (requests) => {
        calls.transactionKeys++;
        calls.items += requests.length;
        return keys.transactionKeys(requests);
      },
    };
    const local = new Wallet({ identity: keypair.shieldedAddress() });
    await decryptWithKeys(keys, { wallet: local, transactions: [split, chainedMerge, merge] });

    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const report = await decryptWithKeys(remote, {
      wallet,
      transactions: [split, chainedMerge, merge],
    });

    expect(report).toMatchObject({ storedUtxos: 4, undecryptableCandidates: 0 });
    expect(wallet.utxos()).toEqual(local.utxos());
    expect(wallet.privateTransactions()).toEqual(local.privateTransactions());
    expect(calls.items).toBeGreaterThan(calls.decrypt + calls.derive + calls.transactionKeys);
    expect(calls.decrypt).toBeLessThanOrEqual(2);
    expect(calls.derive).toBeLessThanOrEqual(6);
  });

  it("hands the sync's request context to every key holder batch", async () => {
    const { keypair, keys, split, merge, chainedMerge } = mergeAfterSplit();
    const seen: unknown[] = [];
    const remote: ShieldedKeys = {
      address: () => keys.address(),
      viewingPublicKeys: () => keys.viewingPublicKeys(),
      decrypt: (requests, context) => {
        seen.push(context);
        return keys.decrypt(requests);
      },
      derive: (requests, context) => {
        seen.push(context);
        return keys.derive(requests);
      },
      transactionKeys: (requests, context) => {
        seen.push(context);
        return keys.transactionKeys(requests);
      },
    };
    const context = { signal: new AbortController().signal, timeoutMs: 1_000 };

    await decryptWithKeys(remote, {
      wallet: new Wallet({ identity: keypair.shieldedAddress() }),
      transactions: [split, chainedMerge, merge],
      context,
    });

    expect(seen.length).toBeGreaterThan(1);
    expect(seen.every((entry) => entry === context)).toBe(true);
  });

  /** `depth` merges, each consolidating the previous one's single output. */
  function mergeChain(depth: number) {
    const fixture = mergeAfterSplit();
    const { keypair } = fixture;
    const identityTag = keypair.signingPublicKey().confidentialViewTag();
    const merges = [fixture.merge];
    let previous = {
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 42n,
        blinding: mergeOutputBlinding(keypair.nullifierKey(), fixture.merge.nullifiers[0]!),
      }),
      context: fixture.merge.outputSlots[0]!.outputContext,
    };
    for (let index = 1; index < depth; index++) {
      const spent = previous.utxo.nullifier(previous.context.hash, keypair.nullifierKey());
      const utxo = new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 42n,
        blinding: mergeOutputBlinding(keypair.nullifierKey(), spent),
      });
      const context = {
        hash: utxo.hash(keypair.nullifierPublicKey()),
        tree: TREE,
        leafIndex: BigInt(index + 2),
      };
      merges.push({
        slot: BigInt(index + 2),
        txSignature: String(index + 3)
          .repeat(64)
          .slice(0, 64) as Signature,
        outputSlots: [{ viewTag: identityTag, outputContext: context, payload: new Uint8Array() }],
        messages: [],
        nullifiers: [
          spent,
          ...Array.from({ length: 7 }, (_, offset) =>
            mergeDummyNullifier(keypair.nullifierKey(), spent, offset + 1),
          ),
        ],
        proofless: false,
      });
      previous = { utxo, context };
    }
    return { ...fixture, merges };
  }

  it("restores a wallet through a long chain of merges in one batch", async () => {
    // Every merge in the chain needs the nullifier of the previous one's
    // output, so a fresh restore resolves one merge per key round. The round
    // budget follows the batch, not a fixed depth.
    const { keypair, keys, split, merges } = mergeChain(9);
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });

    const report = await decryptWithKeys(keys, {
      wallet,
      transactions: [split, ...[...merges].reverse()],
    });

    expect(report).toMatchObject({ storedUtxos: 2 + merges.length, undecryptableCandidates: 0 });
    expect(wallet.balance(SOL_MINT).amount).toBe(42n);
    expect(wallet.utxos().filter((entry) => !entry.spent)).toHaveLength(1);
  });

  it("refuses a key holder that answers a batch short or with a hole", async () => {
    const { keypair, keys, split, merge } = mergeAfterSplit();
    const short: ShieldedKeys = {
      ...remoteOver(keys),
      derive: async (requests) => (await keys.derive(requests)).slice(1),
    };
    await expect(
      decryptWithKeys(short, {
        wallet: new Wallet({ identity: keypair.shieldedAddress() }),
        transactions: [split, merge],
      }),
    ).rejects.toMatchObject({ code: "TRANSACTION_KEYS_BATCH_MISMATCH" });

    const holed: ShieldedKeys = {
      ...remoteOver(keys),
      decrypt: async (requests) => {
        const answers = [...(await keys.decrypt(requests))];
        // The right length with a hole: never "ask again", an error.
        answers.pop();
        answers.length = requests.length;
        return answers;
      },
    };
    await expect(
      decryptWithKeys(holed, {
        wallet: new Wallet({ identity: keypair.shieldedAddress() }),
        transactions: [split, merge],
      }),
    ).rejects.toMatchObject({ code: "TRANSACTION_KEYS_BATCH_MISMATCH" });
  });

  it("destroys the per-transaction keys a round minted when another call of the round fails", async () => {
    const { wallet, keys, indexedTransactions } = await syncConfidentialSelfSend(
      (transfer, identity) => transfer.send(identity, SOL_MINT, 40n),
    );
    // The nullifier derivation and the transaction key are asked for in the
    // same round; the keys handed out must not survive the derivation failing.
    const minted: ViewingKey[] = [];
    const failing: ShieldedKeys = {
      ...remoteOver(keys),
      derive: () => Promise.reject(new Error("holder offline")),
      transactionKeys: async (requests) => {
        const result = await keys.transactionKeys(requests);
        minted.push(...result);
        return result;
      },
    };
    await expect(
      decryptWithKeys(failing, {
        wallet: new Wallet({ identity: wallet.identity }),
        transactions: indexedTransactions,
      }),
    ).rejects.toThrow("holder offline");
    expect(minted.length).toBeGreaterThan(0);
    for (const key of minted) {
      expect(() => key.publicKey()).toThrow("KEYPAIR_INVALID_SECRET_KEY");
    }
  });

  async function syncConfidentialSelfSend(
    configure: (
      transfer: ConfidentialTransfer,
      identity: ReturnType<ShieldedKeypair["shieldedAddress"]>,
    ) => void,
  ) {
    const keypair = ShieldedKeypair.generate();
    const identity = keypair.shieldedAddress();
    const wallet = new Wallet({ identity });
    const blinding = bytes(14);
    const utxo = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 100n,
      blinding,
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
    const transfer = new ConfidentialTransfer(
      identity,
      [ProofInputUtxo.fromKeypair(utxo, keypair)],
      identity.solanaAddress(),
    );
    configure(transfer, identity);
    const signed = transfer.sign(keypair, wallet.registry);
    const external = signed.externalData;
    const keys = LocalShieldedKeys.fromKeypair(keypair);
    const indexedTransactions = [
      {
        slot: 1n,
        txSignature: SIGNATURE,
        txViewingPublicKey: external.txViewingPublicKey,
        salt: external.salt,
        outputSlots: external.outputs.map((output, index) => ({
          viewTag: external.resolvedOwnerTags[index]!,
          outputContext: {
            hash: output.utxoHash,
            tree: TREE,
            leafIndex: BigInt(index + 1),
          },
          payload: output.data ?? new Uint8Array(),
        })),
        messages: [],
        nullifiers: signed.inputContexts().map((input) => input.nullifier),
        proofless: false,
      },
    ];

    await decryptWithKeys(keys, {
      wallet,
      transactions: indexedTransactions,
    });

    return { wallet, keys, indexedTransactions, keypair };
  }

  it("classifies a confidential send to the same wallet as a self transfer", async () => {
    const { wallet, keys, indexedTransactions, keypair } = await syncConfidentialSelfSend(
      (transfer, identity) => transfer.send(identity, SOL_MINT, 40n),
    );
    let transactions = wallet.privateTransactions();
    expect(transactions).toHaveLength(1);
    expect(transactions[0]).toMatchObject({
      kind: "privateTransfer",
      direction: "selfTransfer",
      asset: SOL_MINT,
      amount: 40n,
    });
    expect(transactions[0]?.counterpartyViewingPublicKey?.toBytes()).toEqual(
      keypair.viewingPublicKey().toBytes(),
    );

    wallet._replace({
      ...wallet._state(),
      transactions: transactions.map((transaction) => ({
        ...transaction,
        direction: "outbound",
      })),
    });
    await decryptWithKeys(keys, { wallet, transactions: indexedTransactions });
    transactions = wallet.privateTransactions();
    expect(transactions).toHaveLength(1);
    expect(transactions[0]?.direction).toBe("selfTransfer");
  });

  it("replaces a row recorded with a stale amount instead of keeping both", async () => {
    // Keyed by content, a transfer synced before its change was known and
    // again after would show twice; the row's identity is the transaction and
    // its index, so the corrected row takes the stale one's place.
    const { wallet, keys, indexedTransactions } = await syncConfidentialSelfSend(
      (transfer, identity) => transfer.send(identity, SOL_MINT, 40n),
    );
    const [row] = wallet.privateTransactions();
    expect(row).toBeDefined();
    wallet._replace({
      ...wallet._state(),
      transactions: [{ ...row!, amount: 999n, kind: "publicWithdrawal" }],
    });
    await decryptWithKeys(keys, { wallet, transactions: indexedTransactions });
    const transactions = wallet.privateTransactions();
    expect(transactions).toHaveLength(1);
    expect(transactions[0]).toMatchObject({ kind: "privateTransfer", amount: 40n });
  });

  it("classifies an exact default to custom move as a ring entry", async () => {
    const { wallet } = await syncConfidentialSelfSend((transfer, identity) =>
      transfer.sendToRing(identity, SOL_MINT, 40n, TREE),
    );
    const restored = deserializeWallet(serializeWallet(wallet));

    expect(restored.privateTransactions()).toMatchObject([
      {
        kind: "ringEntry",
        direction: "selfTransfer",
        asset: SOL_MINT,
        amount: 40n,
      },
    ]);
    expect(restored.privateTransactions()[0]?.counterpartyViewingPublicKey).toBeUndefined();
  });

  it("classifies a send to a rotated-out viewing key as a self transfer", async () => {
    // Same signing and nullifier roles, two viewing keys: the wallet before and
    // after a rotation. The UTXO owner and nullifiers are unchanged, so the
    // pre-rotation transaction is still this wallet's to decode.
    const signing = SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(11) as Bytes32);
    const retired = ShieldedKeypair.withViewingKey(
      signing,
      ViewingKey.fromBytes(new Uint8Array(32).fill(21) as Bytes32),
    );
    const current = ShieldedKeypair.withViewingKey(
      signing,
      ViewingKey.fromBytes(new Uint8Array(32).fill(22) as Bytes32),
    );
    const identity = current.shieldedAddress();
    const wallet = new Wallet({ identity });
    const blinding = bytes(15);
    const utxo = new Utxo({
      owner: current.signingPublicKey(),
      asset: SOL_MINT,
      amount: 100n,
      blinding,
    });
    const hash = utxo.hash(current.nullifierPublicKey());
    wallet._replace({
      ...wallet._state(),
      utxos: [
        {
          utxo,
          outputContext: { hash, tree: TREE, leafIndex: 0n },
          nullifier: current.nullifier(hash, blinding),
          spent: false,
        },
      ],
    });

    const retiredIdentity = retired.shieldedAddress();
    const transfer = new ConfidentialTransfer(
      retiredIdentity,
      [ProofInputUtxo.fromKeypair(utxo, retired)],
      retiredIdentity.solanaAddress(),
    );
    transfer.send(retiredIdentity, SOL_MINT, 40n);
    const signed = transfer.sign(retired, wallet.registry);
    const external = signed.externalData;

    // Both keys, current first, the way an authority reports a rotation.
    const keys = LocalShieldedKeys.fromKeys({
      address: identity,
      viewingKeys: [current.viewingKey(), retired.viewingKey()],
      nullifierKey: current.nullifierKey(),
    });

    await decryptTransactions({
      wallet,
      keys,
      transactions: [
        {
          slot: 1n,
          txSignature: SIGNATURE,
          txViewingPublicKey: external.txViewingPublicKey,
          salt: external.salt,
          outputSlots: external.outputs.map((output, index) => ({
            viewTag: external.resolvedOwnerTags[index]!,
            outputContext: {
              hash: output.utxoHash,
              tree: TREE,
              leafIndex: BigInt(index + 1),
            },
            payload: output.data ?? new Uint8Array(),
          })),
          messages: [],
          nullifiers: signed.inputContexts().map((input) => input.nullifier),
          proofless: false,
        },
      ],
    });

    const transactions = wallet.privateTransactions();
    expect(
      transactions.map((row) => ({
        direction: row.direction,
        amount: row.amount,
        counterparty: row.counterpartyViewingPublicKey?.toBytes(),
      })),
    ).toEqual([
      {
        direction: "selfTransfer",
        amount: 40n,
        counterparty: retired.viewingPublicKey().toBytes(),
      },
    ]);
  });

  it("classifies an anonymous send whose only recipient is this wallet as a self transfer", async () => {
    // The anonymous rail carries its recipient list in the sender's own change
    // slot, so the sender-side row is classified from that list. It used to be
    // hardcoded outbound while the matching receipt already said selfTransfer.
    const keypair = ShieldedKeypair.generate();
    const identity = keypair.shieldedAddress();
    const wallet = new Wallet({ identity });
    const spentBlinding = bytes(31);
    const spent = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 100n,
      blinding: spentBlinding,
    });
    const spentHash = spent.hash(keypair.nullifierPublicKey());
    const nullifier = keypair.nullifier(spentHash, spentBlinding);
    wallet._replace({
      ...wallet._state(),
      utxos: [
        {
          utxo: spent,
          outputContext: { hash: spentHash, tree: TREE, leafIndex: 0n },
          nullifier,
          spent: false,
        },
      ],
    });

    // 100 in, 60 back as change: the row's amount is the 40 that moved.
    const blindingSeed = bytes(32);
    const change = anonymousSenderUtxos(
      {
        ownerPublicKey: keypair.signingPublicKey(),
        splAssetId: 0n,
        splAmount: 0n,
        solAmount: 60n,
        blindingSeed,
        recipientViewingPublicKeys: [keypair.viewingPublicKey()],
        splData: new Data(),
        solData: new Data(),
      },
      wallet.registry,
      SOL_MINT,
    );
    const sender = anonymousSenderFromUtxos(
      change,
      { owner: keypair.signingPublicKey(), assets: wallet.registry },
      { blindingSeed, recipientViewingPublicKeys: [keypair.viewingPublicKey()] },
    );
    const recipientPlaintext = {
      ownerPublicKey: keypair.signingPublicKey(),
      senderPublicKey: keypair.viewingPublicKey(),
      assetId: SOL_ASSET_ID,
      amount: 40n,
      blinding: bytes(33),
      data: new Data(),
    };
    const recipientUtxo = anonymousRecipientUtxo(recipientPlaintext, wallet.registry);

    const keys = LocalShieldedKeys.fromKeypair(keypair);
    // The sender bundle is tagged with the identity's signing tag, which is one
    // of the two stable families `decryptTransactions` opens.
    const identityTag = keypair.signingPublicKey().confidentialViewTag();
    const [txKey] = await keys.transactionKeys([
      { viewingPublicKey: identity.viewingPublicKey, firstNullifier: nullifier },
    ]);
    const envelope = encryptAnonymousTransfer(txKey!, {
      viewingPublicKey: identity.viewingPublicKey,
      senderViewTag: identityTag,
      sender,
      recipients: [
        {
          viewTag: keypair.viewingKey().recipientBootstrapViewTag(),
          recipientPublicKey: keypair.viewingPublicKey(),
          plaintext: recipientPlaintext,
        },
      ],
    });
    txKey!.destroy();
    const slotUtxos = [...change, recipientUtxo];

    await decryptWithKeys(keys, {
      wallet,
      transactions: [
        {
          slot: 1n,
          txSignature: SIGNATURE,
          txViewingPublicKey: envelope.txViewingPublicKey,
          salt: envelope.salt,
          outputSlots: envelope.payload.map((slot, index) => ({
            viewTag: slot?.viewTag ?? bytes(0),
            outputContext: {
              hash: slotUtxos[index]!.hash(keypair.nullifierPublicKey()),
              tree: TREE,
              leafIndex: BigInt(index + 1),
            },
            payload: slot?.data ?? new Uint8Array(),
          })),
          messages: [],
          nullifiers: [nullifier],
          proofless: false,
        },
      ],
    });

    // Two rows, unlike the confidential rail, which suppresses an authored
    // slot's receipt: the sender-bundle row and the recipient receipt. The point
    // is that neither contradicts the other -- before, the bundle row said
    // outbound while the receipt beside it already said selfTransfer.
    const moved = wallet
      .privateTransactions()
      .filter((row) => row.kind === "privateTransfer" && row.amount === 40n);
    expect(moved.map((row) => row.direction)).toEqual(["selfTransfer", "selfTransfer"]);
    expect(wallet.privateTransactions().filter((row) => row.direction === "outbound")).toEqual([]);
  });

  it("stores an inbound ring confidential output with its ring", async () => {
    const recipient = ShieldedKeypair.generate();
    const sender = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });
    const salt = new Uint8Array(16).fill(3) as Bytes16;
    const output = new Utxo({
      owner: recipient.signingPublicKey(),
      asset: SOL_MINT,
      amount: 42n,
      blinding: bytes(31),
      ringProgramId: OWNER,
    });
    const payload = encodeOutputData(
      EncryptedScheme.ringConfidential,
      encryptConfidential(
        sender,
        recipient.viewingPublicKey(),
        {
          assetId: 1n,
          amount: output.amount,
          blinding: output.blinding,
          ringProgramId: OWNER,
          data: output.data,
        },
        salt,
        0,
      ),
      "encrypted",
    );

    const report = await decryptWithKeys(LocalShieldedKeys.fromKeypair(recipient), {
      wallet,
      transactions: [
        {
          slot: 2n,
          txSignature: SIGNATURE,
          txViewingPublicKey: sender.viewingPublicKey(),
          salt,
          outputSlots: [
            {
              viewTag: recipient.signingPublicKey().confidentialViewTag(),
              outputContext: {
                hash: output.hash(recipient.nullifierPublicKey()),
                tree: TREE,
                leafIndex: 4n,
              },
              payload,
            },
          ],
          messages: [],
          nullifiers: [bytes(32)],
          proofless: false,
        },
      ],
    });

    expect(report).toMatchObject({ storedUtxos: 1, undecryptableCandidates: 0 });
    expect(wallet.utxos()[0]?.utxo.ringProgramId).toBe(OWNER);
  });

  it("opens a ring deposit through the key holder under the ring-deposit label", async () => {
    // A ring deposit carries its own envelope in the published output and is
    // opened under the ring-deposit cipher label, the one request in a sync
    // that is not the transfer cipher. The holder must see that label, and the
    // UTXO it opens is stored ring-bound.
    const recipient = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });
    const envelope = ViewingKey.generate();
    const salt = new Uint8Array(16).fill(5) as Bytes16;
    const blinding = bytes(29);
    const utxo = new Utxo({
      owner: recipient.signingPublicKey(),
      asset: SOL_MINT,
      amount: 7_000_000n,
      blinding,
      data: new Data([{ kind: "ringData", bytes: new Uint8Array() }]),
      ringProgramId: OWNER,
    });
    const ciphertext = envelope.encryptRingDeposit(
      recipient.viewingPublicKey(),
      encodeRingDepositPlaintext({ blinding, ringData: new Uint8Array() }),
      salt,
    );
    const amount = new Uint8Array(8);
    new DataView(amount.buffer).setBigUint64(0, utxo.amount, true);
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, ciphertext.length, true);
    // Borsh `RingDepositOutput`: owner UTXO hash, asset, amount, no data hash,
    // ring, zero ring data hash, then the envelope.
    const body = Uint8Array.from([
      ...bytes(1),
      ...getAddressEncoder().encode(SOL_MINT),
      ...amount,
      0,
      ...getAddressEncoder().encode(OWNER),
      ...new Uint8Array(32),
      ...envelope.publicKey().toBytes(),
      ...salt,
      ...length,
      ...ciphertext,
    ]);
    const seen: Parameters<ShieldedKeys["decrypt"]>[0][] = [];
    const local = LocalShieldedKeys.fromKeypair(recipient);
    const holder: ShieldedKeys = {
      ...remoteOver(local),
      decrypt: (requests) => {
        seen.push(requests);
        return local.decrypt(requests);
      },
    };

    const report = await decryptWithKeys(holder, {
      wallet,
      transactions: [
        {
          slot: 3n,
          txSignature: SIGNATURE,
          outputSlots: [
            {
              viewTag: recipient.viewingPublicKey().x(),
              outputContext: {
                hash: utxo.hash(recipient.nullifierPublicKey()),
                tree: TREE,
                leafIndex: 9n,
              },
              payload: encodeOutputData(EncryptedScheme.ringDeposit, body, "encrypted"),
            },
          ],
          messages: [],
          nullifiers: [],
          proofless: true,
        },
      ],
    });

    expect(report).toMatchObject({ storedUtxos: 1, undecryptableCandidates: 0 });
    expect(seen.flat().map((request) => [request.label, request.slotIndex])).toEqual([
      ["ringDeposit", 0],
    ]);
    expect(wallet.utxos()[0]?.utxo).toEqual(utxo);
    expect(wallet.ringBalances()).toMatchObject([
      { ringProgramId: OWNER, assets: [{ mint: SOL_MINT, amount: 7_000_000n }] },
    ]);
  });

  it("selects the ring confidential marker for a ring output", () => {
    const recipient = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: recipient.shieldedAddress() });
    const slots = encodeConfidentialSlots(
      [
        createProofOutput({
          ownerAddress: recipient.shieldedAddress(),
          asset: SOL_MINT,
          amount: 1n,
          ringProgramId: OWNER,
        }),
      ],
      wallet.registry,
      recipient.viewingKey(),
      new Uint8Array(16) as Bytes16,
    );

    expect(readOutputData(slots[0]?.data ?? new Uint8Array()).scheme).toBe(
      EncryptedScheme.ringConfidential,
    );
  });

  it("records an outbound ring confidential transfer and keeps ring change", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: sender.shieldedAddress() });
    const inputBlinding = bytes(33);
    const input = new Utxo({
      owner: sender.signingPublicKey(),
      asset: SOL_MINT,
      amount: 10n,
      blinding: inputBlinding,
      ringProgramId: OWNER,
    });
    const inputHash = input.hash(sender.nullifierPublicKey());
    const nullifier = sender.nullifier(inputHash, inputBlinding);
    wallet._replace({
      ...wallet._state(),
      utxos: [
        {
          utxo: input,
          outputContext: { hash: inputHash, tree: TREE, leafIndex: 0n },
          nullifier,
          spent: false,
        },
      ],
    });
    const txKey = sender.transactionViewingKey(nullifier);
    const salt = new Uint8Array(16).fill(4) as Bytes16;
    const change = new Utxo({
      owner: sender.signingPublicKey(),
      asset: SOL_MINT,
      amount: 3n,
      blinding: bytes(34),
      ringProgramId: OWNER,
    });
    const payment = new Utxo({
      owner: recipient.signingPublicKey(),
      asset: SOL_MINT,
      amount: 7n,
      blinding: bytes(35),
      ringProgramId: OWNER,
    });
    const changePayload = encodeOutputData(
      EncryptedScheme.ringConfidential,
      encryptConfidential(
        txKey,
        sender.viewingPublicKey(),
        {
          assetId: 1n,
          amount: change.amount,
          blinding: change.blinding,
          ringProgramId: OWNER,
          data: change.data,
        },
        salt,
        0,
      ),
      "encrypted",
    );
    const paymentPayload = encodeOutputData(
      EncryptedScheme.ringConfidential,
      encryptConfidential(
        txKey,
        recipient.viewingPublicKey(),
        {
          assetId: 1n,
          amount: payment.amount,
          blinding: payment.blinding,
          ringProgramId: OWNER,
          data: payment.data,
        },
        salt,
        1,
      ),
      "encrypted",
    );

    await decryptWithKeys(LocalShieldedKeys.fromKeypair(sender), {
      wallet,
      transactions: [
        {
          slot: 3n,
          txSignature: SIGNATURE,
          txViewingPublicKey: txKey.publicKey(),
          salt,
          outputSlots: [
            {
              viewTag: sender.signingPublicKey().confidentialViewTag(),
              outputContext: {
                hash: change.hash(sender.nullifierPublicKey()),
                tree: TREE,
                leafIndex: 1n,
              },
              payload: changePayload,
            },
            {
              viewTag: recipient.signingPublicKey().confidentialViewTag(),
              outputContext: {
                hash: payment.hash(recipient.nullifierPublicKey()),
                tree: TREE,
                leafIndex: 2n,
              },
              payload: paymentPayload,
            },
          ],
          messages: [],
          nullifiers: [nullifier],
          proofless: false,
        },
      ],
    });

    expect(wallet.utxos().find((entry) => !entry.spent)?.utxo.ringProgramId).toBe(OWNER);
    expect(wallet.privateTransactions()).toContainEqual(
      expect.objectContaining({ kind: "privateTransfer", direction: "outbound", amount: 7n }),
    );
  });

  it("ignores a merge whose first nullifier is not owned", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const blinding = new Uint8Array(32).fill(5) as Bytes32;
    const existing = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 42n,
      blinding,
    });
    const hash = existing.hash(keypair.nullifierPublicKey());
    wallet._replace({
      ...wallet._state(),
      utxos: [
        {
          utxo: existing,
          outputContext: { hash, tree: TREE, leafIndex: 0n },
          nullifier: keypair.nullifier(hash, blinding),
          spent: false,
        },
      ],
    });
    const transaction = {
      slot: 1n,
      txSignature: SIGNATURE,
      outputSlots: [
        {
          viewTag: keypair.signingPublicKey().confidentialViewTag(),
          outputContext: {
            hash: bytes(78),
            tree: TREE,
            leafIndex: 1n,
          },
          payload: new Uint8Array(),
        },
      ],
      messages: [],
      nullifiers: Array.from({ length: 8 }, (_, index) => bytes(index + 80)),
      proofless: false,
    } as const;
    const client = syncReads({
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        transactions: [transaction],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        transactions: [],
      })),
    });
    const report = await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(keypair),
      client,
    });

    expect(report).toMatchObject({
      unknownAssetFields: [],
      unknownAssetIds: [],
    });
    expect(report.undecryptableCandidates).toBeGreaterThan(0);
    expect(wallet.balance(SOL_MINT).amount).toBe(42n);
  });

  it("marks a multi-device spend through paginated nullifier lookup", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const entries = [31n, 11n].map((amount, index) => {
      const blinding = bytes(index + 20);
      const utxo = new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding,
      });
      const hash = utxo.hash(keypair.nullifierPublicKey());
      return {
        utxo,
        outputContext: { hash, tree: TREE, leafIndex: BigInt(index) },
        nullifier: keypair.nullifier(hash, blinding),
        spent: index === 1,
      };
    });
    wallet._replace({ ...wallet._state(), utxos: entries });
    const cursor = Uint8Array.of(7);
    const spendingTransaction = {
      slot: 9n,
      txSignature: SIGNATURE,
      outputSlots: [],
      messages: [],
      nullifiers: [entries[0]!.nullifier],
      proofless: false,
    } as const;
    const getShieldedTransactionsByTags = vi.fn(async () => ({
      context: { blockTime: 1n, slot: 0n },
      transactions: [],
    }));
    const getEncryptedUtxosByTags = vi.fn(async () => ({
      context: { blockTime: 1n, slot: 0n },
      matches: [],
    }));
    const getShieldedTransactionsByNullifiers = vi
      .fn()
      .mockResolvedValueOnce({
        context: { blockTime: 1n, slot: 0n },
        transactions: [],
        nextCursor: cursor,
      })
      .mockResolvedValueOnce({
        context: { blockTime: 1n, slot: 0n },
        transactions: [spendingTransaction],
      });
    const client = syncReads({
      getShieldedTransactionsByTags,
      getEncryptedUtxosByTags,
      getShieldedTransactionsByNullifiers,
    });

    await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(keypair),
      client,
    });

    expect(wallet.utxos().every((entry) => entry.spent)).toBe(true);
    expect(getShieldedTransactionsByTags).toHaveBeenCalledOnce();
    expect(getEncryptedUtxosByTags).toHaveBeenCalledOnce();
    expect(getShieldedTransactionsByNullifiers).toHaveBeenCalledTimes(2);
    // entries[1] was already known spent, so it is not asked about again: a
    // nullifier appears at most once on chain, and that answer is already in
    // hand. Only the unspent entries[0] is still an open question.
    const unspent = [entries[0]!.nullifier];
    expect(getShieldedTransactionsByNullifiers.mock.calls[0]?.[0]).toMatchObject({
      nullifiers: unspent,
      limit: 1000,
    });
    expect(getShieldedTransactionsByNullifiers.mock.calls[1]?.[0]).toMatchObject({
      nullifiers: unspent,
      cursor,
      limit: 1000,
    });
  });

  it("does not ask about UTXOs already known spent", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const entries = [31n, 11n, 17n].map((amount, index) => {
      const blinding = bytes(index + 40);
      const utxo = new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding,
      });
      const hash = utxo.hash(keypair.nullifierPublicKey());
      return {
        utxo,
        outputContext: { hash, tree: TREE, leafIndex: BigInt(index) },
        nullifier: keypair.nullifier(hash, blinding),
        // Only the last UTXO is still unspent.
        spent: index < 2,
      };
    });
    wallet._replace({ ...wallet._state(), utxos: entries });

    const getShieldedTransactionsByNullifiers = vi.fn(
      async (_request: Readonly<{ nullifiers: readonly Bytes32[] }>) => ({
        context: { blockTime: 1n, slot: 0n },
        transactions: [],
      }),
    );
    const client = syncReads({
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        transactions: [],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers,
    });

    await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(keypair),
      client,
    });

    // One request carrying one nullifier -- not three, and not one request per
    // UTXO the wallet has ever held.
    expect(getShieldedTransactionsByNullifiers).toHaveBeenCalledOnce();
    expect(getShieldedTransactionsByNullifiers.mock.calls[0]?.[0]).toMatchObject({
      nullifiers: [entries[2]!.nullifier],
    });
  });

  it("resumes the nullifier stream from where the indexer said it scanned to", async () => {
    // The rows cannot supply this. An unspent UTXO matches nothing, so there is
    // no last row whose position could be remembered, and every sync would walk
    // the whole stream again.
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    // Blinding is a field element, so the leading byte has to stay below the
    // BN254 modulus -- 51 (0x33) does not.
    const blinding = bytes(23);
    const utxo = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 5n,
      blinding,
    });
    const hash = utxo.hash(keypair.nullifierPublicKey());
    const nullifier = keypair.nullifier(hash, blinding);
    wallet._replace({
      ...wallet._state(),
      utxos: [
        { utxo, outputContext: { hash, tree: TREE, leafIndex: 0n }, nullifier, spent: false },
      ],
    });

    const scannedThrough = Uint8Array.of(4, 2);
    const getShieldedTransactionsByNullifiers = vi.fn(
      async (_request: Readonly<{ nullifiers: readonly Bytes32[]; cursor?: Uint8Array }>) => ({
        context: { blockTime: 1n, slot: 0n },
        transactions: [],
        scannedThrough,
      }),
    );
    const client = syncReads({
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        transactions: [],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers,
    });
    const keys = LocalShieldedKeys.fromKeypair(keypair);

    await syncWallet({ wallet, keys, client });
    expect(getShieldedTransactionsByNullifiers.mock.calls[0]?.[0]?.cursor).toBeUndefined();

    getShieldedTransactionsByNullifiers.mockClear();
    await syncWallet({ wallet, keys, client });
    expect(getShieldedTransactionsByNullifiers.mock.calls[0]?.[0]?.cursor).toEqual(scannedThrough);
  });

  it("rejects a non-advancing nullifier cursor", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const blinding = bytes(30);
    const utxo = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 1n,
      blinding,
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
    const cursor = Uint8Array.of(8);
    const getShieldedTransactionsByNullifiers = vi.fn(async () => ({
      context: { blockTime: 1n, slot: 0n },
      transactions: [],
      nextCursor: cursor,
    }));

    await expect(
      syncWallet({
        wallet,
        keys: LocalShieldedKeys.fromKeypair(keypair),
        client: syncReads({
          getShieldedTransactionsByTags: vi.fn(async () => ({
            context: { blockTime: 1n, slot: 0n },
            transactions: [],
          })),
          getEncryptedUtxosByTags: vi.fn(async () => ({
            context: { blockTime: 1n, slot: 0n },
            matches: [],
          })),
          getShieldedTransactionsByNullifiers,
        }),
      }),
    ).rejects.toMatchObject({
      code: "WALLET_SYNC",
      causeCode: "CLIENT_INVALID_RPC_RESPONSE",
    });
    expect(getShieldedTransactionsByNullifiers).toHaveBeenCalledTimes(2);
  });

  it("performs one follow-up nullifier lookup for a newly discovered UTXO", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const blinding = bytes(33);
    const utxo = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 42n,
      blinding,
    });
    const hash = utxo.hash(keypair.nullifierPublicKey());
    const nullifier = keypair.nullifier(hash, blinding);
    const outputSlot = {
      viewTag: keypair.viewingKey().recipientBootstrapViewTag(),
      outputContext: { hash, tree: TREE, leafIndex: 4n },
      payload: encodeOutputData(
        EncryptedScheme.proofless,
        encodeProofless({
          owner: keypair.signingPublicKey().ownerProofInputHash(),
          blinding,
          asset: SOL_MINT,
          amount: 42n,
        }),
        "plaintext",
      ),
    };
    const spendingTransaction = {
      slot: 10n,
      txSignature: SIGNATURE,
      outputSlots: [],
      messages: [],
      nullifiers: [nullifier],
      proofless: false,
    } as const;
    const getShieldedTransactionsByNullifiers = vi.fn(
      async (_request: Readonly<{ nullifiers: readonly Bytes32[] }>) => ({
        context: { blockTime: 1n, slot: 0n },
        transactions: [spendingTransaction],
      }),
    );
    const client = syncReads({
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        transactions: [],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        matches: [{ slot: 9n, txSignature: SIGNATURE, outputSlot }],
      })),
      getShieldedTransactionsByNullifiers,
    });

    await syncWallet({
      wallet,
      keys: LocalShieldedKeys.fromKeypair(keypair),
      client,
    });

    expect(getShieldedTransactionsByNullifiers).toHaveBeenCalledOnce();
    expect(getShieldedTransactionsByNullifiers.mock.calls[0]?.[0]).toMatchObject({
      nullifiers: [nullifier],
      limit: 1000,
    });
    expect(wallet.utxos()).toHaveLength(1);
    expect(wallet.utxos()[0]?.spent).toBe(true);
  });

  it("rejects a non-advancing indexer cursor", async () => {
    const keypair = ShieldedKeypair.generate();
    const cursor = Uint8Array.of(9);
    const getShieldedTransactionsByTags = vi.fn(async () => ({
      context: { blockTime: 1n, slot: 0n },
      transactions: [],
      nextCursor: cursor,
    }));
    const client = syncReads({
      getShieldedTransactionsByTags,
      getEncryptedUtxosByTags: vi.fn(),
    });

    await expect(
      syncWallet({
        wallet: new Wallet({ identity: keypair.shieldedAddress() }),
        keys: LocalShieldedKeys.fromKeypair(keypair),
        client,
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
    const client = syncReads({
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        transactions: [transaction(1), transaction(2)],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n, slot: 0n },
        matches: [],
      })),
    });

    const report = await syncWallet({
      wallet: new Wallet({ identity: keypair.shieldedAddress() }),
      keys: LocalShieldedKeys.fromKeypair(keypair),
      client,
    });

    expect(report.unparsedTransactions).toBe(2);
  });
});
