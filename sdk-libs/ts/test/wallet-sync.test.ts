import { address, getAddressEncoder, getBase64Decoder, type Signature } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ZolanaClient } from "../src/client/index.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import { mergeDummyNullifier, mergeOutputBlinding } from "../src/keypair/merge/index.js";
import { SHIELDED_POOL_PROGRAM_ID, type Bytes16, type Bytes32 } from "../src/interface/index.js";
import { StateDiscriminator } from "../src/interface/state.js";
import {
  Data,
  LocalWalletAuthority,
  SOL_MINT,
  Utxo,
  Wallet,
  decryptTransactions,
} from "../src/transaction/index.js";
import {
  EncryptedScheme,
  encodeOutputData,
  encodeProofless,
} from "../src/transaction/serialization/codecs.js";
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
      getShieldedTransactionsByNullifiers: vi.fn(),
    } as unknown as ZolanaClient;

    const report = await syncWallet({
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
      client,
    });

    expect(wallet.lastSynced).toBe(1_700_000_000n);
    expect(report).toMatchObject({ storedUtxos: 0, unparsedTransactions: 0 });
  });

  it("resumes each tag stream from where it was read to", async () => {
    // Without this every sync re-reads the wallet's whole history: 569 ECDH
    // operations for a wallet holding a handful of notes, growing forever.
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const cursor = Uint8Array.of(1, 2, 3);
    // One page carrying a cursor, then the end. Repeating a cursor would trip
    // the SDK's loop guard, which is a different behaviour under test.
    let served = 0;
    const getShieldedTransactionsByTags = vi.fn(async () => {
      served += 1;
      return {
        context: { blockTime: 1_700_000_000n },
        transactions: [],
        ...(served === 1 ? { nextCursor: cursor } : {}),
      };
    });
    const client = {
      getShieldedTransactionsByTags,
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1_700_000_000n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers: vi.fn(),
    } as unknown as ZolanaClient;
    const authority = new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair });

    await syncWallet({ wallet, authority, client });
    const calls = () =>
      getShieldedTransactionsByTags.mock.calls as unknown as [{ cursor?: Uint8Array }][];
    const firstCall = calls()[0]?.[0];
    expect(firstCall?.cursor).toBeUndefined();

    getShieldedTransactionsByTags.mockClear();
    await syncWallet({ wallet, authority, client });
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

    const getShieldedTransactionsByTags = vi.fn(async () => ({
      context: { blockTime: 1_700_000_000n },
      transactions: [],
    }));
    const client = {
      getShieldedTransactionsByTags,
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1_700_000_000n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers: vi.fn(),
    } as unknown as ZolanaClient;

    await syncWallet({
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
      client,
    });

    // The wallet's real tags have no watermark, so every query starts at the
    // beginning -- the unrelated tag's cursor must not leak into them.
    for (const call of getShieldedTransactionsByTags.mock.calls as unknown as [
      { cursor?: Uint8Array },
    ][]) {
      expect(call[0]?.cursor).toBeUndefined();
    }
  });

  it("filters registry backfill before downloading program accounts", async () => {
    const keypair = ShieldedKeypair.generate();
    const send = vi.fn(async () => []);
    const getProgramAccounts = vi.fn(() => ({ send }));
    const client = {
      commitment: "confirmed",
      solanaRpc: { getProgramAccounts },
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
    const client = {
      commitment: "confirmed",
      solanaRpc: { getProgramAccounts: () => ({ send }) },
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        transactions: [],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers: vi.fn(async () => ({
        context: { blockTime: 1n },
        transactions: [],
      })),
    } as unknown as ZolanaClient;

    const report = await syncWallet({
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
      client,
    });

    expect(report.unknownAssetIds).toEqual([]);
    expect(send).toHaveBeenCalledOnce();
    expect(wallet.registry.entries()).toContainEqual([2n, SPL_MINT]);
    expect(wallet.balance(SPL_MINT)).toMatchObject({ assetId: 2n, amount: 42n });
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
    const client = {
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        transactions: [transaction],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers: vi.fn(async () => ({
        context: { blockTime: 1n },
        transactions: [],
      })),
    } as unknown as ZolanaClient;
    const authority = {
      syncMaterial: async () => ({
        identity: keypair.shieldedAddress(),
        viewingKeys: [keypair.viewingKey()],
        nullifierKey: keypair.nullifierKey(),
      }),
    } as never;

    const report = await syncWallet({
      wallet,
      authority,
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
      context: { blockTime: 1n },
      transactions: [],
    }));
    const getEncryptedUtxosByTags = vi.fn(async () => ({
      context: { blockTime: 1n },
      matches: [],
    }));
    const getShieldedTransactionsByNullifiers = vi
      .fn()
      .mockResolvedValueOnce({
        context: { blockTime: 1n },
        transactions: [],
        nextCursor: cursor,
      })
      .mockResolvedValueOnce({
        context: { blockTime: 1n },
        transactions: [spendingTransaction],
      });
    const client = {
      getShieldedTransactionsByTags,
      getEncryptedUtxosByTags,
      getShieldedTransactionsByNullifiers,
    } as unknown as ZolanaClient;

    await syncWallet({
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
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

  it("does not ask about notes already known spent", async () => {
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
        // Only the last note is still unspent.
        spent: index < 2,
      };
    });
    wallet._replace({ ...wallet._state(), utxos: entries });

    const getShieldedTransactionsByNullifiers = vi.fn(
      async (_request: Readonly<{ nullifiers: readonly Bytes32[] }>) => ({
        context: { blockTime: 1n },
        transactions: [],
      }),
    );
    const client = {
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        transactions: [],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers,
    } as unknown as ZolanaClient;

    await syncWallet({
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
      client,
    });

    // One request carrying one nullifier -- not three, and not one request per
    // note the wallet has ever held.
    expect(getShieldedTransactionsByNullifiers).toHaveBeenCalledOnce();
    expect(getShieldedTransactionsByNullifiers.mock.calls[0]?.[0]).toMatchObject({
      nullifiers: [entries[2]!.nullifier],
    });
  });

  it("resumes the nullifier stream from where the indexer said it scanned to", async () => {
    // The rows cannot supply this: an unspent note matches nothing, so there is
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
        context: { blockTime: 1n },
        transactions: [],
        scannedThrough,
      }),
    );
    const client = {
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        transactions: [],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        matches: [],
      })),
      getShieldedTransactionsByNullifiers,
    } as unknown as ZolanaClient;
    const authority = new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair });

    await syncWallet({ wallet, authority, client });
    expect(getShieldedTransactionsByNullifiers.mock.calls[0]?.[0]?.cursor).toBeUndefined();

    getShieldedTransactionsByNullifiers.mockClear();
    await syncWallet({ wallet, authority, client });
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
      context: { blockTime: 1n },
      transactions: [],
      nextCursor: cursor,
    }));

    await expect(
      syncWallet({
        wallet,
        authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
        client: {
          getShieldedTransactionsByTags: vi.fn(async () => ({
            context: { blockTime: 1n },
            transactions: [],
          })),
          getEncryptedUtxosByTags: vi.fn(async () => ({
            context: { blockTime: 1n },
            matches: [],
          })),
          getShieldedTransactionsByNullifiers,
        } as unknown as ZolanaClient,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_SYNC",
      causeCode: "CLIENT_INVALID_RPC_RESPONSE",
    });
    expect(getShieldedTransactionsByNullifiers).toHaveBeenCalledTimes(2);
  });

  it("performs one follow-up nullifier lookup for a newly discovered note", async () => {
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
          owner: keypair.signingPublicKey().ownerPublicKeyField(),
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
        context: { blockTime: 1n },
        transactions: [spendingTransaction],
      }),
    );
    const client = {
      getShieldedTransactionsByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        transactions: [],
      })),
      getEncryptedUtxosByTags: vi.fn(async () => ({
        context: { blockTime: 1n },
        matches: [{ slot: 9n, txSignature: SIGNATURE, outputSlot }],
      })),
      getShieldedTransactionsByNullifiers,
    } as unknown as ZolanaClient;

    await syncWallet({
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
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
    });

    expect(report.unparsedTransactions).toBe(2);
  });
});
