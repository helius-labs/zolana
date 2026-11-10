import { address, type Address, type Signature } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import type { EncryptedUtxoMatch } from "../src/client/rpc.js";
import { bytesKey } from "../src/interface/bytes.js";
import { DEFAULT_TREE_ID, type Bytes16, type Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair, X25519PublicKey } from "../src/keypair/index.js";
import { mergeOutputKey } from "../src/keypair/merge/index.js";
import { SOL_ASSET_ID } from "../src/transaction/asset.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";
import {
  Data,
  LocalShieldedKeys,
  SOL_MINT,
  Utxo,
  Wallet,
  type ShieldedKeys,
} from "../src/transaction/index.js";
import {
  EncryptedScheme,
  encodeOutputData,
  encodeProofless,
  encryptConfidential,
  type ConfidentialOutputPlaintext,
} from "../src/transaction/serialization/codecs.js";
import {
  encodeMergeOutputData,
  encryptMergeOutput,
} from "../src/transaction/serialization/merge.js";
import { syncWallet } from "../src/wallet/sync.js";
import { solanaRpcReads, syncReads } from "./helpers/clients.js";
import { outputItems, transactionItems } from "./helpers/pages.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
/** A mint no asset registration names. */
const UNREGISTERED_MINT = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
/** The slot every indexer page is read through. */
const TIP = 10n;
const CRAFTED_SLOT = 3n;

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

/** 63 zero bytes then `value`: a valid signature that orders by `value`. */
function signature(value: number): Signature {
  return `${"1".repeat(63)}${String(value + 1)}` as Signature;
}

function salt(value: number): Bytes16 {
  return new Uint8Array(16).fill(value) as Bytes16;
}

/** Above the BN254 modulus, so no commitment can be computed over it. */
const NON_CANONICAL = bytes(0xff);

interface Scan {
  readonly transactions: readonly IndexedShieldedTransaction[];
  readonly deposits: readonly EncryptedUtxoMatch[];
}

interface Fixture {
  readonly keypair: ShieldedKeypair;
  readonly identityTag: Bytes32;
  /** A real 42 lamport confidential transfer to the wallet. */
  readonly real: IndexedShieldedTransaction;
}

function fixture(): Fixture {
  const keypair = ShieldedKeypair.generate();
  const sender = ShieldedKeypair.generate();
  const identityTag = keypair.signingPublicKey().confidentialViewTag();
  const envelopeSalt = salt(3);
  const utxo = new Utxo({
    owner: keypair.signingPublicKey(),
    asset: SOL_MINT,
    amount: 42n,
    blinding: bytes(31),
  });
  const real: IndexedShieldedTransaction = {
    slot: 2n,
    txSignature: signature(2),
    txViewingPublicKey: sender.viewingPublicKey(),
    salt: envelopeSalt,
    outputSlots: [
      {
        viewTag: identityTag,
        outputContext: {
          hash: utxo.hash(keypair.nullifierPublicKey(), DEFAULT_TREE_ID),
          tree: TREE,
          leafIndex: 0n,
        },
        payload: encodeOutputData(
          EncryptedScheme.confidential,
          encryptConfidential(
            sender,
            keypair.viewingPublicKey(),
            {
              assetId: SOL_ASSET_ID,
              amount: utxo.amount,
              blinding: utxo.blinding,
              data: utxo.data,
            },
            envelopeSalt,
            0,
          ),
          "encrypted",
        ),
      },
    ],
    messages: [],
    nullifiers: [bytes(40)],
    proofless: false,
  };
  sender.destroy();
  return { keypair, identityTag, real };
}

/**
 * A confidential slot under the wallet's identity tag, encrypted to its
 * viewing key by a stranger. Nothing on chain checks the plaintext.
 */
function craftedConfidential(
  recipient: ShieldedKeypair,
  plaintext: ConfidentialOutputPlaintext,
): IndexedShieldedTransaction {
  const attacker = ShieldedKeypair.generate();
  const envelopeSalt = salt(4);
  try {
    return {
      slot: CRAFTED_SLOT,
      txSignature: signature(3),
      txViewingPublicKey: attacker.viewingPublicKey(),
      salt: envelopeSalt,
      outputSlots: [
        {
          viewTag: recipient.signingPublicKey().confidentialViewTag(),
          outputContext: { hash: bytes(77), tree: TREE, leafIndex: 1n },
          payload: encodeOutputData(
            EncryptedScheme.confidential,
            encryptConfidential(attacker, recipient.viewingPublicKey(), plaintext, envelopeSalt, 0),
            "encrypted",
          ),
        },
      ],
      messages: [],
      nullifiers: [bytes(41)],
      proofless: false,
    };
  } finally {
    attacker.destroy();
  }
}

/** A transaction with no viewing key and no salt, one slot under the wallet's identity tag. */
function envelopeless(identityTag: Bytes32, payload: Uint8Array): IndexedShieldedTransaction {
  return {
    slot: CRAFTED_SLOT,
    txSignature: signature(3),
    outputSlots: [
      {
        viewTag: identityTag,
        outputContext: { hash: bytes(78), tree: TREE, leafIndex: 1n },
        payload,
      },
    ],
    messages: [],
    // A nullifier this wallet never held.
    nullifiers: [bytes(42)],
    proofless: false,
  };
}

/** Another wallet's well-formed merge output. */
function foreignMergePayload(): Uint8Array {
  const other = ShieldedKeypair.generate();
  const nullifierKey = other.nullifierKey();
  const mergeSalt = salt(11);
  try {
    return encodeMergeOutputData({
      salt: mergeSalt,
      ciphertext: encryptMergeOutput(
        { amount: 42n, mint: SOL_MINT },
        mergeOutputKey(nullifierKey, bytes(42)),
        mergeSalt,
      ),
    });
  } finally {
    nullifierKey.destroy();
    other.destroy();
  }
}

/**
 * A plaintext deposit-shaped slot under the wallet's bootstrap tag in a
 * transaction with no viewing key and no salt, which the indexer serves as a
 * proofless deposit.
 */
function craftedDeposit(
  recipient: ShieldedKeypair,
  output: Readonly<{ asset: Address; amount: bigint; blinding: Bytes32; hash: Bytes32 }>,
): EncryptedUtxoMatch {
  return {
    slot: CRAFTED_SLOT,
    txSignature: signature(4),
    outputSlot: {
      viewTag: recipient.viewingPublicKey().x(),
      outputContext: { hash: output.hash, tree: TREE, leafIndex: 2n },
      payload: encodeOutputData(
        EncryptedScheme.proofless,
        encodeProofless({
          owner: bytes(1),
          blinding: output.blinding,
          asset: output.asset,
          amount: output.amount,
        }),
        "plaintext",
      ),
    },
  };
}

interface RequestWithFloor {
  readonly filters?: Readonly<{ slot?: Readonly<{ gt?: bigint }> }>;
}

function above<T extends { readonly slot: bigint }>(
  items: readonly T[],
  request: RequestWithFloor,
): readonly T[] {
  const floor = request.filters?.slot?.gt;
  return items.filter((item) => floor === undefined || item.slot > floor);
}

/** An indexer serving `scan` through slot `TIP` and an RPC listing no SPL registration. */
function client(scan: Scan) {
  const page = { context: { blockTime: 1n, slot: TIP }, paginationToken: null };
  const getProgramAccounts = vi.fn((_program: unknown, _config: unknown) => ({
    send: async () => [],
  }));
  const getShieldedTransactionsByTags = vi.fn(async (request: RequestWithFloor) => ({
    ...page,
    data: transactionItems(above(scan.transactions, request)),
  }));
  const getEncryptedUtxosByTags = vi.fn(async (request: RequestWithFloor) => ({
    ...page,
    data: outputItems(above(scan.deposits, request)),
  }));
  return {
    getProgramAccounts,
    getShieldedTransactionsByTags,
    getEncryptedUtxosByTags,
    sync: syncReads({
      commitment: "confirmed",
      solanaRpc: solanaRpcReads({ getProgramAccounts }),
      getShieldedTransactionsByTags,
      getEncryptedUtxosByTags,
      getShieldedTransactionsByNullifiers: vi.fn(async () => ({
        ...page,
        data: transactionItems([]),
      })),
    }),
  };
}

/**
 * Syncs a wallet over its real transfer and one crafted output, then again:
 * both syncs commit, the real output is held and every checkpoint reaches the
 * tip.
 */
async function syncPastCrafted(
  setup: Fixture,
  crafted: Partial<Scan>,
  keys: ShieldedKeys = LocalShieldedKeys.fromKeypair(setup.keypair),
) {
  const { keypair, identityTag, real } = setup;
  const wallet = new Wallet({ identity: keypair.shieldedAddress() });
  const reads = client({
    transactions: [real, ...(crafted.transactions ?? [])],
    deposits: crafted.deposits ?? [],
  });

  const report = await syncWallet({ wallet, keys, client: reads.sync });

  expect(report.storedUtxos).toBe(1);
  // The crafted output is counted, as undecryptable or, when no slot parses,
  // as an unparsed transaction.
  expect(report.undecryptableCandidates + report.unparsedTransactions).toBe(1);
  expect(wallet.utxos().map((entry) => entry.outputContext)).toEqual([
    real.outputSlots[0]!.outputContext,
  ]);
  expect(wallet.balance(SOL_MINT).amount).toBe(42n);
  const tags = [identityTag, keypair.viewingPublicKey().x()].map(bytesKey);
  for (const stream of ["transactions", "proofless"] as const) {
    for (const tag of tags) expect(wallet._syncCheckpoint(stream, tag)).toBe(TIP);
  }
  expect(wallet.lastSynced).toBeGreaterThan(0n);

  reads.getShieldedTransactionsByTags.mockClear();
  reads.getEncryptedUtxosByTags.mockClear();
  const again = await syncWallet({ wallet, keys, client: reads.sync });
  expect(again.storedUtxos).toBe(0);
  for (const query of [reads.getShieldedTransactionsByTags, reads.getEncryptedUtxosByTags]) {
    expect(query.mock.calls.map(([request]) => request.filters?.slot?.gt)).toEqual([TIP]);
  }
  expect(wallet.balance(SOL_MINT).amount).toBe(42n);
  return { report, reads };
}

describe("a crafted output does not stop a wallet's sync", () => {
  it("skips an output naming an asset id no registration has", async () => {
    const setup = fixture();
    const crafted = craftedConfidential(setup.keypair, {
      assetId: 777n,
      amount: 5n,
      blinding: bytes(9),
      data: new Data(),
    });

    const { report, reads } = await syncPastCrafted(setup, { transactions: [crafted] });

    expect(report.unknownAssetIds).toEqual([777n]);
    // The registry is read at or past every fetched transaction, so an id it
    // lacks names no asset an output there could hold.
    expect(reads.getProgramAccounts).toHaveBeenCalledOnce();
    expect(reads.getProgramAccounts.mock.calls[0]?.[1]).toMatchObject({
      minContextSlot: CRAFTED_SLOT,
    });
  });

  it.each([
    ["another wallet's merge output", foreignMergePayload],
    [
      "a confidential slot",
      (keypair: ShieldedKeypair) =>
        encodeOutputData(
          EncryptedScheme.confidential,
          Uint8Array.from([...keypair.viewingPublicKey().toBytes(), ...new Uint8Array(80)]),
          "encrypted",
        ),
    ],
    ["an empty payload", () => new Uint8Array()],
  ])(
    "skips %s under the identity tag of a transaction with no viewing key and salt",
    async (_name, payloadFor) => {
      const setup = fixture();
      await syncPastCrafted(setup, {
        transactions: [envelopeless(setup.identityTag, payloadFor(setup.keypair))],
      });
    },
  );

  it("skips a confidential output whose blinding is not a field element", async () => {
    const setup = fixture();
    await syncPastCrafted(setup, {
      transactions: [
        craftedConfidential(setup.keypair, {
          assetId: SOL_ASSET_ID,
          amount: 5n,
          blinding: NON_CANONICAL,
          data: new Data(),
        }),
      ],
    });
  });

  it("skips a deposit whose blinding is not a field element", async () => {
    const setup = fixture();
    await syncPastCrafted(setup, {
      deposits: [
        craftedDeposit(setup.keypair, {
          asset: SOL_MINT,
          amount: 5n,
          blinding: NON_CANONICAL,
          hash: bytes(79),
        }),
      ],
    });
  });

  it("skips a zero-amount output of a mint no registration names", async () => {
    // The commitment is genuine: a transfer may append a zero-amount output of
    // any mint, and the circuit balances it.
    const setup = fixture();
    const blinding = bytes(9);
    const worthless = new Utxo({
      owner: setup.keypair.signingPublicKey(),
      asset: UNREGISTERED_MINT,
      amount: 0n,
      blinding,
    });
    await syncPastCrafted(setup, {
      deposits: [
        craftedDeposit(setup.keypair, {
          asset: UNREGISTERED_MINT,
          amount: 0n,
          blinding,
          hash: worthless.hash(setup.keypair.nullifierPublicKey(), DEFAULT_TREE_ID),
        }),
      ],
    });
  });

  it("still holds the checkpoints past a valued deposit of a mint the registry cannot name", async () => {
    // Only a registered mint carries value, so the registry read was behind:
    // committing would skip the deposit for good.
    const { keypair, real } = fixture();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    const blinding = bytes(9);
    const valued = new Utxo({
      owner: keypair.signingPublicKey(),
      asset: UNREGISTERED_MINT,
      amount: 5n,
      blinding,
    });
    const reads = client({
      transactions: [real],
      deposits: [
        craftedDeposit(keypair, {
          asset: UNREGISTERED_MINT,
          amount: 5n,
          blinding,
          hash: valued.hash(keypair.nullifierPublicKey(), DEFAULT_TREE_ID),
        }),
      ],
    });
    const before = wallet._state();

    await expect(
      syncWallet({ wallet, keys: LocalShieldedKeys.fromKeypair(keypair), client: reads.sync }),
    ).rejects.toMatchObject({ code: "WALLET_SYNC", causeCode: "WALLET_UNRESOLVED_ASSET" });
    expect(wallet._state()).toEqual(before);
    expect(
      wallet._syncCheckpoint("proofless", bytesKey(keypair.viewingPublicKey().x())),
    ).toBeUndefined();
  });

  it("asks no key holder to open a slot addressed to a key the wallet does not hold", async () => {
    const setup = fixture();
    const local = LocalShieldedKeys.fromKeypair(setup.keypair);
    const opened: X25519PublicKey[][] = [];
    const keys: ShieldedKeys = {
      address: () => local.address(),
      viewingPublicKeys: () => local.viewingPublicKeys(),
      decrypt: (requests) => {
        opened.push(requests.map((request) => request.viewingPublicKey));
        return local.decrypt(requests);
      },
      derive: (requests) => local.derive(requests),
      transactionKeys: (requests) => local.transactionKeys(requests),
    };
    const stranger = ShieldedKeypair.generate();
    const misaddressed = craftedConfidential(stranger, {
      assetId: SOL_ASSET_ID,
      amount: 5n,
      blinding: bytes(9),
      data: new Data(),
    });
    stranger.destroy();
    const crafted = {
      ...misaddressed,
      outputSlots: misaddressed.outputSlots.map((slot) => ({
        ...slot,
        viewTag: setup.identityTag,
      })),
    };

    const { report } = await syncPastCrafted(setup, { transactions: [crafted] }, keys);

    expect(report.undecryptableCandidates).toBe(1);
    // One batch opens the real transfer; the misaddressed slot is never sent.
    expect(opened).toEqual([[setup.keypair.viewingPublicKey()]]);
  });
});
