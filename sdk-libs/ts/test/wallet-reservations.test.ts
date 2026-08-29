import { address, type Address, type Transaction } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AuthorizedPrivateTransaction, ZolanaClient } from "../src/client/client.js";
import type { Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import {
  Data,
  KeypairWalletAuthority,
  SOL_MINT,
  Utxo,
  Wallet,
  deserializeWallet,
  serializeWallet,
} from "../src/transaction/index.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import { createSplit, createTransfer } from "../src/wallet/actions.js";
import { createMerge, MergeMaterial } from "../src/wallet/merge.js";
import { buildTransferTransaction } from "../src/wallet/transactions.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const TRANSACTION = Object.freeze({
  messageBytes: new Uint8Array(),
  signatures: Object.freeze({}),
}) as unknown as Transaction;

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function spendingKeypair(): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(42)));
}

function fundedWallet(
  keypair: ShieldedKeypair,
  amounts: readonly bigint[],
  ringBound: readonly number[] = [],
): Wallet {
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry([]),
  });
  wallet._replace({
    utxos: amounts.map((amount, index) =>
      walletUtxo(keypair, amount, index, ringBound.includes(index)),
    ),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

function walletUtxo(keypair: ShieldedKeypair, amount: bigint, index: number, ringBound = false) {
  return {
    utxo: new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount,
      blinding: new Uint8Array(32).fill(index + 1) as Bytes32,
      data: new Data(),
      ...(ringBound ? { ringProgramId: PAYER } : {}),
    }),
    outputContext: {
      hash: filled(index + 1),
      tree: TREE,
      leafIndex: BigInt(index),
    },
    nullifier: filled(index + 20),
    spent: false,
  };
}

function transferParams(wallet: Wallet, amount: bigint) {
  return {
    wallet,
    payer: PAYER,
    recipient: ShieldedKeypair.generate().shieldedAddress(),
    asset: SOL_MINT as Address,
    amount,
  };
}

function buildParams(client: ZolanaClient, wallet: Wallet, keypair: ShieldedKeypair) {
  return {
    client,
    wallet,
    authority: new KeypairWalletAuthority({
      solanaPublicKey: keypair.shieldedAddress().solanaAddress(),
      keypair,
    }),
    feePayer: keypair.shieldedAddress().solanaAddress(),
    recipient: ShieldedKeypair.generate().shieldedAddress(),
    amount: 3n,
  };
}

function assemblingClient(): Readonly<{
  client: ZolanaClient;
  assemble: ReturnType<typeof vi.fn>;
}> {
  const assemble = vi.fn(
    async (_input: Readonly<{ authorized: AuthorizedPrivateTransaction }>) => TRANSACTION,
  );
  return {
    client: {
      tree: TREE,
      getAccount: vi.fn(async () => undefined),
      assembleAuthorizedPrivateTransaction: assemble,
    } as unknown as ZolanaClient,
    assemble,
  };
}

describe("note reservations", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("holds created inputs against a second selection", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    await createTransfer(transferParams(wallet, 3n));
    await expect(createTransfer(transferParams(wallet, 3n))).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
      causeCode: "WALLET_INSUFFICIENT_BALANCE",
    });
  });

  it("lets exactly one of two concurrent builds spend a note", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    const { client, assemble } = assemblingClient();
    const results = await Promise.allSettled([
      buildTransferTransaction(buildParams(client, wallet, keypair)),
      buildTransferTransaction(buildParams(client, wallet, keypair)),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(assemble).toHaveBeenCalledTimes(1);
    const failed = results.find((result) => result.status === "rejected");
    expect(failed?.reason).toMatchObject({
      code: "WALLET_BUILD_TRANSFER",
      causeCodes: ["WALLET_CREATE_TRANSFER", "WALLET_INSUFFICIENT_BALANCE"],
    });
  });

  it("releases the reservation when the build fails", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    const { client, assemble } = assemblingClient();
    assemble.mockRejectedValueOnce(new Error("assembly down"));
    await expect(
      buildTransferTransaction(buildParams(client, wallet, keypair)),
    ).rejects.toMatchObject({ code: "WALLET_BUILD_TRANSFER" });
    await expect(createTransfer(transferParams(wallet, 3n))).resolves.toBeDefined();
  });

  it("frees the notes after the reservation expires", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    await createTransfer(transferParams(wallet, 3n));
    now.mockReturnValue(1_000_000 + 119_999);
    await expect(createTransfer(transferParams(wallet, 3n))).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
    });
    now.mockReturnValue(1_000_000 + 120_000);
    await expect(createTransfer(transferParams(wallet, 3n))).resolves.toBeDefined();
  });

  it("drops the reservation when sync marks its note spent", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    await createTransfer(transferParams(wallet, 3n));
    expect(wallet._reservationEntries()).toHaveLength(1);
    wallet._replace({
      utxos: [{ ...walletUtxo(keypair, 5n, 0), spent: true }],
      transactions: [],
      nullifiers: new Set(),
    });
    expect(wallet._reservationEntries()).toHaveLength(0);
  });

  it("round-trips reservations through serialization", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    await createTransfer(transferParams(wallet, 3n));
    const serialized = serializeWallet(wallet);
    const restored = deserializeWallet(serialized);
    await expect(createTransfer(transferParams(restored, 3n))).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
      causeCode: "WALLET_INSUFFICIENT_BALANCE",
    });
    const { reservations, ...withoutReservations } = JSON.parse(serialized) as Record<
      string,
      unknown
    >;
    expect(reservations).toHaveLength(1);
    const accepted = deserializeWallet(JSON.stringify(withoutReservations));
    await expect(createTransfer(transferParams(accepted, 3n))).resolves.toBeDefined();
  });

  it("releases at once when merge preparation refuses the notes", () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [6n, 4n], [1]);
    expect(() =>
      createMerge({
        wallet,
        material: MergeMaterial.fromKeypair(keypair),
        asset: SOL_MINT,
        inputs: [filled(1), filled(2)],
      }),
    ).toThrowError(expect.objectContaining({ code: "TRANSACTION_MERGE_INPUT_RING_MISMATCH" }));
    expect(wallet._reservationEntries()).toHaveLength(0);
  });

  it("refuses named inputs another build reserved", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [6n, 4n]);
    await createTransfer(transferParams(wallet, 5n));
    expect(() =>
      createSplit({ wallet, payer: PAYER, asset: SOL_MINT, parts: 2, input: filled(1) }),
    ).toThrowError(expect.objectContaining({ code: "WALLET_NOTE_RESERVED" }));
    expect(() =>
      createMerge({
        wallet,
        material: MergeMaterial.fromKeypair(keypair),
        asset: SOL_MINT,
        inputs: [filled(1), filled(2)],
      }),
    ).toThrowError(expect.objectContaining({ code: "WALLET_NOTE_RESERVED" }));
    expect(() =>
      createMerge({ wallet, material: MergeMaterial.fromKeypair(keypair), asset: SOL_MINT }),
    ).toThrowError(expect.objectContaining({ code: "WALLET_NOTHING_TO_MERGE" }));
  });
});
