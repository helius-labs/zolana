import { address, getAddressEncoder, type Address } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AuthorizedPrivateTransaction } from "../src/client/client.js";
import { LocalKeys } from "../src/client/keys.js";
import { prepareMerge } from "../src/client/prover/merge.js";
import type { PrivateTransactionClient } from "../src/wallet/index.js";
import type { Bytes128, Bytes32 } from "../src/interface/index.js";
import { USER_REGISTRY_PROGRAM_ID } from "../src/interface/program.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import {
  Data,
  LocalShieldedKeys,
  SOL_MINT,
  Utxo,
  Wallet,
  deserializeWallet,
  serializeWallet,
} from "../src/transaction/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import { extendReservation } from "../src/flows/reserve.js";
import { approveUnattended, type ApprovalRequest } from "../src/transaction/wallet/intent.js";
import { createSplit, createTransfer } from "../src/wallet/actions.js";
import { buildMergeTransaction, createMerge, type MergeClient } from "../src/wallet/merge.js";
import { internalUserRecordPda } from "../src/wallet/registry.js";
import { buildTransferTransaction } from "../src/wallet/transactions.js";
import { privateTransactionClient } from "./helpers/clients.js";
import { emptyTransaction } from "./helpers/transactions.js";

const TREE = treeAddress(0);
const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const TRANSACTION = emptyTransaction(PAYER);

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function spendingKeypair(): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(42)));
}

function localKeys(keypair: ShieldedKeypair): LocalKeys {
  return LocalKeys.fromKeypair(keypair, {
    prove: () => Promise.reject(new Error("prove must not be called")),
    proveMerge: () => Promise.reject(new Error("proveMerge must not be called")),
  });
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

function buildParams(client: PrivateTransactionClient, wallet: Wallet, keypair: ShieldedKeypair) {
  return {
    client,
    wallet,
    keys: localKeys(keypair),
    feePayer: keypair.shieldedAddress().solanaAddress(),
    recipient: ShieldedKeypair.generate().shieldedAddress(),
    amount: 3n,
  };
}

function assemblingClient(): Readonly<{
  client: PrivateTransactionClient;
  assemble: ReturnType<typeof vi.fn>;
}> {
  const assemble = vi.fn(
    async (_input: Readonly<{ authorized: AuthorizedPrivateTransaction }>) => TRANSACTION,
  );
  return {
    client: privateTransactionClient({
      getAccount: vi.fn(async () => undefined),
      assembleAuthorizedPrivateTransaction: assemble,
    }),
    assemble,
  };
}

/** A merge client whose user record matches `keypair` and whose prover answers at once. */
async function mergeClient(keypair: ShieldedKeypair): Promise<MergeClient> {
  const shielded = keypair.shieldedAddress();
  const owner = shielded.solanaAddress();
  const pda = await internalUserRecordPda(owner);
  const record = Uint8Array.of(
    1,
    ...getAddressEncoder().encode(owner),
    pda.bump,
    ...shielded.nullifierPublicKey,
    ...shielded.viewingPublicKey.toBytes(),
    1,
  );
  return {
    proofDataSource: "client",
    tree: TREE,
    treeId: 0,
    getAccount: async (key: Address) =>
      key === pda.address
        ? { owner: USER_REGISTRY_PROGRAM_ID, data: record, lamports: 1n }
        : undefined,
    proveMerge: async ({ prepared }) => {
      const complete = prepareMerge(prepared, TREE).finish({
        slot: { id: 0, utxoRoot: filled(1), nullifierRoot: filled(2) },
        utxoRootIndex: 0,
        nullifierRootIndex: 0,
      });
      return {
        data: complete.instructionData({
          a: filled(0),
          b: new Uint8Array(128) as Bytes128,
          c: filled(0),
        }),
        outputHash: complete.outputHash,
      };
    },
    assembleAuthorizedMergeTransaction: async () => TRANSACTION,
  };
}

/** Grants the intent once `before` settles. */
function approveAfter(before: () => unknown) {
  return async (request: ApprovalRequest) => {
    await before();
    return approveUnattended(request);
  };
}

const START = 1_000_000;
/** One step of a build that outlasts the reservation's two-minute lease. */
const SLOW_STEP_MS = 121_000;

describe("UTXO reservations", () => {
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

  it("lets exactly one of two concurrent builds spend a UTXO", async () => {
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

  it("frees the UTXOs after the reservation expires", async () => {
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

  it("keeps an extended reservation past its first expiry", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    await createTransfer(transferParams(wallet, 3n));
    const reservation = wallet._reservationEntries()[0];
    if (reservation === undefined) throw new Error("reservation");
    now.mockReturnValue(1_000_000 + 100_000);
    extendReservation(wallet, reservation.id);
    now.mockReturnValue(1_000_000 + 200_000);
    await expect(createTransfer(transferParams(wallet, 3n))).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
    });
    now.mockReturnValue(1_000_000 + 220_000);
    await expect(createTransfer(transferParams(wallet, 3n))).resolves.toBeDefined();
  });

  it("drops the reservation when sync marks its UTXO spent", async () => {
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

  it("releases at once when merge preparation refuses the UTXOs", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [6n, 4n], [1]);
    await expect(
      createMerge({
        wallet,
        keys: LocalShieldedKeys.fromKeypair(keypair),
        asset: SOL_MINT,
        inputs: [filled(1), filled(2)],
      }),
    ).rejects.toMatchObject({ code: "TRANSACTION_MERGE_INPUT_RING_MISMATCH" });
    expect(wallet._reservationEntries()).toHaveLength(0);
  });

  it("refuses named inputs another build reserved", async () => {
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [6n, 4n]);
    await createTransfer(transferParams(wallet, 5n));
    expect(() =>
      createSplit({ wallet, payer: PAYER, asset: SOL_MINT, parts: 2, input: filled(1) }),
    ).toThrowError(expect.objectContaining({ code: "WALLET_NOTE_RESERVED" }));
    const keys = LocalShieldedKeys.fromKeypair(keypair);
    await expect(
      createMerge({ wallet, keys, asset: SOL_MINT, inputs: [filled(1), filled(2)] }),
    ).rejects.toMatchObject({ code: "WALLET_NOTE_RESERVED" });
    await expect(createMerge({ wallet, keys, asset: SOL_MINT })).rejects.toMatchObject({
      code: "WALLET_NOTHING_TO_MERGE",
    });
  });
  it.each(["key holder", "approval", "prover"] as const)(
    "holds a transfer's UTXO while the %s outlasts the lease",
    async (step) => {
      const now = vi.spyOn(Date, "now").mockReturnValue(START);
      const keypair = spendingKeypair();
      const wallet = fundedWallet(keypair, [5n]);
      const { client, assemble } = assemblingClient();
      const keys = localKeys(keypair);
      let second: unknown;
      const stall = async (): Promise<void> => {
        now.mockReturnValue(START + SLOW_STEP_MS);
        second = await buildTransferTransaction(buildParams(client, wallet, keypair)).catch(
          (cause: unknown) => cause,
        );
      };
      if (step === "key holder") {
        const mint = keys.transactionKeys.bind(keys);
        vi.spyOn(keys, "transactionKeys").mockImplementationOnce(async (requests) => {
          await stall();
          return mint(requests);
        });
      }
      if (step === "prover") {
        assemble.mockImplementationOnce(async () => {
          await stall();
          return TRANSACTION;
        });
      }
      const first = await buildTransferTransaction({
        ...buildParams(client, wallet, keypair),
        keys,
        ...(step === "approval" ? { approve: approveAfter(stall) } : {}),
      });
      expect(first).toBe(TRANSACTION);
      expect(second).toMatchObject({
        code: "WALLET_BUILD_TRANSFER",
        causeCodes: ["WALLET_CREATE_TRANSFER", "WALLET_INSUFFICIENT_BALANCE"],
      });
      expect(assemble).toHaveBeenCalledTimes(1);
      // A built transaction that is never sent frees its UTXO one lease after it returns.
      now.mockReturnValue(START + SLOW_STEP_MS + 119_999);
      await expect(createTransfer(transferParams(wallet, 3n))).rejects.toMatchObject({
        causeCode: "WALLET_INSUFFICIENT_BALANCE",
      });
      now.mockReturnValue(START + SLOW_STEP_MS + 120_000);
      await expect(createTransfer(transferParams(wallet, 3n))).resolves.toBeDefined();
    },
  );

  it("saves a held reservation with its lease, so a restarted wallet frees it", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(START);
    const keypair = spendingKeypair();
    const wallet = fundedWallet(keypair, [5n]);
    const { client } = assemblingClient();
    let snapshot = "";
    await buildTransferTransaction({
      ...buildParams(client, wallet, keypair),
      approve: approveAfter(() => {
        now.mockReturnValue(START + SLOW_STEP_MS);
        snapshot = serializeWallet(wallet);
      }),
    });
    await expect(createTransfer(transferParams(wallet, 3n))).rejects.toMatchObject({
      causeCode: "WALLET_INSUFFICIENT_BALANCE",
    });
    await expect(
      createTransfer(transferParams(deserializeWallet(snapshot), 3n)),
    ).resolves.toBeDefined();
  });

  it.each(["approval", "prover"] as const)(
    "refuses a transfer whose UTXO a sync sees spent while the %s runs",
    async (step) => {
      const keypair = spendingKeypair();
      const wallet = fundedWallet(keypair, [5n]);
      const { client, assemble } = assemblingClient();
      const spend = (): void =>
        wallet._replace({
          utxos: [{ ...walletUtxo(keypair, 5n, 0), spent: true }],
          transactions: [],
          nullifiers: new Set(),
        });
      if (step === "prover") {
        assemble.mockImplementationOnce(async () => {
          spend();
          return TRANSACTION;
        });
      }
      await expect(
        buildTransferTransaction({
          ...buildParams(client, wallet, keypair),
          ...(step === "approval" ? { approve: approveAfter(spend) } : {}),
        }),
      ).rejects.toMatchObject({
        code: "WALLET_BUILD_TRANSFER",
        causeCode: "WALLET_RESERVATION_LOST",
      });
      expect(assemble).toHaveBeenCalledTimes(step === "prover" ? 1 : 0);
      expect(wallet._reservationEntries()).toHaveLength(0);
    },
  );

  it.each(["key holder", "approval"] as const)(
    "holds a merge's UTXOs while the %s outlasts the lease",
    async (step) => {
      const now = vi.spyOn(Date, "now").mockReturnValue(START);
      const keypair = spendingKeypair();
      const wallet = fundedWallet(keypair, [20n, 30n]);
      const client = await mergeClient(keypair);
      const keys = localKeys(keypair);
      const feePayer = keypair.shieldedAddress().solanaAddress();
      let second: unknown;
      const stall = async (): Promise<void> => {
        now.mockReturnValue(START + SLOW_STEP_MS);
        second = await buildMergeTransaction({ client, wallet, keys, feePayer }).catch(
          (cause: unknown) => cause,
        );
      };
      if (step === "key holder") {
        const derive = keys.derive.bind(keys);
        vi.spyOn(keys, "derive").mockImplementationOnce(async (requests) => {
          await stall();
          return derive(requests);
        });
      }
      const first = await buildMergeTransaction({
        client,
        wallet,
        keys,
        feePayer,
        ...(step === "approval" ? { approve: approveAfter(stall) } : {}),
      });
      expect(first).toBe(TRANSACTION);
      expect(second).toMatchObject({
        code: "WALLET_BUILD_MERGE",
        causeCode: "WALLET_NOTHING_TO_MERGE",
      });
      expect(wallet._reservationEntries()).toHaveLength(1);
    },
  );
});
