import { address, generateKeyPairSigner, signTransactionWithSigners } from "@solana/kit";
import { afterEach, describe, expect, it, vi } from "vitest";

import { LocalKeys } from "../src/client/keys.js";
import type { RingSubmissionStatus, RingSubmissionTransport } from "../src/client/ports.js";
import type { Bytes32, Transaction } from "../src/interface/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import { Data, SOL_MINT, Utxo, Wallet } from "../src/transaction/index.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import { hex } from "../src/transaction/wallet/state.js";
import { createTransfer } from "../src/wallet/actions.js";
import {
  createSplitSubmission,
  createTransferSubmission,
  createWithdrawalSubmission,
} from "../src/ring/spend-submission.js";
import { privateTransactionClient } from "./helpers/clients.js";
import { emptyTransaction } from "./helpers/transactions.js";

const TREE = treeAddress(0);
const RECIPIENT = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const LEASE_PLUS_TEN_MINUTES = 120_000 + 600_000;

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function fundedWallet(keypair: ShieldedKeypair, amounts: readonly bigint[]): Wallet {
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry([]),
  });
  wallet._replace({
    utxos: amounts.map((amount, index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: filled(index + 1),
        data: new Data(),
      }),
      outputContext: { hash: filled(index + 1), tree: TREE, leafIndex: BigInt(index) },
      nullifier: filled(index + 20),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

async function fixture(amounts: readonly bigint[] = [5n]) {
  const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(42)));
  const wallet = fundedWallet(keypair, amounts);
  const payer = await generateKeyPairSigner();
  const assemble = vi.fn(async () => emptyTransaction(payer.address));
  const sign = vi.fn(async (transaction: Transaction) =>
    signTransactionWithSigners([payer], transaction),
  );
  const params = {
    client: privateTransactionClient({ assembleAuthorizedPrivateTransaction: assemble }),
    wallet,
    keys: LocalKeys.fromKeypair(keypair, {
      prove: () => Promise.reject(new Error("prove must not be called")),
      proveMerge: () => Promise.reject(new Error("proveMerge must not be called")),
    }),
    feePayer: keypair.shieldedAddress().solanaAddress(),
  };
  const transfer = {
    ...params,
    recipient: ShieldedKeypair.generate().shieldedAddress(),
    amount: 3n,
  };
  return { wallet, params, transfer, assemble, sign };
}

/** Answers each status read with the next entry, repeating the last. */
function transport(
  sign: RingSubmissionTransport["sign"],
  statuses: readonly RingSubmissionStatus[],
  send: RingSubmissionTransport["send"] = async () => undefined,
): RingSubmissionTransport {
  let read = 0;
  return {
    sign,
    send,
    status: async () => statuses[Math.min(read++, statuses.length - 1)] ?? { kind: "unknown" },
  };
}

function spendAgain(wallet: Wallet) {
  return createTransfer({
    wallet,
    payer: RECIPIENT,
    recipient: ShieldedKeypair.generate().shieldedAddress(),
    asset: SOL_MINT,
    amount: 3n,
  });
}

describe("default-pool spend submissions", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("holds the inputs past the selection lease until the transfer settles", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);
    const f = await fixture();
    const submission = await createTransferSubmission(f.transfer);
    now.mockReturnValue(1_000_000 + LEASE_PLUS_TEN_MINUTES);
    await expect(spendAgain(f.wallet)).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
      causeCode: "WALLET_INSUFFICIENT_BALANCE",
    });
    const result = await submission.send(transport(f.sign, [{ kind: "failed" }]));
    expect(result).toMatchObject({ kind: "failed", attempts: 1 });
    await expect(spendAgain(f.wallet)).resolves.toBeDefined();
  });

  it("keeps an unknown broadcast pending instead of paying again", async () => {
    const f = await fixture();
    const submission = await createTransferSubmission(f.transfer);
    const send = vi.fn(async () => {
      throw new Error("confirmation timed out");
    });
    const unknown = transport(f.sign, [{ kind: "unknown" }], send);
    const first = await submission.send(unknown);
    const second = await submission.send(unknown);
    expect(first).toMatchObject({ kind: "unknown", attempts: 1 });
    expect(second).toEqual(first);
    expect(f.sign).toHaveBeenCalledTimes(1);
    expect(send).toHaveBeenCalledTimes(1);
    expect(f.wallet.pendingSubmissions()).toHaveLength(1);
    expect(() => submission.cancel()).toThrow("RING_SUBMISSION_PENDING");
    await expect(spendAgain(f.wallet)).rejects.toMatchObject({ code: "WALLET_CREATE_TRANSFER" });
    const confirmed = await submission.send(
      transport(f.sign, [{ kind: "confirmed", slot: 9n }], send),
    );
    expect(confirmed).toMatchObject({ kind: "confirmed", slot: 9n, attempts: 1 });
    expect(f.sign).toHaveBeenCalledTimes(1);
  });

  it("rebuilds an expired transfer from the same UTXOs", async () => {
    const f = await fixture([5n, 5n]);
    const submission = await createTransferSubmission(f.transfer);
    const held = f.wallet._reservationEntries().map((entry) => entry.utxoHashes.map(hex));
    const result = await submission.send(
      transport(f.sign, [{ kind: "expired" }, { kind: "confirmed", slot: 7n }]),
    );
    expect(result).toMatchObject({ kind: "confirmed", attempts: 2 });
    expect(f.assemble).toHaveBeenCalledTimes(2);
    expect(f.wallet._reservationEntries().map((entry) => entry.utxoHashes.map(hex))).toEqual(held);
    // The rebuild left the second UTXO alone, so another spend can still take it.
    await expect(spendAgain(f.wallet)).resolves.toBeDefined();
  });

  it("releases its inputs when the first build fails", async () => {
    const f = await fixture();
    f.assemble.mockRejectedValueOnce(new Error("assembly down"));
    await expect(createTransferSubmission(f.transfer)).rejects.toMatchObject({
      code: "WALLET_BUILD_TRANSFER",
    });
    expect(f.wallet._reservationEntries()).toHaveLength(0);
    await expect(spendAgain(f.wallet)).resolves.toBeDefined();
  });

  it("holds the input of a withdrawal and of a split past the selection lease", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1_000_000);
    const withdrawal = await fixture();
    await createWithdrawalSubmission({ ...withdrawal.params, recipient: RECIPIENT, amount: 3n });
    const split = await fixture([4n]);
    await createSplitSubmission(split.params);
    now.mockReturnValue(1_000_000 + LEASE_PLUS_TEN_MINUTES);
    await expect(spendAgain(withdrawal.wallet)).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
    });
    await expect(spendAgain(split.wallet)).rejects.toMatchObject({
      code: "WALLET_CREATE_TRANSFER",
    });
  });
});
