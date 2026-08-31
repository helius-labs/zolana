import { address, type Address, type Transaction } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { ZolanaClient } from "../src/client/client.js";
import type { AuthorizedPrivateTransaction } from "../src/client/ports.js";
import { TransactWithdrawal, type Bytes32 } from "../src/interface/types.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import { Data, KeypairWalletAuthority, SOL_MINT, Utxo, Wallet } from "../src/transaction/index.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import type { TransactionIntent } from "../src/transaction/wallet/intent.js";
import {
  buildSplitTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
} from "../src/wallet/transactions.js";
import { privateTransactionClient } from "./helpers/clients.js";
import { forged } from "./helpers/forged.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const SPL_MINT = address("So11111111111111111111111111111111111111112");
const RING = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");
const RECIPIENT = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const TRANSACTION = forged<Transaction>(
  Object.freeze({ messageBytes: new Uint8Array(), signatures: Object.freeze({}) }),
);

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function spendingKeypair(): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(42)));
}

function fundedWallet(keypair: ShieldedKeypair, asset: Address = SOL_MINT): Wallet {
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry(asset === SOL_MINT ? [] : [[2n, asset]]),
  });
  wallet._replace({
    utxos: [
      {
        utxo: new Utxo({
          owner: keypair.signingPublicKey(),
          asset,
          amount: 100n,
          blinding: filled(1),
          data: new Data(),
        }),
        outputContext: { hash: filled(1), tree: TREE, leafIndex: 0n },
        nullifier: filled(20),
        spent: false,
      },
    ],
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

async function capture(
  build: (input: {
    client: ReturnType<typeof privateTransactionClient>;
    wallet: Wallet;
    authority: KeypairWalletAuthority;
    feePayer: ReturnType<ShieldedKeypair["shieldedAddress"]> extends never ? never : string;
  }) => Promise<unknown>,
  asset: Address = SOL_MINT,
): Promise<AuthorizedPrivateTransaction> {
  const keypair = spendingKeypair();
  const wallet = fundedWallet(keypair, asset);
  const authority = new KeypairWalletAuthority({
    solanaPublicKey: keypair.shieldedAddress().solanaAddress(),
    keypair,
  });
  let captured: AuthorizedPrivateTransaction | undefined;
  const client = privateTransactionClient({
    assembleAuthorizedPrivateTransaction: async (input) => {
      captured = input.authorized;
      return TRANSACTION;
    },
  });
  await build({
    client,
    wallet,
    authority,
    feePayer: forged(keypair.shieldedAddress().solanaAddress()),
  });
  if (captured === undefined) throw new Error("authorized transaction not captured");
  return captured;
}

function transferAuthorized(): Promise<AuthorizedPrivateTransaction> {
  return capture(({ client, wallet, authority, feePayer }) =>
    buildTransferTransaction({
      client,
      wallet,
      authority,
      feePayer: forged(feePayer),
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 25n,
    }),
  );
}

function splWithdrawalAuthorized(): Promise<AuthorizedPrivateTransaction> {
  return capture(
    ({ client, wallet, authority, feePayer }) =>
      buildWithdrawalTransaction({
        client,
        wallet,
        authority,
        feePayer: forged(feePayer),
        recipient: RECIPIENT,
        asset: SPL_MINT,
        amount: 25n,
      }),
    SPL_MINT,
  );
}

function splitAuthorized(): Promise<AuthorizedPrivateTransaction> {
  return capture(({ client, wallet, authority, feePayer }) =>
    buildSplitTransaction({
      client,
      wallet,
      authority,
      feePayer: forged(feePayer),
      parts: 2,
    }),
  );
}

function offlineClient(): Readonly<{ client: ZolanaClient; fetch: ReturnType<typeof vi.fn> }> {
  const fetch = vi.fn(async () => {
    throw new Error("network reached");
  });
  return {
    client: new ZolanaClient({ tree: TREE, fetch: forged<typeof globalThis.fetch>(fetch) }),
    fetch,
  };
}

function withIntent(
  authorized: AuthorizedPrivateTransaction,
  intent: TransactionIntent,
): AuthorizedPrivateTransaction {
  return Object.freeze({ ...authorized, intent });
}

describe("authorized transaction binding", () => {
  async function rejectsOffline(
    forgedAuthorized: AuthorizedPrivateTransaction,
    expected: Readonly<{ code: string; details?: Readonly<{ field: string }> }>,
  ): Promise<void> {
    const { client, fetch } = offlineClient();
    await expect(
      client.assembleAuthorizedPrivateTransaction({
        authorized: forgedAuthorized,
        feePayer: forgedAuthorized.proofInputs.payer,
      }),
    ).rejects.toMatchObject(expected);
    expect(fetch).not.toHaveBeenCalled();
  }

  it("refuses an inflated amount before the prover sees it", async () => {
    const authorized = await transferAuthorized();
    const intent = authorized.intent;
    if (intent.kind !== "transfer") throw new Error("expected a transfer intent");
    await rejectsOffline(withIntent(authorized, { ...intent, amount: intent.amount + 1n }), {
      code: "CLIENT_INTENT_MISMATCH",
      details: { field: "amount" },
    });
  });

  it("refuses a swapped recipient", async () => {
    const authorized = await transferAuthorized();
    const intent = authorized.intent;
    if (intent.kind !== "transfer") throw new Error("expected a transfer intent");
    await rejectsOffline(
      withIntent(authorized, {
        ...intent,
        recipient: ShieldedKeypair.generate().shieldedAddress(),
      }),
      { code: "CLIENT_INTENT_MISMATCH", details: { field: "recipient" } },
    );
  });

  it("refuses a swapped asset", async () => {
    const authorized = await transferAuthorized();
    const intent = authorized.intent;
    if (intent.kind !== "transfer") throw new Error("expected a transfer intent");
    await rejectsOffline(withIntent(authorized, { ...intent, asset: SPL_MINT }), {
      code: "CLIENT_INTENT_MISMATCH",
      details: { field: "asset" },
    });
  });

  it("refuses a drifted split shape", async () => {
    const authorized = await splitAuthorized();
    const intent = authorized.intent;
    if (intent.kind !== "split") throw new Error("expected a split intent");
    await rejectsOffline(withIntent(authorized, { ...intent, numOutputs: 3 }), {
      code: "CLIENT_INTENT_MISMATCH",
      details: { field: "numOutputs" },
    });
  });

  it("refuses a ring intent on the default rail", async () => {
    const authorized = await transferAuthorized();
    const intent = authorized.intent;
    if (intent.kind !== "transfer") throw new Error("expected a transfer intent");
    await rejectsOffline(
      withIntent(authorized, {
        kind: "ringTransfer",
        ringProgramId: RING,
        asset: intent.asset,
        amount: intent.amount,
        recipient: intent.recipient,
        boundary: "transfer",
        defaultFunding: 0n,
      }),
      { code: "CLIENT_INTENT_MISMATCH", details: { field: "kind" } },
    );
  });

  it("refuses a withdrawal whose accounts name a different mint", async () => {
    const authorized = await splWithdrawalAuthorized();
    const withdrawal = authorized.withdrawal;
    if (withdrawal?.kind !== "spl") throw new Error("expected an spl withdrawal");
    await rejectsOffline(
      Object.freeze({
        ...authorized,
        withdrawal: TransactWithdrawal.spl({
          mint: RING,
          splTokenInterface: withdrawal.splTokenInterface,
          recipientTokenAccount: withdrawal.recipientTokenAccount,
          tokenProgram: withdrawal.tokenProgram,
        }),
      }),
      { code: "CLIENT_INTENT_MISMATCH", details: { field: "asset" } },
    );
  });

  it("refuses an unknown intent kind", async () => {
    const authorized = await transferAuthorized();
    await rejectsOffline(withIntent(authorized, forged({ kind: "mint", asset: SOL_MINT })), {
      code: "CLIENT_INTENT_MISMATCH",
      details: { field: "kind" },
    });
  });

  it("refuses amounts and counts outside their integer ranges", async () => {
    const transfer = await transferAuthorized();
    const transferIntent = transfer.intent;
    if (transferIntent.kind !== "transfer") throw new Error("expected a transfer intent");
    await rejectsOffline(withIntent(transfer, { ...transferIntent, amount: 1n << 64n }), {
      code: "CLIENT_INTENT_MISMATCH",
      details: { field: "amount" },
    });
    const split = await splitAuthorized();
    const splitIntent = split.intent;
    if (splitIntent.kind !== "split") throw new Error("expected a split intent");
    await rejectsOffline(withIntent(split, { ...splitIntent, numOutputs: 300 }), {
      code: "CLIENT_INTENT_MISMATCH",
      details: { field: "numOutputs" },
    });
  });

  it("refuses a structurally forged authorization", async () => {
    const authorized = await transferAuthorized();
    await rejectsOffline(
      forged<AuthorizedPrivateTransaction>({ ...authorized, owner: "not-an-address" }),
      {
        code: "CLIENT_INVALID_TRANSACTION",
      },
    );
    await rejectsOffline(Object.freeze({ ...authorized, senderOutputCount: 99 }), {
      code: "CLIENT_INTENT_MISMATCH",
      details: { field: "senderOutputCount" },
    });
  });

  it("passes the untouched authorization through the binding", async () => {
    const authorized = await transferAuthorized();
    const { client } = offlineClient();
    // The builder wiped the captured input keys after assembly, so signing
    // fails past the binding, no forgery case reaches that stage.
    await expect(
      client.assembleAuthorizedPrivateTransaction({
        authorized,
        feePayer: authorized.proofInputs.payer,
      }),
    ).rejects.toMatchObject({ code: "CLIENT_KEYPAIR" });
  });
});
