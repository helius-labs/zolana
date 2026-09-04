import { address, type Address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { ZolanaClient } from "../src/client/client.js";
import { ClientError } from "../src/client/error.js";
import { LocalKeys } from "../src/client/keys.js";
import {
  AuthorizedPrivateTransaction,
  authorizedPrivateTransactionMaterial,
  type AuthorizedPrivateTransactionMaterial,
} from "../src/client/ports.js";
import { type Bytes32 } from "../src/interface/types.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import { Data, SOL_MINT, Utxo, Wallet } from "../src/transaction/index.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import { SppProofInputs } from "../src/transaction/instructions/transact.js";
import { createProofOutput } from "../src/transaction/utxo.js";
import {
  checkAuthorizedBinding,
  type TransactionIntent,
} from "../src/transaction/wallet/intent.js";
import { createSplit, createTransfer, createWithdrawal } from "../src/wallet/actions.js";
import { authorizePrivateTransaction } from "../src/wallet/private-transaction.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const SPL_MINT = address("So11111111111111111111111111111111111111112");
const RING = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");
const RECIPIENT = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");

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

async function authorize(kind: "transfer" | "withdrawal" | "split") {
  const keypair = spendingKeypair();
  const asset = kind === "withdrawal" ? SPL_MINT : SOL_MINT;
  const wallet = fundedWallet(keypair, asset);
  const feePayer = keypair.shieldedAddress().solanaAddress();
  const keys = LocalKeys.fromKeypair(keypair, {
    prove: () => Promise.reject(new Error("prove must not be called")),
    proveMerge: () => Promise.reject(new Error("proveMerge must not be called")),
  });
  const transaction =
    kind === "transfer"
      ? (
          await createTransfer({
            wallet,
            payer: feePayer,
            recipient: ShieldedKeypair.generate().shieldedAddress(),
            asset,
            amount: 25n,
          })
        ).transaction
      : kind === "withdrawal"
        ? (
            await createWithdrawal({
              wallet,
              payer: feePayer,
              recipient: RECIPIENT,
              asset,
              amount: 25n,
            })
          ).transaction
        : createSplit({ wallet, payer: feePayer, asset, parts: 2 }).transaction;
  const authorized = await authorizePrivateTransaction(transaction, wallet, keys);
  const material = authorizedPrivateTransactionMaterial(authorized);
  if (material === undefined) throw new Error("authorization was not minted");
  return { authorized, material, feePayer, keys };
}

function mismatch(field: string): ClientError {
  return new ClientError("CLIENT_INTENT_MISMATCH", { details: { field } });
}

function withIntent(
  material: AuthorizedPrivateTransactionMaterial,
  intent: TransactionIntent,
): AuthorizedPrivateTransactionMaterial {
  return Object.freeze({ ...material, intent });
}

function expectMismatch(material: AuthorizedPrivateTransactionMaterial, field: string): void {
  expect(() => checkAuthorizedBinding(material, mismatch)).toThrowError(
    expect.objectContaining({ code: "CLIENT_INTENT_MISMATCH", details: { field } }),
  );
}

function offlineClient() {
  const fetch = vi.fn<typeof globalThis.fetch>(async () => {
    throw new Error("network reached");
  });
  return { client: new ZolanaClient({ tree: TREE, fetch }), fetch };
}

describe("authorized transaction binding", () => {
  it("binds the amount, recipient, asset, rail, and split shape", async () => {
    const transfer = (await authorize("transfer")).material;
    const transferIntent = transfer.intent;
    if (transferIntent.kind !== "transfer") throw new Error("expected transfer");
    expectMismatch(withIntent(transfer, { ...transferIntent, amount: 26n }), "amount");
    expectMismatch(
      withIntent(transfer, {
        ...transferIntent,
        recipient: ShieldedKeypair.generate().shieldedAddress(),
      }),
      "recipient",
    );
    expectMismatch(withIntent(transfer, { ...transferIntent, asset: SPL_MINT }), "asset");
    expectMismatch(
      withIntent(transfer, {
        kind: "ringTransfer",
        ringProgramId: RING,
        asset: transferIntent.asset,
        amount: transferIntent.amount,
        recipient: transferIntent.recipient,
        boundary: "transfer",
        defaultFunding: 0n,
      }),
      "kind",
    );

    const split = (await authorize("split")).material;
    const splitIntent = split.intent;
    if (splitIntent.kind !== "split") throw new Error("expected split");
    expectMismatch(withIntent(split, { ...splitIntent, numOutputs: 3 }), "numOutputs");
  });

  it("binds SPL withdrawal accounts to the approved mint", async () => {
    const withdrawal = (await authorize("withdrawal")).material;
    const accounts = withdrawal.withdrawal;
    if (accounts?.kind !== "spl") throw new Error("expected SPL withdrawal");
    expectMismatch(
      Object.freeze({
        ...withdrawal,
        withdrawal: Object.freeze({ ...accounts, mint: RING }),
      }),
      "asset",
    );
  });

  it("rejects invalid intent ranges and exact shapes", async () => {
    const transfer = (await authorize("transfer")).material;
    const intent = transfer.intent;
    if (intent.kind !== "transfer") throw new Error("expected transfer");
    expectMismatch(withIntent(transfer, { ...intent, amount: 1n << 64n }), "amount");
    expect(() =>
      Reflect.apply(checkAuthorizedBinding, undefined, [
        { ...transfer, intent: { ...intent, memo: "not authorized" } },
        mismatch,
      ]),
    ).toThrowError(expect.objectContaining({ details: { field: "shape" } }));
  });

  it("rejects a coherent clone before the prover sees it", async () => {
    const { material, feePayer, keys } = await authorize("transfer");
    const intent = material.intent;
    if (intent.kind !== "transfer") throw new Error("expected transfer");
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const outputs = material.proofInputs.outputs.map((output, index) =>
      index < material.senderOutputCount || output.isDummy()
        ? output
        : createProofOutput({
            ownerAddress: recipient,
            asset: output.asset,
            amount: output.amount,
            blinding: output.blinding,
            data: output.data,
          }),
    );
    const coherent: AuthorizedPrivateTransactionMaterial = Object.freeze({
      ...material,
      intent: Object.freeze({ ...intent, recipient }),
      proofInputs: new SppProofInputs({
        payer: material.proofInputs.payer,
        inputUtxos: material.proofInputs.inputUtxos,
        outputs,
        externalData: material.proofInputs.externalData,
      }),
    });
    expect(() => checkAuthorizedBinding(coherent, mismatch)).not.toThrow();

    const counterfeit = Object.assign(
      Object.create(AuthorizedPrivateTransaction.prototype),
      coherent,
    );
    const { client, fetch } = offlineClient();
    await expect(
      Reflect.apply(client.assembleAuthorizedPrivateTransaction, client, [
        { authorized: counterfeit, feePayer, keys },
      ]),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_TRANSACTION" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects caller-supplied setup instructions", async () => {
    const { authorized, feePayer, keys } = await authorize("transfer");
    const { client, fetch } = offlineClient();
    await expect(
      Reflect.apply(client.assembleAuthorizedPrivateTransaction, client, [
        {
          authorized,
          feePayer,
          keys,
          setupInstructions: [{ programAddress: RING }],
        },
      ]),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_TRANSACTION" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("requires assembler fields to be own properties", async () => {
    const { authorized, feePayer, keys } = await authorize("transfer");
    const { client, fetch } = offlineClient();
    await expect(
      Reflect.apply(client.assembleAuthorizedPrivateTransaction, client, [
        Object.create({ authorized, feePayer, keys }),
      ]),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_TRANSACTION" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("snapshots the public request before asynchronous work", async () => {
    const { authorized, feePayer, keys } = await authorize("transfer");
    const { client, fetch } = offlineClient();
    let authorizedReads = 0;
    let feePayerReads = 0;
    let keysReads = 0;
    const request = Object.defineProperties(
      {},
      {
        authorized: {
          enumerable: true,
          get: () => {
            authorizedReads += 1;
            return authorized;
          },
        },
        feePayer: {
          enumerable: true,
          get: () => {
            feePayerReads += 1;
            return feePayer;
          },
        },
        keys: {
          enumerable: true,
          get: () => {
            keysReads += 1;
            return keys;
          },
        },
      },
    );

    await expect(
      Reflect.apply(client.assembleAuthorizedPrivateTransaction, client, [request]),
    ).rejects.toBeDefined();
    expect(fetch).toHaveBeenCalled();
    expect(authorizedReads).toBe(1);
    expect(feePayerReads).toBe(1);
    expect(keysReads).toBe(1);
  });

  it("refuses keys that cannot prove", async () => {
    const { authorized, feePayer } = await authorize("transfer");
    const { client, fetch } = offlineClient();
    await expect(
      Reflect.apply(client.assembleAuthorizedPrivateTransaction, client, [
        { authorized, feePayer, keys: { prove: "not a function" } },
      ]),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_PROOF_AUTHORITY" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("accepts an untouched capability", async () => {
    const { authorized, feePayer, keys } = await authorize("transfer");
    const { client, fetch } = offlineClient();
    await expect(
      client.assembleAuthorizedPrivateTransaction({ authorized, feePayer, keys }),
    ).rejects.toBeDefined();
    expect(fetch).toHaveBeenCalled();
  });
});
