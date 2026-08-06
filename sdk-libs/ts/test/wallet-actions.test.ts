import {
  address,
  assertIsFullySignedTransaction,
  generateKeyPairSigner,
  signTransactionWithSigners,
  type Address,
  type Blockhash,
  type Transaction,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import type { AuthorizedPrivateTransaction, ZolanaClient } from "../src/client/client.js";
import { SPL_TOKEN_2022_PROGRAM_ID, type Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import { Data, LocalWalletAuthority, SOL_MINT, Utxo, Wallet } from "../src/transaction/index.js";
import { AssetRegistry } from "../src/transaction/wallet/asset.js";
import { createSplit, createTransfer, createWithdrawal } from "../src/wallet/actions.js";
import { buildDepositTransaction, createDeposit } from "../src/wallet/deposit.js";
import { createMerge, MergeMaterial } from "../src/wallet/merge.js";
import { authorizePrivateTransaction } from "../src/wallet/private-transaction.js";
import {
  buildSplitTransaction,
  buildTransferTransaction,
  buildWithdrawalTransaction,
} from "../src/wallet/transactions.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const RECIPIENT = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const SPL_MINT = address("So11111111111111111111111111111111111111112");
const ZONE = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");
const BLOCKHASH = "11111111111111111111111111111111" as Blockhash;
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
  options: Readonly<{ asset?: Address; zoneProgramId?: Address }> = {},
): Wallet {
  const asset = options.asset ?? SOL_MINT;
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry(asset === SOL_MINT ? [] : [[2n, asset]]),
  });
  wallet._replace({
    utxos: amounts.map((amount, index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset,
        amount,
        blinding: new Uint8Array(32).fill(index + 1) as Bytes32,
        data: new Data(),
        ...(options.zoneProgramId === undefined ? {} : { zoneProgramId: options.zoneProgramId }),
      }),
      outputContext: {
        hash: filled(index + 1),
        tree: TREE,
        leafIndex: BigInt(index),
      },
      nullifier: filled(index + 20),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

function latestBlockhashClient(feeTree = TREE): ZolanaClient {
  return {
    tree: feeTree,
    getLatestBlockhash: vi.fn(async () => ({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 1n,
    })),
  } as unknown as ZolanaClient;
}

function capturePrivateBuild(): Readonly<{
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

describe("private transaction construction", () => {
  it("rejects zero-value public actions before building them", async () => {
    const keypair = ShieldedKeypair.generate();
    await expect(
      buildDepositTransaction({
        client: latestBlockhashClient(),
        feePayer: PAYER,
        recipient: keypair.shieldedAddress(),
        amount: 0n,
      }),
    ).rejects.toMatchObject({ code: "WALLET_INVALID_AMOUNT" });
    await expect(
      createWithdrawal({
        wallet: fundedWallet(keypair, [100n]),
        payer: PAYER,
        recipient: RECIPIENT,
        asset: SOL_MINT,
        amount: 0n,
      }),
    ).rejects.toMatchObject({ code: "WALLET_INVALID_AMOUNT" });
  });

  it("selects the minimum prefix of notes needed for withdrawal", async () => {
    const keypair = ShieldedKeypair.generate();
    const created = await createWithdrawal({
      wallet: fundedWallet(keypair, [20n, 40n, 80n]),
      payer: PAYER,
      recipient: RECIPIENT,
      asset: SOL_MINT,
      amount: 50n,
    });
    expect(created.transaction.inputCount()).toBe(2);
    expect(created.transaction.tree()).toBe(TREE);
  });

  it("rejects an Ed25519 spend whose fee payer is not its owner", async () => {
    const keypair = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(7)));
    const wallet = fundedWallet(keypair, [100n]);
    const created = await createWithdrawal({
      wallet,
      payer: PAYER,
      recipient: RECIPIENT,
      asset: SOL_MINT,
      amount: 50n,
    });

    await expect(
      authorizePrivateTransaction(
        created.transaction,
        wallet,
        new LocalWalletAuthority({
          solanaPublicKey: keypair.shieldedAddress().solanaAddress(),
          keypair,
        }),
      ),
    ).rejects.toMatchObject({ code: "TRANSACTION_ED25519_PAYER_MISMATCH" });
  });

  it("does not spend zone-bound notes through a default-zone action", async () => {
    const keypair = ShieldedKeypair.generate();
    await expect(
      createWithdrawal({
        wallet: fundedWallet(keypair, [100n], { zoneProgramId: ZONE }),
        payer: PAYER,
        recipient: RECIPIENT,
        asset: SOL_MINT,
        amount: 50n,
      }),
    ).rejects.toMatchObject({ code: "WALLET_INSUFFICIENT_BALANCE" });
  });

  it("refuses to turn an unregistered private recipient into a public withdrawal", async () => {
    const keypair = ShieldedKeypair.generate();
    const getAccount = vi.fn(async () => undefined);
    await expect(
      createTransfer({
        client: { getAccount },
        wallet: fundedWallet(keypair, [100n]),
        payer: PAYER,
        recipient: RECIPIENT,
        asset: SOL_MINT,
        amount: 10n,
      }),
    ).rejects.toMatchObject({ code: "WALLET_RECIPIENT_NOT_REGISTERED" });
    expect(getAccount).toHaveBeenCalledOnce();
  });

  it("accepts an already-resolved shielded recipient without an RPC read", async () => {
    const sender = ShieldedKeypair.generate();
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const created = await createTransfer({
      wallet: fundedWallet(sender, [100n]),
      payer: PAYER,
      recipient,
      asset: SOL_MINT,
      amount: 10n,
    });
    expect(created.recipient).toMatchObject({
      kind: "shielded",
      address: recipient,
    });
  });

  it("keeps split and merge conservation in their internal intent models", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = fundedWallet(keypair, [20n, 30n, 100n]);
    const split = createSplit({
      wallet,
      payer: PAYER,
      asset: SOL_MINT,
      parts: 2,
      input: wallet.utxos()[2]!.outputContext.hash,
    });
    const merge = createMerge({
      wallet,
      material: MergeMaterial.fromKeypair(keypair),
      asset: SOL_MINT,
    });
    expect(split).toMatchObject({ numOutputs: 2, perOutputAmount: 50n });
    expect(merge).toMatchObject({ numInputs: 3, mergedAmount: 150n });
  });
});

describe("unsigned public transaction builders", () => {
  it("builds a normal unsigned deposit that consumers sign with Kit", async () => {
    const signer = await generateKeyPairSigner();
    const transaction = await buildDepositTransaction({
      client: latestBlockhashClient(),
      feePayer: signer.address,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 42n,
    });

    expect(() => assertIsFullySignedTransaction(transaction)).toThrow();
    const signed = await signTransactionWithSigners([signer], transaction);
    expect(() => assertIsFullySignedTransaction(signed)).not.toThrow();
  });

  it("threads Token-2022 through an SPL deposit", async () => {
    const deposit = await createDeposit({
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      asset: SPL_MINT,
      amount: 42n,
      splTokenAccount: RECIPIENT,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
    const instruction = await deposit.instruction(TREE, PAYER);
    expect(
      instruction.accounts?.some((account) => account.address === SPL_TOKEN_2022_PROGRAM_ID),
    ).toBe(true);
  });

  it("includes idempotent Token-2022 ATA setup in a withdrawal build", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n], { asset: SPL_MINT });
    const { client, assemble } = capturePrivateBuild();

    await buildWithdrawalTransaction({
      client,
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: payer, keypair }),
      feePayer: payer,
      recipient: RECIPIENT,
      asset: SPL_MINT,
      amount: 25n,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });

    const request = assemble.mock.calls[0]?.[0] as Readonly<{
      authorized: AuthorizedPrivateTransaction;
      setupInstructions?: readonly Readonly<{
        accounts?: readonly Readonly<{ address: Address }>[];
      }>[];
    }>;
    expect(request.setupInstructions).toHaveLength(1);
    expect(
      request.setupInstructions?.[0]?.accounts?.some(
        (account) => account.address === SPL_TOKEN_2022_PROGRAM_ID,
      ),
    ).toBe(true);
    expect(request.authorized.withdrawal).toMatchObject({
      kind: "spl",
      tokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
  });

  it("does not mutate spend state and permits rebuilding before sync", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n]);
    const { client, assemble } = capturePrivateBuild();
    const input = {
      client,
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: payer, keypair }),
      feePayer: payer,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      amount: 25n,
    } as const;

    await buildTransferTransaction(input);
    await buildTransferTransaction(input);

    expect(assemble).toHaveBeenCalledTimes(2);
    expect(wallet.balance(SOL_MINT).amount).toBe(100n);
    expect(wallet.utxos()[0]?.spent).toBe(false);
  });

  it("applies split defaults without mutating the wallet", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n]);
    const { client, assemble } = capturePrivateBuild();

    await buildSplitTransaction({
      client,
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: payer, keypair }),
      feePayer: payer,
    });

    const authorized = (assemble.mock.calls[0]![0] as { authorized: AuthorizedPrivateTransaction })
      .authorized;
    expect(authorized.proofInputs.outputs.filter((output) => output.amount > 0n)).toHaveLength(2);
    expect(wallet.balance(SOL_MINT).amount).toBe(100n);
  });
});
