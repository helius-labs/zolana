import { address, type Address, type Signature, type TransactionSendingSigner } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import type { TransactionSignOnlySigner, ZolanaClient } from "../src/client/index.js";
import { SPL_TOKEN_2022_PROGRAM_ID, type Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import { Data, LocalWalletAuthority, SOL_MINT, Utxo, Wallet } from "../src/transaction/index.js";
import { AssetRegistry } from "../src/transaction/wallet/asset.js";
import { createSplit, createTransfer, createWithdrawal } from "../src/wallet/actions.js";
import { createDeposit, deposit } from "../src/wallet/deposit.js";
import { split, transfer, withdraw } from "../src/wallet/execute.js";
import {
  preparePrivateTransaction,
  signPrivateTransaction,
} from "../src/wallet/private-transaction.js";
import { MergeMaterial, createMerge, merge } from "../src/wallet/submit.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const RECIPIENT = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const SPL_MINT = address("So11111111111111111111111111111111111111112");
const ZONE = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");
const SIGNATURE = "1".repeat(64) as Signature;
type SubmitPrivateRequest = Parameters<ZolanaClient["submitPrivateTransaction"]>[0];

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function signer(signerAddress: Address = PAYER): TransactionSignOnlySigner {
  return {
    address: signerAddress,
    signTransactions: vi.fn(),
  } as unknown as TransactionSignOnlySigner;
}

function spendingKeypair(): ShieldedKeypair {
  return ShieldedKeypair.fromEd25519(filled(42), 0);
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

describe("private transaction construction", () => {
  it("rejects zero-value public actions before building them", async () => {
    const keypair = ShieldedKeypair.generate();
    await expect(
      createDeposit({
        recipient: keypair.shieldedAddress(),
        asset: SOL_MINT,
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
    const keypair = ShieldedKeypair.fromEd25519(filled(7), 0);
    const wallet = fundedWallet(keypair, [100n]);
    const created = await createWithdrawal({
      wallet,
      payer: PAYER,
      recipient: RECIPIENT,
      asset: SOL_MINT,
      amount: 50n,
    });

    await expect(
      preparePrivateTransaction(
        created.transaction,
        wallet,
        new LocalWalletAuthority({
          solanaPublicKey: keypair.shieldedAddress().solanaAddress(),
          keypair,
        }),
      ),
    ).rejects.toMatchObject({ code: "TRANSACTION_ED25519_PAYER_MISMATCH" });
  });

  it("rejects sending-only signers before private proof generation", async () => {
    const feePayer: TransactionSendingSigner = {
      address: PAYER,
      signAndSendTransactions: vi.fn(),
    };
    const keypair = ShieldedKeypair.generate();
    const client = {
      submitPrivateTransaction: vi.fn(),
    } as unknown as ZolanaClient;

    await expect(
      withdraw({
        client,
        wallet: fundedWallet(keypair, [100n]),
        authority: new LocalWalletAuthority({ solanaPublicKey: PAYER, keypair }),
        feePayer: feePayer as never,
        recipient: RECIPIENT,
        amount: 50n,
      }),
    ).rejects.toMatchObject({ code: "WALLET_UNSUPPORTED_TRANSACTION_SIGNER" });
    expect(client.submitPrivateTransaction).not.toHaveBeenCalled();

    await expect(signPrivateTransaction({ feePayer } as never)).rejects.toMatchObject({
      code: "WALLET_UNSUPPORTED_TRANSACTION_SIGNER",
    });
    await expect(merge({ feePayer } as never)).rejects.toMatchObject({
      code: "WALLET_UNSUPPORTED_TRANSACTION_SIGNER",
    });
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

  it("uses split defaults in the action layer without changing conservation", () => {
    const keypair = ShieldedKeypair.generate();
    const created = createSplit({
      wallet: fundedWallet(keypair, [100n]),
      payer: PAYER,
      asset: SOL_MINT,
      parts: 2,
    });
    expect(created.numOutputs).toBe(2);
    expect(created.perOutputAmount).toBe(50n);
  });

  it("selects merge inputs and conserves their amount", () => {
    const keypair = ShieldedKeypair.generate();
    const created = createMerge({
      wallet: fundedWallet(keypair, [20n, 30n, 100n]),
      material: MergeMaterial.fromKeypair(keypair),
      asset: SOL_MINT,
    });
    expect(created.numInputs).toBe(3);
    expect(created.mergedAmount).toBe(150n);
  });
});

describe("build, sign, send action wrappers", () => {
  it("submits and indexes a withdrawal exactly once", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n]);
    const outputTag = filled(91);
    const submitPrivateTransaction = vi.fn(async () => ({
      signature: SIGNATURE,
      outputTags: [outputTag],
    }));
    const confirmPrivateTransaction = vi.fn(async () => undefined);
    const client = {
      tree: TREE,
      submitPrivateTransaction,
      confirmPrivateTransaction,
    } as unknown as ZolanaClient;

    const result = await withdraw({
      client,
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: payer, keypair }),
      feePayer: signer(payer),
      recipient: RECIPIENT,
      amount: 25n,
    });

    expect(result.signature).toBe(SIGNATURE);
    expect(submitPrivateTransaction).toHaveBeenCalledOnce();
    expect(confirmPrivateTransaction).toHaveBeenCalledWith(SIGNATURE, undefined);
    expect(wallet.utxos()[0]?.spent).toBe(true);
  });

  it("creates a missing SPL recipient ATA in the withdrawal transaction", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n], { asset: SPL_MINT });
    const submitPrivateTransaction = vi.fn(async (request: SubmitPrivateRequest) => {
      request.onReadyToSubmit?.();
      return { signature: SIGNATURE, outputTags: [filled(94)] };
    });
    const client = {
      tree: TREE,
      submitPrivateTransaction,
      confirmPrivateTransaction: vi.fn(async () => undefined),
    } as unknown as ZolanaClient;

    await withdraw({
      client,
      wallet,
      authority: new LocalWalletAuthority({ solanaPublicKey: payer, keypair }),
      feePayer: signer(payer),
      recipient: RECIPIENT,
      asset: SPL_MINT,
      amount: 25n,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });

    const request = submitPrivateTransaction.mock.calls[0]?.[0];
    expect(request?.setupInstructions).toHaveLength(1);
    expect(
      request?.setupInstructions?.[0]?.accounts?.some(
        (account) => account.address === SPL_TOKEN_2022_PROGRAM_ID,
      ),
    ).toBe(true);
    expect(request?.signed.withdrawal).toMatchObject({
      kind: "spl",
      tokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
  });

  it("reserves inputs before asynchronous proof submission", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const wallet = fundedWallet(keypair, [100n]);
    let entered!: () => void;
    let release!: () => void;
    const submissionEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const submissionGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const submitPrivateTransaction = vi.fn(async (request: SubmitPrivateRequest) => {
      entered();
      await submissionGate;
      request.onReadyToSubmit?.();
      return { signature: SIGNATURE, outputTags: [filled(95)] };
    });
    const client = { tree: TREE, submitPrivateTransaction } as unknown as ZolanaClient;
    const authority = new LocalWalletAuthority({ solanaPublicKey: payer, keypair });
    const recipient = ShieldedKeypair.generate().shieldedAddress();

    const first = transfer({
      client,
      wallet,
      authority,
      feePayer: signer(payer),
      recipient,
      amount: 25n,
      waitForIndexer: false,
    });
    await submissionEntered;

    await expect(
      transfer({
        client,
        wallet,
        authority,
        feePayer: signer(payer),
        recipient,
        amount: 25n,
        waitForIndexer: false,
      }),
    ).rejects.toMatchObject({ code: "WALLET_INSUFFICIENT_BALANCE" });

    release();
    await expect(first).resolves.toMatchObject({ signature: SIGNATURE });
    expect(submitPrivateTransaction).toHaveBeenCalledOnce();
  });

  it("does not submit when address resolution finds no shielded recipient", async () => {
    const keypair = ShieldedKeypair.generate();
    const getAccount = vi.fn(async () => undefined);
    const submitPrivateTransaction = vi.fn(async () => ({
      signature: SIGNATURE,
      outputTags: [filled(92)],
    }));
    const confirmPrivateTransaction = vi.fn(async () => undefined);
    const client = {
      tree: TREE,
      getAccount,
      submitPrivateTransaction,
      confirmPrivateTransaction,
    } as unknown as ZolanaClient;

    await expect(
      transfer({
        client,
        wallet: fundedWallet(keypair, [100n]),
        authority: new LocalWalletAuthority({ solanaPublicKey: PAYER, keypair }),
        feePayer: signer(),
        recipient: RECIPIENT,
        amount: 25n,
      }),
    ).rejects.toMatchObject({ code: "WALLET_RECIPIENT_NOT_REGISTERED" });
    expect(getAccount).toHaveBeenCalledOnce();
    expect(submitPrivateTransaction).not.toHaveBeenCalled();
    expect(confirmPrivateTransaction).not.toHaveBeenCalled();
  });

  it("builds and sends a deposit with protocol defaults", async () => {
    const keypair = ShieldedKeypair.generate();
    const signAndSendInstructions = vi.fn(
      async (_input: Readonly<{ instructions: readonly unknown[] }>) => SIGNATURE,
    );
    const confirmPrivateTransaction = vi.fn(async () => undefined);
    const client = {
      tree: TREE,
      signAndSendInstructions,
      confirmPrivateTransaction,
    } as unknown as ZolanaClient;

    const result = await deposit({
      client,
      feePayer: signer(),
      recipient: keypair.shieldedAddress(),
      amount: 42n,
    });

    expect(result.signature).toBe(SIGNATURE);
    expect(signAndSendInstructions).toHaveBeenCalledOnce();
    expect(confirmPrivateTransaction).toHaveBeenCalledOnce();
    const call = signAndSendInstructions.mock.calls[0]?.[0];
    expect(call?.instructions).toHaveLength(1);
  });

  it("threads Token-2022 through an SPL deposit", async () => {
    const keypair = ShieldedKeypair.generate();
    const signAndSendInstructions = vi.fn(
      async (_input: Readonly<{ instructions: readonly unknown[] }>) => SIGNATURE,
    );
    const client = {
      tree: TREE,
      signAndSendInstructions,
      confirmPrivateTransaction: vi.fn(async () => undefined),
    } as unknown as ZolanaClient;

    await deposit({
      client,
      feePayer: signer(),
      recipient: keypair.shieldedAddress(),
      asset: SPL_MINT,
      amount: 42n,
      splTokenAccount: RECIPIENT,
      splTokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });

    const instruction = signAndSendInstructions.mock.calls[0]?.[0].instructions[0] as Readonly<{
      accounts?: readonly Readonly<{ address: Address }>[];
    }>;
    expect(
      instruction.accounts?.some((account) => account.address === SPL_TOKEN_2022_PROGRAM_ID),
    ).toBe(true);
  });

  it("applies split defaults before one submit and confirmation", async () => {
    const keypair = spendingKeypair();
    const payer = keypair.shieldedAddress().solanaAddress();
    const outputTag = filled(93);
    const submitPrivateTransaction = vi.fn(async () => ({
      signature: SIGNATURE,
      outputTags: [outputTag],
    }));
    const confirmPrivateTransaction = vi.fn(async () => undefined);
    const client = {
      tree: TREE,
      submitPrivateTransaction,
      confirmPrivateTransaction,
    } as unknown as ZolanaClient;

    const result = await split({
      client,
      wallet: fundedWallet(keypair, [100n]),
      authority: new LocalWalletAuthority({ solanaPublicKey: payer, keypair }),
      feePayer: signer(payer),
    });

    expect(result).toMatchObject({ signature: SIGNATURE, numOutputs: 2, perOutputAmount: 50n });
    expect(submitPrivateTransaction).toHaveBeenCalledOnce();
    expect(confirmPrivateTransaction).toHaveBeenCalledWith(SIGNATURE, undefined);
  });
});
