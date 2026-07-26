import type { Rpc, ZolanaClient } from "@zolana/client";
import { type Address, type Bytes32, type Signature, type Transaction } from "@zolana/interface";
import { associatedTokenAddress } from "@zolana/interface/pda";
import { randomBlinding, ShieldedKeypair } from "@zolana/keypair";
import { AssetRegistry, Data, SOL_MINT, Utxo, Wallet } from "@zolana/transaction";
import { describe, expect, it, vi } from "vitest";

import {
  buildDepositTransaction,
  buildPrivateTransaction,
  createAssociatedTokenAccount,
  createDeposit,
  createMerge,
  createSplit,
  createTransfer,
  createWithdrawal,
  getPrivateTokenBalances,
  getPrivateTransactions,
  LocalWalletAuthority,
  signPrivateTransaction,
  type TransactionSigner,
} from "../src/index.js";
import { base58, fixture, hex, hexBytes, walletFixture } from "./helpers/fixtures.js";

const OWNER = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi" as Address;
const TREE = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR" as Address;
const MINT = "BMLm6t2ykqZ8TJ974ze9CR8ApeR44XoFAearTLeHj8ya" as Address;
const SIGNATURE = "1".repeat(64) as Signature;
const bytes32 = (value: number): Bytes32 => new Uint8Array(32).fill(value) as Bytes32;

function rpc(overrides: Partial<Rpc> = {}): Rpc {
  const unsupported = (): Promise<never> => Promise.reject(new Error("unexpected RPC call"));
  return {
    getAccount: unsupported,
    getMultipleAccounts: unsupported,
    getBalance: unsupported,
    getLatestBlockhash: () =>
      Promise.resolve({
        blockhash: "11111111111111111111111111111111",
        lastValidBlockHeight: 1n,
      }),
    sendTransaction: unsupported,
    confirmTransaction: unsupported,
    transactOutputViewTags: unsupported,
    getMerkleProofs: unsupported,
    getNonInclusionProofs: unsupported,
    getInputMerkleProofs: unsupported,
    ...overrides,
  };
}

function fundedWallet(
  amounts: readonly bigint[],
  asset: Address = SOL_MINT,
  keypair: ShieldedKeypair = ShieldedKeypair.generate(),
): Wallet {
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry(asset === SOL_MINT ? [] : [[1n, asset]]),
  });
  wallet._replace({
    utxos: amounts.map((amount, index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset,
        amount,
        blinding: randomBlinding(),
        data: new Data(),
      }),
      outputContext: {
        hash: bytes32(index + 1),
        tree: TREE,
        leafIndex: BigInt(index),
      },
      nullifier: bytes32(index + 20),
      spent: false,
    })),
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

describe("wallet actions", () => {
  it("routes SOL and SPL deposits and builds unsigned custody messages", async () => {
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const sol = createDeposit({ recipient, asset: SOL_MINT, amount: 42n });
    expect(sol.spl).toBeUndefined();
    expect(sol.data.amount).toBe(42n);
    expect(sol.viewTag()).toEqual(recipient.confidentialViewTag());

    const token = createDeposit({
      recipient,
      asset: MINT,
      amount: 9n,
      splTokenAccount: OWNER,
      memo: Uint8Array.of(1, 2),
    });
    expect(token.spl?.userToken).toBe(OWNER);
    expect(typeof token.spl?.tokenProgram).toBe("string");
    const transaction = await buildDepositTransaction({
      rpc: rpc(),
      payer: OWNER,
      tree: TREE,
      depositor: OWNER,
      deposit: token,
    });
    expect(transaction.signatures).toEqual([undefined]);
    expect(transaction.messageBytes.length).toBeGreaterThan(
      token.instruction(TREE, OWNER).data.length,
    );
  });

  // A deposit tagged by anything other than the owner signing pubkey is
  // invisible to a wallet that scans only what the spec defines, and nothing on
  // the write path rejects it. Pin both halves so a return to the viewing key
  // fails here instead of silently losing deposits.
  it("tags a deposit with the recipient signing pubkey", () => {
    const recipient = ShieldedKeypair.generate().shieldedAddress();
    const deposit = createDeposit({ recipient, asset: SOL_MINT, amount: 42n });

    expect(deposit.viewTag()).toEqual(recipient.confidentialViewTag());
    expect(deposit.viewTag()).not.toEqual(recipient.viewingPublicKey.x());
  });

  it("selects inputs in wallet order and validates split divisibility", () => {
    const wallet = fundedWallet([3n, 8n, 12n]);
    const withdrawal = createWithdrawal({
      wallet,
      payer: OWNER,
      recipient: TREE,
      asset: SOL_MINT,
      amount: 10n,
    });
    expect(withdrawal.transaction.inputCount()).toBe(2);
    expect(withdrawal.withdrawal).toEqual({ kind: "sol", recipient: TREE });

    const split = createSplit({ wallet, payer: OWNER, asset: SOL_MINT, parts: 4 });
    expect(split.perOutputAmount).toBe(3n);
    expect(split.transaction.inputCount()).toBe(1);
    expect(() =>
      createSplit({ wallet: fundedWallet([11n]), payer: OWNER, asset: SOL_MINT, parts: 2 }),
    ).toThrow(expect.objectContaining({ code: "WALLET_SPLIT_NOT_DIVISIBLE" }));
  });

  it("builds a zero-amount withdrawal and refuses one outside the u64 range", () => {
    // `create_withdrawal` has no amount check and `select_inputs` returns on the
    // first eligible note, so zero is a withdrawal Rust builds.
    const zero = createWithdrawal({
      wallet: fundedWallet([3n, 8n]),
      payer: OWNER,
      recipient: TREE,
      asset: SOL_MINT,
      amount: 0n,
    });
    expect(zero.transaction.inputCount()).toBe(1);
    expect(zero.withdrawal).toEqual({ kind: "sol", recipient: TREE });

    expect(() =>
      createWithdrawal({
        wallet: fundedWallet([3n]),
        payer: OWNER,
        recipient: TREE,
        asset: SOL_MINT,
        amount: 0x1_0000_0000_0000_0000n,
      }),
    ).toThrow(expect.objectContaining({ code: "WALLET_INVALID_AMOUNT" }));
  });

  it("falls back to a public withdrawal for an unregistered recipient", async () => {
    const wallet = fundedWallet([10n]);
    const created = await createTransfer({
      rpc: rpc({ getAccount: () => Promise.resolve(undefined) }),
      wallet,
      payer: OWNER,
      recipient: TREE,
      asset: SOL_MINT,
      amount: 5n,
    });
    expect(created.recipient.kind).toBe("publicWithdrawal");
    expect(created.transaction.inputCount()).toBe(1);
  });

  it("submits the idempotent ATA instruction through the external signer", async () => {
    const fixture = await walletFixture<{
      inputs: { owner: Address; mint: Address };
      expected: {
        address: Address;
        transaction: { messageBytes: string; signatures: Signature[] };
      };
    }>("create_associated_token_account");
    let signedMessage: Uint8Array | undefined;
    const signer: TransactionSigner = {
      address: "7nLFtY5yiR4CZnkB6bYMth3bbAns9DnFhtgjHGqcCiRn" as Address,
      signNativeTransaction(transaction: Transaction): Promise<Transaction> {
        signedMessage = transaction.messageBytes;
        return Promise.resolve({
          ...transaction,
          signatures: fixture.expected.transaction.signatures,
        });
      },
    };
    const sendTransaction = vi.fn(() => Promise.resolve(SIGNATURE));
    const result = await createAssociatedTokenAccount({
      rpc: rpc({
        getLatestBlockhash: () =>
          Promise.resolve({
            blockhash: base58(new Uint8Array(32).fill(29)),
            lastValidBlockHeight: 1n,
          }),
        sendTransaction,
      }),
      payer: signer,
      owner: fixture.inputs.owner,
      mint: fixture.inputs.mint,
    });
    expect(result.address).toBe(fixture.expected.address);
    expect(result.address).toBe(associatedTokenAddress(fixture.inputs.owner, fixture.inputs.mint));
    expect(signedMessage === undefined ? undefined : hex(signedMessage)).toBe(
      fixture.expected.transaction.messageBytes,
    );
    expect(sendTransaction).toHaveBeenCalledTimes(1);
  });

  it("returns immutable balance and history snapshots", () => {
    const wallet = fundedWallet([2n, 5n]);
    // `get_private_token_balances` passes `skip_utxos = true`, so the note list
    // is dropped and only the aggregate survives.
    const balances = getPrivateTokenBalances(wallet);
    const history = getPrivateTransactions(wallet);
    expect(balances).toEqual([{ assetId: 1n, mint: SOL_MINT, amount: 7n, utxos: [] }]);
    expect(history).toEqual([]);

    const state = wallet._state();
    wallet._replace({
      utxos: state.utxos.map((entry, index) => (index === 0 ? { ...entry, spent: true } : entry)),
      transactions: [
        {
          id: { signature: SIGNATURE, slot: 1n, index: 0n },
          kind: "deposit",
          direction: "inbound",
          status: "confirmed",
          asset: SOL_MINT,
          amount: 2n,
        },
      ],
      nullifiers: state.nullifiers,
    });

    // Rust returns owned values from both calls, so a result taken before the
    // wallet moved still reads as it did and cannot be written back through.
    expect(balances).toEqual([{ assetId: 1n, mint: SOL_MINT, amount: 7n, utxos: [] }]);
    expect(history).toEqual([]);
    expect(Object.isFrozen(balances[0])).toBe(true);
    expect(getPrivateTokenBalances(wallet)).toEqual([
      { assetId: 1n, mint: SOL_MINT, amount: 5n, utxos: [] },
    ]);
    expect(getPrivateTransactions(wallet)).toHaveLength(1);
  });

  it("auto-merges the frozen smallest-input set and rejects duplicates", async () => {
    const fixture = await walletFixture<{
      expected: {
        merge: {
          selectedAmounts: string[];
          mergedAmount: string;
          realInputCount: string;
          paddedInputCount: string;
        };
      };
    }>("transaction");
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({
      identity: keypair.shieldedAddress(),
      registry: new AssetRegistry(),
    });
    const entries = [20n, 50n, 10n].map((amount, index) => ({
      utxo: new Utxo({
        owner: keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount,
        blinding: randomBlinding(),
        data: new Data(),
      }),
      outputContext: {
        hash: bytes32(index + 1),
        tree: TREE,
        leafIndex: BigInt(index),
      },
      nullifier: bytes32(index + 20),
      spent: false,
    }));
    wallet._replace({ utxos: entries, transactions: [], nullifiers: new Set() });
    const created = createMerge({ wallet, keypair, asset: SOL_MINT });
    expect(created.numInputs).toBe(Number(fixture.expected.merge.realInputCount));
    expect(created.mergedAmount).toBe(BigInt(fixture.expected.merge.mergedAmount));
    expect(
      created.prepared.inputs.filter((input) => !input.isDummy()).map((input) => input.utxo.amount),
    ).toEqual(fixture.expected.merge.selectedAmounts.map(BigInt));
    expect(created.prepared.inputs).toHaveLength(Number(fixture.expected.merge.paddedInputCount));
    const duplicate = entries[0];
    if (duplicate === undefined) throw new Error("missing merge input");
    expect(() =>
      createMerge({
        wallet,
        keypair,
        asset: SOL_MINT,
        inputs: [duplicate.outputContext.hash, duplicate.outputContext.hash],
      }),
    ).toThrow(expect.objectContaining({ code: "WALLET_DUPLICATE_INPUT_UTXO" }));
  });

  it("keeps external-custody and signer convenience message bytes identical", async () => {
    const clientFixture = await fixture<{
      expected: { legacyMessages: { limitOnlyBytes: string } };
    }>("client/rpc-indexer-v1");
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({
      identity: keypair.shieldedAddress(),
      registry: new AssetRegistry(),
    });
    wallet._replace({
      utxos: [
        {
          utxo: new Utxo({
            owner: keypair.signingPublicKey(),
            asset: SOL_MINT,
            amount: 10n,
            blinding: randomBlinding(),
            data: new Data(),
          }),
          outputContext: { hash: bytes32(1), tree: TREE, leafIndex: 0n },
          nullifier: bytes32(20),
          spent: false,
        },
      ],
      transactions: [],
      nullifiers: new Set(),
    });
    const authority = new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair });
    const transaction = createWithdrawal({
      wallet,
      payer: OWNER,
      recipient: TREE,
      asset: SOL_MINT,
      amount: 5n,
    }).transaction;
    const native: Transaction = {
      messageBytes: hexBytes(clientFixture.expected.legacyMessages.limitOnlyBytes),
      signatures: [undefined],
    };
    const client = {
      rpc: rpc(),
      finishSubmissionUnsigned: () => Promise.resolve(native),
    } as unknown as ZolanaClient;
    const unsigned = await buildPrivateTransaction({
      transaction,
      wallet,
      authority,
      client,
      feePayer: OWNER,
    });
    const signed = await signPrivateTransaction({
      transaction,
      wallet,
      authority,
      client,
      feePayer: {
        address: OWNER,
        signNativeTransaction: (value) => Promise.resolve({ ...value, signatures: [SIGNATURE] }),
      },
    });
    expect(signed.messageBytes).toEqual(unsigned.messageBytes);
    expect(hex(unsigned.messageBytes)).toBe(clientFixture.expected.legacyMessages.limitOnlyBytes);
    expect(unsigned.signatures).toEqual([undefined]);
    expect(signed.signatures).toEqual([SIGNATURE]);
  });

  it("takes the signing rail from the authority address", async () => {
    const client = {
      rpc: rpc(),
      finishSubmissionUnsigned: () =>
        Promise.resolve({ messageBytes: Uint8Array.of(1), signatures: [undefined] }),
    } as unknown as ZolanaClient;
    const signatureCount = async (keypair: ShieldedKeypair): Promise<number> => {
      const wallet = fundedWallet([10n], SOL_MINT, keypair);
      const authority = new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair });
      const signP256 = vi.spyOn(authority, "signP256");
      const transaction = createWithdrawal({
        wallet,
        payer: OWNER,
        recipient: TREE,
        asset: SOL_MINT,
        amount: 5n,
      }).transaction;
      await buildPrivateTransaction({ transaction, wallet, authority, client, feePayer: OWNER });
      return signP256.mock.calls.length;
    };

    expect(await signatureCount(ShieldedKeypair.generate())).toBe(1);
    expect(await signatureCount(ShieldedKeypair.fromEd25519(bytes32(3), 0))).toBe(0);
  });

  it("rejects an input note swapped between build and sign", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = fundedWallet([10n], SOL_MINT, keypair);
    const transaction = createWithdrawal({
      wallet,
      payer: OWNER,
      recipient: TREE,
      asset: SOL_MINT,
      amount: 5n,
    }).transaction;
    const original = wallet.utxos()[0];
    if (original === undefined) throw new Error("missing funded note");
    // Same commitment, nullifier, asset, amount, and blinding: the swap is only
    // visible once the attached data is compared too.
    wallet._replace({
      utxos: [
        {
          ...original,
          utxo: new Utxo({
            owner: keypair.signingPublicKey(),
            asset: SOL_MINT,
            amount: 10n,
            blinding: original.utxo.blinding,
            data: new Data([{ kind: "memo", bytes: Uint8Array.of(7) }]),
          }),
        },
      ],
      transactions: [],
      nullifiers: new Set(),
    });

    await expect(
      buildPrivateTransaction({
        transaction,
        wallet,
        authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
        client: { rpc: rpc() } as unknown as ZolanaClient,
        feePayer: OWNER,
      }),
    ).rejects.toThrow(expect.objectContaining({ code: "WALLET_UNSIGNED_INPUT_UNAVAILABLE" }));
  });

  // The caller's signer stands in for `Transaction::try_sign`, whose failure
  // `sign_private_transaction` reports as `SolanaTransactionSigning`. A fee
  // payer that cannot sign must be identifiable by the same code here.
  it("names a fee payer that cannot sign as Rust's signing failure", async () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = fundedWallet([10n], SOL_MINT, keypair);
    const client = {
      rpc: rpc(),
      finishSubmissionUnsigned: () =>
        Promise.resolve({ messageBytes: Uint8Array.of(1), signatures: [undefined] }),
    } as unknown as ZolanaClient;

    await expect(
      signPrivateTransaction({
        transaction: createWithdrawal({
          wallet,
          payer: OWNER,
          recipient: TREE,
          asset: SOL_MINT,
          amount: 5n,
        }).transaction,
        wallet,
        authority: new LocalWalletAuthority({ solanaPublicKey: OWNER, keypair }),
        client,
        feePayer: {
          address: OWNER,
          signNativeTransaction: () => Promise.reject(new Error("keystore locked")),
        },
      }),
    ).rejects.toThrow(
      expect.objectContaining({
        code: "WALLET_SIGN_PRIVATE_TRANSACTION",
        causeCode: "CLIENT_SOLANA_TRANSACTION_SIGNING",
      }),
    );
  });
});
