import {
  address,
  decompileTransactionMessage,
  getCompiledTransactionMessageDecoder,
  type Address,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { LocalKeys } from "../src/client/keys.js";
import {
  authorizedPrivateTransactionMaterial,
  type AuthorizedPrivateTransaction,
  type ProofService,
} from "../src/client/ports.js";
import type { RpcAccount } from "../src/client/rpc.js";
import { reservedUtxoKeys } from "../src/flows/reserve.js";
import { InstructionTag } from "../src/interface/index.js";
import { associatedTokenAddress, treeAddress } from "../src/interface/pda/index.js";
import {
  SHIELDED_POOL_PROGRAM_ID,
  SPL_TOKEN_2022_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
} from "../src/interface/program.js";
import type { Bytes32 } from "../src/interface/types.js";
import { ShieldedKeypair, SigningKey } from "../src/keypair/index.js";
import { Data, SOL_MINT, Utxo, Wallet } from "../src/transaction/index.js";
import { AssetRegistry } from "../src/transaction/asset.js";
import { createWithdrawal } from "../src/wallet/actions.js";
import { buildDepositTransaction, createDeposit } from "../src/wallet/deposit.js";
import { WalletError } from "../src/wallet/error.js";
import { buildWithdrawalTransaction } from "../src/wallet/transactions.js";

import { depositClient, privateTransactionClient } from "./helpers/clients.js";
import { emptyTransaction } from "./helpers/transactions.js";

const TREE = treeAddress(0);
const MINT = address("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB");
const RECIPIENT = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");

function filled(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

/** An initialized mint account with six decimals, owned by `owner`. */
function mintAccount(owner: Address): RpcAccount {
  const data = new Uint8Array(82);
  data[44] = 6;
  data[45] = 1;
  return { owner, data, lamports: 1n };
}

function spendingKeypair(): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(filled(42)));
}

/** Unit tests never reach the prover; the keys still need one to exist. */
function stubProofs(): ProofService {
  const refuse = vi.fn(async () => {
    throw new Error("the prover must not be called");
  });
  return { prove: refuse, proveMerge: refuse };
}

function splWallet(keypair: ShieldedKeypair): Wallet {
  const wallet = new Wallet({
    identity: keypair.shieldedAddress(),
    registry: new AssetRegistry([[2n, MINT]]),
  });
  wallet._replace({
    utxos: [
      {
        utxo: new Utxo({
          owner: keypair.signingPublicKey(),
          asset: MINT,
          amount: 100n,
          blinding: filled(1),
          data: new Data(),
        }),
        outputContext: { hash: filled(2), tree: TREE, leafIndex: 0n },
        nullifier: filled(3),
        spent: false,
      },
    ],
    transactions: [],
    nullifiers: new Set(),
  });
  return wallet;
}

/** A private-transaction client whose chain holds only `mint`, if any. */
function withdrawalBuild(mint: RpcAccount | undefined) {
  const keypair = spendingKeypair();
  const wallet = splWallet(keypair);
  const getAccount = vi.fn(async (account: Address) => (account === MINT ? mint : undefined));
  const assemble = vi.fn(async (_input: Readonly<{ authorized: AuthorizedPrivateTransaction }>) =>
    emptyTransaction(RECIPIENT),
  );
  const build = (splTokenProgram?: Address) =>
    buildWithdrawalTransaction({
      client: privateTransactionClient({
        getAccount,
        assembleAuthorizedPrivateTransaction: assemble,
      }),
      wallet,
      keys: LocalKeys.fromKeypair(keypair, stubProofs()),
      feePayer: keypair.shieldedAddress().solanaAddress(),
      recipient: RECIPIENT,
      asset: MINT,
      amount: 25n,
      ...(splTokenProgram === undefined ? {} : { splTokenProgram }),
    });
  return { wallet, getAccount, assemble, build };
}

describe("SPL token program of a withdrawal", () => {
  it("settles a Token-2022 withdrawal at the Token-2022 account when the program is not named", async () => {
    const { assemble, build } = withdrawalBuild(mintAccount(SPL_TOKEN_2022_PROGRAM_ID));
    await build();

    const request = assemble.mock.calls[0]?.[0];
    if (request === undefined) throw new Error("assembly request was not captured");
    const material = authorizedPrivateTransactionMaterial(request.authorized);
    if (material === undefined) throw new Error("authorization was not minted");
    const tokenAccount = await associatedTokenAddress(RECIPIENT, MINT, SPL_TOKEN_2022_PROGRAM_ID);
    expect(material.withdrawal).toMatchObject({
      kind: "splWithdrawal",
      recipientTokenAccount: tokenAccount,
      tokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
    });
    // The proof binds the token account the withdrawal pays.
    expect(material.proofInputs.externalData.interfaceTransfers).toMatchObject([
      { kind: "spl", isDeposit: false, mint: MINT, tokenAccount },
    ]);
    expect(material.setupInstructions).toHaveLength(1);
    expect(material.setupInstructions[0]?.accounts?.map((account) => account.address)).toContain(
      SPL_TOKEN_2022_PROGRAM_ID,
    );
  });

  it("uses a named token program without reading the mint", async () => {
    const { getAccount, assemble, build } = withdrawalBuild(undefined);
    await build(SPL_TOKEN_PROGRAM_ID);
    expect(getAccount.mock.calls.map(([account]) => account)).not.toContain(MINT);
    expect(assemble).toHaveBeenCalledOnce();
  });

  it.each([
    ["missing", undefined],
    ["owner", mintAccount(SHIELDED_POOL_PROGRAM_ID)],
  ] as const)(
    "refuses a mint whose token program cannot be read (%s) before reserving or proving",
    async (reason, mint) => {
      const { wallet, assemble, build } = withdrawalBuild(mint);
      const error = await build().catch((cause: unknown) => cause);
      expect(error).toMatchObject({
        code: "WALLET_BUILD_WITHDRAWAL",
        causeCodes: ["WALLET_ASSET_METADATA"],
      });
      expect(error instanceof WalletError ? error.cause : undefined).toMatchObject({
        details: { mint: MINT, reason },
      });
      expect(assemble).not.toHaveBeenCalled();
      expect(reservedUtxoKeys(wallet).size).toBe(0);
    },
  );

  it("refuses an SPL withdrawal without a token program, as Rust does", async () => {
    const wallet = splWallet(spendingKeypair());
    await expect(
      createWithdrawal({
        wallet,
        payer: RECIPIENT,
        recipient: RECIPIENT,
        asset: MINT,
        amount: 25n,
      }),
    ).rejects.toMatchObject({
      code: "TRANSACTION_MISSING_SPL_TOKEN_PROGRAM",
      details: { mint: MINT },
    });
    expect(reservedUtxoKeys(wallet).size).toBe(0);
  });
});

describe("SPL token program of a deposit", () => {
  function depositInstructionOf(transaction: Awaited<ReturnType<typeof buildDepositTransaction>>) {
    const compiled = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
    const instructions = decompileTransactionMessage(compiled, {
      lastValidBlockHeight: 1n,
    }).instructions;
    const deposit = instructions.find((entry) => entry.data?.[0] === InstructionTag.deposit);
    if (deposit === undefined) throw new Error("the transaction carries a deposit");
    return deposit;
  }

  it("draws a Token-2022 deposit from the Token-2022 account when the program is not named", async () => {
    const depositor = spendingKeypair().shieldedAddress().solanaAddress();
    const transaction = await buildDepositTransaction({
      client: depositClient({
        getAccount: async (account) =>
          account === MINT ? mintAccount(SPL_TOKEN_2022_PROGRAM_ID) : undefined,
      }),
      feePayer: depositor,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      asset: MINT,
      amount: 5n,
      createSplInterface: false,
    });
    const addresses = (depositInstructionOf(transaction).accounts ?? []).map(
      (account) => account.address,
    );
    expect(addresses).toContain(SPL_TOKEN_2022_PROGRAM_ID);
    expect(addresses).toContain(
      await associatedTokenAddress(depositor, MINT, SPL_TOKEN_2022_PROGRAM_ID),
    );
    expect(addresses).not.toContain(SPL_TOKEN_PROGRAM_ID);
  });

  it("refuses an SPL deposit without a token program, as Rust does", async () => {
    await expect(
      createDeposit({
        recipient: ShieldedKeypair.generate().shieldedAddress(),
        asset: MINT,
        amount: 5n,
        depositor: RECIPIENT,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_CREATE_DEPOSIT",
      causeCode: "TRANSACTION_MISSING_SPL_TOKEN_PROGRAM",
    });
  });

  it("reads no mint for a SOL deposit", async () => {
    const getAccount = vi.fn(async () => undefined);
    await buildDepositTransaction({
      client: depositClient({ getAccount }),
      feePayer: RECIPIENT,
      recipient: ShieldedKeypair.generate().shieldedAddress(),
      asset: SOL_MINT,
      amount: 5n,
    });
    expect(getAccount).not.toHaveBeenCalled();
  });
});
