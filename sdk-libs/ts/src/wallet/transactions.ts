import type { ZolanaClient } from "../client/client.js";
import type { Address, Bytes32, RequestContext, Transaction } from "../interface/types.js";
import { createAssociatedTokenAccountInstruction } from "../interface/instructions/index.js";
import type { WalletAuthority } from "../transaction/wallet/authority.js";
import { SOL_MINT } from "../transaction/wallet/asset.js";
import type { Wallet } from "../transaction/wallet/state.js";

import {
  createSplit,
  createTransfer,
  createWithdrawal,
  type TransferDestination,
} from "./actions.js";
import { wrapWalletError } from "./error.js";
import { authorizePrivateTransaction } from "./private-transaction.js";

export interface PrivateTransactionParams {
  readonly client: ZolanaClient;
  readonly wallet: Wallet;
  readonly authority: WalletAuthority;
  readonly feePayer: Address;
}

export interface TransferTransactionParams extends PrivateTransactionParams {
  readonly recipient: TransferDestination;
  readonly asset?: Address;
  readonly amount: bigint;
}

export interface WithdrawalTransactionParams extends PrivateTransactionParams {
  readonly recipient: Address;
  readonly asset?: Address;
  readonly amount: bigint;
  readonly splTokenProgram?: Address | null;
}

export interface SplitTransactionParams extends PrivateTransactionParams {
  readonly asset?: Address;
  readonly parts?: number;
  readonly input?: Bytes32;
}

export async function buildTransferTransaction(
  input: TransferTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const created = await createTransfer(
      {
        client: input.client,
        wallet: input.wallet,
        payer: input.feePayer,
        recipient: input.recipient,
        asset: input.asset ?? SOL_MINT,
        amount: input.amount,
      },
      context,
    );
    return await buildAuthorizedTransaction(input, created.transaction, [], context);
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_TRANSFER", cause);
  }
}

export async function buildWithdrawalTransaction(
  input: WithdrawalTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const asset = input.asset ?? SOL_MINT;
    const created = await createWithdrawal({
      wallet: input.wallet,
      payer: input.feePayer,
      recipient: input.recipient,
      asset,
      amount: input.amount,
      ...(input.splTokenProgram === undefined ? {} : { splTokenProgram: input.splTokenProgram }),
    });
    const setupInstructions =
      asset === SOL_MINT
        ? []
        : [
            await createAssociatedTokenAccountInstruction({
              payer: input.feePayer,
              owner: input.recipient,
              mint: asset,
              ...(input.splTokenProgram === undefined
                ? {}
                : { tokenProgram: input.splTokenProgram }),
            }),
          ];
    return await buildAuthorizedTransaction(input, created.transaction, setupInstructions, context);
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_WITHDRAWAL", cause);
  }
}

export async function buildSplitTransaction(
  input: SplitTransactionParams,
  context?: RequestContext,
): Promise<Transaction> {
  try {
    const created = createSplit({
      wallet: input.wallet,
      payer: input.feePayer,
      asset: input.asset ?? SOL_MINT,
      parts: input.parts ?? 2,
      ...(input.input === undefined ? {} : { input: input.input }),
    });
    return await buildAuthorizedTransaction(input, created.transaction, [], context);
  } catch (cause) {
    throw wrapWalletError("WALLET_BUILD_SPLIT", cause);
  }
}

async function buildAuthorizedTransaction(
  input: PrivateTransactionParams,
  transaction: Parameters<typeof authorizePrivateTransaction>[0],
  setupInstructions: Parameters<
    ZolanaClient["assembleAuthorizedPrivateTransaction"]
  >[0]["setupInstructions"],
  context: RequestContext | undefined,
): Promise<Transaction> {
  const authorized = await authorizePrivateTransaction(transaction, input.wallet, input.authority);
  try {
    return await input.client.assembleAuthorizedPrivateTransaction(
      {
        authorized,
        feePayer: input.feePayer,
        ...(setupInstructions === undefined || setupInstructions.length === 0
          ? {}
          : { setupInstructions }),
      },
      context,
    );
  } finally {
    for (const proofInput of authorized.proofInputs.inputUtxos) proofInput.destroy();
  }
}

export type { TransferDestination } from "./actions.js";
