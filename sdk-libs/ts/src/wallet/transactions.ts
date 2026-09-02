import type { ChainReader, TransactionAssembler, WalletKeys } from "../client/ports.js";
import type {
  Address,
  Bytes32,
  Instruction,
  RequestContext,
  Transaction,
} from "../interface/types.js";
import type { ApprovalHandler } from "../transaction/wallet/intent.js";
import { SOL_MINT } from "../transaction/asset.js";
import type { Wallet } from "../transaction/wallet/state.js";

import {
  createSplit,
  createTransfer,
  createWithdrawal,
  type TransferDestination,
} from "./actions.js";
import { wrapWalletError } from "./error.js";
import { authorizePrivateTransaction } from "./private-transaction.js";
import { withdrawalSetupInstructions } from "../flows/settlement.js";

export type PrivateTransactionClient = TransactionAssembler & Pick<ChainReader, "getAccount">;

export interface PrivateTransactionParams {
  readonly client: PrivateTransactionClient;
  readonly wallet: Wallet;
  /** The wallet's privacy roles, in-process (`LocalKeys`) or behind a remote holder. */
  readonly keys: WalletKeys;
  /** The fee payer is also the shielded owner, so its signature authorizes the spend. */
  readonly feePayer: Address;
  /** Approves the intent before proving; unattended when absent. */
  readonly approve?: ApprovalHandler;
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
    const setupInstructions = await withdrawalSetupInstructions({
      payer: input.feePayer,
      recipient: input.recipient,
      asset,
      ...(input.splTokenProgram === undefined ? {} : { splTokenProgram: input.splTokenProgram }),
    });
    const created = await createWithdrawal({
      wallet: input.wallet,
      payer: input.feePayer,
      recipient: input.recipient,
      asset,
      amount: input.amount,
      ...(input.splTokenProgram === undefined ? {} : { splTokenProgram: input.splTokenProgram }),
    });
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
  setupInstructions: readonly Instruction[],
  context: RequestContext | undefined,
): Promise<Transaction> {
  try {
    const authorized = await authorizePrivateTransaction(
      transaction,
      input.wallet,
      input.keys,
      setupInstructions,
      input.approve,
    );
    return await input.client.assembleAuthorizedPrivateTransaction(
      { authorized, feePayer: input.feePayer, keys: input.keys },
      context,
    );
  } catch (cause) {
    const reservationId = transaction._reservationId();
    if (reservationId !== undefined) input.wallet._releaseReservation(reservationId);
    throw cause;
  }
}

export type { TransferDestination } from "./actions.js";
