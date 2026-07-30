import type { Address, Instruction, Signature } from "@solana/kit";

import { isTransactionSignOnlySigner } from "../client/kit.js";
import type { ZolanaClient } from "../client/client.js";
import type { SubmittedPrivateTransaction } from "../client/client.js";
import type { TransactionSignOnlySigner } from "../client/kit.js";
import type { Bytes32, RequestContext, TransactWithdrawal } from "../interface/types.js";
import { createAssociatedTokenAccountInstruction } from "../interface/instructions/index.js";
import type { WalletAuthority } from "../transaction/wallet/authority.js";
import { SOL_MINT } from "../transaction/wallet/asset.js";
import type { Wallet } from "../transaction/wallet/state.js";

import { WalletError, wrapWalletError } from "./error.js";
import {
  createSplit,
  createTransfer,
  createWithdrawal,
  type TransferDestination,
  type TransferRecipient,
  type UnsignedPrivateTransaction,
} from "./actions.js";
import { preparePrivateTransaction } from "./private-transaction.js";

export interface PrivateActionParams {
  readonly client: Pick<ZolanaClient, "submitPrivateTransaction" | "confirmPrivateTransaction">;
  readonly wallet: Wallet;
  readonly authority: WalletAuthority;
  readonly feePayer: TransactionSignOnlySigner;
  readonly skipPreflight?: boolean;
  readonly waitForIndexer?: boolean;
}

export interface TransferActionParams extends PrivateActionParams {
  readonly client: PrivateActionParams["client"] & Pick<ZolanaClient, "getAccount">;
  readonly recipient: TransferDestination;
  readonly asset?: Address;
  readonly amount: bigint;
}

export interface WithdrawalActionParams extends PrivateActionParams {
  readonly recipient: Address;
  readonly asset?: Address;
  readonly amount: bigint;
  readonly splTokenProgram?: Address | null;
}

export interface SplitActionParams extends PrivateActionParams {
  readonly asset?: Address;
  readonly parts?: number;
  readonly input?: Bytes32;
}

export interface SubmittedTransfer extends SubmittedPrivateTransaction {
  readonly recipient: TransferRecipient;
}

export interface SubmittedWithdrawal extends SubmittedPrivateTransaction {
  readonly withdrawal: TransactWithdrawal;
}

export interface SubmittedSplit extends SubmittedPrivateTransaction {
  readonly numOutputs: number;
  readonly perOutputAmount: bigint;
}

export async function transfer(
  input: TransferActionParams,
  context?: RequestContext,
): Promise<SubmittedTransfer> {
  try {
    const created = await createTransfer(
      {
        client: input.client,
        wallet: input.wallet,
        payer: input.feePayer.address,
        recipient: input.recipient,
        asset: input.asset ?? SOL_MINT,
        amount: input.amount,
      },
      context,
    );
    const submitted = await submitPrivate(input, created.transaction, context);
    return Object.freeze({ ...submitted, recipient: created.recipient });
  } catch (cause) {
    throw wrapWalletError("WALLET_SUBMIT_PRIVATE_TRANSACTION", cause);
  }
}

export async function withdraw(
  input: WithdrawalActionParams,
  context?: RequestContext,
): Promise<SubmittedWithdrawal> {
  try {
    const asset = input.asset ?? SOL_MINT;
    const created = await createWithdrawal({
      wallet: input.wallet,
      payer: input.feePayer.address,
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
    const submitted = await submitPrivate(input, created.transaction, context, setupInstructions);
    return Object.freeze({ ...submitted, withdrawal: created.withdrawal });
  } catch (cause) {
    throw wrapWalletError("WALLET_SUBMIT_PRIVATE_TRANSACTION", cause);
  }
}

export async function split(
  input: SplitActionParams,
  context?: RequestContext,
): Promise<SubmittedSplit> {
  try {
    const created = createSplit({
      wallet: input.wallet,
      payer: input.feePayer.address,
      asset: input.asset ?? SOL_MINT,
      parts: input.parts ?? 2,
      ...(input.input === undefined ? {} : { input: input.input }),
    });
    const submitted = await submitPrivate(input, created.transaction, context);
    return Object.freeze({
      ...submitted,
      numOutputs: created.numOutputs,
      perOutputAmount: created.perOutputAmount,
    });
  } catch (cause) {
    throw wrapWalletError("WALLET_SUBMIT_PRIVATE_TRANSACTION", cause);
  }
}

async function submitPrivate(
  input: PrivateActionParams,
  transaction: UnsignedPrivateTransaction,
  context: RequestContext | undefined,
  setupInstructions: readonly Instruction[] = [],
): Promise<Readonly<{ signature: Signature; outputTags: readonly Bytes32[] }>> {
  if (!isTransactionSignOnlySigner(input.feePayer)) {
    throw new WalletError("WALLET_UNSUPPORTED_TRANSACTION_SIGNER");
  }
  const reservation = input.wallet._reserveSubmission(
    transaction._inputs().map(({ entry }) => entry.outputContext.hash),
  );
  let committed = false;
  try {
    const signed = await preparePrivateTransaction(
      transaction,
      input.wallet,
      input.authority,
      reservation,
    );
    const submitted = await input.client.submitPrivateTransaction(
      {
        signed,
        feePayer: input.feePayer,
        ...(setupInstructions.length === 0 ? {} : { setupInstructions }),
        ...(input.skipPreflight === undefined ? {} : { skipPreflight: input.skipPreflight }),
        onReadyToSubmit: () => {
          input.wallet._commitSubmission(reservation);
          committed = true;
        },
      },
      context,
    );
    // Test doubles and compatible custom clients may not implement the hook;
    // a successful return is still an unambiguous submission boundary.
    if (!committed) {
      input.wallet._commitSubmission(reservation);
      committed = true;
    }
    if (input.waitForIndexer !== false) {
      await input.client.confirmPrivateTransaction(submitted.signature, context);
    }
    return submitted;
  } catch (cause) {
    if (!committed) input.wallet._releaseSubmission(reservation);
    throw cause;
  }
}
