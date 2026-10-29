import { isTransactionWithBlockhashLifetime } from "@solana/kit";
import { ClientError } from "../client/error.js";
import { authorizedPrivateTransactionMaterial } from "../client/ports.js";
import { reserveEntries } from "../flows/reserve.js";
import { withdrawalSetupInstructions } from "../flows/settlement.js";
import type { Instruction, RequestContext } from "../interface/types.js";
import { SOL_MINT } from "../transaction/asset.js";
import { intentHash } from "../transaction/wallet/intent.js";
import type { Wallet, WalletUtxo } from "../transaction/wallet/state.js";
import {
  createMultiTransfer,
  createSplit,
  createTransfer,
  createWithdrawal,
  type UnsignedPrivateTransaction,
} from "../wallet/actions.js";
import { WalletError, wrapWalletError, type WalletErrorCode } from "../wallet/error.js";
import { equalBytes } from "../wallet/internal.js";
import {
  authorizeAndAssemble,
  type MultiTransferTransactionParams,
  type PrivateTransactionParams,
  type SplitTransactionParams,
  type TransferTransactionParams,
  type WithdrawalTransactionParams,
} from "../wallet/transactions.js";
import {
  checkRetainedEntries,
  RingTransactionSubmission,
  type RingSubmissionAttempt,
  type RingSubmissionBuildState,
} from "./submission.js";

/**
 * A default-pool transfer that signs, broadcasts and settles itself. Its UTXOs
 * stay reserved until the transfer confirms, fails or expires unseen, so `send`
 * after an unknown outcome checks the first signature instead of paying again,
 * and a rebuild after expiry spends the same UTXOs.
 */
export async function createTransferSubmission(
  input: TransferTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  return createSpendSubmission(
    input,
    "WALLET_BUILD_TRANSFER",
    async (context) => ({
      transaction: (
        await createTransfer(
          {
            client: input.client,
            wallet: input.wallet,
            payer: input.feePayer,
            recipient: input.recipient,
            asset: input.asset ?? SOL_MINT,
            amount: input.amount,
          },
          context,
        )
      ).transaction,
      setupInstructions: [],
    }),
    context,
  );
}

/** `buildMultiTransferTransaction` as a submission, see `createTransferSubmission`. */
export async function createMultiTransferSubmission(
  input: MultiTransferTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  return createSpendSubmission(
    input,
    "WALLET_BUILD_TRANSFER",
    async (context) => ({
      transaction: (
        await createMultiTransfer(
          {
            client: input.client,
            wallet: input.wallet,
            payer: input.feePayer,
            payments: input.payments,
            asset: input.asset ?? SOL_MINT,
          },
          context,
        )
      ).transaction,
      setupInstructions: [],
    }),
    context,
  );
}

/** `buildWithdrawalTransaction` as a submission, see `createTransferSubmission`. */
export async function createWithdrawalSubmission(
  input: WithdrawalTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  return createSpendSubmission(
    input,
    "WALLET_BUILD_WITHDRAWAL",
    async () => {
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
      return { transaction: created.transaction, setupInstructions };
    },
    context,
  );
}

/** `buildSplitTransaction` as a submission, see `createTransferSubmission`. */
export async function createSplitSubmission(
  input: SplitTransactionParams,
  context?: RequestContext,
): Promise<RingTransactionSubmission> {
  return createSpendSubmission(
    input,
    "WALLET_BUILD_SPLIT",
    async () => ({
      transaction: createSplit({
        wallet: input.wallet,
        payer: input.feePayer,
        asset: input.asset ?? SOL_MINT,
        parts: input.parts ?? 2,
        ...(input.input === undefined ? {} : { input: input.input }),
      }).transaction,
      setupInstructions: [],
    }),
    context,
  );
}

/** A default-pool spend has no ring instruction, so only expiry triggers a rebuild. */
const NO_RING_INSTRUCTION = -1;

type CreatedSpend = Readonly<{
  transaction: UnsignedPrivateTransaction;
  setupInstructions: readonly Instruction[];
}>;

async function createSpendSubmission(
  input: PrivateTransactionParams,
  code: WalletErrorCode,
  create: (context?: RequestContext) => Promise<CreatedSpend>,
  context: RequestContext | undefined,
): Promise<RingTransactionSubmission> {
  // The first build selects; every rebuild proves the same unsigned spend again.
  let created: CreatedSpend | undefined;
  return RingTransactionSubmission.fromBuilder(
    {
      wallet: input.wallet,
      build: async (retry, context) => {
        try {
          if (created !== undefined && retry.entries !== undefined) {
            checkRetainedEntries(input.wallet, retry.entries);
          }
          const spend = created ?? holdUntilSettled(input.wallet, retry, await create(context));
          created = spend;
          return await spendAttempt(input, spend, retry, context);
        } catch (cause) {
          throw wrapWalletError(code, cause);
        }
      },
      windowChanged: async () => false,
    },
    context,
  );
}

/** Swaps the selection's wall-clock lease for a reservation that ends with the submission. */
function holdUntilSettled(
  wallet: Wallet,
  retry: RingSubmissionBuildState,
  created: CreatedSpend,
): CreatedSpend {
  const entries: readonly WalletUtxo[] = created.transaction._inputs().map(({ entry }) => entry);
  const lease = created.transaction._reservationId();
  if (lease !== undefined) wallet._releaseReservation(lease);
  retry.reservation = reserveEntries(wallet, entries, retry.lifetime);
  retry.entries = entries;
  return created;
}

async function spendAttempt(
  input: PrivateTransactionParams,
  created: CreatedSpend,
  retry: RingSubmissionBuildState,
  context: RequestContext | undefined,
): Promise<RingSubmissionAttempt> {
  const { authorized, transaction } = await authorizeAndAssemble(
    input,
    created.transaction,
    created.setupInstructions,
    context,
  );
  const material = authorizedPrivateTransactionMaterial(authorized);
  if (material === undefined || !isTransactionWithBlockhashLifetime(transaction)) {
    throw new ClientError("CLIENT_INVALID_TRANSACTION");
  }
  const hash = intentHash(material.intent);
  if (retry.intent !== undefined && !equalBytes(retry.intent, hash)) {
    throw new WalletError("WALLET_INTENT_MISMATCH", { details: { field: "retryIntent" } });
  }
  retry.intent = hash;
  return {
    transaction,
    lastValidBlockHeight: transaction.lifetimeConstraint.lastValidBlockHeight,
    intentHash: hash,
    ringInstructionIndex: NO_RING_INSTRUCTION,
  };
}
