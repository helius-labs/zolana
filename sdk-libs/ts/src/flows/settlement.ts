import { createAssociatedTokenAccountInstruction } from "../interface/instructions/index.js";
import { associatedTokenAddress, splInterfaceWithBump } from "../interface/pda/index.js";
import {
  DepositAsset,
  TransactSettlement,
  type Address,
  type Instruction,
  type TransactWithdrawal,
} from "../interface/types.js";
import { TransactionError } from "../transaction/error.js";
import { WithdrawalTarget } from "../transaction/instructions/transact.js";
import { SOL_MINT } from "../transaction/asset.js";

/**
 * The token program an SPL settlement of `mint` uses. There is no default: the
 * associated token account depends on it, and guessing the classic program for
 * a Token-2022 mint settles against an account that does not exist.
 */
function requiredTokenProgram(mint: Address, tokenProgram: Address | null | undefined): Address {
  if (tokenProgram === undefined || tokenProgram === null) {
    throw new TransactionError("TRANSACTION_MISSING_SPL_TOKEN_PROGRAM", { mint });
  }
  return tokenProgram;
}

/** @internal Derives the depositor's associated token account when none is named. */
export async function resolveDepositSettlement(
  input: Readonly<{
    asset: Address;
    depositor?: Address;
    splTokenAccount?: Address;
    splTokenProgram?: Address | null;
  }>,
  missingAccount: () => Error,
): Promise<DepositAsset> {
  if (input.asset === SOL_MINT) return DepositAsset.sol();
  const tokenProgram = requiredTokenProgram(input.asset, input.splTokenProgram);
  const sourceTokenAccount =
    input.splTokenAccount ??
    (input.depositor === undefined
      ? undefined
      : await associatedTokenAddress(input.depositor, input.asset, tokenProgram));
  if (sourceTokenAccount === undefined) throw missingAccount();
  return DepositAsset.spl({ mint: input.asset, sourceTokenAccount, tokenProgram });
}

/** The proof-side target and the settlement accounts of one public withdrawal. */
export async function resolveWithdrawalSettlement(
  recipient: Address,
  asset: Address,
  splTokenProgram?: Address | null,
): Promise<Readonly<{ target: WithdrawalTarget; accounts: TransactWithdrawal }>> {
  if (asset === SOL_MINT) {
    return {
      target: WithdrawalTarget.sol({ recipient }),
      accounts: TransactSettlement.solWithdrawal({ recipient }),
    };
  }
  const tokenProgram = requiredTokenProgram(asset, splTokenProgram);
  const [recipientTokenAccount, [splTokenInterface, splInterfaceBump]] = await Promise.all([
    associatedTokenAddress(recipient, asset, tokenProgram),
    splInterfaceWithBump(asset),
  ]);
  return {
    target: WithdrawalTarget.spl({ recipientTokenAccount, splTokenInterface, splInterfaceBump }),
    accounts: TransactSettlement.splWithdrawal({
      mint: asset,
      splTokenInterface,
      recipientTokenAccount,
      tokenProgram,
    }),
  };
}

export async function withdrawalSetupInstructions(
  input: Readonly<{
    payer: Address;
    recipient: Address;
    asset: Address;
    splTokenProgram?: Address | null;
  }>,
): Promise<readonly Instruction[]> {
  if (input.asset === SOL_MINT) return [];
  return [
    await createAssociatedTokenAccountInstruction({
      payer: input.payer,
      owner: input.recipient,
      mint: input.asset,
      tokenProgram: requiredTokenProgram(input.asset, input.splTokenProgram),
    }),
  ];
}
