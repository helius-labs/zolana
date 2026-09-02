import { createAssociatedTokenAccountInstruction } from "../interface/instructions/index.js";
import { SPL_TOKEN_PROGRAM_ID } from "../interface/program.js";
import { associatedTokenAddress, splInterfaceWithBump } from "../interface/pda/index.js";
import {
  DepositAsset,
  TransactWithdrawal,
  type Address,
  type Instruction,
} from "../interface/types.js";
import { WithdrawalTarget } from "../transaction/instructions/transact.js";
import { SOL_MINT } from "../transaction/asset.js";

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
  const tokenProgram = input.splTokenProgram ?? SPL_TOKEN_PROGRAM_ID;
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
      accounts: TransactWithdrawal.sol({ recipient }),
    };
  }
  const tokenProgram = splTokenProgram ?? SPL_TOKEN_PROGRAM_ID;
  const [recipientTokenAccount, [splTokenInterface, splInterfaceBump]] = await Promise.all([
    associatedTokenAddress(recipient, asset, tokenProgram),
    splInterfaceWithBump(asset),
  ]);
  return {
    target: WithdrawalTarget.spl({ recipientTokenAccount, splTokenInterface, splInterfaceBump }),
    accounts: TransactWithdrawal.spl({
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
      ...(input.splTokenProgram === undefined ? {} : { tokenProgram: input.splTokenProgram }),
    }),
  ];
}
