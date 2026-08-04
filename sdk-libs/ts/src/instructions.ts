import type { ZolanaClient } from "./client/client.js";
import { ClientError } from "./client/error.js";
import {
  depositInstruction,
  mergeTransactInstruction,
  transactInstruction,
  type SignerAccount,
} from "./interface/instructions/index.js";
import { associatedTokenAddress } from "./interface/pda/index.js";
import { SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID } from "./interface/program.js";
import { SOL_MINT } from "./transaction/wallet/asset.js";
import type {
  Address,
  AssetDeposit,
  Bytes32,
  TransactWithdrawal,
  Instruction,
  MergeTransactInstructionData,
  TransactInstructionData,
  UtxoData,
} from "./interface/types.js";

export interface SemanticAssetDeposit {
  readonly asset: Address;
  readonly viewTag: Bytes32;
  readonly recipientOwnerHash: Bytes32;
  readonly blinding: Bytes32;
  readonly amount: bigint;
  readonly utxoData?: UtxoData;
}

export async function getDepositInstructionAsync(
  input: Readonly<{
    client: Pick<ZolanaClient, "getAccount">;
    tree: Address;
    sender: SignerAccount;
    deposits: readonly SemanticAssetDeposit[];
  }>,
): Promise<Instruction> {
  const deposits = await resolveDeposits(input.client, input.sender, input.deposits);
  return depositInstruction({ tree: input.tree, sender: input.sender, deposits });
}

async function resolveDeposits(
  client: Pick<ZolanaClient, "getAccount">,
  signer: SignerAccount,
  deposits: readonly SemanticAssetDeposit[],
): Promise<readonly AssetDeposit[]> {
  const sender = typeof signer === "string" ? signer : signer.address;
  return Promise.all(
    deposits.map(async (deposit) => {
      if (deposit.asset === SOL_MINT) {
        return { ...deposit, asset: { kind: "sol" as const } };
      }
      const account = await client.getAccount(deposit.asset);
      if (account === undefined) {
        throw new ClientError("CLIENT_RPC", {
          details: { method: "getAccount", reason: `mint not found: ${deposit.asset}` },
        });
      }
      if (account.owner !== SPL_TOKEN_PROGRAM_ID && account.owner !== SPL_TOKEN_2022_PROGRAM_ID) {
        throw new ClientError("CLIENT_RPC", {
          details: {
            method: "getAccount",
            reason: `unsupported mint owner ${account.owner}: ${deposit.asset}`,
          },
        });
      }
      return {
        ...deposit,
        asset: {
          kind: "spl" as const,
          accounts: {
            mint: deposit.asset,
            sourceTokenAccount: await associatedTokenAddress(sender, deposit.asset, account.owner),
            tokenProgram: account.owner,
          },
        },
      };
    }),
  );
}

export function getTransactInstruction(
  input: Readonly<{
    feePayer: SignerAccount;
    tree: Address;
    withdrawal?: TransactWithdrawal;
    data: TransactInstructionData;
  }>,
): Instruction {
  return transactInstruction({
    ...input,
    inputTree: input.tree,
    outputTree: input.tree,
  });
}

export function getMergeTransactInstruction(
  input: Readonly<{
    tree: Address;
    feePayer: SignerAccount;
    userRecord: Address;
    data: MergeTransactInstructionData;
  }>,
): Instruction {
  return mergeTransactInstruction({
    ...input,
    inputTree: input.tree,
    outputTree: input.tree,
  });
}

export {
  batchUpdateNullifierTreeInstruction as getBatchUpdateNullifierTreeInstructionAsync,
  createAssetCounterInstruction as getCreateAssetCounterInstructionAsync,
  createAssociatedTokenAccountInstruction as getCreateAssociatedTokenAccountInstructionAsync,
  createProtocolConfigInstruction as getCreateProtocolConfigInstructionAsync,
  createSplInterfaceInstruction as getCreateSplInterfaceInstructionAsync,
  createTreeInstruction as getCreateTreeInstructionAsync,
  pauseTreeInstruction as getPauseTreeInstructionAsync,
  updateProtocolConfigInstruction as getUpdateProtocolConfigInstructionAsync,
  type ProtocolConfigUpdate,
  type SignerAccount,
} from "./interface/instructions/index.js";
export type {
  BatchUpdateNullifierTreeInstructionData,
  DepositInstructionData,
  TransactWithdrawal,
  MergeTransactInstructionData,
  TransactInstructionData,
} from "./interface/index.js";
