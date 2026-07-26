import type {
  Address,
  DepositInstructionData,
  DepositSplAccounts,
  Instruction,
} from "@zolana/interface";
import { depositInstruction } from "@zolana/interface/instructions";

export function depositSolInstruction(
  input: Readonly<{
    tree: Address;
    depositor: Address;
    data: DepositInstructionData;
  }>,
): Instruction {
  return depositInstruction(input);
}

export function depositSplInstruction(
  input: Readonly<{
    tree: Address;
    depositor: Address;
    spl: DepositSplAccounts;
    data: DepositInstructionData;
  }>,
): Instruction {
  return depositInstruction(input);
}
