import type { Address, Bytes32, Signature } from "@zolana/interface";

import { TestKitError } from "./error.js";

export interface ParsedInstruction {
  readonly programAddress: Address;
  readonly accounts: readonly Address[];
  readonly data: Uint8Array;
  readonly stackHeight?: number;
}

export interface InstructionGroup {
  readonly outer: ParsedInstruction;
  readonly inner: readonly ParsedInstruction[];
}

export interface CompiledInstruction {
  readonly programIndex: number;
  readonly accountIndexes: readonly number[];
  readonly data: Uint8Array;
  readonly stackHeight?: number;
}

export interface IndexedOutput {
  readonly viewTag: Bytes32;
  readonly utxoHash: Bytes32;
  readonly tree: Address;
  readonly leafIndex: bigint;
  readonly data: Uint8Array;
}

export interface IndexedTransaction {
  readonly signature: Signature;
  readonly outputs: readonly IndexedOutput[];
  readonly nullifiers: readonly Bytes32[];
  readonly proofless: boolean;
}

export function groupInstructions(
  outer: readonly ParsedInstruction[],
  inner: ReadonlyMap<number, readonly ParsedInstruction[]>,
): readonly InstructionGroup[] {
  for (const index of inner.keys()) {
    if (!Number.isSafeInteger(index) || index < 0 || index >= outer.length) {
      throw new TestKitError("TEST_KIT_FIXTURE", {
        details: { reason: "innerInstructionIndex", index, outerCount: outer.length },
      });
    }
  }
  return Object.freeze(
    outer.map((instruction, index) =>
      Object.freeze({
        outer: copyInstruction(instruction),
        inner: Object.freeze((inner.get(index) ?? []).map(copyInstruction)),
      }),
    ),
  );
}

export function parseCompiledInstruction(
  accountKeys: readonly Address[],
  instruction: CompiledInstruction,
): ParsedInstruction {
  const programAddress = accountKeys[instruction.programIndex];
  if (programAddress === undefined) {
    throw new TestKitError("TEST_KIT_FIXTURE", {
      details: {
        reason: "programIndex",
        index: instruction.programIndex,
        accountCount: accountKeys.length,
      },
    });
  }
  const accounts = instruction.accountIndexes.map((index) => {
    const account = accountKeys[index];
    if (account === undefined) {
      throw new TestKitError("TEST_KIT_FIXTURE", {
        details: { reason: "accountIndex", index, accountCount: accountKeys.length },
      });
    }
    return account;
  });
  return Object.freeze({
    programAddress,
    accounts: Object.freeze(accounts),
    data: new Uint8Array(instruction.data),
    ...(instruction.stackHeight === undefined ? {} : { stackHeight: instruction.stackHeight }),
  });
}

export function singleOutput(transaction: IndexedTransaction): IndexedOutput {
  if (transaction.outputs.length !== 1) {
    throw new TestKitError("TEST_KIT_FIXTURE", {
      details: { reason: "singleOutput", actual: transaction.outputs.length },
    });
  }
  return copyOutput(transaction.outputs[0] as IndexedOutput);
}

function copyInstruction(instruction: ParsedInstruction): ParsedInstruction {
  return Object.freeze({
    ...instruction,
    accounts: Object.freeze([...instruction.accounts]),
    data: new Uint8Array(instruction.data),
  });
}

export function copyOutput(output: IndexedOutput): IndexedOutput {
  return Object.freeze({
    ...output,
    viewTag: new Uint8Array(output.viewTag) as Bytes32,
    utxoHash: new Uint8Array(output.utxoHash) as Bytes32,
    data: new Uint8Array(output.data),
  });
}
