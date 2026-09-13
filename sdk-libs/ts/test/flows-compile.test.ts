import {
  address,
  decompileTransactionMessage,
  getCompiledTransactionMessageDecoder,
  type Blockhash,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
  compileUnsignedTransaction,
} from "../src/flows/compile.js";
import { TRANSACTION_SIZE_LIMIT } from "../src/interface/transaction-size.js";

const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const PROGRAM = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const SETUP_PROGRAM = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");
const COMPUTE_BUDGET = address("ComputeBudget111111111111111111111111111111");
const LIFETIME = {
  blockhash: "11111111111111111111111111111111" as Blockhash,
  lastValidBlockHeight: 1n,
};

function decompiled(transaction: ReturnType<typeof compileUnsignedTransaction>) {
  const compiled = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
  if (compiled.version !== 1) {
    throw new Error(`expected a version 1 message, got ${String(compiled.version)}`);
  }
  return decompileTransactionMessage(compiled, { lastValidBlockHeight: 1n });
}

function programsOf(transaction: ReturnType<typeof compileUnsignedTransaction>) {
  return decompiled(transaction).instructions.map((instruction) => instruction.programAddress);
}

describe("transaction compiler", () => {
  it("carries the budget in the version 1 header, not in an instruction", () => {
    const transaction = compileUnsignedTransaction({
      feePayer: PAYER,
      lifetime: LIFETIME,
      computeUnitLimit: 200_000,
      priorityFeeLamports: 5n,
      setupInstructions: [{ programAddress: SETUP_PROGRAM }],
      instructions: [{ programAddress: PROGRAM }],
    });
    const message = decompiled(transaction);
    expect(message.config).toEqual({
      computeUnitLimit: 200_000,
      loadedAccountsDataSizeLimit: LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
      priorityFeeLamports: 5n,
    });
    expect(programsOf(transaction)).toEqual([SETUP_PROGRAM, PROGRAM]);
    expect(programsOf(transaction)).not.toContain(COMPUTE_BUDGET);
  });

  it("budgets compute units and account data when no fee is asked for", () => {
    const message = decompiled(
      compileUnsignedTransaction({
        feePayer: PAYER,
        lifetime: LIFETIME,
        computeUnitLimit: 1_400_000,
        instructions: [{ programAddress: PROGRAM }],
      }),
    );
    expect(message.config).toEqual({
      computeUnitLimit: 1_400_000,
      loadedAccountsDataSizeLimit: LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
    });
  });

  it("compiles a payload the legacy packet could not carry", () => {
    const transaction = compileUnsignedTransaction({
      feePayer: PAYER,
      lifetime: LIFETIME,
      computeUnitLimit: 200_000,
      instructions: [{ programAddress: PROGRAM, data: new Uint8Array(1_300) }],
    });
    expect(transaction.messageBytes.length).toBeGreaterThan(1_232);
    expect(programsOf(transaction)).toEqual([PROGRAM]);
  });

  it("names the proof shape when the compiled bytes exceed the limit", () => {
    const payload = {
      programAddress: PROGRAM,
      data: new Uint8Array(TRANSACTION_SIZE_LIMIT),
    };
    expect(() =>
      compileUnsignedTransaction({
        feePayer: PAYER,
        lifetime: LIFETIME,
        computeUnitLimit: 200_000,
        instructions: [payload],
        sizeShape: { inputs: 2, outputs: 3 },
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "INTERFACE_TRANSACTION_TOO_LARGE",
        details: expect.objectContaining({ limit: TRANSACTION_SIZE_LIMIT, inputs: 2, outputs: 3 }),
      }),
    );
  });

  it("refuses a budget the runtime would clamp or cannot encode", () => {
    expect(() =>
      compileUnsignedTransaction({
        feePayer: PAYER,
        lifetime: LIFETIME,
        computeUnitLimit: -1,
        instructions: [{ programAddress: PROGRAM }],
      }),
    ).toThrow("CLIENT_INVALID_INTEGER");
    expect(() =>
      compileUnsignedTransaction({
        feePayer: PAYER,
        lifetime: LIFETIME,
        computeUnitLimit: 1_400_001,
        instructions: [{ programAddress: PROGRAM }],
      }),
    ).toThrow("CLIENT_INVALID_INTEGER");
    expect(() =>
      compileUnsignedTransaction({
        feePayer: PAYER,
        lifetime: LIFETIME,
        computeUnitLimit: 200_000,
        priorityFeeLamports: -1n,
        instructions: [{ programAddress: PROGRAM }],
      }),
    ).toThrow("CLIENT_INVALID_INTEGER");
  });
});
