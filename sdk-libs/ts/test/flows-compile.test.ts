import { address, getCompiledTransactionMessageDecoder, type Blockhash } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { compileUnsignedTransaction } from "../src/flows/compile.js";

const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const PROGRAM = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const SETUP_PROGRAM = address("9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz");
const COMPUTE_BUDGET = address("ComputeBudget111111111111111111111111111111");
const LIFETIME = {
  blockhash: "11111111111111111111111111111111" as Blockhash,
  lastValidBlockHeight: 1n,
};

type DecodedMessage = Readonly<{
  instructions: readonly Readonly<{ programAddressIndex: number }>[];
  staticAccounts: readonly string[];
}>;

function decoded(transaction: ReturnType<typeof compileUnsignedTransaction>): DecodedMessage {
  return getCompiledTransactionMessageDecoder().decode(
    transaction.messageBytes,
  ) as unknown as DecodedMessage;
}

function programsOf(transaction: ReturnType<typeof compileUnsignedTransaction>) {
  const message = decoded(transaction);
  return message.instructions.map(
    (instruction) => message.staticAccounts[instruction.programAddressIndex],
  );
}

describe("transaction compiler", () => {
  it("orders budget, setup, then payload instructions", () => {
    const transaction = compileUnsignedTransaction({
      feePayer: PAYER,
      lifetime: LIFETIME,
      computeUnitLimit: 200_000,
      computeUnitPriceMicroLamports: 5n,
      setupInstructions: [{ programAddress: SETUP_PROGRAM }],
      instructions: [{ programAddress: PROGRAM }],
    });
    expect(programsOf(transaction)).toEqual([
      COMPUTE_BUDGET,
      COMPUTE_BUDGET,
      SETUP_PROGRAM,
      PROGRAM,
    ]);
  });

  it("adds no budget instruction when none is asked for", () => {
    const transaction = compileUnsignedTransaction({
      feePayer: PAYER,
      lifetime: LIFETIME,
      instructions: [{ programAddress: PROGRAM }],
    });
    expect(programsOf(transaction)).toEqual([PROGRAM]);
  });

  it("compresses accounts through the lookup tables", () => {
    const covered = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
    const table = address("So11111111111111111111111111111111111111112");
    const instruction = {
      programAddress: PROGRAM,
      accounts: [{ address: covered, role: 0 }],
    };
    const plain = compileUnsignedTransaction({
      feePayer: PAYER,
      lifetime: LIFETIME,
      instructions: [instruction],
    });
    const compressed = compileUnsignedTransaction({
      feePayer: PAYER,
      lifetime: LIFETIME,
      instructions: [instruction],
      lookupTables: { [table]: [covered] },
    });
    const staticAccounts = (transaction: typeof plain) => decoded(transaction).staticAccounts;
    expect(staticAccounts(compressed)).not.toContain(covered);
    expect(staticAccounts(plain)).toContain(covered);
  });

  it("names the proof shape when the compiled bytes exceed the packet", () => {
    const payload = {
      programAddress: PROGRAM,
      data: new Uint8Array(1_300),
    };
    expect(() =>
      compileUnsignedTransaction({
        feePayer: PAYER,
        lifetime: LIFETIME,
        instructions: [payload],
        sizeShape: { inputs: 2, outputs: 3 },
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "INTERFACE_TRANSACTION_TOO_LARGE",
        details: expect.objectContaining({ inputs: 2, outputs: 3 }),
      }),
    );
  });

  it("refuses an invalid compute budget", () => {
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
        computeUnitPriceMicroLamports: -1n,
        instructions: [{ programAddress: PROGRAM }],
      }),
    ).toThrow("CLIENT_INVALID_INTEGER");
  });
});
