import {
  address,
  decompileTransactionMessage,
  getCompiledTransactionMessageDecoder,
  type Blockhash,
} from "@solana/kit";
import { describe, expect, it } from "vitest";

import { LOADED_ACCOUNTS_DATA_SIZE_LIMIT } from "../src/flows/compile.js";
import {
  DEFAULT_TRANSACT_COMPUTE_UNIT_LIMIT,
  compileVersion1Transaction,
  type Version1TransactionOptions,
} from "../src/index.js";

const PAYER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const PROGRAM = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");
const BASE: Version1TransactionOptions = {
  feePayer: PAYER,
  lifetime: {
    blockhash: "11111111111111111111111111111111" as Blockhash,
    lastValidBlockHeight: 1n,
  },
  instructions: [{ programAddress: PROGRAM }],
};

function config(options: Version1TransactionOptions) {
  const compiled = getCompiledTransactionMessageDecoder().decode(
    compileVersion1Transaction(options).messageBytes,
  );
  if (compiled.version !== 1) throw new Error(`version ${String(compiled.version)}`);
  const message = decompileTransactionMessage(compiled, { lastValidBlockHeight: 1n });
  expect(message.instructions.map((instruction) => instruction.programAddress)).toEqual([PROGRAM]);
  return message.config;
}

describe("compileVersion1Transaction", () => {
  it("always writes both header limits", () => {
    expect(config(BASE)).toEqual({
      computeUnitLimit: DEFAULT_TRANSACT_COMPUTE_UNIT_LIMIT,
      loadedAccountsDataSizeLimit: LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
    });
    expect(config({ ...BASE, computeUnitLimit: 900_000, priorityFeeLamports: 7n })).toEqual({
      computeUnitLimit: 900_000,
      loadedAccountsDataSizeLimit: LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
      priorityFeeLamports: 7n,
    });
  });

  // The shared limit check accepts zero, which compiles but cannot execute.
  it("refuses a zero compute-unit limit", () => {
    expect(() => compileVersion1Transaction({ ...BASE, computeUnitLimit: 0 })).toThrow(
      expect.objectContaining({
        code: "CLIENT_INVALID_INTEGER",
        details: { field: "computeUnitLimit" },
      }),
    );
  });
});
