import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { test, expect } from "./harness";
import { fixture, keyUrl } from "./fixtures";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "..");

/** `<file>:<line>:<col>` of the requirement statement `needle`, as the native error reports it. */
function requirementAt(file: string, needle: string): string {
  const lines = readFileSync(join(ROOT, file), "utf8").split("\n");
  const matches = lines.flatMap((line, index) => {
    const column = line.indexOf(needle);
    return column < 0 ? [] : [`${file}:${index + 1}:${column + 1}`];
  });
  if (matches.length !== 1) throw new Error(`${file} contains ${matches.length} copies of ${needle}`);
  return matches[0]!;
}

function requirementFailed(location: string) {
  return {
    kind: "Error",
    name: "CircuitError.RequirementFailed",
    code: "PROGRAM_REQUIREMENT_FAILED",
    message: `requirement failed at ${location}`,
  };
}

function invalidInput(message: string) {
  return { kind: "Error", name: "ClientError.InvalidInput", code: "TRANSACTION_INVALID_INPUT", message };
}

function plainError(message: string | RegExp) {
  return { kind: "Error", name: "Error", message: typeof message === "string" ? message : expect.stringMatching(message) };
}

test("each invalid transaction or proof request fails with its specific error", async ({ harness }) => {
  const escrow = fixture("escrow");
  const withdraw = fixture("withdraw");
  const errors = await harness.page.evaluate(async ({ escrow, withdraw, url }) => {
    const api = window.zkProgram;
    type EscrowInputs = { private: { amount: string; tokenUtxosAssetA: unknown[] } };
    type WithdrawInputs = { public: { ownerIdentity: string } };
    const escrowInputs = () => structuredClone(escrow.inputs) as EscrowInputs;
    const overdraft = escrowInputs();
    overdraft.private.amount = "5000";
    const zeroAmount = escrowInputs();
    zeroAmount.private.amount = "0";
    const tooManyTokens = escrowInputs();
    tooManyTokens.private.tokenUtxosAssetA = new Array(6).fill(tooManyTokens.private.tokenUtxosAssetA[0]);
    const noTokens = escrowInputs();
    noTokens.private.tokenUtxosAssetA = [];
    // Five padding slots: the shape is complete but no slot carries a balance.
    const dummyTokens = escrowInputs();
    const padding = dummyTokens.private.tokenUtxosAssetA.at(-1);
    dummyTokens.private.tokenUtxosAssetA = new Array(5).fill(padding);
    const wrongOwner = structuredClone(withdraw.inputs) as WithdrawInputs;
    wrongOwner.public.ownerIdentity = "1";

    const { transaction } = await api.transaction("escrow", escrow.inputs, escrow.sender, escrow.payer);
    const withdrawTransaction = (await api.transaction("withdraw", withdraw.inputs, withdraw.sender, withdraw.payer)).transaction;
    const truncatedProofInputs = Object.fromEntries(Object.entries(transaction.proofInputs).slice(0, -1));
    const attempts = {
      malformedInputs: await api.attempt("transaction", "escrow", { private: {} }, escrow.sender, escrow.payer),
      overdraft: await api.attempt("transaction", "escrow", overdraft, escrow.sender, escrow.payer),
      zeroAmount: await api.attempt("transaction", "escrow", zeroAmount, escrow.sender, escrow.payer),
      dummyTokens: await api.attempt("transaction", "escrow", dummyTokens, escrow.sender, escrow.payer),
      wrongOwner: await api.attempt("transaction", "withdraw", wrongOwner, withdraw.sender, withdraw.payer),
      tooManyTokens: await api.attempt("transaction", "escrow", tooManyTokens, escrow.sender, escrow.payer),
      noTokens: await api.attempt("transaction", "escrow", noTokens, escrow.sender, escrow.payer),
      shortSender: await api.attempt("transaction", "escrow", escrow.inputs, escrow.sender.slice(1), escrow.payer),
      invalidPayer: await api.attempt("transaction", "escrow", escrow.inputs, escrow.sender, "not-an-address"),
      malformedRecords: await api.attempt("transactionWithRecords", "escrow", escrow.inputs, { addresses: [] }, escrow.sender, escrow.payer),
      truncatedProofInputs: await api.attempt("prove", "escrow", "streaming", url, truncatedProofInputs),
      otherCircuitProofInputs: await api.attempt("prove", "escrow", "streaming", url, withdrawTransaction.proofInputs),
      withdrawKey: await api.attempt("proveWithKey", "escrow", "withdraw", transaction.proofInputs),
      escrowKey: await api.attempt("proveWithKey", "withdraw", "escrow", withdrawTransaction.proofInputs),
    };
    return Object.fromEntries(Object.entries(attempts).map(([name, outcome]) => [name, outcome.error ?? "succeeded"]));
  }, { escrow, withdraw, url: keyUrl("escrow", "streaming") });

  expect(errors).toEqual({
    malformedInputs: invalidInput("input `private`: missing field `tx_context`"),
    // The borrow check in the shared balance debit is the requirement that fails.
    overdraft: requirementFailed(
      requirementAt("sdk-libs/circuit/src/protocol/utxo/balance.rs", "crate::require_eq(high, u64::from(borrow));"),
    ),
    zeroAmount: requirementFailed(
      requirementAt("sdk-libs/program/tests/wasm/program/src/escrow.rs", "require(private.amount != 0);"),
    ),
    dummyTokens: requirementFailed(
      requirementAt("sdk-libs/circuit/src/protocol/utxo/balance.rs", "crate::require_eq(high, u64::from(borrow));"),
    ),
    wrongOwner: requirementFailed(
      requirementAt(
        "sdk-libs/program/tests/wasm/program/src/withdraw.rs",
        "require_eq(escrow.creator.key().identity()?, self.public.owner_identity);",
      ),
    ),
    tooManyTokens: invalidInput("input `private.token_utxos_asset_a`: expected 5 elements, got 6"),
    noTokens: invalidInput("input `private.token_utxos_asset_a`: expected 5 elements, got 0"),
    shortSender: invalidInput("invalid shielded address length"),
    invalidPayer: invalidInput("Invalid Base58 string"),
    malformedRecords: invalidInput("Error: missing field `inputs`"),
    truncatedProofInputs: plainError("missing input `public_hash`"),
    otherCircuitProofInputs: plainError(/^unknown input `program\.private\.escrow\.[a-z_.]+` \(circuit inputs: \["program", "public_hash"\]\)$/),
    withdrawKey: plainError(/^h_query has \d+ points; no evaluation domain of that size fits \d+ rows/),
    escrowKey: plainError(/^a_query has \d+ points, circuit needs \d+/),
  });
});

test("the module still builds and proves after a failed requirement", async ({ harness }) => {
  const data = fixture("escrow");
  const result = await harness.page.evaluate(async ({ data, url }) => {
    const api = window.zkProgram;
    const overdraft = structuredClone(data.inputs) as { private: { amount: string } };
    overdraft.private.amount = "5000";
    const failures = [];
    for (let attempt = 0; attempt < 2; attempt++) {
      failures.push((await api.attempt("transaction", "escrow", overdraft, data.sender, data.payer)).error?.code);
    }
    const { transaction } = await api.transaction("escrow", data.inputs, data.sender, data.payer);
    const proof = await api.prove("escrow", "streaming", url, transaction.proofInputs);
    return { failures, transaction, verified: await api.verify("escrow", proof) };
  }, { data, url: keyUrl("escrow", "streaming") });
  expect(result.failures).toEqual(["PROGRAM_REQUIREMENT_FAILED", "PROGRAM_REQUIREMENT_FAILED"]);
  expect(result.transaction).toEqual(data.transaction);
  expect(result.verified).toBe(true);
});
