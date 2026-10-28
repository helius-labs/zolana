import { test, expect } from "./harness";
import { fixture, keyUrl } from "./fixtures";
test("invalid field inputs fail without producing a proof", async ({ harness }) => {
  const data = fixture("escrow");
  const result = await harness.page.evaluate(async ({ data, url }) => {
    const input = (await window.zkProgram.transaction("escrow", data.inputs, data.sender, data.payer)).transaction.proofInputs;
    input.public_hash = "-1";
    return window.zkProgram.attempt("prove", "escrow", "streaming", url, input);
  }, { data, url: keyUrl("escrow", "streaming") });
  expect(result).toHaveProperty("error");
});
