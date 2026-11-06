import { test, expect } from "./harness";
import { fixture } from "./fixtures";
test("transaction preparation works without loading a proving key", async ({ harness }) => {
  const data = fixture("escrow");
  const result = await harness.page.evaluate(async data => window.zkProgram.transaction("escrow", data.inputs, data.sender, data.payer), data);
  expect(result.transaction.publicHash).toEqual(data.transaction.publicHash);
});
