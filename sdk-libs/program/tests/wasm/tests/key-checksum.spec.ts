import { test, expect } from "./harness";
import { fixture } from "./fixtures";
test("a changed proving key is refused before parsing", async ({ harness }) => {
  const data = fixture("escrow");
  const result = await harness.page.evaluate(async data => {
    const input = (await window.zkProgram.transaction("escrow", data.inputs, data.sender, data.payer)).transaction.proofInputs;
    return window.zkProgram.attempt("mutateKey", "escrow", input);
  }, data);
  expect(result.error?.name).toBe("KeyChecksumMismatch");
});
