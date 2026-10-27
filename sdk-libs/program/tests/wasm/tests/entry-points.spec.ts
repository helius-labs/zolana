import { test, expect } from "./harness";
test("the SDK bridge exports transactions and state decoding while Xark owns proving", async ({ harness }) => {
  const names = await harness.page.evaluate(async () => Object.keys(await import("/pkg/wasm_test_program.js")));
  expect(names).toEqual(expect.arrayContaining(["escrowTransaction", "withdrawTransaction", "escrowTermsDataUtxo", "compactCounterDataUtxo", "compressedProgramProof"]));
  expect(names).not.toContain("EscrowProver");
});
