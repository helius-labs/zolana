import { test, expect } from "./harness";
test("one application module exports SDK transactions and the Xark runtime", async ({ harness }) => {
  const names = await harness.page.evaluate(async () => Object.keys(await import("/pkg/wasm_test_program.js")));
  expect(names).toEqual(expect.arrayContaining(["escrowTransaction", "withdrawTransaction", "escrowTermsDataUtxo", "compactCounterDataUtxo", "compressedProgramProof", "checkProvingKey", "preloadStreaming", "proveStreamingPreloaded", "Schema", "VerifyingKey", "StreamingProof", "KeyTranscoder", "kernel_cols", "kernel_rows", "kernel_msm", "kernel_decompress"]));
  expect(names).not.toContain("EscrowProver");
});
