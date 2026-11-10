import { test, expect } from "./harness";
import { fixture, keyUrl } from "./fixtures";
// Xark 0.3.0's runtime neither refuses zero WebCrypto output nor a caller's
// `seed` option (see the spr-program README), so only missing WebCrypto is
// refused here.
test("proofs use fresh randomness and refuse missing WebCrypto", async ({ harness }) => {
  const data = fixture("escrow");
  const result = await harness.page.evaluate(async ({ data, url }) => {
    const input = (await window.zkProgram.transaction("escrow", data.inputs, data.sender, data.payer)).transaction.proofInputs;
    const a = await window.zkProgram.prove("escrow", "streaming", url, input);
    const b = await window.zkProgram.prove("escrow", "streaming", url, input);
    const missing = await window.zkProgram.attempt("randomness", "escrow", input);
    return { a: Array.from(a.proof), b: Array.from(b.proof), valid: await window.zkProgram.verify("escrow", a), missing };
  }, { data, url: keyUrl("escrow", "streaming") });
  expect(result.valid).toBe(true);
  expect(result.a).not.toEqual(result.b);
  expect(result.missing.error?.name).toBe("SecureRandomUnavailable");
});
