import { test, expect } from "./harness";
import { fixture, keyUrl } from "./fixtures";
test("proofs use fresh nonzero randomness and reject missing, zero and seeded entropy", async ({ harness }) => {
  const data = fixture("escrow");
  const result = await harness.page.evaluate(async ({ data, url }) => {
    const input = (await window.zkProgram.transaction("escrow", data.inputs, data.sender, data.payer)).transaction.proofInputs;
    const a = await window.zkProgram.prove("escrow", "streaming", url, input);
    const b = await window.zkProgram.prove("escrow", "streaming", url, input);
    const rejected = [];
    for (const mode of ["missing", "zero", "seed"]) rejected.push(await window.zkProgram.attempt("randomness", "escrow", input, mode));
    return { a: Array.from(a.proof), b: Array.from(b.proof), valid: await window.zkProgram.verify("escrow", a), rejected };
  }, { data, url: keyUrl("escrow", "streaming") });
  expect(result.valid).toBe(true);
  expect(result.a).not.toEqual(result.b);
  expect(result.rejected.map(value => value.error?.name)).toEqual(["SecureRandomUnavailable", "InvalidProofRandomness", "InvalidProofRandomness"]);
});
