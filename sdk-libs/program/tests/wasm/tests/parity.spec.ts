import { test, expect } from "./harness";
import { fixture, keyUrl, type Program } from "./fixtures";
for (const program of ["escrow", "withdraw"] as Program[]) {
  test(`${program} streaming and resident proofs match native commitments and snarkjs`, async ({ harness }) => {
    const data = fixture(program);
    const result = await harness.page.evaluate(async ({ data, program, url }) => {
      const input = (await window.zkProgram.transaction(program, data.inputs, data.sender, data.payer)).transaction.proofInputs;
      const a = await window.zkProgram.prove(program, "streaming", url, input);
      const b = await window.zkProgram.prove(program, "resident", url, input);
      return { publicA: Array.from(a.publicInputs), publicB: Array.from(b.publicInputs),
        independent: await window.zkProgram.verifyIndependent(program, a, data.transaction.publicHash),
        resident: await window.zkProgram.verify(program, b) };
    }, { data, program, url: keyUrl(program, "streaming") });
    expect(result.publicA).toEqual(result.publicB);
    expect(result.independent).toBe(true);
    expect(result.resident).toBe(true);
  });
}
