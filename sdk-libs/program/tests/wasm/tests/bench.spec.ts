import { test, expect } from "./harness";
import { fixture, keyUrl, type Program } from "./fixtures";
const RUNS = 5;
function median(values: number[]) { return [...values].sort((a,b) => a-b)[Math.floor(values.length/2)]; }
test("SDK transaction preparation and Xark proving @bench", async ({ harness }) => {
  const rows: string[] = [];
  for (const program of ["escrow", "withdraw"] as Program[]) {
    const data = fixture(program);
    const result = await harness.page.evaluate(async ({ data, program, url, runs }) => {
      const tx = (await window.zkProgram.transaction(program, data.inputs, data.sender, data.payer)).transaction;
      const prep = []; for (let i=0;i<runs;i++) prep.push(window.zkProgram.timeTransaction(program, data.inputs, data.sender, data.payer));
      const modes = {};
      for (const mode of ["streaming", "resident"]) {
        const load = await window.zkProgram.timeKeyLoad(program, mode, url);
        await window.zkProgram.timeProof(program, mode, url, tx.proofInputs);
        const proof = []; for (let i=0;i<runs;i++) proof.push(await window.zkProgram.timeProof(program, mode, url, tx.proofInputs));
        modes[mode] = { load, proof };
      }
      const proof = await window.zkProgram.prove(program, "streaming", url, tx.proofInputs);
      return { prep, modes, verified: await window.zkProgram.verify(program, proof) };
    }, { data, program, url: keyUrl(program, "streaming"), runs: RUNS });
    expect(result.verified).toBe(true);
    for (const [mode, value] of Object.entries(result.modes)) rows.push(`${program} ${mode}: preparation ${median(result.prep).toFixed(1)} ms, proof ${median(value.proof).toFixed(1)} ms, total ${(median(result.prep)+median(value.proof)).toFixed(1)} ms, key load ${value.load.toFixed(1)} ms, workers ${mode==="streaming"?harness.threads:1}`);
  }
  console.log(rows.join("\n"));
  test.info().annotations.push({ type: "bench", description: rows.join("; ") });
});
