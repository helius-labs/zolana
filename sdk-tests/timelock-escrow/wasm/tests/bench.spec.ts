import { expect, test } from "./harness";
import { fixture, keyUrl, type Program } from "./fixtures";

const programs: Program[] = ["escrow", "withdraw"];
const RUNS = 5;

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] ?? Number.NaN;
}

test("witness generation, key load and proof time against snarkjs @bench", async ({ harness }) => {
  const rows: string[] = [];
  const moduleLoadMs = await harness.page.evaluate(() => window.escrow.moduleLoadMs);
  rows.push(`module load: ${moduleLoadMs.toFixed(0)} ms`);
  for (const program of programs) {
    const data = fixture(program);
    const timings = await harness.page.evaluate(
      async ({ program, arkworksUrl, zkeyUrl, data, runs }) => {
        const { transaction } = await window.escrow.transaction(
          program,
          data.inputs,
          data.sender,
          data.payer,
        );
        const witnessMs: number[] = [];
        for (let run = 0; run < runs; run += 1) {
          witnessMs.push(
            window.escrow.timeTransaction(program, data.inputs, data.sender, data.payer),
          );
        }
        const keyLoadMs = {
          arkworks: await window.escrow.timeKeyLoad(program, "arkworks", arkworksUrl),
          zkey: await window.escrow.timeKeyLoad(program, "zkey", zkeyUrl),
        };
        await window.escrow.timeProof(program, "arkworks", arkworksUrl, transaction.proofInputs);
        const proofMs: number[] = [];
        for (let run = 0; run < runs; run += 1) {
          proofMs.push(
            await window.escrow.timeProof(program, "arkworks", arkworksUrl, transaction.proofInputs),
          );
        }
        const snarkjs = await window.escrow.timeSnarkjs(zkeyUrl, transaction.proofInputs, runs);
        const proof = await window.escrow.prove(program, "arkworks", arkworksUrl, transaction.proofInputs);
        const verifyStart = performance.now();
        await window.escrow.verify(data.verifyingKey, proof);
        const verifyMs = performance.now() - verifyStart;
        return {
          verifyMs,
          witnessMs,
          keyLoadMs,
          proofMs,
          snarkjsMs: snarkjs.proofMs,
          snarkjsPublicSignal: snarkjs.publicSignal,
          publicHash: transaction.publicHash,
        };
      },
      {
        program,
        arkworksUrl: keyUrl(program, "arkworks"),
        zkeyUrl: keyUrl(program, "zkey"),
        data,
        runs: RUNS,
      },
    );
    const publicHash = BigInt(
      `0x${timings.publicHash.map((byte) => byte.toString(16).padStart(2, "0")).join("")}`,
    ).toString();
    expect(timings.snarkjsPublicSignal).toBe(publicHash);
    const witness = median(timings.witnessMs);
    const proof = median(timings.proofMs);
    const snarkjsProof = median(timings.snarkjsMs);
    rows.push(
      `${program}: proving ${(witness + proof).toFixed(0)} ms (witness ${witness.toFixed(0)} + proof ${proof.toFixed(0)}), ` +
        `snarkjs ${(witness + snarkjsProof).toFixed(0)} ms (Rust witness + snarkjs proof ${snarkjsProof.toFixed(0)}), ` +
        `key load ${timings.keyLoadMs.arkworks.toFixed(0)} ms arkworks / ${timings.keyLoadMs.zkey.toFixed(0)} ms zkey, ` +
        `standalone verify ${timings.verifyMs.toFixed(0)} ms (medians of ${RUNS})`,
    );
  }
  console.log(rows.join("\n"));
  test.info().annotations.push({ type: "bench", description: rows.join("; ") });
});
