import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "@playwright/test";

const HERE = dirname(fileURLToPath(import.meta.url));
const program = process.argv[2] ?? "escrow";
const runs = Number(process.argv[3] ?? 3);
const base = process.env.ESCROW_WASM_BASE_URL ?? "http://127.0.0.1:4327";
const data = JSON.parse(readFileSync(join(HERE, "..", "tests", "fixtures", `${program}.json`), "utf8"));

const browser = await chromium.launch();
const page = await browser.newPage();
await page.goto(`${base}/`);
await page.waitForFunction(() => "escrow" in window);
const proofInputs = await page.evaluate(
  async ({ program, data }) =>
    (await window.escrow.transaction(program, data.inputs, data.sender, data.payer)).transaction
      .proofInputs,
  { program, data },
);
const url = `/keys/${program}.pk`;
await page.evaluate(({ program, url, proofInputs }) => window.escrow.prove(program, "arkworks", url, proofInputs), {
  program,
  url,
  proofInputs,
});

const session = await page.context().newCDPSession(page);
await session.send("Profiler.enable");
await session.send("Profiler.setSamplingInterval", { interval: 100 });
await session.send("Profiler.start");
await page.evaluate(
  async ({ program, url, proofInputs, runs, data }) => {
    for (let run = 0; run < runs; run += 1) {
      window.escrow.timeTransaction(program, data.inputs, data.sender, data.payer);
      await window.escrow.timeProof(program, "arkworks", url, proofInputs);
    }
  },
  { program, url, proofInputs, runs, data },
);
const { profile } = await session.send("Profiler.stop");
await browser.close();

const byId = new Map(profile.nodes.map((node) => [node.id, node]));
const intervals = profile.timeDeltas;
const selfMs = new Map();
profile.samples.forEach((id, index) => {
  const name = byId.get(id)?.callFrame.functionName || "(anonymous)";
  selfMs.set(name, (selfMs.get(name) ?? 0) + (intervals[index] ?? 0) / 1000);
});
const total = [...selfMs.values()].reduce((sum, ms) => sum + ms, 0);
const rows = [...selfMs.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40);
console.log(`${program}: ${runs} runs, ${total.toFixed(0)} ms sampled`);
for (const [name, ms] of rows) {
  console.log(`${((100 * ms) / total).toFixed(1).padStart(5)}%  ${ms.toFixed(0).padStart(6)} ms  ${name}`);
}
