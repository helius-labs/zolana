// Prints the JSON reports the differential suites write. Reconnaissance output,
// not a gate: it never exits non-zero on a divergence.
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const reportDirectory = join(dirname(fileURLToPath(import.meta.url)), "..", "report");
const files = readdirSync(reportDirectory).filter((name) => name.endsWith(".json")).sort();

let total = 0;
for (const file of files) {
  const report = JSON.parse(readFileSync(join(reportDirectory, file), "utf8"));
  console.log(`\n=== ${report.packet}`);
  for (const probe of report.probes) {
    const symbol = probe.rustSymbol;
    console.log(
      `${symbol}\n  cases=${probe.cases} agreed=${probe.agreed} bothRejected=${probe.bothRejected} boundaryRejected=${probe.boundaryRejected} divergences=${probe.divergences.length}`,
    );
    for (const divergence of probe.divergences) {
      total += 1;
      console.log(`  [${divergence.kind}] sampled=${divergence.sampled}`);
      console.log(`    input: ${JSON.stringify(divergence.input)}`);
      console.log(`    rust:  ${JSON.stringify(divergence.rust)}`);
      console.log(`    ts:    ${JSON.stringify(divergence.typescript)}`);
    }
  }
  console.log("  rejection reason pairs (rust <-> typescript):");
  for (const pair of report.rejectionPairs) {
    console.log(
      `    ${pair.rustSymbol.split("::").slice(1).join("::")}: ${pair.rustCode} <-> ${pair.typescriptCode} (${pair.sampled})`,
    );
  }
}
console.log(`\ntotal divergence classes: ${total}`);
