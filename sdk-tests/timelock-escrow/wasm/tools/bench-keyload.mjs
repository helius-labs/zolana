// One-off: time key loads in Chromium without proving (proving currently
// panics on the arkworks 0.6 local rayon pools, unrelated to key loading).
// Serves the package like tools/serve.mjs, then times Prover.fromKey (memory
// image) and Prover.fromZkey in a worker.
import { spawn } from "node:child_process";
import { chromium } from "playwright";

const PORT = 4399;

const server = spawn("node", ["tools/serve.mjs"], {
  env: { ...process.env, PORT: String(PORT) },
  stdio: "ignore",
});
await new Promise((resolve) => setTimeout(resolve, 500));

const browser = await chromium.launch();
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.on("console", (message) => console.log("console:", message.text()));
  page.on("pageerror", (error) => console.log("pageerror:", error.message));
  await page.goto(`http://127.0.0.1:${PORT}/index.html`);
  await page.waitForFunction(() => window.escrow !== undefined);

  const rows = await page.evaluate(async () => {
    const out = [];
    for (const program of ["escrow", "withdraw"]) {
      for (const [format, url] of [
        ["image (.pk)", `/keys/${program}.pk`],
        ["zkey", `/keys/${program}.zkey`],
      ]) {
        const times = [];
        for (let run = 0; run < 5; run += 1) {
          times.push(await window.escrow.timeKeyLoad(program, format === "zkey" ? "zkey" : "arkworks", url));
        }
        times.sort((a, b) => a - b);
        out.push(`${program} ${format}: median ${times[2].toFixed(1)} ms, best ${times[0].toFixed(1)} ms`);
      }
    }
    return out;
  });
  for (const row of rows) console.log(row);
} finally {
  await browser.close();
  server.kill();
}
