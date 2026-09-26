import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { brotliCompressSync, constants, gzipSync } from "node:zlib";

import { expect, test as base, type Page } from "@playwright/test";

import { fixture, keyUrl, type Program } from "./fixtures";

type InputsOnlyRun = {
  verified: boolean;
  publicSignals: string[];
  publicHash: string;
  witnessMs: number[];
  proofMs: number[];
  totalMs: number[];
};

declare global {
  interface Window {
    inputsOnly: {
      moduleLoadMs: number;
      exports: string[];
      proveWithSnarkjs(
        program: string,
        inputs: unknown,
        sender: number[],
        payer: string,
        zkeyUrl: string,
        vkeyUrl: string,
        runs: number,
      ): Promise<InputsOnlyRun>;
    };
  }
}

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const programs: Program[] = ["escrow", "withdraw"];
const RUNS = 5;

const test = base.extend<{ inputsPage: Page }>({
  inputsPage: async ({ page }, use) => {
    const noise: string[] = [];
    page.on("pageerror", (error) => noise.push(`pageerror: ${error.message}`));
    page.on("console", (message) => {
      if (message.type() === "error") {
        noise.push(`console: ${message.text()}`);
      }
    });
    await page.goto("/inputs.html");
    await page.waitForFunction(() => "inputsOnly" in window, undefined, { timeout: 60_000 });
    await use(page);
    expect(noise, "the page reported errors during this test").toEqual([]);
  },
});

function run(page: Page, program: Program, runs: number): Promise<InputsOnlyRun> {
  const data = fixture(program);
  return page.evaluate(
    ({ program, data, zkeyUrl, vkeyUrl, runs }) =>
      window.inputsOnly.proveWithSnarkjs(
        program,
        data.inputs,
        data.sender,
        data.payer,
        zkeyUrl,
        vkeyUrl,
        runs,
      ),
    { program, data, zkeyUrl: keyUrl(program, "zkey"), vkeyUrl: `/keys/${program}.vkey.json`, runs },
  );
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)] ?? Number.NaN;
}

function sizes(file: string): string {
  const bytes = readFileSync(join(PACKAGE_ROOT, file));
  const gzip = gzipSync(bytes, { level: 9 }).length;
  const brotli = brotliCompressSync(bytes, {
    params: { [constants.BROTLI_PARAM_QUALITY]: 11 },
  }).length;
  const kb = (size: number) => `${(size / 1024).toFixed(0)} KB`;
  return `${file}: ${kb(bytes.length)} raw, ${kb(gzip)} gzip, ${kb(brotli)} brotli`;
}

for (const program of programs) {
  test(`${program} proof inputs built without the prover prove and verify with snarkjs`, async ({
    inputsPage,
  }) => {
    const result = await run(inputsPage, program, 1);
    const exports = await inputsPage.evaluate(() => window.inputsOnly.exports);
    const publicHash = BigInt(
      `0x${fixture(program)
        .transaction.publicHash.map((byte) => byte.toString(16).padStart(2, "0"))
        .join("")}`,
    ).toString();

    expect({
      verified: result.verified,
      publicSignals: result.publicSignals,
      proverExports: exports.filter((name) =>
        ["EscrowProver", "WithdrawProver", "verifyProof", "initThreadPool"].includes(name),
      ),
    }).toEqual({ verified: true, publicSignals: [publicHash], proverExports: [] });
  });
}

test("proof inputs module size and speed with snarkjs proving @bench", async ({ inputsPage }) => {
  const rows = [
    sizes("web/pkg-inputs/timelock_escrow_wasm_bg.wasm"),
    sizes("web/pkg/timelock_escrow_wasm_bg.wasm"),
    sizes("node_modules/snarkjs/build/snarkjs.min.js"),
    `module load: ${(await inputsPage.evaluate(() => window.inputsOnly.moduleLoadMs)).toFixed(0)} ms`,
  ];
  for (const program of programs) {
    const result = await run(inputsPage, program, RUNS);
    expect(result.verified).toBe(true);
    rows.push(
      `${program}: proof inputs ${median(result.witnessMs).toFixed(1)} ms, snarkjs proof ${median(result.proofMs).toFixed(0)} ms, total ${median(result.totalMs).toFixed(0)} ms (medians of ${RUNS})`,
    );
  }
  console.log(rows.join("\n"));
  test.info().annotations.push({ type: "bench", description: rows.join("; ") });
});
