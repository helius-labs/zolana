import { expect, test } from "@playwright/test";
import { keyUrl } from "./fixtures";

test("fromKey requires the pinned checksum before loading an image", async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => "zkProgram" in window);
  const result = await page.evaluate(async (url) => {
    // The generated module is loaded by app.js before the harness is ready.
    const moduleUrl = "/pkg/wasm_test_program.js";
    const wasm = await import(moduleUrl);
    const bytes = new Uint8Array(await (await fetch(url)).arrayBuffer());
    const text = await (await fetch(`${url}.sha256`)).text();
    const digest = text.trim().split(/\s+/)[0];
    const checksum = Uint8Array.from(digest.match(/../g)!, (byte) => parseInt(byte, 16));
    function attempt(key: Uint8Array, expected?: Uint8Array) {
      try {
        const prover = wasm.EscrowProver.fromKey(key, expected);
        prover.free();
        return "accepted";
      } catch (error) {
        return (error as Error).name;
      }
    }
    const corrupted = bytes.slice();
    corrupted[corrupted.length - 1] ^= 1;
    const wrong = checksum.slice();
    wrong[0] ^= 1;
    return {
      valid: attempt(bytes, checksum),
      corrupted: attempt(corrupted, checksum),
      wrong: attempt(bytes, wrong),
      short: attempt(bytes, checksum.slice(1)),
      omitted: attempt(bytes),
      stillLoads: attempt(bytes, checksum),
    };
  }, keyUrl("escrow", "arkworks"));
  expect(result).toEqual({
    valid: "accepted",
    corrupted: "ProverError.KeyImageChecksumMismatch",
    wrong: "ProverError.KeyImageChecksumMismatch",
    short: "ProverError.InvalidArgument",
    omitted: "TypeError",
    stillLoads: "accepted",
  });
});
