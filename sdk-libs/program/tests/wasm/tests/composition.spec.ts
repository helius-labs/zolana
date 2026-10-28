import { test, expect } from "./harness";
import { fixture, keyUrl } from "./fixtures";

test("parallel proofs execute Xark kernels from the application module", async ({ harness }) => {
  const fixtureData = fixture("withdraw");
  const comparison = await harness.page.evaluate(async ({ fixtureData, url }) => {
    const before = await window.zkProgram.workerInfo();
    const tx = await window.zkProgram.transaction("withdraw", fixtureData.inputs, fixtureData.sender, fixtureData.payer);
    const proof = await window.zkProgram.prove("withdraw", "streaming", url, tx.transaction.proofInputs);
    return { before, after: await window.zkProgram.workerInfo(), verified: await window.zkProgram.verify("withdraw", proof) };
  }, { fixtureData, url: keyUrl("withdraw", "streaming") });
  expect(comparison.verified).toBe(true);
  expect(comparison.after.threads).toBe(2);
  expect(comparison.after.stats!.fftCalls).toBeGreaterThan(comparison.before.stats!.fftCalls);
  expect(comparison.after.stats!.msmCalls).toBeGreaterThan(comparison.before.stats!.msmCalls);
});

test("input-only module prepares transactions without the proving runtime", async ({ harness }) => {
  const fixtureData = fixture("escrow");
  const prepared = await harness.page.evaluate(async fixtureData => {
    const wasm = await import("/pkg-inputs/wasm_test_program.js");
    await wasm.default();
    const tx = wasm.escrowTransaction(fixtureData.inputs, fixtureData.records, new Uint8Array(fixtureData.sender), fixtureData.payer);
    return { names: Object.keys(wasm), publicHash: Array.from(tx.publicHash) };
  }, fixtureData);
  expect(prepared.names).not.toContain("proveStreamingPreloaded");
  expect(prepared.names).not.toContain("proofToSnarkjs");
  expect(prepared.publicHash).toEqual(fixtureData.transaction.publicHash);
});

test("the client API uses the supplied application runtime", async ({ harness }) => {
  const fixtureData = fixture("withdraw");
  const verified = await harness.page.evaluate(async fixtureData => {
    const tx = await window.zkProgram.transaction("withdraw", fixtureData.inputs, fixtureData.sender, fixtureData.payer);
    return window.zkProgram.proveWithClient("withdraw", { program: fixtureData.inputs, public_hash: tx.transaction.proofInputs["public_hash"] });
  }, fixtureData);
  expect(verified).toBe(true);
});

test("single-threaded worker uses the same module without a pool", async ({ browser }) => {
  const page = await browser.newPage();
  try {
    await page.goto("/?threads=1");
    await page.waitForFunction(() => "zkProgram" in window);
    const fixtureData = fixture("withdraw");
    const checked = await page.evaluate(async ({ fixtureData, url }) => {
      const tx = await window.zkProgram.transaction("withdraw", fixtureData.inputs, fixtureData.sender, fixtureData.payer);
      const proof = await window.zkProgram.prove("withdraw", "streaming", url, tx.transaction.proofInputs);
      return { worker: await window.zkProgram.workerInfo(), verified: await window.zkProgram.verify("withdraw", proof) };
    }, { fixtureData, url: keyUrl("withdraw", "streaming") });
    expect(checked.worker.threads).toBe(1);
    expect(checked.verified).toBe(true);
  } finally { await page.close(); }
});
