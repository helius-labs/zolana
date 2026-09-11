import { readFile } from "node:fs/promises";

// Diagnostic wrapper around the shipped kernel; no arithmetic or UI changes.
export async function profileKernel(driver, count, options = {}) {
  const shim = await readFile(
    new URL("../../core/src/vendor/wasm_exec.js", import.meta.url),
    "utf8",
  );
  const code = shim + "\n(" + workerMain.toString() + ")();";
  await driver.manage().setTimeouts({ script: 180000 });
  return driver.executeAsyncScript(
    function (code, count, options, done) {
      const url = URL.createObjectURL(new Blob([code], { type: "text/javascript" }));
      const worker = new Worker(url, { type: "module" });
      const finish = (value) => {
        worker.terminate();
        URL.revokeObjectURL(url);
        done(value);
      };
      worker.onmessage = (event) => finish(event.data);
      worker.onerror = (event) => finish({ error: event.message });
      worker.postMessage({
        count,
        base: options.assetBase ?? new URL("./", location.href).href.replace(/\/$/, ""),
        kernelBase: options.kernelBase,
        wasmUrl: options.wasmUrl,
        warmupCount: options.warmups ?? 3,
        sampleCount: options.samples ?? 30,
      });
    },
    code,
    count,
    options,
  );
}

function workerMain() {
  self.onmessage = async ({
    data: { count, base, kernelBase, wasmUrl, warmupCount, sampleCount },
  }) => {
    try {
      kernelBase ??= base + "/prover/accelerator";
      const kernel = await import(kernelBase + "/gnark_kernel.js");
      await kernel.default();
      await kernel.initThreadPool(count);
      let phases = {};
      let rustProfile;
      for (const name of ["parts", "commitment"]) {
        const original = kernel.Key.prototype[name];
        if (typeof original !== "function") throw new Error(`Missing kernel method ${name}`);
        kernel.Key.prototype[name] = function (...args) {
          const start = performance.now();
          try {
            return original.apply(this, args);
          } finally {
            phases[name] = (phases[name] || 0) + performance.now() - start;
            if (name === "parts" && typeof this.profile === "function")
              rustProfile = JSON.parse(this.profile());
          }
        };
      }
      globalThis.__moproGnarkKernel = kernel.Key;
      const ready = new Promise((resolve) => {
        globalThis.__zolanaProverReady = resolve;
      });
      const go = new globalThis.Go();
      const { instance } = await WebAssembly.instantiateStreaming(
        fetch(wasmUrl ?? base + "/prover/zolana-prover.wasm"),
        go.importObject,
      );
      void go.run(instance);
      await ready;
      const api = globalThis.__zolanaProver;
      const unwrap = (result) => {
        if (result.error) throw new Error(result.error);
        return result;
      };
      const file = "transfer_confidential_2_3.key";
      const manifest = await (await fetch(base + "/keys/manifest.json")).json();
      const key = new Uint8Array(await (await fetch(base + "/keys/" + file)).arrayBuffer());
      const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", key))]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      if (key.length !== manifest[file].size || digest !== manifest[file].sha256)
        throw new Error("Key digest mismatch");
      const request = await (await fetch(base + "/fixtures/transfer-2x3.json")).text();
      const prepareStart = performance.now();
      const prepare = unwrap(api.loadKey(file, key));
      const prepareMs = performance.now() - prepareStart;
      if (prepare.constraints !== 54031 || !prepare.accelerated)
        throw new Error("Expected accelerated 54,031-constraint transfer circuit");
      const warmups = [],
        samples = [];
      for (let i = 0; i < warmupCount + sampleCount; i++) {
        phases = {};
        rustProfile = undefined;
        const start = performance.now();
        const proof = unwrap(api.prove(request));
        const totalMs = performance.now() - start;
        const verified = unwrap(api.verify(request, proof.proof));
        if (verified.valid !== true) throw new Error("Proof verification failed");
        const kernelMs = Object.values(phases).reduce((a, b) => a + b, 0);
        (i < warmupCount ? warmups : samples).push({
          totalMs,
          kernelMs,
          otherMs: totalMs - kernelMs,
          phases,
          rustProfile,
          goProfile: proof.profile ? JSON.parse(proof.profile) : undefined,
          proof: proof.proof,
        });
      }
      self.postMessage({
        count,
        solver: "gnark-go",
        kernelBase,
        wasmUrl,
        prepare,
        prepareMs,
        warmups,
        samples,
      });
    } catch (error) {
      self.postMessage({ error: String(error), stack: error.stack });
    }
  };
}
