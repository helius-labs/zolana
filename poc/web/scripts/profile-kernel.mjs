import { readFile } from 'node:fs/promises';

// Diagnostic wrapper around the shipped kernel; no arithmetic or UI changes.
export async function profileKernel(driver, count) {
  const shim = await readFile(new URL('../../core/src/vendor/wasm_exec.js', import.meta.url), 'utf8');
  const code = shim + '\n(' + workerMain.toString() + ')();';
  await driver.manage().setTimeouts({ script: 180000 });
  return driver.executeAsyncScript(function(code, count, done) {
    const url = URL.createObjectURL(new Blob([code], { type: 'text/javascript' }));
    const worker = new Worker(url, { type: 'module' });
    const finish = value => { worker.terminate(); URL.revokeObjectURL(url); done(value); };
    worker.onmessage = event => finish(event.data);
    worker.onerror = event => finish({ error: event.message });
    worker.postMessage({ count, base: location.origin });
  }, code, count);
}

function workerMain() {
  self.onmessage = async ({ data: { count, base } }) => {
    try {
      const kernel = await import(base + '/prover/accelerator/gnark_kernel.js');
      await kernel.default();
      await kernel.initThreadPool(count);
      let phases = {};
      let rustSolver = false;
      const setSolver = kernel.Key.prototype.set_solver;
      kernel.Key.prototype.set_solver = function(...args) {
        rustSolver = setSolver.apply(this, args);
        return rustSolver;
      };
      for (const name of ['parts', 'solve_parts', 'commitment']) {
        const original = kernel.Key.prototype[name];
        kernel.Key.prototype[name] = function(...args) {
          const start = performance.now();
          try { return original.apply(this, args); }
          finally { phases[name] = (phases[name] || 0) + performance.now() - start; }
        };
      }
      globalThis.__moproGnarkKernel = kernel.Key;
      const ready = new Promise(resolve => { globalThis.__zolanaProverReady = resolve; });
      const go = new globalThis.Go();
      const { instance } = await WebAssembly.instantiateStreaming(fetch(base + '/prover/zolana-prover.wasm'), go.importObject);
      void go.run(instance);
      await ready;
      const api = globalThis.__zolanaProver;
      const unwrap = result => { if (result.error) throw new Error(result.error); return result; };
      const file = 'transfer_confidential_2_3.key';
      const manifest = await (await fetch(base + '/keys/manifest.json')).json();
      const key = new Uint8Array(await (await fetch(base + '/keys/' + file)).arrayBuffer());
      const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', key))].map(b => b.toString(16).padStart(2, '0')).join('');
      if (key.length !== manifest[file].size || digest !== manifest[file].sha256) throw new Error('Key digest mismatch');
      const request = await (await fetch(base + '/fixtures/transfer-2x3.json')).text();
      const prepare = unwrap(api.loadKey(file, key));
      const warmups = [], samples = [];
      for (let i = 0; i < 18; i++) {
        phases = {};
        const start = performance.now();
        const proof = unwrap(api.prove(request));
        const totalMs = performance.now() - start;
        const verified = unwrap(api.verify(request, proof.proof));
        if (verified.valid !== true) throw new Error('Proof verification failed');
        const kernelMs = Object.values(phases).reduce((a, b) => a + b, 0);
        (i < 3 ? warmups : samples).push({ totalMs, kernelMs, otherMs: totalMs - kernelMs, phases });
      }
      self.postMessage({ count, rustSolver, prepare, warmups, samples });
    } catch (error) { self.postMessage({ error: String(error), stack: error.stack }); }
  };
}
