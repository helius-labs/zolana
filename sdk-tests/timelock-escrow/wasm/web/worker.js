import init, * as wasm from "./pkg/timelock_escrow_wasm.js";
import { createProvers, PROVERS } from "./prover.js";
import { failure, fetchBytes, toBytes } from "./util.js";

const threads = typeof wasm.initThreadPool === "function" ? navigator.hardwareConcurrency : 1;
const ready = (async () => {
  await init();
  if (threads > 1) {
    await wasm.initThreadPool(threads);
  }
})();
const provers = createProvers();

const methods = {
  info: () => ({ crossOriginIsolated: self.crossOriginIsolated, threads }),
  prove: (program, format, url, proofInputs) => provers.prove(program, format, url, proofInputs),
  async verify(source, proof) {
    const verifyingKey = typeof source === "string" ? await fetchBytes(source) : toBytes(source);
    return wasm.verifyProof(verifyingKey, proof);
  },
  async timeKeyLoad(program, format, url) {
    const bytes = await fetchBytes(url);
    const Prover = PROVERS[program];
    const start = performance.now();
    const prover = format === "zkey" ? Prover.fromZkey(bytes) : Prover.fromKey(bytes);
    const keyLoadMs = performance.now() - start;
    prover.free();
    return keyLoadMs;
  },
  async timeProof(program, format, url, proofInputs) {
    const prover = await provers.load(program, format, url);
    const bytes = toBytes(proofInputs);
    const start = performance.now();
    prover.prove(bytes);
    return performance.now() - start;
  },
};

self.addEventListener("message", async ({ data }) => {
  try {
    await ready;
    self.postMessage({ id: data.id, result: await methods[data.method](...data.args) });
  } catch (error) {
    self.postMessage({ id: data.id, ...failure(error) });
  }
});
