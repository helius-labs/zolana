import init from "./pkg/timelock_escrow_wasm.js";
import { createProvers, failure } from "./prover.js";

const ready = init();
const provers = createProvers();

const methods = {
  prove: (program, format, url, proofInputs) => provers.prove(program, format, url, proofInputs),
};

self.addEventListener("message", async ({ data }) => {
  await ready;
  try {
    self.postMessage({ id: data.id, result: await methods[data.method](...data.args) });
  } catch (error) {
    self.postMessage({ id: data.id, ...failure(error) });
  }
});
