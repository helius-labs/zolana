import init, * as wasm from "./pkg/wasm_test_program.js";
import { failure, plain, toBytes } from "./util.js";
const start = performance.now();
await init();
const moduleLoadMs = performance.now() - start;
const fixtures = Object.fromEntries(await Promise.all(["escrow", "withdraw"].map(async name => [name, await (await fetch(`/fixtures/${name}.json`)).json()])));
const methods = { escrow: wasm.escrowTransaction, withdraw: wasm.withdrawTransaction };
const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
const requests = new Map();
let sequence = 0;
worker.onmessage = ({ data }) => {
  const request = requests.get(data.id); requests.delete(data.id);
  if (data.error) { const error = new Error(data.error.message); error.name = data.error.name; request.reject(error); }
  else request.resolve(data.result);
};
worker.onerror = event => { for (const request of requests.values()) request.reject(new Error(event.message)); requests.clear(); };
function call(method, ...args) { const id = sequence++; return new Promise((resolve, reject) => { requests.set(id, { resolve, reject }); worker.postMessage({ id, method, args }); }); }
let snarkjsLoaded;
function snarkjs() {
  return snarkjsLoaded ??= new Promise((resolve, reject) => {
    const script = document.createElement("script"); script.src = "/vendor/snarkjs/build/snarkjs.min.js";
    script.onload = () => resolve(window.snarkjs); script.onerror = () => reject(new Error("snarkjs failed to load")); document.head.append(script);
  });
}
const api = {
  moduleLoadMs,
  workerInfo: () => call("info"),
  async transaction(program, inputs, sender, payer) {
    return { transaction: plain(methods[program](inputs, fixtures[program].records, toBytes(sender), payer)) };
  },
  timeTransaction(program, inputs, sender, payer) {
    const start = performance.now(); methods[program](inputs, fixtures[program].records, toBytes(sender), payer); return performance.now() - start;
  },
  async verifyIndependent(program, proof, publicHash) {
    const library = await snarkjs();
    const bytes = new Uint8Array(await (await fetch(`/keys/${program}/vk.bin`)).arrayBuffer());
    const vk = plain(wasm.verifyingKeyToSnarkjs(bytes));
    const value = plain(wasm.proofToSnarkjs(toBytes(proof.proof)));
    const signal = BigInt(`0x${publicHash.map(byte => byte.toString(16).padStart(2, "0")).join("")}`).toString();
    return library.groth16.verify(vk, [signal], value);
  },
  prove: (program, format, url, inputs) => call("prove", program, format, url, inputs),
  verify: (program, proof) => call("verify", program, proof),
  timeKeyLoad: (program, format, url) => call("timeKeyLoad", program, format, url),
  timeProof: (program, format, url, inputs) => call("timeProof", program, format, url, inputs),
  mutateKey: (program, inputs) => call("mutateKey", program, inputs),
  randomness: (program, inputs, mode) => call("randomness", program, inputs, mode),
  async attempt(method, ...args) { try { return { value: await api[method](...args) }; } catch (error) { return failure(error); } },
};
window.zkProgram = api;
