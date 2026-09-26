import init, * as wasm from "./pkg-inputs/timelock_escrow_wasm.js";
import { fetchBytes, toBytes } from "./util.js";

const TRANSACTIONS = {
  escrow: wasm.escrowTransaction,
  withdraw: wasm.withdrawTransaction,
};

const moduleStart = performance.now();
await init();
const moduleLoadMs = performance.now() - moduleStart;

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url}: ${response.status}`);
  }
  return response.json();
}

function publicHashDecimal(bytes) {
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return BigInt(`0x${hex}`).toString();
}

window.inputsOnly = {
  moduleLoadMs,
  exports: Object.keys(wasm).sort(),
  async proveWithSnarkjs(program, inputs, sender, payer, zkeyUrl, vkeyUrl, runs) {
    const build = TRANSACTIONS[program];
    const witnessMs = [];
    let transaction = build(inputs, toBytes(sender), payer);
    for (let run = 0; run < runs; run += 1) {
      const start = performance.now();
      transaction = build(inputs, toBytes(sender), payer);
      witnessMs.push(performance.now() - start);
    }
    const zkey = await fetchBytes(zkeyUrl);
    const vkey = await fetchJson(vkeyUrl);
    const wtns = transaction.proofInputs;
    const { proof, publicSignals } = await window.snarkjs.groth16.prove(zkey, wtns);
    const proofMs = [];
    const totalMs = [];
    for (let run = 0; run < runs; run += 1) {
      const start = performance.now();
      const fresh = build(inputs, toBytes(sender), payer);
      const proofStart = performance.now();
      await window.snarkjs.groth16.prove(zkey, fresh.proofInputs);
      const end = performance.now();
      proofMs.push(end - proofStart);
      totalMs.push(end - start);
    }
    return {
      verified: await window.snarkjs.groth16.verify(vkey, publicSignals, proof),
      publicSignals,
      publicHash: publicHashDecimal(transaction.publicHash),
      witnessMs,
      proofMs,
      totalMs,
    };
  },
};
document.getElementById("status").textContent = "ready";
