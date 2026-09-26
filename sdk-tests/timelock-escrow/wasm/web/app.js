import init, * as wasm from "./pkg/timelock_escrow_wasm.js";
import { failure, fetchBytes, plain, toBytes } from "./util.js";

const TRANSACTIONS = {
  escrow: wasm.escrowTransaction,
  withdraw: wasm.withdrawTransaction,
};

const moduleStart = performance.now();
await init();
const moduleLoadMs = performance.now() - moduleStart;

const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
const pending = new Map();
let nextId = 0;

worker.addEventListener("message", ({ data }) => {
  const request = pending.get(data.id);
  pending.delete(data.id);
  if (data.error) {
    const error = new Error(data.error.message);
    error.name = data.error.name;
    request?.reject(error);
  } else {
    request?.resolve(data.result);
  }
});
worker.addEventListener("error", (event) => {
  for (const request of pending.values()) {
    request.reject(new Error(`the prover worker failed: ${event.message}`));
  }
  pending.clear();
});

function callWorker(method, ...args) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, method, args });
  });
}

async function sha256(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const api = {
  moduleLoadMs,
  workerInfo: () => callWorker("info"),
  async transaction(program, inputs, sender, payer) {
    const transaction = TRANSACTIONS[program](inputs, toBytes(sender), payer);
    return {
      transaction: plain(transaction),
      proofInputsSha256: await sha256(transaction.proofInputs),
      amountType: typeof transaction.finalizedTx.outputUtxos[0]?.amount,
      proofInputsType: transaction.proofInputs.constructor.name,
    };
  },
  prove(program, format, url, proofInputs) {
    return callWorker("prove", program, format, url, proofInputs);
  },
  proveInWorker(program, format, url, proofInputs) {
    return callWorker("prove", program, format, url, proofInputs);
  },
  verify(source, proof) {
    return callWorker("verify", source, proof);
  },
  dummyWalletUtxo(treeId) {
    return plain(wasm.dummyWalletUtxo(treeId));
  },
  async attempt(method, ...args) {
    try {
      return { value: await api[method](...args) };
    } catch (error) {
      return failure(error);
    }
  },
  timeKeyLoad(program, format, url) {
    return callWorker("timeKeyLoad", program, format, url);
  },
  timeProof(program, format, url, proofInputs) {
    return callWorker("timeProof", program, format, url, proofInputs);
  },
  timeTransaction(program, inputs, sender, payer) {
    const start = performance.now();
    TRANSACTIONS[program](inputs, toBytes(sender), payer);
    return performance.now() - start;
  },
  async timeSnarkjs(zkeyUrl, proofInputs, runs) {
    const snarkjs = await loadSnarkjs();
    const zkey = await fetchBytes(zkeyUrl);
    const wtns = toBytes(proofInputs);
    const first = await snarkjs.groth16.prove(zkey, wtns);
    const proofMs = [];
    for (let run = 0; run < runs; run += 1) {
      const start = performance.now();
      await snarkjs.groth16.prove(zkey, wtns);
      proofMs.push(performance.now() - start);
    }
    return { proofMs, publicSignal: first.publicSignals[0] };
  },
};

let snarkjsLoaded;
function loadSnarkjs() {
  snarkjsLoaded ??= new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "/vendor/snarkjs/build/snarkjs.min.js";
    script.onload = () => resolve(window.snarkjs);
    script.onerror = () => reject(new Error("snarkjs failed to load"));
    document.head.append(script);
  });
  return snarkjsLoaded;
}

window.escrow = api;
document.getElementById("status").textContent = "ready";
