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
let workerFailure = null;

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
function failWorker(message) {
  workerFailure = new Error(`the prover worker failed: ${message}`);
  for (const request of pending.values()) {
    request.reject(workerFailure);
  }
  pending.clear();
}
worker.addEventListener("error", (event) => failWorker(event.message));
worker.addEventListener("messageerror", () => failWorker("a message could not be deserialized"));

function callWorker(method, ...args) {
  if (workerFailure !== null) {
    return Promise.reject(workerFailure);
  }
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, method, args });
  });
}

function kind(value) {
  return value instanceof Uint8Array ? "Uint8Array" : typeof value;
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
    const finalized = transaction.finalizedTx;
    return {
      transaction: plain(transaction),
      proofInputsSha256: await sha256(transaction.proofInputs),
      encoding: {
        proofInputs: kind(transaction.proofInputs),
        publicHash: kind(transaction.publicHash),
        outputHash: kind(finalized.outputHashes[0]),
        outputAmount: kind(finalized.outputUtxos[0]?.amount),
        outputBlinding: kind(finalized.outputUtxos[0]?.blinding),
        inputLeafIndex: kind(finalized.inputUtxos[0]?.leafIndex),
        inputAssetId: kind(finalized.inputUtxos[0]?.utxo.asset.assetId),
        inputOwner: kind(finalized.inputUtxos[0]?.utxo.owner),
        resolvedOwnerTag: kind(finalized.ownerTags[0]?.resolved),
        sender: kind(finalized.sender),
        payer: kind(finalized.payer),
        outputTreeId: kind(finalized.outputTreeId),
      },
    };
  },
  prove(program, format, url, proofInputs) {
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
