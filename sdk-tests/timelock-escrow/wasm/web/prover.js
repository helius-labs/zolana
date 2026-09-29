import * as wasm from "./pkg/timelock_escrow_wasm.js";
import { fetchBytes, plain, toBytes } from "./util.js";

export const PROVERS = { escrow: wasm.EscrowProver, withdraw: wasm.WithdrawProver };

export function createProvers() {
  const cache = new Map();
  return {
    load(program, format, url) {
      const key = `${program}:${format}:${url}`;
      if (!cache.has(key)) {
        const Prover = PROVERS[program];
        const loading = fetchBytes(url).then((bytes) =>
          format === "zkey" ? Prover.fromZkey(bytes) : Prover.fromKey(bytes),
        );
        loading.catch(() => cache.delete(key));
        cache.set(key, loading);
      }
      return cache.get(key);
    },
    async prove(program, format, url, proofInputs) {
      const prover = await this.load(program, format, url);
      return plain(prover.prove(toBytes(proofInputs)));
    },
  };
}
