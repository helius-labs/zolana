import * as wasm from "./pkg/timelock_escrow_wasm.js";

export const PROVERS = { escrow: wasm.EscrowProver, withdraw: wasm.WithdrawProver };

export async function fetchBytes(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url}: ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

export function toBytes(source) {
  return source instanceof Uint8Array ? source : new Uint8Array(source);
}

export function plain(value) {
  if (value instanceof Uint8Array) {
    return Array.from(value);
  }
  if (typeof value === "bigint") {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`${value} does not fit a JSON number`);
    }
    return Number(value);
  }
  if (Array.isArray(value)) {
    return value.map(plain);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, plain(entry)]));
  }
  return value;
}

export function failure(error) {
  return { error: { name: error?.name ?? "Error", message: String(error?.message ?? error) } };
}

export function createProvers() {
  const cache = new Map();
  return {
    async load(program, format, url) {
      const key = `${program}:${format}:${url}`;
      if (!cache.has(key)) {
        const Prover = PROVERS[program];
        const bytes = await fetchBytes(url);
        cache.set(key, format === "zkey" ? Prover.fromZkey(bytes) : Prover.fromKey(bytes));
      }
      return cache.get(key);
    },
    async prove(program, format, url, proofInputs) {
      const prover = await this.load(program, format, url);
      return plain(prover.prove(toBytes(proofInputs)));
    },
  };
}
