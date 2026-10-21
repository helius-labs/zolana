export type * from "../../../target/zk/timelock-escrow-program/wasm-node/timelock_escrow_program.js";

type EscrowWasm =
  typeof import("../../../target/zk/timelock-escrow-program/wasm-node/timelock_escrow_program.js");

const loadStarted = performance.now();

const runtime = await import("../../../target/zk/timelock-escrow-program/wasm-node/node.mjs");
export const wasm: EscrowWasm = await runtime.default();

export const wasmLoadMs = performance.now() - loadStarted;
