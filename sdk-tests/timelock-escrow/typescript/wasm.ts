import { createRequire } from "node:module";

export type * from "../../../target/zk/timelock-escrow-program/wasm-node/timelock_escrow_program.js";

type EscrowWasm =
  typeof import("../../../target/zk/timelock-escrow-program/wasm-node/timelock_escrow_program.js");

const loadStarted = performance.now();

export const wasm: EscrowWasm = createRequire(import.meta.url)(
  "../../../target/zk/timelock-escrow-program/wasm-node/timelock_escrow_program.js",
);

export const wasmLoadMs = performance.now() - loadStarted;
