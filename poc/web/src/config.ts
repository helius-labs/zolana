/**
 * Endpoints and fixtures the PoC needs, read from the same variables
 * `just test-ts-e2e` exports so one running stack serves both.
 *
 * Vite only exposes variables prefixed `VITE_`, so the justfile recipe maps the
 * canonical `ZOLANA_*` names across. Defaults point at the unshifted localnet
 * ports; a clone using `ZOLANA_PORT_OFFSET` gets the shifted values from the
 * recipe.
 */

export interface PocConfig {
  readonly solanaRpcUrl: string;
  readonly indexerUrl: string;
  readonly proverUrl: string;
  /** Where `zolana-prover.wasm` and `wasm_exec.js` are served from. */
  readonly wasmBaseUrl: string;
  /** Where the `*.key` proving keys are served from. */
  readonly keyBaseUrl: string;
  /** Pool tree address; created by `zolana dev pool create-tree`. */
  readonly tree?: string;
  readonly testMint?: string;
}

function env(name: string): string | undefined {
  const value = (import.meta.env as Record<string, string | undefined>)[name];
  return value === undefined || value === "" ? undefined : value;
}

export function loadConfig(): PocConfig {
  return Object.freeze({
    solanaRpcUrl: env("VITE_ZOLANA_LOCALNET_URL") ?? "http://127.0.0.1:8899",
    indexerUrl: env("VITE_ZOLANA_INDEXER_URL") ?? "http://127.0.0.1:8784",
    proverUrl: env("VITE_ZOLANA_PROVER_URL") ?? "http://127.0.0.1:3001",
    wasmBaseUrl: env("VITE_ZOLANA_WASM_URL") ?? "/prover",
    keyBaseUrl: env("VITE_ZOLANA_KEYS_URL") ?? "/keys",
    ...(env("VITE_ZOLANA_TREE") === undefined ? {} : { tree: env("VITE_ZOLANA_TREE") as string }),
    ...(env("VITE_ZOLANA_TEST_MINT") === undefined
      ? {}
      : { testMint: env("VITE_ZOLANA_TEST_MINT") as string }),
  });
}
