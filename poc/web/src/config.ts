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
  readonly testMint?: string;
}

export type EndpointName = "solanaRpcUrl" | "indexerUrl" | "proverUrl";

export const ENDPOINT_LABELS: Readonly<Record<EndpointName, string>> = {
  solanaRpcUrl: "Solana RPC",
  indexerUrl: "Indexer",
  proverUrl: "Prover (remote)",
};

const STORAGE_KEY = "zolana-poc-endpoints";

function env(name: string): string | undefined {
  const value = (import.meta.env as Record<string, string | undefined>)[name];
  return value === undefined || value === "" ? undefined : value;
}

function storedEndpoints(): Partial<Record<EndpointName, string>> {
  try {
    const raw = globalThis.localStorage?.getItem(STORAGE_KEY);
    if (raw === null || raw === undefined) return {};
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return {};
    const out: Partial<Record<EndpointName, string>> = {};
    for (const name of Object.keys(ENDPOINT_LABELS) as EndpointName[]) {
      const value = (parsed as Record<string, unknown>)[name];
      if (typeof value === "string" && value !== "") out[name] = value;
    }
    return out;
  } catch {
    return {};
  }
}

export function loadConfig(): PocConfig {
  return Object.freeze({
    ...preset(env("VITE_ZOLANA_DEFAULT_PRESET") === "devnet" ? "devnet" : "localnet"),
    wasmBaseUrl: env("VITE_ZOLANA_WASM_URL") ?? "/prover",
    keyBaseUrl: env("VITE_ZOLANA_KEYS_URL") ?? "/keys",
    ...(env("VITE_ZOLANA_TEST_MINT") === undefined
      ? {}
      : { testMint: env("VITE_ZOLANA_TEST_MINT") as string }),
    ...storedEndpoints(),
  });
}

export type PresetName = "localnet" | "devnet";

/** Devnet's indexer and prover are plaintext HTTP, unreachable from an HTTPS page, proxied same-origin by vite.config.ts and deploy/nginx.conf. */
export function preset(name: PresetName): Record<EndpointName, string> {
  if (name === "devnet") {
    const origin = globalThis.location.origin;
    return {
      solanaRpcUrl: "https://api.devnet.solana.com",
      indexerUrl: `${origin}/devnet/indexer`,
      proverUrl: `${origin}/devnet/prover`,
    };
  }
  return {
    solanaRpcUrl: env("VITE_ZOLANA_LOCALNET_URL") ?? "http://127.0.0.1:8899",
    indexerUrl: env("VITE_ZOLANA_INDEXER_URL") ?? "http://127.0.0.1:8784",
    proverUrl: env("VITE_ZOLANA_PROVER_URL") ?? "http://127.0.0.1:3001",
  };
}

export function withEndpoint(config: PocConfig, name: EndpointName, value: string): PocConfig {
  return withEndpoints(config, { [name]: value });
}

export function withEndpoints(
  config: PocConfig,
  values: Partial<Record<EndpointName, string>>,
): PocConfig {
  const next = Object.freeze({ ...config, ...values });
  try {
    globalThis.localStorage?.setItem(
      STORAGE_KEY,
      JSON.stringify({
        solanaRpcUrl: next.solanaRpcUrl,
        indexerUrl: next.indexerUrl,
        proverUrl: next.proverUrl,
      }),
    );
  } catch {
    // Storage blocked, override lasts one page load.
  }
  return next;
}
