/**
 * The URL of each service a client talks to.
 *
 * `solanaRpcUrl` serves the indexer and the prover too, so naming it once is
 * enough. A config that names no URL at all means the local stack, where the
 * validator, photon, and the prover each listen on their own port.
 */

/** The ports a local validator stack listens on. */
export const LOCALNET_SOLANA_ENDPOINT = "http://127.0.0.1:8899";
export const LOCALNET_PHOTON_ENDPOINT = "http://127.0.0.1:8784";
// 127.0.0.1 rather than localhost: on a dual-stack host localhost can resolve to
// ::1 and miss a validator listening on IPv4.
export const LOCALNET_PROVER_ENDPOINT = "http://127.0.0.1:3001";

/** Where a Helius RPC host serves the indexer and the prover. */
export const ZOLANA_GATEWAY_PATH = "/v1/zolana";

/**
 * The devnet Nitro Enclave prover the SDK's default TEE deployment pins. A
 * Helius devnet RPC URL sends proofs here rather than to its gateway.
 */
export const DEFAULT_TEE_PROVER_ENDPOINT = "https://d55y5ksdsm1vw.cloudfront.net";

const HELIUS_RPC_HOST = /(^|\.)helius-rpc\.com$/u;
// devnet.helius-rpc.com and beta-devnet.helius-rpc.com.
const HELIUS_DEVNET_HOST = /(^|[.-])devnet\.helius-rpc\.com$/u;

/** Whether `url` is the prover of the SDK's default TEE deployment, whose enclave has no indexer. */
export function isDefaultTeeProver(url: URL): boolean {
  return url.hostname === new URL(DEFAULT_TEE_PROVER_ENDPOINT).hostname;
}

function isHeliusDevnet(rpc: string | URL | undefined): boolean {
  if (rpc === undefined) return false;
  try {
    return HELIUS_DEVNET_HOST.test(new URL(rpc).hostname);
  } catch {
    return false;
  }
}

/**
 * Whether `url` is the Helius gateway's zolana namespace on a
 * `*.helius-rpc.com` host. It serves the indexer at `/v1/zolana/<method>` and
 * proofs only at the key-less `/v1/zolana/prove` and `/v1/zolana/prove/status`,
 * with no indexed route.
 */
export function isZolanaGateway(url: URL): boolean {
  return (
    HELIUS_RPC_HOST.test(url.hostname) && url.pathname.replace(/\/+$/u, "") === ZOLANA_GATEWAY_PATH
  );
}

/** A Helius RPC root URL as its zolana namespace, query kept; any other URL unchanged. */
function zolanaServiceUrl(rpc: string | URL): string | URL {
  let url: URL;
  try {
    url = new URL(rpc);
  } catch {
    return rpc;
  }
  if (!HELIUS_RPC_HOST.test(url.hostname) || url.pathname.replace(/\/+$/u, "") !== "") return rpc;
  url.pathname = ZOLANA_GATEWAY_PATH;
  return url;
}

/** The routing fields of `ZolanaClientConfig`, which is what resolution reads. */
export interface ClientEndpointConfig {
  readonly solanaRpcUrl?: string | URL | undefined;
  readonly solanaRpcSubscriptionsUrl?: string | URL | undefined;
  readonly indexerUrl?: string | URL | undefined;
  readonly proverUrl?: string | URL | undefined;
}

/** Resolved service URLs and source fields used for Photon and prover errors. */
export interface ResolvedClientEndpoints {
  readonly solana: string | URL;
  readonly photon: string | URL;
  readonly photonField: string;
  readonly prover: string | URL;
  readonly proverField: string;
  readonly solanaRpcSubscriptions?: string | URL;
}

/**
 * Resolves a config into one URL per service.
 *
 * Each service takes the URL named for it, else `solanaRpcUrl`, else its local
 * default. A Helius RPC root lends the indexer and the prover its `/v1/zolana`
 * namespace, except that a Helius devnet RPC URL sends proofs to
 * `DEFAULT_TEE_PROVER_ENDPOINT`. Resolution lives here alone so the local defaults and the named URLs
 * cannot disagree about where a service ended up.
 */
export function resolveClientEndpoints(input: ClientEndpointConfig): ResolvedClientEndpoints {
  const solana = input.solanaRpcUrl ?? LOCALNET_SOLANA_ENDPOINT;

  const resolve = (
    named: string | URL | undefined,
    namedField: string,
    localDefault: string,
  ): { url: string | URL; field: string } => {
    if (named !== undefined) {
      return { url: named, field: namedField };
    }
    // Without an RPC URL to inherit, the local port is the only sensible answer.
    if (input.solanaRpcUrl !== undefined) {
      return { url: zolanaServiceUrl(input.solanaRpcUrl), field: "solanaRpcUrl" };
    }
    return { url: localDefault, field: namedField };
  };

  const photon = resolve(input.indexerUrl, "indexerUrl", LOCALNET_PHOTON_ENDPOINT);
  const prover =
    input.proverUrl === undefined && isHeliusDevnet(input.solanaRpcUrl)
      ? { url: DEFAULT_TEE_PROVER_ENDPOINT, field: "solanaRpcUrl" }
      : resolve(input.proverUrl, "proverUrl", LOCALNET_PROVER_ENDPOINT);
  const subscriptions = input.solanaRpcSubscriptionsUrl;

  return Object.freeze({
    solana,
    photon: photon.url,
    photonField: photon.field,
    prover: prover.url,
    proverField: prover.field,
    ...(subscriptions === undefined ? {} : { solanaRpcSubscriptions: subscriptions }),
  });
}
