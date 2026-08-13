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
 * default. Resolution lives here alone so the local defaults and the named URLs
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
      return { url: input.solanaRpcUrl, field: "solanaRpcUrl" };
    }
    return { url: localDefault, field: namedField };
  };

  const photon = resolve(input.indexerUrl, "indexerUrl", LOCALNET_PHOTON_ENDPOINT);
  const prover = resolve(input.proverUrl, "proverUrl", LOCALNET_PROVER_ENDPOINT);
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
