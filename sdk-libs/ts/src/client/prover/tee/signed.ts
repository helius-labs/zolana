import { ed25519 } from "@noble/curves/ed25519.js";
import { concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import {
  TransportFailure,
  checkedEndpoint,
  checkedFetch,
  readBoundedJson,
} from "../../../services/transport.js";
import { composeSignal, untilAborted } from "../../internal.js";
import { invalidPolicy, refused } from "./platform.js";
import { teePolicyFromJson } from "./policy.js";
import type { TeePolicy } from "./registry.js";

/** Prefixes the payload bytes a signer signs. */
const DOMAIN = utf8ToBytes("zolana/prover-tee/v1/policy");
const MAX_FILE_BYTES = 64 * 1024;
const DOWNLOAD_TIMEOUT_MS = 30_000;

/** Where a network's signed policy lives and who signs it. */
export type SignedTeePolicyConfig = Readonly<{
  /** HTTPS, or HTTP on a loopback host. */
  url: string | URL;
  network: string;
  /** Lowercase hex Ed25519 keys of the signers. */
  publicKeys: readonly string[];
  /** How many distinct signers a file needs. */
  threshold: number;
}>;

type Signers = Readonly<{ network: string; keys: readonly string[]; threshold: number }>;

/**
 * Each network's policy URL and signers. `test/prover-tee-signed.test.ts`
 * pins it to the Rust client's `src/prover/tee/signers.json`.
 */
/** The interim one-account KMS signers; replace with the three-account keys before release. */
const SIGNERS = {
  publicKeys: [
    "1fe5d29c79064ea17a16308452040b799df8aeaaae588d44a527a8da9ffa924a",
    "f90d4e9b178f0262cbf8b40482a6a6459c50001825f5c3dbf3d26aa2f38d70ef",
    "2afe6599217e9a1b8424d228603c31735ab26db5f07b916c7a357636b56797ef",
  ],
  threshold: 2,
} as const;

/** A network whose signed policy the SDK pins. */
export type TeeNetwork = "mainnet" | "devnet";

export const NETWORKS: Readonly<Record<TeeNetwork, Omit<SignedTeePolicyConfig, "network">>> =
  Object.freeze({
    mainnet: { url: "https://d3gbdb0egjwcw9.cloudfront.net/tee-policy/mainnet.json", ...SIGNERS },
    devnet: { url: "https://d3gbdb0egjwcw9.cloudfront.net/tee-policy/devnet.json", ...SIGNERS },
  });

type Current = Readonly<{
  policy: TeePolicy;
  version: number;
  payload: string;
  expiresAt: number;
  checkedAt: number;
}>;

/**
 * A policy published at `url` as one file that a quorum of pinned keys signs.
 * It is downloaded again once it is `max_age_secs` old, when the client also attests
 * again, and never used past its expiry.
 */
export class SignedTeePolicy {
  readonly #url: URL;
  readonly #signers: Signers;
  #current: Current | undefined;
  #download: Promise<TeePolicy> | undefined;

  constructor(config: SignedTeePolicyConfig) {
    if (typeof config !== "object" || config === null) throw invalidPolicy("signed");
    try {
      this.#url = checkedEndpoint(config.url, { field: "tee.url", allowLoopbackHttp: true });
    } catch {
      throw invalidPolicy("url");
    }
    if (typeof config.network !== "string" || config.network === "") {
      throw invalidPolicy("network");
    }
    const keys = config.publicKeys;
    if (
      !Array.isArray(keys) ||
      !keys.every((key) => lowerHex(key, 32) && onCurve(key)) ||
      new Set(keys).size !== keys.length
    ) {
      throw invalidPolicy("publicKeys");
    }
    const { threshold } = config;
    if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > keys.length) {
      throw invalidPolicy("threshold");
    }
    this.#signers = Object.freeze({
      network: config.network,
      keys: Object.freeze([...keys]),
      threshold,
    });
  }

  /** The signed policy the SDK pins for `network`. */
  static forNetwork(network: TeeNetwork): SignedTeePolicy {
    const preset = Object.hasOwn(NETWORKS, network) ? NETWORKS[network] : undefined;
    if (preset === undefined) throw invalidPolicy("network");
    return new SignedTeePolicy({ ...preset, network });
  }

  /** The policy in force, downloading the file again with `fetch` once `max_age_secs` old. */
  current(fetch: typeof globalThis.fetch = checkedFetch(undefined)): Promise<TeePolicy> {
    const current = this.#current;
    const age = current === undefined ? -1 : Date.now() - current.checkedAt;
    const fresh = current !== undefined && age >= 0 && age < current.policy.maxAgeSecs * 1000;
    if (current !== undefined && fresh && !expired(current)) {
      return Promise.resolve(current.policy);
    }
    this.#download ??= this.#refresh(fetch).finally(() => {
      this.#download = undefined;
    });
    return this.#download;
  }

  /** A failed download keeps a policy that has not expired. */
  async #refresh(fetch: typeof globalThis.fetch): Promise<TeePolicy> {
    const current = this.#current;
    let next: Current;
    try {
      next = this.#next(await download(this.#url, fetch), current);
    } catch (error) {
      if (current === undefined || expired(current)) throw error;
      next = { ...current, checkedAt: Date.now() };
    }
    this.#current = Object.freeze(next);
    return next.policy;
  }

  /** Refuses an older version, or another payload under the same version. */
  #next(file: unknown, current: Current | undefined): Current {
    const verified = verifySignedTeePolicy(file, this.#signers, Math.floor(Date.now() / 1000));
    if (current !== undefined) {
      if (
        verified.version < current.version ||
        (verified.version === current.version && verified.payload !== current.payload)
      ) {
        throw refused("policy_rollback");
      }
      if (verified.payload === current.payload) return { ...current, checkedAt: Date.now() };
    }
    return { ...verified, checkedAt: Date.now() };
  }
}

/** Settles by its deadline even when `fetch` ignores the signal, so the next call can download again. */
async function download(url: URL, fetch: typeof globalThis.fetch): Promise<unknown> {
  const request = composeSignal({ timeoutMs: DOWNLOAD_TIMEOUT_MS }, "attest");
  try {
    return await untilAborted(read(url, fetch, request.signal), request, () =>
      refused("policy_unavailable"),
    );
  } finally {
    request.cleanup();
  }
}

async function read(
  url: URL,
  fetch: typeof globalThis.fetch,
  signal: AbortSignal,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(url, { redirect: "error", signal });
  } catch {
    throw refused("policy_unavailable");
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw refused("policy_unavailable");
  }
  try {
    return await readBoundedJson(response, MAX_FILE_BYTES);
  } catch (error) {
    throw refused(error instanceof TransportFailure ? "policy_malformed" : "policy_unavailable");
  }
}

/** Checks a downloaded file against its signers at `nowSecs`. */
export function verifySignedTeePolicy(
  file: unknown,
  signers: Signers,
  nowSecs: number,
): Omit<Current, "checkedAt"> {
  const { payload, signatures } = exactRecord(file, ["payload", "signatures"]);
  if (!lowerHex(payload) || !Array.isArray(signatures)) throw malformed();
  const bytes = hexToBytes(payload);
  const message = concatBytes(DOMAIN, bytes);
  const signed = new Set<string>();
  for (const entry of signatures) {
    const { public_key: key, signature } = exactRecord(entry, ["public_key", "signature"]);
    if (!lowerHex(key, 32) || !lowerHex(signature, 64)) throw malformed();
    if (!signers.keys.includes(key) || signed.has(key)) continue;
    let valid = false;
    try {
      valid = ed25519.verify(hexToBytes(signature), message, hexToBytes(key), { zip215: false });
    } catch {
      // A signature that does not decode signs nothing.
    }
    if (valid) signed.add(key);
  }
  if (signed.size < signers.threshold) throw refused("policy_signature");

  let approved: unknown;
  try {
    approved = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw malformed();
  }
  const fields = exactRecord(approved, ["network", "version", "expires_at", "policy"]);
  const { network, version, expires_at: expiresAt } = fields;
  if (
    typeof network !== "string" ||
    typeof version !== "number" ||
    !Number.isSafeInteger(version) ||
    version < 1 ||
    typeof expiresAt !== "number" ||
    !Number.isSafeInteger(expiresAt) ||
    expiresAt < 0 ||
    typeof fields["policy"] !== "object" ||
    fields["policy"] === null ||
    Object.hasOwn(fields["policy"], "deployment")
  ) {
    throw malformed();
  }
  let policy: TeePolicy;
  try {
    policy = teePolicyFromJson(fields["policy"]);
  } catch {
    throw malformed();
  }
  if (network !== signers.network) throw refused("policy_network");
  if (nowSecs >= expiresAt) throw refused("policy_expired");
  return Object.freeze({ policy, version, payload, expiresAt });
}

const malformed = (): Error => refused("policy_malformed");

/** Lowercase hex, of exactly `bytes` bytes when given. */
function lowerHex(value: unknown, bytes?: number): value is string {
  return (
    typeof value === "string" &&
    /^(?:[0-9a-f]{2})*$/u.test(value) &&
    (bytes === undefined || value.length === 2 * bytes)
  );
}

function exactRecord(value: unknown, keys: readonly string[]): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw malformed();
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).length !== keys.length ||
    !keys.every((key) => Object.hasOwn(record, key))
  ) {
    throw malformed();
  }
  return record;
}

function onCurve(key: string): boolean {
  try {
    ed25519.Point.fromHex(key);
    return true;
  } catch {
    return false;
  }
}

function expired(current: Current): boolean {
  return Date.now() >= current.expiresAt * 1000;
}
