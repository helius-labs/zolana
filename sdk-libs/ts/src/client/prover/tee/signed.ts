import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

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

/** Prefixes the release payload bytes a release signer signs. */
const RELEASE_DOMAIN = utf8ToBytes("zolana/prover-tee/v2/release");
/** Prefixes the freshness payload bytes a freshness signer signs. */
const FRESHNESS_DOMAIN = utf8ToBytes("zolana/prover-tee/v2/freshness");
const MAX_FILE_BYTES = 64 * 1024;
const DOWNLOAD_TIMEOUT_MS = 30_000;

/**
 * How far past the client's clock a freshness part may be issued, for a device
 * clock that runs behind. A client can therefore hold one part for up to the
 * release's `max_lifetime_secs` plus this, by its own clock.
 */
const MAX_CLOCK_SKEW_SECS = 86_400;

/** Where a network's signed policy lives and who signs its releases. */
export type SignedTeePolicyConfig = Readonly<{
  /** HTTPS, or HTTP on a loopback host. */
  url: string | URL;
  network: string;
  /** Lowercase hex Ed25519 keys of the release signers. */
  publicKeys: readonly string[];
  /** How many distinct release signers a release needs. */
  threshold: number;
}>;

type Keys = Readonly<{ keys: readonly string[]; threshold: number }>;
type Signers = Readonly<{ network: string } & Keys>;

/**
 * Who approves releases today: one KMS key for every network. More release
 * signers join by adding their keys here and raising `threshold`, which is an
 * SDK release. Each release names its own freshness keys.
 */
const SIGNERS = {
  publicKeys: ["1fe5d29c79064ea17a16308452040b799df8aeaaae588d44a527a8da9ffa924a"],
  threshold: 1,
} as const;

/** A network whose signed policy the SDK pins. */
export type TeeNetwork = "mainnet" | "devnet";

/**
 * Each network's policy URL and release signers. `test/prover-tee-signed.test.ts`
 * pins it to the Rust client's `src/prover/tee/signers.json`.
 */
export const NETWORKS: Readonly<Record<TeeNetwork, Omit<SignedTeePolicyConfig, "network">>> =
  Object.freeze({
    mainnet: { url: "https://d3gbdb0egjwcw9.cloudfront.net/tee-policy/mainnet.json", ...SIGNERS },
    devnet: { url: "https://d3gbdb0egjwcw9.cloudfront.net/tee-policy/devnet.json", ...SIGNERS },
  });

type Current = Readonly<{
  policy: TeePolicy;
  version: number;
  /** Hex of the release payload. */
  payload: string;
  issuedAt: number;
  /** The earlier of the release and freshness expiries. */
  expiresAt: number;
  checkedAt: number;
}>;

/**
 * A policy published at `url` as one file: a release that enough of the pinned
 * release keys sign, kept in force by a freshness part that the freshness keys
 * the release names sign. It is downloaded again once it is `max_age_secs` old, when the client
 * also attests again, and never used past either expiry.
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
    if (!Array.isArray(keys) || !distinctKeys(keys)) throw invalidPolicy("publicKeys");
    const { threshold } = config;
    if (!meets(threshold, keys)) throw invalidPolicy("threshold");
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

  /** Downloads again at the next call: a prover that lost its key has likely changed release. */
  invalidate(): void {
    if (this.#current !== undefined) {
      this.#current = Object.freeze({ ...this.#current, checkedAt: Number.NEGATIVE_INFINITY });
    }
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

  /**
   * Refuses an older release version, another release payload under the same
   * version, or an older freshness part for the same release.
   */
  #next(file: unknown, current: Current | undefined): Current {
    const verified = verifySignedTeePolicy(file, this.#signers, Math.floor(Date.now() / 1000));
    if (current !== undefined) {
      const same = verified.payload === current.payload;
      if (
        verified.version < current.version ||
        (verified.version === current.version && !same) ||
        (same && verified.issuedAt < current.issuedAt)
      ) {
        throw refused("policy_rollback");
      }
      if (same) {
        const { issuedAt, expiresAt } = verified;
        return { ...current, issuedAt, expiresAt, checkedAt: Date.now() };
      }
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
    throw refused(
      error instanceof TransportFailure && error.kind !== "read"
        ? "policy_malformed"
        : "policy_unavailable",
    );
  }
}

/** Checks a downloaded file against its signers at `nowSecs`. */
export function verifySignedTeePolicy(
  file: unknown,
  signers: Signers,
  nowSecs: number,
): Omit<Current, "checkedAt"> {
  const parts = exactRecord(file, ["release", "freshness"]);
  const release = signedPart(parts["release"]);
  const fresh = signedPart(parts["freshness"]);

  if (!quorum(RELEASE_DOMAIN, release, signers)) throw refused("policy_signature");
  const fields = exactRecord(json(release.bytes), [
    "network",
    "version",
    "expires_at",
    "freshness",
    "policy",
  ]);
  const { network, version, expires_at: releaseExpiresAt } = fields;
  const named = exactRecord(fields["freshness"], ["public_keys", "threshold", "max_lifetime_secs"]);
  const { public_keys: freshnessKeys, max_lifetime_secs: maxLifetime } = named;
  if (
    typeof network !== "string" ||
    !positive(version) ||
    !integer(releaseExpiresAt) ||
    !Array.isArray(freshnessKeys) ||
    !distinctKeys(freshnessKeys) ||
    !meets(named["threshold"], freshnessKeys) ||
    !positive(maxLifetime) ||
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
  if (nowSecs >= releaseExpiresAt) throw refused("policy_expired");

  const freshnessSigners = { keys: freshnessKeys, threshold: named["threshold"] };
  if (!quorum(FRESHNESS_DOMAIN, fresh, freshnessSigners)) throw refused("policy_freshness");
  const freshness = exactRecord(json(fresh.bytes), [
    "network",
    "release_version",
    "release_sha256",
    "issued_at",
    "expires_at",
  ]);
  const { issued_at: issuedAt, expires_at: freshUntil } = freshness;
  if (
    typeof freshness["network"] !== "string" ||
    !positive(freshness["release_version"]) ||
    typeof freshness["release_sha256"] !== "string" ||
    !integer(issuedAt) ||
    !integer(freshUntil) ||
    issuedAt >= freshUntil
  ) {
    throw malformed();
  }
  if (
    freshness["network"] !== signers.network ||
    freshness["release_version"] !== version ||
    freshness["release_sha256"] !== bytesToHex(sha256(release.bytes))
  ) {
    throw refused("policy_freshness");
  }
  if (freshUntil - issuedAt > maxLifetime) throw refused("policy_lifetime");
  if (issuedAt > nowSecs + MAX_CLOCK_SKEW_SECS) throw refused("policy_future");
  if (nowSecs >= freshUntil) throw refused("policy_stale");
  return Object.freeze({
    policy,
    version,
    payload: release.payload,
    issuedAt,
    expiresAt: Math.min(releaseExpiresAt, freshUntil),
  });
}

type Part = Readonly<{
  payload: string;
  bytes: Uint8Array;
  signatures: readonly Readonly<{ key: string; signature: string }>[];
}>;

/** A payload and its signatures, with no check of the signatures. */
function signedPart(value: unknown): Part {
  const { payload, signatures } = exactRecord(value, ["payload", "signatures"]);
  if (!lowerHex(payload) || !Array.isArray(signatures)) throw malformed();
  return {
    payload,
    bytes: hexToBytes(payload),
    signatures: signatures.map((entry: unknown) => {
      const { public_key: key, signature } = exactRecord(entry, ["public_key", "signature"]);
      if (!lowerHex(key, 32) || !lowerHex(signature, 64)) throw malformed();
      return { key, signature };
    }),
  };
}

/** Whether `threshold` distinct pinned keys signed the part under `domain`. */
function quorum(domain: Uint8Array, part: Part, keys: Keys): boolean {
  const message = concatBytes(domain, part.bytes);
  const signed = new Set<string>();
  for (const { key, signature } of part.signatures) {
    if (!keys.keys.includes(key) || signed.has(key)) continue;
    let valid = false;
    try {
      valid = ed25519.verify(hexToBytes(signature), message, hexToBytes(key), { zip215: false });
    } catch {
      // A signature that does not decode signs nothing.
    }
    if (valid) signed.add(key);
  }
  return signed.size >= keys.threshold;
}

function json(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw malformed();
  }
}

/** A safe integer of at least 0. */
function integer(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/** A safe integer of at least 1. */
function positive(value: unknown): value is number {
  return integer(value) && value >= 1;
}

/** Distinct lowercase hex Ed25519 points. */
function distinctKeys(keys: readonly unknown[]): keys is readonly string[] {
  return (
    keys.every((key) => lowerHex(key, 32) && onCurve(key)) && new Set(keys).size === keys.length
  );
}

/** A threshold `keys` can meet. */
function meets(threshold: unknown, keys: readonly unknown[]): threshold is number {
  return (
    Number.isSafeInteger(threshold) && Number(threshold) >= 1 && Number(threshold) <= keys.length
  );
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
