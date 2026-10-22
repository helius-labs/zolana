import { checkRingOutputOwners, checkMergeRingData } from "./outputs.js";
import type {
  IndexedProofInputs,
  IndexedProofResult,
  PreparedTransferInput,
  PreparedMergeInputs,
} from "../ports.js";
import {
  decodeIndexedInputs,
  indexedRequestEnvelope,
  parseIndexedResponse,
  resolvedTrees,
} from "./indexed.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { bytesToBigInt } from "../../keypair/bytes.js";

import { wireDecoder } from "../../interface/decode.js";
import { InterfaceError } from "../../interface/errors.js";
import {
  PROVING_KEY_SHA256S,
  expectedProvingKey,
  ringProvingKey,
  type ExpectedProvingKey,
  type ProvingKeyCircuit,
} from "../../interface/proving-keys.js";
import type { RequestContext } from "../../interface/types.js";
import { isDefaultTeeProver, isZolanaGateway } from "../../endpoint.js";

import { ClientError } from "../error.js";
import {
  checkedBytes,
  field,
  checkedServiceUrl,
  composeSignal,
  requestError,
  sleep,
  type ComposedSignal,
} from "../internal.js";
import {
  TransportFailure,
  checkedFetch,
  isLoopbackHost,
  readBoundedJson,
} from "../../services/transport.js";
import { parseCheckedProof } from "./proof.js";
import { MAX_ATTEMPTS, RETRY_DELAY_MS } from "./retry.js";
import {
  recordJson,
  ringProofCircuit,
  ringProofRequestBody,
  type RingProofRequest,
} from "./ring.js";
import { DEFAULT_TEE_POLICY_FILE } from "./tee/default.js";
import { defaultTeePolicy } from "./tee/policy.js";
import type { TeePolicy } from "./tee/registry.js";
import { TeeSession, sendCall, type ProverCall } from "./tee/session.js";
import type { AttestedProver } from "./tee/verify.js";
import type {
  AnonymousEddsaAuthorization,
  Field,
  MergeInputs,
  Proof,
  ProverInputs,
  TransferInput,
  TransferOutput,
  TreeSlotFields,
} from "./types.js";

const MAX_RESPONSE_BYTES = 1024 * 1024;
/** An error body is a code and a message; anything larger is not read. */
const MAX_REASON_BYTES = 4096;
/// Per-request bound, mirroring the Rust client's `PROVE_REQUEST_TIMEOUT_SECS`.
/// Generous enough for a cold prove that first loads a 63MB proving key, so a
/// clean server-side timeout still returns before it.
const REQUEST_TIMEOUT_MS = 600_000;
/**
 * First gap between status polls, doubling up to `pollIntervalCapMs`.
 *
 * Matches the Rust client's `INITIAL_POLL_MS`. A flat interval pays its full
 * length on every proof: at 3s, a proof that finished in 1.3s still waited for
 * the next tick, which was most of the TypeScript SDK's per-transfer latency and
 * looked like slow local compute because sleeping burns no CPU and issues no
 * request. Starting small and backing off keeps the common case tight without
 * hammering the prover while a genuinely long proof runs.
 */
const INITIAL_POLL_INTERVAL_MS = 25;
/**
 * Prefix of every proof path: a proof is sent to `/prove/<key>`, `<key>` being
 * its proving key's file name without `.key`. The key is in the path because a
 * gateway routes and prices on the path alone, so it can send each key to its
 * own prover pool at its own price.
 */
const PROVE_PATH = "/prove";
const INDEXED_PATH = "/indexed";
const STATUS_PATH = "/status";
const HEALTH_PATH = "/health";
const PROVING_KEYS_PATH = "/proving-keys";
const ATTESTATION_PATH = "/tee/v1/attestation";
type Delivery = "inResponse" | "queued";
type Route = "sync" | "queued" | "indexed";

/// Polling cadence and ceiling for queued (async) proofs. A Redis-backed prover
/// returns a job handle instead of a proof, and the client polls the proving
/// key's `/prove/<key>/status` until it completes.
export interface AsyncPollConfig {
  /**
   * Ceiling for the gap between status polls. Polling starts at 25ms and
   * doubles up to this, so a fast proof is noticed quickly and a slow one does
   * not generate a request per 25ms for its whole duration.
   */
  readonly pollIntervalCapMs: number;
  readonly maxWaitMs: number;
}

const DEFAULT_ASYNC_POLL_CONFIG: AsyncPollConfig = Object.freeze({
  pollIntervalCapMs: 1_000,
  maxWaitMs: 1_200_000,
});

export interface ProverHealth {
  readonly status: string;
  readonly circuits: readonly string[];
}

/** How one proving key the SDK knows stands on the prover. */
export interface ProvingKeyCheck {
  /** Key file name, as proving-keys.lock and the prover's `/proving-keys` name it. */
  readonly name: string;
  /** Whether the prover lists the key at all. */
  readonly served: boolean;
  readonly available: boolean;
  readonly loaded: boolean;
}

/** A prover's proving keys, every digest matching the SDK's verifying keys. */
export interface ProvingKeyReport {
  /** The prover's proving-key version, its lockfile prefix. */
  readonly prefix: string;
  readonly keys: readonly ProvingKeyCheck[];
}

/**
 * The session a prover gets: the caller's policy, none for `false`, else the
 * pinned default deployment except on loopback and on the Helius gateway, which
 * cannot relay encrypted requests.
 */
function teeSession(
  tee: TeePolicy | false | undefined,
  url: URL,
  gateway: boolean,
): TeeSession | undefined {
  if (tee === false) return undefined;
  if (tee !== undefined) return new TeeSession(tee);
  if (gateway || isLoopbackHost(url.hostname) || DEFAULT_TEE_POLICY_FILE.deployment === null) {
    return undefined;
  }
  return new TeeSession(defaultTeePolicy());
}

export class ProverClient {
  readonly #fetch: typeof globalThis.fetch;
  readonly #url: URL;
  /** The Helius gateway routes only the key-less `/prove` and `/prove/status`. */
  readonly #keyless: boolean;
  readonly #indexed: boolean;
  readonly #asyncPoll: AsyncPollConfig;
  readonly #tee: TeeSession | undefined;

  constructor(
    input: Readonly<{
      url: URL | string;
      fetch?: typeof globalThis.fetch;
      asyncPoll?: AsyncPollConfig;
      /** See `ZolanaClientConfig.allowInsecureHttp`. */
      allowInsecureHttp?: boolean;
      /**
       * Encrypts every call, health and key checks included, to a prover that
       * attests to the policy. Left out, a remote prover other than the Helius
       * gateway gets `defaultTeePolicy()`; `false` sends plaintext, which carries
       * every proof's witness.
       */
      tee?: TeePolicy | false;
    }>,
  ) {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_CONFIG");
    }
    const url = checkedServiceUrl(input.url, "url", input.allowInsecureHttp ?? false);
    this.#keyless = isZolanaGateway(url);
    this.#indexed = !this.#keyless && !isDefaultTeeProver(url);
    url.pathname = `${url.pathname.replace(/\/+$/u, "")}${PROVE_PATH}`;
    try {
      this.#fetch = checkedFetch(input.fetch);
    } catch (error) {
      if (!(error instanceof TransportFailure)) throw error;
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "fetch" } });
    }
    this.#url = url;
    this.#asyncPoll = asyncPollConfig(input.asyncPoll);
    this.#tee = teeSession(input.tee, url, this.#keyless);
  }

  /**
   * Whether the prover reads proof data from its own indexer. The Helius
   * gateway and the default TEE prover have no `/indexed` route.
   */
  get hasIndexedRoute(): boolean {
    return this.#indexed;
  }

  /** Attests the prover now against the `tee` policy. */
  async attest(context?: RequestContext): Promise<AttestedProver> {
    if (this.#tee === undefined) {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "tee" } });
    }
    const request = composeSignal(context, "attest");
    try {
      return await this.#tee.attest(this.#fetch, this.#siblingUrl(ATTESTATION_PATH), request);
    } finally {
      request.cleanup();
    }
  }

  /** A path beside `/prove`, keeping any gateway prefix and query. */
  #siblingUrl(path: string): URL {
    const url = new URL(this.#url);
    url.pathname = url.pathname.replace(/\/prove$/u, path);
    return url;
  }

  #call(
    url: URL,
    signal: ComposedSignal,
    post?: Readonly<{ headers: Readonly<Record<string, string>>; body: string }>,
  ): ProverCall {
    return {
      fetch: this.#fetch,
      attestationUrl: this.#siblingUrl(ATTESTATION_PATH),
      url,
      method: post === undefined ? "GET" : "POST",
      headers: post?.headers ?? {},
      ...(post === undefined ? {} : { body: post.body }),
      signal,
      maxResponseBytes: MAX_RESPONSE_BYTES,
    };
  }

  async prove(inputs: ProverInputs, context?: RequestContext): Promise<Proof> {
    const body = JSON.stringify(proverRequest(inputs, completeSecret));
    const key = provingKeyFor({
      circuit: transferCircuit(inputs),
      nInputs: inputs.payload.inputs.length,
      nOutputs: inputs.payload.outputs.length,
    });
    return parseCheckedProof(await this.#send(body, "sync", key, context), key);
  }

  async proveMerge(inputs: MergeInputs, context?: RequestContext): Promise<Proof> {
    const body = JSON.stringify(mergeProverRequest(inputs, completeSecret));
    const key = provingKeyFor({ circuit: mergeCircuit(inputs), nInputs: inputs.inputs.length });
    return parseCheckedProof(await this.#send(body, "sync", key, context), key);
  }

  async proveIndexed(
    request: IndexedProofInputs,
    context?: RequestContext,
  ): Promise<IndexedProofResult> {
    const inputs = decodeIndexedInputs(request);
    const prepared =
      inputs.circuit === "merge"
        ? mergeProverRequest(inputs.payload, completeSecret)
        : proverRequest(inputs, completeSecret);
    const key = provingKeyFor(
      inputs.circuit === "merge"
        ? { circuit: mergeCircuit(inputs.payload), nInputs: inputs.payload.inputs.length }
        : {
            circuit: transferCircuit(inputs),
            nInputs: inputs.payload.inputs.length,
            nOutputs: inputs.payload.outputs.length,
          },
    );
    const body = JSON.stringify(indexedRequestEnvelope(inputs, prepared));
    const result = parseIndexedResponse(await this.#send(body, "indexed", key, context), key);
    resolvedTrees(inputs, result.resolution);
    return result;
  }

  /** One ring proof, the 192-byte `CustomRingProof` the ring program verifies. */
  async proveRing(request: RingProofRequest, context?: RequestContext): Promise<Proof> {
    const body = JSON.stringify(ringProofRequestBody(request));
    const key = ringProvingKey(ringProofCircuit(request));
    return parseCheckedProof(await this.#send(body, "queued", key, context), key);
  }

  /** The circuits the server serves. */
  async health(context?: RequestContext): Promise<ProverHealth> {
    const url = this.#siblingUrl(HEALTH_PATH);
    const request = composeSignal(context, "health");
    try {
      const response = await sendCall(this.#tee, this.#call(url, request));
      if (response === undefined) {
        if (request.timedOut()) throw requestError("health", request);
        throw new ClientError("CLIENT_PROVER_REQUEST", {
          details: { method: "health", attempts: 1 },
        });
      }
      if (!response.ok) {
        throw new ClientError("CLIENT_PROVER_HTTP", {
          details: { method: "health", status: response.status, ...(await proverReason(response)) },
        });
      }
      const value = await decodeResponse(response);
      if (!isObject(value) || typeof value["status"] !== "string") {
        throw new ClientError("CLIENT_PROVER_JSON");
      }
      const circuits = Array.isArray(value["circuits"]) ? value["circuits"] : [];
      return Object.freeze({
        status: value["status"],
        circuits: Object.freeze(
          circuits.filter((circuit): circuit is string => typeof circuit === "string"),
        ),
      });
    } finally {
      request.cleanup();
    }
  }

  /**
   * Compare the prover's proving keys (`GET /proving-keys`) with the
   * proving-key sha256 each committed verifying key pins, so a prover on
   * another key set fails before the first proof instead of on-chain. A
   * differing digest throws `CLIENT_PROVER_PROVING_KEYS_MISMATCH` naming every
   * such key; a key the prover lacks or cannot load is only reported.
   */
  async checkProvingKeys(context?: RequestContext): Promise<ProvingKeyReport> {
    const url = this.#siblingUrl(PROVING_KEYS_PATH);
    const request = composeSignal(context, "provingKeys");
    try {
      const response = await sendCall(this.#tee, this.#call(url, request));
      if (response === undefined) {
        if (request.timedOut() || request.signal.aborted)
          throw requestError("provingKeys", request);
        throw new ClientError("CLIENT_PROVER_REQUEST", {
          details: { method: "provingKeys", attempts: 1 },
        });
      }
      if (!response.ok) {
        throw new ClientError("CLIENT_PROVER_HTTP", {
          details: {
            method: "provingKeys",
            status: response.status,
            ...(await proverReason(response)),
          },
        });
      }
      return checkProverKeys(decodeProverKeys(await decodeResponse(response)));
    } finally {
      request.cleanup();
    }
  }

  async #send(
    body: string,
    route: Route,
    key: ExpectedProvingKey,
    context?: RequestContext,
  ): Promise<unknown> {
    if (route === "indexed" && !this.#indexed) {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "proofDataSource" } });
    }
    const url = this.#keyUrl(key);
    if (route === "indexed") url.pathname += INDEXED_PATH;
    let delivery: Delivery = route === "queued" ? "queued" : "inResponse";
    const signal = composeSignal(context, "prove");
    try {
      deliveryAttempt: for (;;) {
        for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
          if (attempt > 1) await sleep(RETRY_DELAY_MS, { signal: signal.signal });
          const request = composeSignal(
            { signal: signal.signal, timeoutMs: REQUEST_TIMEOUT_MS },
            "prove",
          );
          try {
            const response = await sendCall(
              this.#tee,
              this.#call(url, request, {
                headers: delivery === "inResponse" ? { "X-Sync": "true" } : { "X-Async": "true" },
                body,
              }),
            );
            if (response === undefined) {
              if (signal.signal.aborted) throw requestError("prove", signal);
              if (attempt < MAX_ATTEMPTS) continue;
              if (request.timedOut()) throw requestError("prove", request);
              throw new ClientError("CLIENT_PROVER_REQUEST", {
                details: { method: "prove", attempts: attempt },
              });
            }
            if (response.status === 429 && delivery === "inResponse") {
              await response.body?.cancel();
              delivery = "queued";
              continue deliveryAttempt;
            }
            // Rust fails fast on any non-success status; only a transport failure retries.
            if (!response.ok) {
              if (route === "indexed") throw await indexedHttpFailure(response, attempt);
              throw new ClientError("CLIENT_PROVER_HTTP", {
                details: {
                  method: "prove",
                  status: response.status,
                  attempts: attempt,
                  ...(await proverReason(response)),
                },
              });
            }
            let value: unknown;
            try {
              value = await decodeResponse(response);
            } catch (error) {
              if (signal.signal.aborted) throw requestError("prove", signal);
              if (request.timedOut()) throw requestError("prove", request);
              throw error;
            }
            if (
              isObject(value) &&
              typeof value["jobId"] === "string" &&
              value["proof"] === undefined
            ) {
              return await this.#poll(value["jobId"], signal, route, key);
            }
            return value;
          } finally {
            request.cleanup();
          }
        }
        throw new ClientError("CLIENT_PROVER_REQUEST", {
          details: { method: "prove", attempts: MAX_ATTEMPTS },
        });
      }
    } finally {
      signal.cleanup();
    }
  }

  /// Mirrors `poll_async`: request the status, then wait between attempts, with
  /// the total wall-clock duration bounded by `maxWaitMs`. A 4xx is final, a 5xx or a
  /// transport failure is transient, and every other status has its body read.
  /**
   * `/prove/<key>`: every proof and its status poll go to its proving key's
   * path, so a gateway sends both to the prover pool that serves the key.
   * On the Helius gateway, `/prove`, where the prover reads the key from the body.
   */
  #keyUrl(key: ExpectedProvingKey): URL {
    const url = new URL(this.#url);
    if (this.#keyless) return url;
    url.pathname += `/${encodeURIComponent(key.name.replace(/\.key$/u, ""))}`;
    return url;
  }

  async #poll(
    jobId: string,
    signal: ComposedSignal,
    route: Route,
    key: ExpectedProvingKey,
  ): Promise<unknown> {
    if (!/^[A-Za-z0-9_-]{1,256}$/u.test(jobId)) {
      throw new ClientError("CLIENT_PROVER_JOB", { details: { method: "prove" } });
    }
    const url = this.#keyUrl(key);
    url.pathname += STATUS_PATH;
    url.searchParams.set("jobId", jobId);
    const intervalCap = Math.max(INITIAL_POLL_INTERVAL_MS, this.#asyncPoll.pollIntervalCapMs);
    let interval = INITIAL_POLL_INTERVAL_MS;
    const maxWaitMs = this.#asyncPoll.maxWaitMs;
    const deadline = Date.now() + maxWaitMs;
    const remainingMs = (): number => Math.max(0, deadline - Date.now());
    const timeout = (): never => {
      throw new ClientError("CLIENT_PROVER_TIMEOUT", {
        details: { method: "proveStatus", jobId, timeoutMs: maxWaitMs },
      });
    };
    const waitOrTimeout = async (): Promise<void> => {
      const remaining = remainingMs();
      if (remaining === 0) timeout();
      const sleepMs = Math.min(interval, remaining);
      await sleep(BigInt(sleepMs), { signal: signal.signal });
      interval = Math.min(interval * 2, intervalCap);
    };
    for (;;) {
      // The Rust status GET inherits the shared client's request timeout, so a
      // server that accepts the connection and never answers is a transport
      // failure there. Without a bound here the same server hangs the poll
      // past `maxWaitMs` forever.
      const remaining = remainingMs();
      if (remaining === 0) timeout();
      const request = composeSignal(
        { signal: signal.signal, timeoutMs: Math.min(REQUEST_TIMEOUT_MS, remaining) },
        "proveStatus",
      );
      try {
        const response = await sendCall(this.#tee, this.#call(url, request));
        if (response === undefined) {
          if (signal.signal.aborted) throw requestError("prove", signal);
          await waitOrTimeout();
          continue;
        }
        if (response.status >= 400 && response.status < 500) {
          throw new ClientError("CLIENT_PROVER_HTTP", {
            details: {
              method: "proveStatus",
              status: response.status,
              ...(route === "indexed" ? {} : await proverReason(response)),
            },
          });
        }
        if (response.status >= 500) {
          await waitOrTimeout();
          continue;
        }
        let value: unknown;
        try {
          value = await decodeResponse(response);
        } catch (error) {
          if (signal.signal.aborted) throw requestError("prove", signal);
          // Rust retries when reading the body fails and fails outright when the
          // body is not JSON, so only the read failure is transient here.
          if (!(error instanceof ClientError && error.code === "CLIENT_PROVER_TEXT")) throw error;
          await waitOrTimeout();
          continue;
        }
        const status = isObject(value) ? value["status"] : undefined;
        if (status === "failed") {
          throw (
            (route === "indexed" ? indexedFailure(value) : undefined) ??
            new ClientError("CLIENT_PROVER_SERVER", {
              details: { method: "proveStatus", status: "failed" },
            })
          );
        }
        if (status === "completed") {
          // Rust unwraps the envelope on the key's presence, not on its type:
          // `value.get("result").map_or(&value, ..)`. Requiring an object here
          // sent a `result: null` back into the parser as the whole envelope,
          // where the missing proof read as malformed rather than as absent.
          const result = isObject(value) && "result" in value ? value["result"] : value;
          return result;
        }
        // queued / processing / pending / unknown: keep polling until the bound.
        await waitOrTimeout();
      } finally {
        request.cleanup();
      }
    }
  }
}

type ProverKeyStatus = Readonly<{
  name: string;
  expectedSha256: string | null;
  loadedSha256: string | null;
  available: boolean;
}>;

const invalidProverJson = (): ClientError => new ClientError("CLIENT_PROVER_JSON");
const proverJsonDecoder = wireDecoder(invalidProverJson);
const SHA256_HEX = /^[0-9a-f]{64}$/u;

/** Strict decode of `GET /proving-keys`: any other shape is an error, not a skipped key. */
function decodeProverKeys(
  value: unknown,
): Readonly<{ prefix: string; keys: readonly ProverKeyStatus[] }> {
  const body = proverJsonDecoder.record(value, "$");
  const digest = (entry: Record<string, unknown>, field: string): string | null => {
    const raw = entry[field];
    if (raw === null) return null;
    const hex = proverJsonDecoder.string(raw, `$.keys[].${field}`);
    if (!SHA256_HEX.test(hex)) throw invalidProverJson();
    return hex;
  };
  const keys = proverJsonDecoder.list(body["keys"], "$.keys").map((raw) => {
    const entry = proverJsonDecoder.record(raw, "$.keys[]");
    return Object.freeze({
      name: proverJsonDecoder.string(entry["name"], "$.keys[].name"),
      expectedSha256: digest(entry, "expectedSha256"),
      loadedSha256: digest(entry, "loadedSha256"),
      available: proverJsonDecoder.boolean(entry["available"], "$.keys[].available"),
    });
  });
  return Object.freeze({
    prefix: proverJsonDecoder.string(body["prefix"], "$.prefix"),
    keys: Object.freeze(keys),
  });
}

/** Compare a prover's keys with every proving key the SDK knows, as Rust `ProverKeys::check`. */
function checkProverKeys(
  prover: Readonly<{ prefix: string; keys: readonly ProverKeyStatus[] }>,
): ProvingKeyReport {
  const mismatched: string[] = [];
  const keys = Object.entries(PROVING_KEY_SHA256S).map(([name, pinned]): ProvingKeyCheck => {
    const status = prover.keys.find((key) => key.name === name);
    if (status === undefined) {
      return Object.freeze({ name, served: false, available: false, loaded: false });
    }
    if (
      (status.expectedSha256 !== null && status.expectedSha256 !== pinned) ||
      (status.loadedSha256 !== null && status.loadedSha256 !== pinned)
    ) {
      mismatched.push(name);
    }
    return Object.freeze({
      name,
      served: true,
      available: status.available,
      loaded: status.loadedSha256 !== null,
    });
  });
  if (mismatched.length > 0) {
    throw new ClientError("CLIENT_PROVER_PROVING_KEYS_MISMATCH", {
      details: { keyNames: mismatched.join(",") },
    });
  }
  return Object.freeze({ prefix: prover.prefix, keys: Object.freeze(keys) });
}

/**
 * The proving key `request` must be proven with. A shape without a committed
 * verifying key is a prover input the program could not verify.
 */
function provingKeyFor(request: ProvingKeyCircuit): ExpectedProvingKey {
  try {
    return expectedProvingKey(request);
  } catch (error) {
    if (error instanceof InterfaceError) throw new ClientError("CLIENT_PROVER_INPUT");
    throw error;
  }
}

/** The JSON body the prover accepts; every field a hex string but the slot counts. */
export type ProverRequestBody = Readonly<Record<string, unknown>>;

/** How a nullifier secret slot is written: the prover client requires it, a holder's transport leaves it open. */
type SecretEncoder = (secret: Field | undefined, name: string) => string | null;

const completeSecret: SecretEncoder = (secret, name) => hex(requireSecret(secret), name);
const pendingSecret: SecretEncoder = (secret, name) =>
  secret === undefined ? null : hex(secret, name);

/**
 * The body `ProofService.prove` would post, with `null` in every nullifier
 * secret slot a `ProofAuthority` has yet to fill: what a remote key holder is
 * sent, to complete and forward to its prover. `ProverClient` itself refuses
 * a body with a slot still open.
 */
export function proverRequestBody(inputs: ProverInputs): ProverRequestBody {
  return proverRequest(inputs, pendingSecret);
}

/** The merge counterpart of `proverRequestBody`. */
export function mergeProverRequestBody(inputs: MergeInputs): ProverRequestBody {
  return mergeProverRequest(inputs, pendingSecret);
}

/** A merge inside a custom ring is proven by the `merge-ring` circuit. */
function mergeCircuit(inputs: MergeInputs | PreparedMergeInputs): "merge" | "merge-ring" {
  return BigInt(inputs.ringProgramId) === 0n ? "merge" : "merge-ring";
}

/** Mirrors Rust `MergeParametersJson`, key set included. */
function mergeProverRequest(
  inputs: MergeInputs | PreparedMergeInputs,
  secret: SecretEncoder,
): ProverRequestBody {
  checkMergeRingData(inputs.inputs, inputs.output, inputs.outputRingDataHash);
  const ring = mergeCircuit(inputs) === "merge-ring";
  const anonymous = inputs.anonymous === true;
  const registry =
    inputs.memberRegistryRoot === undefined
      ? undefined
      : anonymous
        ? inputs.registeredCiphertextHash === undefined && inputs.memberRecord === undefined
          ? { memberRegistryRoot: hex(inputs.memberRegistryRoot, "memberRegistryRoot"), anonymous }
          : undefined
        : inputs.registeredCiphertextHash !== undefined && inputs.memberRecord !== undefined
          ? {
              memberRegistryRoot: hex(inputs.memberRegistryRoot, "memberRegistryRoot"),
              registeredCiphertextHash: hex(
                inputs.registeredCiphertextHash,
                "registeredCiphertextHash",
              ),
              memberRecord: recordJson(inputs.memberRecord, "memberRecord"),
            }
          : undefined;
  if (ring !== (registry !== undefined)) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  return Object.freeze({
    circuitType: mergeCircuit(inputs),
    inputs: inputs.inputs.map(mergeInputJson),
    output: mergeOutputJson(inputs.output),
    ...("treeSlots" in inputs
      ? {
          treeSlots: inputs.treeSlots.map(treeSlotJson),
          publicInputHash: hex(inputs.publicInputHash, "publicInputHash"),
        }
      : {}),
    outputTreeId: hex(inputs.outputTreeId, "outputTreeId"),
    mintChunks: inputs.mintChunks.map((chunk) => hex(chunk, "mintChunks")),
    outputCiphertextSalt: hex(inputs.outputCiphertextSalt, "outputCiphertextSalt"),
    ownerPkHash: hex(inputs.ownerPublicKeyHash, "ownerPkHash"),
    userNullifierPk: hex(inputs.userNullifierPublicKey, "userNullifierPk"),
    userNullifierSecret: secret(inputs.userNullifierSecret, "userNullifierSecret"),
    externalDataHash: hex(inputs.externalDataHash, "externalDataHash"),
    privateTxHash: hex(inputs.privateTxHash, "privateTxHash"),
    allowDummyInputs: hex(inputs.allowDummyInputs, "allowDummyInputs"),
    outputRingDataHash: hex(inputs.outputRingDataHash, "outputRingDataHash"),
    ringProgramId: hex(inputs.ringProgramId, "ringProgramId"),
    ...registry,
  });
}

function mergeInputJson(
  input: TransferInput | PreparedTransferInput,
): Readonly<Record<string, unknown>> {
  const utxo = input.circuit;
  return Object.freeze({
    domain: hex(utxo.domain, "domain"),
    amount: hex(utxo.amount, "amount"),
    blinding: hex(utxo.blinding, "blinding"),
    ringDataHash: hex(utxo.ringDataHash, "ringDataHash"),
    ...pathJson(input),
    treeSlot: hex(input.treeSlot, "treeSlot"),
    nullifier: hex(input.nullifier, "nullifier"),
  });
}

function mergeOutputJson(output: TransferOutput): Readonly<Record<string, unknown>> {
  return Object.freeze({
    ringDataHash: hex(output.circuit.ringDataHash, "ringDataHash"),
    hash: hex(output.hash, "hash"),
  });
}

/** Mirrors Rust `TreeSlotJson`. */
function treeSlotJson(slot: TreeSlotFields): Readonly<Record<string, unknown>> {
  return Object.freeze({
    id: hex(slot.id, "treeSlots id"),
    utxoRoot: hex(slot.utxoRoot, "treeSlots utxoRoot"),
    nullifierRoot: hex(slot.nullifierRoot, "treeSlots nullifierRoot"),
  });
}

function hex32(bytes: Uint8Array, field: string): string {
  return bytesHex(checkedBytes(bytes, 32, field));
}

function sized<T>(values: readonly T[], expected: number, field: string): readonly T[] {
  if (!Array.isArray(values) || values.length !== expected) {
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: { field, expected, actual: Array.isArray(values) ? values.length : 0 },
    });
  }
  return values;
}

/** Mirrors Rust `TransferInputsJson`, key set and order included. */
/** The prover circuit a transfer is proven by. */
function transferCircuit(
  inputs: ProverInputs | Exclude<IndexedProofInputs, { circuit: "merge" }>,
): "transfer-ring-authority" | "transfer-ring" | "transfer-eddsa-ring" | "transfer-confidential" {
  switch (inputs.circuit) {
    case "transferRingAuthority":
      return "transfer-ring-authority";
    case "transferRing":
      return "transfer-ring";
    case "transferEddsaRing":
      return "transfer-eddsa-ring";
    case "transfer":
      return "transfer-confidential";
  }
}

function proverRequest(
  inputs: ProverInputs | Exclude<IndexedProofInputs, { circuit: "merge" }>,
  secret: SecretEncoder,
): ProverRequestBody {
  const payload = inputs.payload;
  if (inputs.circuit === "transferRing" || inputs.circuit === "transferEddsaRing")
    checkRingOutputOwners(payload.outputs, payload.publishedOutputOwnerPublicKeyHashes);
  sized(
    payload.ringSecrets,
    inputs.circuit === "transfer" ? 0 : payload.outputs.length,
    "ringSecrets",
  );
  return Object.freeze({
    circuitType: transferCircuit(inputs),
    ...(inputs.circuit === "transferEddsaRing" ? authorizationJson(inputs.authorization) : {}),
    nInputs: payload.inputs.length,
    nOutputs: payload.outputs.length,
    inputs: payload.inputs.map((input) => inputJson(input, secret)),
    outputs: payload.outputs.map(outputJson),
    ...("treeSlots" in payload
      ? {
          treeSlots: payload.treeSlots.map(treeSlotJson),
          publicInputHash: hex(payload.publicInputHash, "publicInputHash"),
        }
      : {}),
    outputTreeId: hex(payload.outputTreeId, "outputTreeId"),
    externalDataHash: hex(payload.externalDataHash, "externalDataHash"),
    privateTxHash: hex(payload.privateTxHash, "privateTxHash"),
    blindingSeed: hex(payload.blindingSeed, "blindingSeed"),
    ringSecrets: hexes(payload.ringSecrets, "ringSecrets"),
    publicAssets: hexes(payload.publicAssets, "publicAssets"),
    publicAmounts: hexes(payload.publicAmounts, "publicAmounts"),
    ringProgramId: hex(payload.ringProgramId, "ringProgramId"),
    signerPkHashes: hexes(payload.signerPublicKeyHashes, "signerPkHashes"),
    inputFlags: hex(payload.inputFlags, "inputFlags"),
    publishedOutputOwnerPkHashes: hexes(
      payload.publishedOutputOwnerPublicKeyHashes,
      "publishedOutputOwnerPkHashes",
    ),
    cacheTreeId: hex(payload.cacheTreeId, "cacheTreeId"),
    cacheReadHashChain: hex(payload.cacheReadHashChain, "cacheReadHashChain"),
    cacheReadHashes: hexes(payload.cacheReadHashes, "cacheReadHashes"),
    cacheIsCached: hexes(payload.cacheIsCached, "cacheIsCached"),
    cacheReadIndex: hexes(payload.cacheReadIndex, "cacheReadIndex"),
  });
}

/** Mirrors Rust `AnonymousEddsaAuthorization::fields`, the digest split into the prover's limbs. */
function authorizationJson(
  authorization: AnonymousEddsaAuthorization,
): Readonly<Record<string, string>> {
  const digest = checkedBytes(authorization.messageDigest, 32, "messageDigest");
  const [payer, cosigner, exit] = authorization.parties;
  return Object.freeze({
    ownerPublicKey: hex32(authorization.ownerPublicKey, "ownerPublicKey"),
    ownerSignature: bytesHex(checkedBytes(authorization.ownerSignature, 64, "ownerSignature")),
    ringProgramAddress: hex32(authorization.ringProgramAddress, "ringProgramAddress"),
    messageHashLow: bytesHex(digest.subarray(16)),
    messageHashHigh: bytesHex(digest.subarray(0, 16)),
    defaultOwnerPkHash: fieldHex(authorization.defaultOwnerPkHash, "defaultOwnerPkHash"),
    payerPkHash: fieldHex(payer, "payerPkHash"),
    cosignerPkHash: fieldHex(cosigner, "cosignerPkHash"),
    exitDestinationPkHash: fieldHex(exit, "exitDestinationPkHash"),
  });
}

/** A 32-byte field element as Rust `hex_field` writes it, without leading zeros. */
function fieldHex(bytes: Uint8Array, name: string): string {
  return `0x${field(bytesToBigInt(checkedBytes(bytes, 32, name)), name).toString(16)}`;
}

function inputJson(
  input: TransferInput | PreparedTransferInput,
  secret: SecretEncoder,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    utxo: utxoJson(input),
    isDummy: hex(input.isDummy, "isDummy"),
    ...pathJson(input),
    treeSlot: hex(input.treeSlot, "treeSlot"),
    nullifier: hex(input.nullifier, "nullifier"),
    ownerPkHash: hex(input.ownerPublicKeyHash, "ownerPkHash"),
    nullifierSecret: secret(input.nullifierSecret, "nullifierSecret"),
  });
}

function pathJson(input: TransferInput | PreparedTransferInput): Readonly<Record<string, unknown>> {
  if (!("statePathElements" in input)) return {};
  return {
    statePathElements: hexes(input.statePathElements, "statePathElements"),
    statePathIndex: hex(input.statePathIndex, "statePathIndex"),
    nullifierLowValue: hex(input.nullifierLowValue, "nullifierLowValue"),
    nullifierNextValue: hex(input.nullifierNextValue, "nullifierNextValue"),
    nullifierLowPathElements: hexes(input.nullifierLowPathElements, "nullifierLowPathElements"),
    nullifierLowPathIndex: hex(input.nullifierLowPathIndex, "nullifierLowPathIndex"),
  };
}

function outputJson(output: TransferOutput): Readonly<Record<string, unknown>> {
  return Object.freeze({
    utxo: utxoJson(output),
    isDummy: hex(output.isDummy, "isDummy"),
    hash: hex(output.hash, "hash"),
    ownerPkHash: hex(output.ownerPublicKeyHash, "ownerPkHash"),
    nullifierPk: hex(output.nullifierPublicKey, "nullifierPk"),
  });
}

function utxoJson(
  value: TransferInput | TransferOutput | PreparedTransferInput,
): Readonly<Record<string, unknown>> {
  const utxo = value.circuit;
  return Object.freeze({
    domain: hex(utxo.domain, "domain"),
    owner: hex(utxo.owner, "owner"),
    asset: hex(utxo.asset, "asset"),
    amount: hex(utxo.amount, "amount"),
    blinding: hex(utxo.blinding, "blinding"),
    dataHash: hex(utxo.dataHash, "dataHash"),
    ringDataHash: hex(utxo.ringDataHash, "ringDataHash"),
    ringProgramId: hex(utxo.ringProgramId, "ringProgramId"),
  });
}

/** Inputs reach the prover only complete; a missing secret is a `ProofAuthority` that did not run. */
function requireSecret(secret: Field | undefined): Field {
  if (secret === undefined) throw new ClientError("CLIENT_MISSING_NULLIFIER_SECRET");
  return secret;
}

function hex(value: Field, name: string): string {
  return `0x${field(value, name).toString(16)}`;
}

function hexes(values: readonly Field[], name: string): readonly string[] {
  return values.map((value) => hex(value, name));
}

function bytesHex(bytes: Uint8Array): string {
  return `0x${bytesToHex(bytes)}`;
}

async function decodeResponse(response: Response): Promise<unknown> {
  try {
    return await readBoundedJson(response, MAX_RESPONSE_BYTES);
  } catch (error) {
    if (!(error instanceof TransportFailure)) throw error;
    if (error.kind === "responseTooLarge")
      throw new ClientError("CLIENT_PROVER_RESPONSE_TOO_LARGE");
    if (error.kind === "text") throw new ClientError("CLIENT_PROVER_TEXT");
    throw new ClientError("CLIENT_PROVER_JSON");
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const MAX_REASON_CHARS = 200;

/**
 * The prover's `{ code, message }` error body as one bounded string, so a
 * refused request says why (an unknown circuit, a malformed field, a missing
 * key) instead of only its status. Untrusted text; absent when unreadable.
 */
async function proverReason(response: Response): Promise<Readonly<{ reason?: string }>> {
  const body = await errorBody(response);
  if (!isObject(body)) return {};
  const parts = [body["code"], body["message"]].filter(
    (part): part is string => typeof part === "string" && part.length > 0,
  );
  return parts.length === 0 ? {} : { reason: parts.join(": ").slice(0, MAX_REASON_CHARS) };
}

/** Indexed failures carry caller data in their message, only the `code` is read. */
async function indexedHttpFailure(response: Response, attempt: number): Promise<ClientError> {
  const body = await errorBody(response);
  const typed = indexedFailure(body);
  if (typed !== undefined) return typed;
  // An old prover has no indexed route and answers a bare 404. A coded one, such
  // as a key the prover does not serve, is reported as it is.
  if (response.status === 404 && !(isObject(body) && typeof body["code"] === "string")) {
    return new ClientError("CLIENT_PROVER_INDEXER_UNCONFIGURED");
  }
  return new ClientError("CLIENT_PROVER_HTTP", {
    details: { method: "prove", status: response.status, attempts: attempt },
  });
}

function indexedFailure(body: unknown): ClientError | undefined {
  if (!isObject(body)) return undefined;
  switch (body["code"]) {
    case "indexer_not_ready":
      return new ClientError("CLIENT_INDEXER_PROOF_DATA_NOT_READY");
    case "indexer_unconfigured":
      return new ClientError("CLIENT_PROVER_INDEXER_UNCONFIGURED");
    default:
      return undefined;
  }
}

async function errorBody(response: Response): Promise<unknown> {
  try {
    return await readBoundedJson(response, MAX_REASON_BYTES);
  } catch {
    return undefined;
  }
}

function asyncPollConfig(input: AsyncPollConfig | undefined): AsyncPollConfig {
  if (input === undefined) return DEFAULT_ASYNC_POLL_CONFIG;
  for (const field of ["pollIntervalCapMs", "maxWaitMs"] as const) {
    const value = input[field];
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new ClientError("CLIENT_INVALID_POLL_CONFIG", { details: { field } });
    }
  }
  return Object.freeze({ pollIntervalCapMs: input.pollIntervalCapMs, maxWaitMs: input.maxWaitMs });
}
