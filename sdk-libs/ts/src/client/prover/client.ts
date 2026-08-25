import { bytesToHex } from "@noble/hashes/utils.js";

import type { RequestContext } from "../../interface/types.js";

import { ClientError } from "../error.js";
import {
  checkedBytes,
  checkedServiceUrl,
  composeSignal,
  requestError,
  sleep,
  type ComposedSignal,
} from "../internal.js";
import { circuitUtxo } from "./assembly.js";
import { parseProof } from "./proof.js";
import type {
  AuditProofRequest,
  Field,
  MergeInputs,
  Proof,
  ProverInputs,
  TransferInput,
  TransferOutput,
} from "./types.js";

const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_ATTEMPTS = 3;
const RETRY_DELAY_MS = 2_000n;
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
const PROVE_PATH = "/prove";
const HEALTH_PATH = "/health";
const UNCOMPRESSED_P256_LENGTH = 65;
type Delivery = "inResponse" | "queued";

/// Polling cadence and ceiling for queued (async) proofs. A Redis-backed prover
/// returns a job handle instead of a proof, and the client polls
/// `/prove/status` until it completes.
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

export class ProverClient {
  readonly #fetch: typeof globalThis.fetch;
  readonly #url: URL;
  readonly #asyncPoll: AsyncPollConfig;

  constructor(
    input: Readonly<{
      url: URL | string;
      fetch?: typeof globalThis.fetch;
      asyncPoll?: AsyncPollConfig;
      /** See `ZolanaClientConfig.allowInsecureHttp`. */
      allowInsecureHttp?: boolean;
    }>,
  ) {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_CONFIG");
    }
    const url = checkedServiceUrl(input.url, "url", input.allowInsecureHttp ?? false);
    url.pathname = `${url.pathname.replace(/\/+$/u, "")}${PROVE_PATH}`;
    // Browsers refuse `fetch` called with another receiver, so the global stays bound.
    const fetchImplementation = input.fetch ?? ((input, init) => globalThis.fetch(input, init));
    if (typeof fetchImplementation !== "function") {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "fetch" } });
    }
    this.#url = url;
    this.#fetch = fetchImplementation;
    this.#asyncPoll = asyncPollConfig(input.asyncPoll);
  }

  async prove(inputs: ProverInputs, context?: RequestContext): Promise<Proof> {
    return this.#send(JSON.stringify(proverRequest(inputs)), "inResponse", context);
  }

  async proveMerge(inputs: MergeInputs, context?: RequestContext): Promise<Proof> {
    return this.#send(JSON.stringify(mergeProverRequest(inputs)), "inResponse", context);
  }

  async proveCustomRingAudit(inputs: AuditProofRequest, context?: RequestContext): Promise<Proof> {
    return this.#send(JSON.stringify(customRingAuditRequest(inputs)), "queued", context);
  }

  /** The circuits the server serves, `custom-ring-audit` among them only with a queue. */
  async health(context?: RequestContext): Promise<ProverHealth> {
    const url = new URL(this.#url);
    url.pathname = url.pathname.replace(/\/prove$/u, HEALTH_PATH);
    const request = composeSignal(context, "health");
    try {
      let response: Response;
      try {
        response = await this.#fetch(url, { redirect: "error", signal: request.signal });
      } catch {
        if (request.timedOut()) throw requestError("health", request);
        throw new ClientError("CLIENT_PROVER_REQUEST", {
          details: { method: "health", attempts: 1 },
        });
      }
      if (!response.ok) {
        throw new ClientError("CLIENT_PROVER_HTTP", {
          details: { method: "health", status: response.status },
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

  async #send(body: string, delivery: Delivery, context?: RequestContext): Promise<Proof> {
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
            let response: Response;
            try {
              response = await this.#fetch(this.#url, {
                method: "POST",
                headers: {
                  "content-type": "application/json",
                  ...(delivery === "inResponse" ? { "X-Sync": "true" } : {}),
                },
                body,
                redirect: "error",
                signal: request.signal,
              });
            } catch {
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
              throw new ClientError("CLIENT_PROVER_HTTP", {
                details: { method: "prove", status: response.status, attempts: attempt },
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
              return await this.#poll(value["jobId"], signal);
            }
            return parseProof(value);
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
  async #poll(jobId: string, signal: ComposedSignal): Promise<Proof> {
    if (!/^[A-Za-z0-9_-]{1,256}$/u.test(jobId)) {
      throw new ClientError("CLIENT_PROVER_JOB", { details: { method: "prove" } });
    }
    const url = new URL(this.#url);
    url.pathname = url.pathname.replace(/\/prove$/u, "/prove/status");
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
      let response: Response;
      try {
        try {
          response = await this.#fetch(url, { redirect: "error", signal: request.signal });
        } catch {
          if (signal.signal.aborted) throw requestError("prove", signal);
          await waitOrTimeout();
          continue;
        }
        if (response.status >= 400 && response.status < 500) {
          throw new ClientError("CLIENT_PROVER_HTTP", {
            details: { method: "proveStatus", status: response.status },
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
          throw new ClientError("CLIENT_PROVER_SERVER", {
            details: { method: "proveStatus", status: "failed" },
          });
        }
        if (status === "completed") {
          // Rust unwraps the envelope on the key's presence, not on its type:
          // `value.get("result").map_or(&value, ..)`. Requiring an object here
          // sent a `result: null` back into the parser as the whole envelope,
          // where the missing proof read as malformed rather than as absent.
          const result = isObject(value) && "result" in value ? value["result"] : value;
          return parseProof(result);
        }
        // queued / processing / pending / unknown: keep polling until the bound.
        await waitOrTimeout();
      } finally {
        request.cleanup();
      }
    }
  }
}

function mergeProverRequest(inputs: MergeInputs): Readonly<Record<string, unknown>> {
  return Object.freeze({
    circuitType: "merge",
    inputs: inputs.inputs.map(mergeInputJson),
    output: mergeOutputJson(inputs.output),
    asset: hex(circuitUtxo(inputs.output).asset),
    ownerPkHash: hex(inputs.ownerPublicKeyHash),
    userNullifierPk: hex(inputs.userNullifierPublicKey),
    userNullifierSecret: hex(inputs.userNullifierSecret),
    externalDataHash: hex(inputs.externalDataHash),
    privateTxHash: hex(inputs.privateTxHash),
    publicInputHash: hex(inputs.publicInputHash),
    allowDummyInputs: hex(inputs.allowDummyInputs),
    outputZoneDataHash: hex(inputs.outputZoneDataHash),
    zoneProgramId: hex(inputs.zoneProgramId),
  });
}

function mergeInputJson(input: TransferInput): Readonly<Record<string, unknown>> {
  const utxo = circuitUtxo(input);
  return Object.freeze({
    domain: hex(utxo.domain),
    amount: hex(utxo.amount),
    blinding: hex(utxo.blinding),
    zoneDataHash: hex(utxo.zoneDataHash),
    statePathElements: input.statePathElements.map(hex),
    statePathIndex: hex(input.statePathIndex),
    nullifierLowValue: hex(input.nullifierLowValue),
    nullifierNextValue: hex(input.nullifierNextValue),
    nullifierLowPathElements: input.nullifierLowPathElements.map(hex),
    nullifierLowPathIndex: hex(input.nullifierLowPathIndex),
    utxoTreeRoot: hex(input.utxoTreeRoot),
    nullifierTreeRoot: hex(input.nullifierTreeRoot),
    nullifier: hex(input.nullifier),
  });
}

function mergeOutputJson(output: TransferOutput): Readonly<Record<string, unknown>> {
  return Object.freeze({
    zoneDataHash: hex(circuitUtxo(output).zoneDataHash),
    hash: hex(output.hash),
  });
}

/** Mirrors Rust `AuditProofRequest::body`, key order included. */
export function customRingAuditRequest(
  inputs: AuditProofRequest,
): Readonly<Record<string, unknown>> {
  const auditorPublicKey = inputs.auditorPublicKey;
  if (
    !(auditorPublicKey instanceof Uint8Array) ||
    auditorPublicKey.length !== UNCOMPRESSED_P256_LENGTH ||
    auditorPublicKey[0] !== 0x04
  ) {
    throw new ClientError("CLIENT_INVALID_P256_KEY");
  }
  return Object.freeze({
    circuitType: "custom-ring-audit",
    variant: "transfer",
    publicInputHash: bytesHex(checkedBytes(inputs.publicInputHash, 32, "publicInputHash")),
    privateTxHash: bytesHex(checkedBytes(inputs.privateTxHash, 32, "privateTxHash")),
    txViewingSk: bytesHex(checkedBytes(inputs.txViewingSecret, 32, "txViewingSecret")),
    ephSk: bytesHex(checkedBytes(inputs.ephemeralSecret, 32, "ephemeralSecret")),
    auditorPk: bytesHex(auditorPublicKey),
  });
}

function proverRequest(inputs: ProverInputs): Readonly<Record<string, unknown>> {
  const payload = inputs.payload;
  return Object.freeze({
    circuitType: inputs.circuit === "transferRing" ? "transfer-ring" : "transfer-confidential",
    nInputs: payload.inputs.length,
    nOutputs: payload.outputs.length,
    inputs: payload.inputs.map(inputJson),
    outputs: payload.outputs.map(outputJson),
    externalDataHash: hex(payload.externalDataHash),
    privateTxHash: hex(payload.privateTxHash),
    publicAssets: payload.publicAssets.map(hex),
    publicAmounts: payload.publicAmounts.map(hex),
    ringProgramId: hex(payload.zoneProgramId),
    signerPkHashes: payload.signerPublicKeyHashes.map(hex),
    allowDummyInputs: hex(payload.allowDummyInputs),
    publishedOutputOwnerPkHashes: payload.publishedOutputOwnerPublicKeyHashes.map(hex),
    publicInputHash: hex(payload.publicInputHash),
  });
}

function inputJson(input: TransferInput): Readonly<Record<string, unknown>> {
  return Object.freeze({
    utxo: utxoJson(input),
    isDummy: hex(input.isDummy),
    statePathElements: input.statePathElements.map(hex),
    statePathIndex: hex(input.statePathIndex),
    nullifierLowValue: hex(input.nullifierLowValue),
    nullifierNextValue: hex(input.nullifierNextValue),
    nullifierLowPathElements: input.nullifierLowPathElements.map(hex),
    nullifierLowPathIndex: hex(input.nullifierLowPathIndex),
    utxoTreeRoot: hex(input.utxoTreeRoot),
    nullifierTreeRoot: hex(input.nullifierTreeRoot),
    nullifier: hex(input.nullifier),
    ownerPkHash: hex(input.ownerPublicKeyHash),
    nullifierSecret: hex(input.nullifierSecret),
  });
}

function outputJson(output: TransferOutput): Readonly<Record<string, unknown>> {
  return Object.freeze({
    utxo: utxoJson(output),
    isDummy: hex(output.isDummy),
    hash: hex(output.hash),
    ownerPkHash: hex(output.ownerPublicKeyHash),
    nullifierPk: hex(output.nullifierPublicKey),
  });
}

function utxoJson(value: object): Readonly<Record<string, unknown>> {
  const utxo = circuitUtxo(value);
  return Object.freeze({
    domain: hex(utxo.domain),
    owner: hex(utxo.owner),
    asset: hex(utxo.asset),
    amount: hex(utxo.amount),
    blinding: hex(utxo.blinding),
    dataHash: hex(utxo.dataHash),
    ringDataHash: hex(utxo.zoneDataHash),
    ringProgramId: hex(utxo.zoneProgramId),
  });
}

function hex(value: Field): string {
  return `0x${value.toString(16)}`;
}

function bytesHex(bytes: Uint8Array): string {
  return `0x${bytesToHex(bytes)}`;
}

async function decodeResponse(response: Response): Promise<unknown> {
  const length = response.headers.get("content-length");
  if (length !== null && /^\d+$/u.test(length) && Number(length) > MAX_RESPONSE_BYTES) {
    throw new ClientError("CLIENT_PROVER_RESPONSE_TOO_LARGE");
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length > MAX_RESPONSE_BYTES) {
    throw new ClientError("CLIENT_PROVER_RESPONSE_TOO_LARGE");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new ClientError("CLIENT_PROVER_TEXT");
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ClientError("CLIENT_PROVER_JSON");
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
