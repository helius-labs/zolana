import type { RequestContext } from "@zolana/interface";

import { ClientError } from "../error.js";
import { composeSignal, requestError, sleep, type ComposedSignal } from "../internal.js";
import { circuitUtxo } from "./assembly.js";
import { parseProof } from "./proof.js";
import type {
  Field,
  MergeInputs,
  Proof,
  ProverInputs,
  TransferInput,
  TransferP256Inputs,
  ZoneProverInputs,
  TransferOutput,
} from "./types.js";

const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_ATTEMPTS = 3;
const RETRY_DELAY_MS = 2_000n;
/// Per-request bound, mirroring the Rust client's `PROVE_REQUEST_TIMEOUT_SECS`.
/// Generous enough for a cold prove that first loads a 63MB proving key, so a
/// clean server-side timeout still returns before it.
const REQUEST_TIMEOUT_MS = 600_000;
/// Floor on the status-poll interval so a misconfigured client cannot spin.
const MIN_POLL_INTERVAL_MS = 1_000;
const PROVE_MERGE = Symbol("proveMerge");
const PROVE_MERGE_ZONE = Symbol("proveMergeZone");

export const SERVER_ADDRESS = "http://127.0.0.1:3001";
export const PROVE_PATH = "/prove";

/// Polling cadence and ceiling for queued (async) proofs. A Redis-backed prover
/// returns a job handle instead of a proof, and the client polls
/// `/prove/status` until it completes.
export interface AsyncPollConfig {
  readonly pollIntervalMs: number;
  readonly maxWaitMs: number;
}

export const DEFAULT_ASYNC_POLL_CONFIG: AsyncPollConfig = Object.freeze({
  pollIntervalMs: 3_000,
  maxWaitMs: 1_200_000,
});

export class ProverClient {
  readonly #fetch: typeof globalThis.fetch;
  readonly #url: URL;
  readonly #asyncPoll: AsyncPollConfig;

  constructor(
    input: Readonly<{
      url: URL | string;
      fetch?: typeof globalThis.fetch;
      asyncPoll?: AsyncPollConfig;
    }>,
  ) {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_CONFIG");
    }
    let url: URL;
    try {
      url = new URL(input.url instanceof URL ? input.url.href : input.url);
    } catch {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "url" } });
    }
    if (
      (url.protocol !== "http:" && url.protocol !== "https:") ||
      url.username !== "" ||
      url.password !== "" ||
      url.hash !== ""
    ) {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "url" } });
    }
    url.pathname = `${url.pathname.replace(/\/+$/u, "")}${PROVE_PATH}`;
    const fetchImplementation = input.fetch ?? globalThis.fetch;
    if (typeof fetchImplementation !== "function") {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "fetch" } });
    }
    this.#url = url;
    this.#fetch = fetchImplementation;
    this.#asyncPoll = asyncPollConfig(input.asyncPoll);
  }

  /// Client for the prover at [`SERVER_ADDRESS`]. Rust's counterpart resolves
  /// `ZOLANA_PROVER_URL` here; this package is browser-compatible and so reads
  /// no environment. Node callers who need the offset-aware URL take it from
  /// `@zolana/test-kit`'s `localStackUrls` and pass it to the constructor.
  static local(
    input?: Readonly<{ fetch?: typeof globalThis.fetch; asyncPoll?: AsyncPollConfig }>,
  ): ProverClient {
    return new ProverClient({ ...input, url: SERVER_ADDRESS });
  }

  async prove(inputs: ProverInputs | ZoneProverInputs, context?: RequestContext): Promise<Proof> {
    return this.#send(JSON.stringify(proverRequest(inputs)), committed(inputs), context);
  }

  async [PROVE_MERGE](inputs: MergeInputs, context?: RequestContext): Promise<Proof> {
    return this.#send(JSON.stringify(mergeProverRequest(inputs)), true, context);
  }

  async [PROVE_MERGE_ZONE](inputs: MergeInputs, context?: RequestContext): Promise<Proof> {
    return this.#send(JSON.stringify(mergeProverRequest(inputs, "merge-zone")), true, context);
  }

  async #send(body: string, p256: boolean, context?: RequestContext): Promise<Proof> {
    const signal = composeSignal(context, "prove");
    try {
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
              headers: { "content-type": "application/json" },
              body,
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
            typeof value["job_id"] === "string" &&
            value["proof"] === undefined
          ) {
            return await this.#poll(value["job_id"], p256, signal);
          }
          return parseProof(value, p256);
        } finally {
          request.cleanup();
        }
      }
      throw new ClientError("CLIENT_PROVER_REQUEST", {
        details: { method: "prove", attempts: MAX_ATTEMPTS },
      });
    } finally {
      signal.cleanup();
    }
  }

  /// Mirrors `poll_async`: request the status, then wait between attempts, with
  /// the total sleep bounded by `maxWaitMs`. A 4xx is final, a 5xx or a
  /// transport failure is transient, and every other status has its body read.
  async #poll(jobId: string, p256: boolean, signal: ComposedSignal): Promise<Proof> {
    if (!/^[A-Za-z0-9_-]{1,256}$/u.test(jobId)) {
      throw new ClientError("CLIENT_PROVER_JOB", { details: { method: "prove" } });
    }
    const url = new URL(this.#url);
    url.pathname = url.pathname.replace(/\/prove$/u, "/prove/status");
    url.searchParams.set("job_id", jobId);
    const interval = Math.max(MIN_POLL_INTERVAL_MS, this.#asyncPoll.pollIntervalMs);
    const maxWaitMs = this.#asyncPoll.maxWaitMs;
    let waitedMs = 0;
    const waitOrTimeout = async (): Promise<void> => {
      if (waitedMs >= maxWaitMs) {
        throw new ClientError("CLIENT_PROVER_TIMEOUT", {
          details: { method: "proveStatus", jobId, timeoutMs: maxWaitMs },
        });
      }
      const sleepMs = Math.min(interval, maxWaitMs - waitedMs);
      await sleep(BigInt(sleepMs), { signal: signal.signal });
      waitedMs += sleepMs;
    };
    for (;;) {
      // The Rust status GET inherits the shared client's request timeout, so a
      // server that accepts the connection and never answers is a transport
      // failure there. Without a bound here the same server hangs the poll
      // past `maxWaitMs` forever.
      const request = composeSignal(
        { signal: signal.signal, timeoutMs: REQUEST_TIMEOUT_MS },
        "proveStatus",
      );
      let response: Response;
      try {
        try {
          response = await this.#fetch(url, { signal: request.signal });
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
          return parseProof(result, p256);
        }
        // queued / processing / pending / unknown: keep polling until the bound.
        await waitOrTimeout();
      } finally {
        request.cleanup();
      }
    }
  }
}

export function proveMerge(
  client: ProverClient,
  inputs: MergeInputs,
  context?: RequestContext,
): Promise<Proof> {
  return client[PROVE_MERGE](inputs, context);
}

export function proveMergeZone(
  client: ProverClient,
  inputs: MergeInputs,
  context?: RequestContext,
): Promise<Proof> {
  return client[PROVE_MERGE_ZONE](inputs, context);
}

export function mergeProverRequest(
  inputs: MergeInputs,
  circuitType: "merge" | "merge-zone" = "merge",
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    circuitType,
    inputs: inputs.inputs.map(inputJson),
    output: outputJson(inputs.output),
    p256PubX: hex(inputs.p256PublicKeyX),
    p256PubY: hex(inputs.p256PublicKeyY),
    ownerPkHash: hex(inputs.ownerPublicKeyHash),
    userNullifierPk: hex(inputs.userNullifierPublicKey),
    userNullifierSecret: hex(inputs.userNullifierSecret),
    txViewingSk: hex(inputs.txViewingSecret),
    userViewingPubkey: inputs.userViewingPublicKey.map(hex),
    externalDataHash: hex(inputs.externalDataHash),
    privateTxHash: hex(inputs.privateTxHash),
    publicInputHash: hex(inputs.publicInputHash),
    zoneProgramId: hex(inputs.zoneProgramId),
  });
}

/// The prover server's `circuitType` per rail. Rust reaches the same five
/// strings through `to_json`, `to_json_p256`, `to_json_zone`, `to_json_p256_zone`
/// and `to_json_zone_authority`, all of which share one request shape and differ
/// only here and in the embedded `publicInputHash`.
const CIRCUIT_TYPES = Object.freeze({
  transfer: "transfer-confidential",
  transferP256: "transfer-p256-confidential",
  transferZone: "transfer-zone",
  transferP256Zone: "transfer-p256-zone",
  transferZoneAuthority: "transfer-zone-authority",
} as const);

/// The P256 rails carry a BSB22 commitment; the ed25519 rails, including the
/// zone authority, are standard Groth16 with A, B, and C only.
function committed(inputs: ProverInputs | ZoneProverInputs): inputs is Readonly<{
  circuit: "transferP256" | "transferP256Zone";
  payload: TransferP256Inputs;
}> {
  return inputs.circuit === "transferP256" || inputs.circuit === "transferP256Zone";
}

export function proverRequest(
  inputs: ProverInputs | ZoneProverInputs,
): Readonly<Record<string, unknown>> {
  const payload = inputs.payload;
  const head = {
    circuitType: CIRCUIT_TYPES[inputs.circuit],
    nInputs: payload.inputs.length,
    nOutputs: payload.outputs.length,
    inputs: payload.inputs.map(inputJson),
    outputs: payload.outputs.map(outputJson),
    externalDataHash: hex(payload.externalDataHash),
  };
  const tail = {
    publicSolAmount: hex(payload.publicSolAmount),
    publicSplAmount: hex(payload.publicSplAmount),
    publicSplAssetPubkey: hex(payload.publicSplAssetPublicKey),
    zoneProgramId: hex(payload.zoneProgramId),
    payerPubkeyHash: hex(payload.payerPublicKeyHash),
  };
  // The key order follows the Rust request structs so the two serializers
  // produce the same bytes, not merely the same object. On the P256 rails the
  // signature fields sit between `externalDataHash` and `privateTxHash`, and
  // `p256SigningPkField` between `payerPubkeyHash` and `publicInputHash`.
  if (!committed(inputs)) {
    return Object.freeze({
      ...head,
      privateTxHash: hex(payload.privateTxHash),
      ...tail,
      publicInputHash: hex(payload.publicInputHash),
    });
  }
  return Object.freeze({
    ...head,
    p256PubX: hex(inputs.payload.p256PublicKeyX),
    p256PubY: hex(inputs.payload.p256PublicKeyY),
    p256SigR: hex(inputs.payload.p256SignatureR),
    p256SigS: hex(inputs.payload.p256SignatureS),
    privateTxHash: hex(payload.privateTxHash),
    p256MessageHashLow: hex(inputs.payload.p256MessageHashLow),
    p256MessageHashHigh: hex(inputs.payload.p256MessageHashHigh),
    ...tail,
    p256SigningPkField: hex(inputs.payload.p256SigningPublicKeyField),
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
    zoneDataHash: hex(utxo.zoneDataHash),
    zoneProgramId: hex(utxo.zoneProgramId),
  });
}

function hex(value: Field): string {
  return `0x${value.toString(16)}`;
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
  for (const field of ["pollIntervalMs", "maxWaitMs"] as const) {
    const value = input[field];
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new ClientError("CLIENT_INVALID_POLL_CONFIG", { details: { field } });
    }
  }
  return Object.freeze({ pollIntervalMs: input.pollIntervalMs, maxWaitMs: input.maxWaitMs });
}