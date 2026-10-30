import { bytesToHex } from "@noble/hashes/utils.js";
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

import { InterfaceError } from "../../interface/errors.js";
import { wireDecoder } from "../../interface/decode.js";
import {
  PROVING_KEY_SHA256S,
  expectedProvingKey,
  type ExpectedProvingKey,
  type ProvingKeyCircuit,
} from "../../interface/proving-keys.js";
import type { RequestContext } from "../../interface/types.js";

import { ClientError } from "../error.js";
import {
  field,
  checkedBytes,
  checkedServiceUrl,
  composeSignal,
  requestError,
  sleep,
  type ComposedSignal,
} from "../internal.js";
import {
  TransportFailure,
  checkedApiKey,
  checkedFetch,
  isLoopbackHost,
  readBoundedJson,
  servicePath,
  serviceUrl,
  setUrlQuery,
} from "../../services/transport.js";
import { parseCheckedProof } from "./proof.js";
import { MAX_ATTEMPTS, RETRY_DELAY_MS } from "./retry.js";
import type { ProverTee } from "./tee/source.js";
import { TeeSession, sendCall, type ProverCall } from "./tee/session.js";
import type { AttestedProver } from "./tee/verify.js";
import type {
  EddsaOwnerAuthorization,
  Field,
  MergeInputs,
  Proof,
  ProverInputs,
  TransferInput,
  TransferOutput,
  TreeSlotFields,
} from "./types.js";
import { isObject } from "../../services/jsonrpc.js";

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
/** Maps an indexed refusal body to the caller's error, `undefined` keeps the prover's own. */
export type ProverRefusal = (body: Readonly<Record<string, unknown>>) => Error | undefined;

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

/** A published serialization of a proving key. */
export interface ProvingKeyArtifact {
  readonly format: "gnark" | "zopro";
  /** SHA-256 of the exact downloaded bytes. */
  readonly sha256: string;
  readonly size: number;
  readonly url: string;
}

/** A key and its published downloads. */
export interface ProvingKeyCheck {
  readonly name: string;
  readonly artifacts: readonly ProvingKeyArtifact[];
}

/** A catalog whose gnark digests match the client's known verifying-key pins. */
export interface ProvingKeyReport {
  readonly keys: readonly ProvingKeyCheck[];
}

export class ProverClient {
  readonly #fetch: typeof globalThis.fetch;
  readonly #url: URL;
  readonly #apiKey: string | undefined;
  readonly #asyncPoll: AsyncPollConfig;
  readonly #tee: TeeSession | undefined;
  readonly #requiresTee: boolean;

  constructor(
    input: Readonly<{
      url: URL | string;
      fetch?: typeof globalThis.fetch;
      asyncPoll?: AsyncPollConfig;
      /** See `ZolanaClientConfig.allowInsecureHttp`. */
      allowInsecureHttp?: boolean;
      /**
       * Encrypts every call, health and key checks included, to a prover that
       * attests to the supplied policy. Required for every remote prover.
       */
      tee?: ProverTee;
    }>,
  ) {
    const candidate: unknown = input;
    if (typeof candidate !== "object" || candidate === null) {
      throw new ClientError("CLIENT_INVALID_CONFIG");
    }
    const url = checkedServiceUrl(input.url, "url", input.allowInsecureHttp ?? false);
    try {
      const keyed = checkedApiKey(url, undefined);
      this.#url = keyed.endpoint;
      this.#apiKey = keyed.apiKey;
      this.#fetch = checkedFetch(input.fetch);
    } catch (error) {
      if (!(error instanceof TransportFailure)) throw error;
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: error.facts });
    }
    this.#asyncPoll = asyncPollConfig(input.asyncPoll);
    this.#requiresTee = !isLoopbackHost(url.hostname);
    this.#tee = input.tee === undefined ? undefined : new TeeSession(input.tee);
  }

  /** Attests the prover now against the `tee` policy. */
  async attest(context?: RequestContext): Promise<AttestedProver> {
    if (this.#tee === undefined) {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "tee" } });
    }
    const request = composeSignal(context, "attest");
    try {
      return await this.#tee.attest(this.#fetch, this.#routeUrl(ATTESTATION_PATH), request);
    } finally {
      request.cleanup();
    }
  }

  #routeUrl(path: string): URL {
    return serviceUrl(this.#url, path, this.#apiKey);
  }

  #call(
    url: URL,
    signal: ComposedSignal,
    post?: Readonly<{ headers: Readonly<Record<string, string>>; body: string }>,
  ): ProverCall {
    if (this.#requiresTee && this.#tee === undefined) {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "tee" } });
    }
    return {
      fetch: this.#fetch,
      attestationUrl: this.#routeUrl(ATTESTATION_PATH),
      url,
      route: servicePath(this.#url, url),
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
    return parseCheckedProof(await this.send(body, "sync", key, context), key);
  }

  async proveMerge(inputs: MergeInputs, context?: RequestContext): Promise<Proof> {
    const body = JSON.stringify(mergeProverRequest(inputs, completeSecret));
    const key = provingKeyFor({ circuit: mergeCircuit(inputs), nInputs: inputs.inputs.length });
    return parseCheckedProof(await this.send(body, "sync", key, context), key);
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
    const result = parseIndexedResponse(await this.send(body, "indexed", key, context), key);
    resolvedTrees(inputs, result.resolution);
    return result;
  }

  /** The circuits the server serves. */
  async health(context?: RequestContext): Promise<ProverHealth> {
    const url = this.#routeUrl(HEALTH_PATH);
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
   * Compare the prover's proving keys (`GET /proving-keys`) with `pins`, by
   * default the proving-key sha256 each committed verifying key pins, so a
   * prover on another key set fails before the first proof instead of on-chain. A
   * differing gnark digest throws `CLIENT_PROVER_PROVING_KEYS_MISMATCH` naming
   * every such key. The returned catalog includes download URLs and artifact
   * checksums; a key absent from the manifest remains absent.
   */
  async checkProvingKeys(
    context?: RequestContext,
    pins: Readonly<Record<string, string>> = PROVING_KEY_SHA256S,
  ): Promise<ProvingKeyReport> {
    const url = this.#routeUrl(PROVING_KEYS_PATH);
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
      return checkProverKeys(decodeProverKeys(await decodeResponse(response)), pins);
    } finally {
      request.cleanup();
    }
  }

  async send(
    body: string,
    route: Route,
    key: ExpectedProvingKey,
    context?: RequestContext,
    refusal?: ProverRefusal,
  ): Promise<unknown> {
    const url = this.#keyUrl(key, route === "indexed" ? INDEXED_PATH : "");
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
              if (route === "indexed") throw await indexedHttpFailure(response, attempt, refusal);
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
              return await this.#poll(value["jobId"], signal, route, key, refusal);
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
   */
  #keyUrl(key: ExpectedProvingKey, suffix = ""): URL {
    const path = `${PROVE_PATH}/${encodeURIComponent(key.name.replace(/\.key$/u, ""))}`;
    return this.#routeUrl(`${path}${suffix}`);
  }

  async #poll(
    jobId: string,
    signal: ComposedSignal,
    route: Route,
    key: ExpectedProvingKey,
    refusal: ProverRefusal | undefined,
  ): Promise<unknown> {
    if (!/^[A-Za-z0-9_-]{1,256}$/u.test(jobId)) {
      throw new ClientError("CLIENT_PROVER_JOB", { details: { method: "prove" } });
    }
    const url = this.#keyUrl(key, STATUS_PATH);
    setUrlQuery(url, "jobId", jobId);
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
            (route === "indexed" ? indexedFailure(value, refusal) : undefined) ??
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

const invalidProverJson = (): ClientError => new ClientError("CLIENT_PROVER_JSON");
const proverJsonDecoder = wireDecoder(invalidProverJson);
/** Decode the catalog's field types; downloads retain their supplied metadata. */
function decodeProverKeys(value: unknown): ProvingKeyReport {
  const body = proverJsonDecoder.record(value, "$");
  const keys = proverJsonDecoder.list(body["keys"], "$.keys").map((raw) => {
    const entry = proverJsonDecoder.record(raw, "$.keys[]");
    const name = proverJsonDecoder.string(entry["name"], "$.keys[].name");
    const artifacts = proverJsonDecoder
      .list(entry["artifacts"], "$.keys[].artifacts")
      .map((rawArtifact): ProvingKeyArtifact => {
        const artifact = proverJsonDecoder.record(rawArtifact, "$.keys[].artifacts[]");
        const format = proverJsonDecoder.string(artifact["format"], "$.artifacts[].format");
        if (format !== "gnark" && format !== "zopro") throw invalidProverJson();
        const size = artifact["size"];
        if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0) {
          throw invalidProverJson();
        }
        return Object.freeze({
          format,
          sha256: proverJsonDecoder.string(artifact["sha256"], "$.artifacts[].sha256"),
          size,
          url: proverJsonDecoder.string(artifact["url"], "$.artifacts[].url"),
        });
      });
    return Object.freeze({ name, artifacts: Object.freeze(artifacts) });
  });
  return Object.freeze({ keys: Object.freeze(keys) });
}

/** Compare the original gnark artifact with the verifying key's pin. */
function checkProverKeys(
  prover: ProvingKeyReport,
  pins: Readonly<Record<string, string>>,
): ProvingKeyReport {
  const mismatched: string[] = [];
  for (const key of prover.keys) {
    if (!Object.hasOwn(pins, key.name)) continue;
    const gnark = key.artifacts.filter((artifact) => artifact.format === "gnark");
    if (gnark.length !== 1) throw invalidProverJson();
    if (gnark[0]?.sha256 !== pins[key.name]) mismatched.push(key.name);
  }
  if (mismatched.length > 0) {
    throw new ClientError("CLIENT_PROVER_PROVING_KEYS_MISMATCH", {
      details: { keyNames: mismatched.join(",") },
    });
  }
  return prover;
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
  const circuitType = mergeCircuit(inputs);
  return Object.freeze({
    circuitType,
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
    // The merge-ring circuit binds no ciphertext, and the prover refuses a
    // salt on a merge-ring request.
    ...(circuitType === "merge"
      ? { outputCiphertextSalt: hex(inputs.outputCiphertextSalt, "outputCiphertextSalt") }
      : {}),
    ownerPkHash: hex(inputs.ownerPublicKeyHash, "ownerPkHash"),
    userNullifierPk: hex(inputs.userNullifierPublicKey, "userNullifierPk"),
    userNullifierSecret: secret(inputs.userNullifierSecret, "userNullifierSecret"),
    externalDataHash: hex(inputs.externalDataHash, "externalDataHash"),
    privateTxHash: hex(inputs.privateTxHash, "privateTxHash"),
    allowDummyInputs: hex(inputs.allowDummyInputs, "allowDummyInputs"),
    outputRingDataHash: hex(inputs.outputRingDataHash, "outputRingDataHash"),
    ringProgramId: hex(inputs.ringProgramId, "ringProgramId"),
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

type TransferRequest = ProverInputs | Exclude<IndexedProofInputs, { circuit: "merge" }>;

/** The prover circuit a transfer is proven by. */
function transferCircuit(
  inputs: TransferRequest,
):
  | "transfer-ring-authority"
  | "transfer-ring"
  | "transfer-confidential-eddsa"
  | "transfer-confidential" {
  switch (inputs.circuit) {
    case "transferRingAuthority":
      return "transfer-ring-authority";
    case "transferRing":
      return "transfer-ring";
    case "transferConfidentialEddsa":
      return "transfer-confidential-eddsa";
    case "transfer":
      return "transfer-confidential";
  }
}

/**
 * The owner fields of the prover's `ConfidentialEddsaTransferParametersJSON`:
 * the key and signature as 0x-hex bytes, the digest split into its high and
 * low 16-byte limbs, each a field element, as Rust `EddsaAuthorization::fields`.
 */
function ownerAuthorizationJson(authorization: EddsaOwnerAuthorization): ProverRequestBody {
  const digest = checkedBytes(authorization.messageDigest, 32, "messageDigest");
  return Object.freeze({
    ownerPublicKey: `0x${bytesToHex(checkedBytes(authorization.ownerPublicKey, 32, "ownerPublicKey"))}`,
    ownerSignature: `0x${bytesToHex(checkedBytes(authorization.ownerSignature, 64, "ownerSignature"))}`,
    messageHashLow: `0x${bytesToHex(digest.subarray(16))}`,
    messageHashHigh: `0x${bytesToHex(digest.subarray(0, 16))}`,
  });
}

/** Mirrors Rust `TransferInputsJson`, key set and order included. */
function proverRequest(inputs: TransferRequest, secret: SecretEncoder): ProverRequestBody {
  const payload = inputs.payload;
  return Object.freeze({
    circuitType: transferCircuit(inputs),
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
    ...(inputs.circuit === "transferConfidentialEddsa"
      ? ownerAuthorizationJson(inputs.payload.ownerAuthorization)
      : {}),
  });
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
async function indexedHttpFailure(
  response: Response,
  attempt: number,
  refusal: ProverRefusal | undefined,
): Promise<Error> {
  const body = await errorBody(response);
  const typed = indexedFailure(body, refusal);
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

function indexedFailure(body: unknown, refusal: ProverRefusal | undefined): Error | undefined {
  if (!isObject(body)) return undefined;
  const refused = refusal?.(body);
  if (refused !== undefined) return refused;
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
