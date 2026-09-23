import { KEY_REGISTRY_CAPACITY, KEY_REGISTRY_HEIGHT } from "../../interface/key-registry.js";
import { RING_DEPOSIT_AUDIT_SLOTS } from "./types.js";
import { isCanonicalField } from "../../interface/canonical-field.js";
import { P256PublicKey } from "../../keypair/public-key.js";
import { ViewingKey } from "../../keypair/viewing-key.js";
import { INPUT_TREES, treeIdField, type TreeSlot } from "../../interface/tree-slot.js";
import { DUMMY_DOMAIN } from "../../interface/program.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { bytesToBigInt } from "../../keypair/bytes.js";
import { poseidon } from "../../keypair/poseidon.js";

import { InterfaceError } from "../../interface/errors.js";
import { wireDecoder } from "../../interface/decode.js";
import {
  PROVING_KEY_SHA256S,
  expectedProvingKey,
  type ExpectedProvingKey,
  type ProvingKeyCircuit,
} from "../../interface/proving-keys.js";
import type { Bytes32, RequestContext } from "../../interface/types.js";

import { ClientError } from "../error.js";
import {
  checkedBytes,
  checkedServiceUrl,
  composeSignal,
  requestError,
  sleep,
  type ComposedSignal,
} from "../internal.js";
import { TransportFailure, checkedFetch, readBoundedJson } from "../../services/transport.js";
import { parseCheckedProof } from "./proof.js";
import {
  RING_INLINE_ASSET_SLOTS,
  RING_INPUT_SLOTS,
  RING_NULLIFIER_PATH_LENGTH,
  RING_OUTPUT_SLOTS,
  RING_ANSWER_SLOTS,
  RING_RULE_SLOTS,
  RING_SOURCE_SLOTS,
  RING_STATE_PATH_LENGTH,
  RING_VELOCITY_SLOTS,
} from "./types.js";
import type {
  CustomRingBaseProofRequest,
  CustomRingDepositProofRequest,
  CustomRingOpening,
  CustomRingSourceOwner,
  CustomRingRuleAnswer,
  CustomRingPolicyProofRequest,
  CustomRingCompressedPolicyProofRequest,
  CustomRingRegistryInsertion,
  CustomRingRegisterKeyProofRequest,
  CustomRingRegistryKey,
  CustomRingSpendRecordProofInput,
  CustomRingVelocityRow,
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
const PROVING_KEYS_PATH = "/proving-keys";
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
    try {
      this.#fetch = checkedFetch(input.fetch);
    } catch (error) {
      if (!(error instanceof TransportFailure)) throw error;
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "fetch" } });
    }
    this.#url = url;
    this.#asyncPoll = asyncPollConfig(input.asyncPoll);
  }

  async prove(inputs: ProverInputs, context?: RequestContext): Promise<Proof> {
    const body = JSON.stringify(proverRequest(inputs, completeSecret));
    const key = provingKeyFor({
      circuit: inputs.circuit === "transferRing" ? "transfer-ring" : "transfer-confidential",
      nInputs: inputs.payload.inputs.length,
      nOutputs: inputs.payload.outputs.length,
    });
    return this.#send(body, "inResponse", key, context);
  }

  async proveMerge(inputs: MergeInputs, context?: RequestContext): Promise<Proof> {
    const body = JSON.stringify(mergeProverRequest(inputs, completeSecret));
    const key = provingKeyFor({ circuit: "merge", nInputs: inputs.inputs.length });
    return this.#send(body, "inResponse", key, context);
  }

  async proveCustomRingPolicy(
    inputs: CustomRingPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Proof> {
    const body = JSON.stringify(customRingPolicyProofRequest(inputs));
    const key = provingKeyFor({ circuit: "custom-ring-policy" });
    return this.#send(body, "queued", key, context);
  }

  async proveCustomRingCompressedPolicy(
    inputs: CustomRingCompressedPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Proof> {
    const body = JSON.stringify(customRingCompressedPolicyProofRequest(inputs));
    const key = provingKeyFor({ circuit: "custom-ring-compressed-policy" });
    return this.#send(body, "queued", key, context);
  }

  async proveCustomRingRegisterKey(
    inputs: CustomRingRegisterKeyProofRequest,
    context?: RequestContext,
  ): Promise<Proof> {
    const body = JSON.stringify(customRingRegisterKeyProofRequest(inputs));
    const key = provingKeyFor({ circuit: "custom-ring-register-key" });
    return this.#send(body, "queued", key, context);
  }

  async proveCustomRingDeposit(
    inputs: CustomRingDepositProofRequest,
    context?: RequestContext,
  ): Promise<Proof> {
    const body = JSON.stringify(customRingDepositProofRequest(inputs));
    const key = provingKeyFor({ circuit: "custom-ring-deposit" });
    return this.#send(body, "queued", key, context);
  }

  async proveCustomRingDelegatePolicy(
    inputs: CustomRingPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Proof> {
    if (inputs.velocity.windowIndex !== 0n || inputs.velocity.approvalRequired)
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
    const body = JSON.stringify({
      circuitType: "custom-ring-delegate-policy",
      policy: customRingPolicyProofRequest(inputs),
    });
    const key = provingKeyFor({ circuit: "custom-ring-delegate-policy" });
    return this.#send(body, "queued", key, context);
  }

  async proveCustomRingBase(
    inputs: CustomRingBaseProofRequest,
    context?: RequestContext,
  ): Promise<Proof> {
    const body = JSON.stringify(customRingBaseProofRequest(inputs));
    const key = provingKeyFor({ circuit: "custom-ring-base" });
    return this.#send(body, "queued", key, context);
  }

  /** The circuits the server serves. */
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
    const url = new URL(this.#url);
    url.pathname = url.pathname.replace(/\/prove$/u, PROVING_KEYS_PATH);
    const request = composeSignal(context, "provingKeys");
    try {
      let response: Response;
      try {
        response = await this.#fetch(url, { redirect: "error", signal: request.signal });
      } catch {
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
    delivery: Delivery,
    key: ExpectedProvingKey,
    context?: RequestContext,
  ): Promise<Proof> {
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
              return await this.#poll(value["jobId"], signal, key);
            }
            return parseCheckedProof(value, key);
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
  async #poll(jobId: string, signal: ComposedSignal, key: ExpectedProvingKey): Promise<Proof> {
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
            details: {
              method: "proveStatus",
              status: response.status,
              ...(await proverReason(response)),
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
          return parseCheckedProof(result, key);
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

const invalidProverKeys = (): ClientError => new ClientError("CLIENT_PROVER_JSON");
const proverKeysDecoder = wireDecoder(invalidProverKeys);
const SHA256_HEX = /^[0-9a-f]{64}$/u;

/** Strict decode of `GET /proving-keys`: any other shape is an error, not a skipped key. */
function decodeProverKeys(
  value: unknown,
): Readonly<{ prefix: string; keys: readonly ProverKeyStatus[] }> {
  const body = proverKeysDecoder.record(value, "$");
  const digest = (entry: Record<string, unknown>, field: string): string | null => {
    const raw = entry[field];
    if (raw === null) return null;
    const hex = proverKeysDecoder.string(raw, `$.keys[].${field}`);
    if (!SHA256_HEX.test(hex)) throw invalidProverKeys();
    return hex;
  };
  const keys = proverKeysDecoder.list(body["keys"], "$.keys").map((raw) => {
    const entry = proverKeysDecoder.record(raw, "$.keys[]");
    return Object.freeze({
      name: proverKeysDecoder.string(entry["name"], "$.keys[].name"),
      expectedSha256: digest(entry, "expectedSha256"),
      loadedSha256: digest(entry, "loadedSha256"),
      available: proverKeysDecoder.boolean(entry["available"], "$.keys[].available"),
    });
  });
  return Object.freeze({
    prefix: proverKeysDecoder.string(body["prefix"], "$.prefix"),
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
type SecretEncoder = (secret: Field | undefined) => string | null;

const completeSecret: SecretEncoder = (secret) => hex(requireSecret(secret));
const pendingSecret: SecretEncoder = (secret) => (secret === undefined ? null : hex(secret));

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

/** Mirrors Rust `MergeParametersJson`, key set included. */
function mergeProverRequest(inputs: MergeInputs, secret: SecretEncoder): ProverRequestBody {
  return Object.freeze({
    circuitType: BigInt(inputs.ringProgramId) === 0n ? "merge" : "merge-ring",
    inputs: inputs.inputs.map(mergeInputJson),
    output: mergeOutputJson(inputs.output),
    treeSlots: inputs.treeSlots.map(treeSlotJson),
    outputTreeId: hex(inputs.outputTreeId),
    asset: hex(inputs.output.circuit.asset),
    ownerPkHash: hex(inputs.ownerPublicKeyHash),
    userNullifierPk: hex(inputs.userNullifierPublicKey),
    userNullifierSecret: secret(inputs.userNullifierSecret),
    externalDataHash: hex(inputs.externalDataHash),
    privateTxHash: hex(inputs.privateTxHash),
    publicInputHash: hex(inputs.publicInputHash),
    allowDummyInputs: hex(inputs.allowDummyInputs),
    outputRingDataHash: hex(inputs.outputRingDataHash),
    ringProgramId: hex(inputs.ringProgramId),
  });
}

function mergeInputJson(input: TransferInput): Readonly<Record<string, unknown>> {
  const utxo = input.circuit;
  return Object.freeze({
    domain: hex(utxo.domain),
    amount: hex(utxo.amount),
    blinding: hex(utxo.blinding),
    ringDataHash: hex(utxo.ringDataHash),
    statePathElements: input.statePathElements.map(hex),
    statePathIndex: hex(input.statePathIndex),
    nullifierLowValue: hex(input.nullifierLowValue),
    nullifierNextValue: hex(input.nullifierNextValue),
    nullifierLowPathElements: input.nullifierLowPathElements.map(hex),
    nullifierLowPathIndex: hex(input.nullifierLowPathIndex),
    treeSlot: hex(input.treeSlot),
    nullifier: hex(input.nullifier),
  });
}

function mergeOutputJson(output: TransferOutput): Readonly<Record<string, unknown>> {
  return Object.freeze({
    ringDataHash: hex(output.circuit.ringDataHash),
    hash: hex(output.hash),
  });
}

/** Mirrors Rust `TreeSlotJson`. */
function treeSlotJson(slot: TreeSlotFields): Readonly<Record<string, unknown>> {
  return Object.freeze({
    id: hex(slot.id),
    utxoRoot: hex(slot.utxoRoot),
    nullifierRoot: hex(slot.nullifierRoot),
  });
}

/** Mirrors Rust `CustomRingBaseProofRequest::body`, key order included. */
export function customRingBaseProofRequest(
  inputs: CustomRingBaseProofRequest,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    circuitType: "custom-ring-base",
    publicInputHash: hex32(inputs.publicInputHash, "publicInputHash"),
    privateTxHash: hex32(inputs.privateTxHash, "privateTxHash"),
    txViewingSk: hex32(inputs.txViewingSecret, "txViewingSecret"),
    ephSk: hex32(inputs.ephemeralSecret, "ephemeralSecret"),
    auditorPk: auditorPkHex(inputs.auditorPublicKey),
    salt: bytesHex(inputs.salt),
    nOut: u8(inputs.nOut, "nOut"),
    outputs: sized(inputs.outputs, RING_OUTPUT_SLOTS, "outputs").map(auditOpeningJson),
  });
}

/** Mirrors Rust `CustomRingPolicyProofRequest::body`, key order included. */
export function customRingPolicyProofRequest(
  inputs: CustomRingPolicyProofRequest,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    circuitType: "custom-ring-policy",
    publicInputHash: hex32(inputs.publicInputHash, "publicInputHash"),
    privateTxHash: hex32(inputs.privateTxHash, "privateTxHash"),
    txViewingSk: hex32(inputs.txViewingSecret, "txViewingSecret"),
    ephSk: hex32(inputs.ephemeralSecret, "ephemeralSecret"),
    auditorPk: auditorPkHex(inputs.auditorPublicKey),
    salt: bytesHex(inputs.salt),
    nIn: u8(inputs.nIn, "nIn"),
    nOut: u8(inputs.nOut, "nOut"),
    inputs: sized(inputs.inputs, RING_INPUT_SLOTS, "inputs").map((opening) => {
      if (opening.key !== undefined) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
      return openingJson(opening);
    }),
    outputs: sized(inputs.outputs, RING_OUTPUT_SLOTS, "outputs").map(openingJson),
    addressChain: hex32(inputs.addressChain, "addressChain"),
    externalDataHash: hex32(inputs.externalDataHash, "externalDataHash"),
    privateTxBlinding: hex32(inputs.privateTxBlinding, "privateTxBlinding"),
    sources: sized(inputs.sources, RING_SOURCE_SLOTS, "sources").map(sourceJson),
    policyLen: u8(inputs.policyLen, "policyLen"),
    ruleEnc: sized(inputs.rules, RING_RULE_SLOTS, "rules").map((rule) => hex32(rule, "rules")),
    inlineAssets: sized(inputs.inlineAssets, RING_INLINE_ASSET_SLOTS, "inlineAssets").map((asset) =>
      hex32(asset, "inlineAssets"),
    ),
    inlineLimits: sized(inputs.inlineLimits, RING_INLINE_ASSET_SLOTS, "inlineLimits").map((limit) =>
      u64FieldHex(limit, "inlineLimits"),
    ),
    inlineCount: u8(inputs.inlineCount, "inlineCount"),
    treeSlots: policyTreeSlots(inputs.treeSlots).map(policyTreeSlotJson),
    addressTreeId: hex32(treeIdField(inputs.addressTreeId), "addressTreeId"),
    windowSlots: u64Json(inputs.velocity.windowSlots, "windowSlots"),
    velocity: paddedVelocityRows(inputs.velocity.rows).map(velocityRowJson),
    velocityCount: u8(inputs.velocity.rows.length, "velocityCount"),
    ringId: hex32(inputs.velocity.ringId, "ringId"),
    namespaceOwnerHash: hex32(inputs.velocity.namespaceOwnerHash, "namespaceOwnerHash"),
    windowIndex: u64Json(inputs.velocity.windowIndex, "windowIndex"),
    approvalRequired: inputs.velocity.approvalRequired,
    ...keyEscrowJson(inputs.keyRegistryRoot),
    record: spendRecordJson(inputs.velocity.record),
    answers: sized(inputs.answers, RING_ANSWER_SLOTS, "answers").map(answersJson),
  });
}

/** Mirrors Go `readTreeSlots`, the populated prefix of one to `INPUT_TREES` slots. */
function policyTreeSlots(slots: readonly TreeSlot[]): readonly TreeSlot[] {
  if (!Array.isArray(slots) || slots.length < 1 || slots.length > INPUT_TREES) {
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: {
        field: "treeSlots",
        expected: INPUT_TREES,
        actual: Array.isArray(slots) ? slots.length : 0,
      },
    });
  }
  return slots;
}

function policyTreeSlotJson(slot: TreeSlot): Readonly<Record<string, unknown>> {
  return Object.freeze({
    id: hex32(treeIdField(slot.id), "treeSlots id"),
    utxoRoot: hex32(slot.utxoRoot, "treeSlots utxoRoot"),
    nullifierRoot: hex32(slot.nullifierRoot, "treeSlots nullifierRoot"),
  });
}

/** Mirrors Go `readKeyEscrow`, the root is zero exactly when escrow is off. */
function keyEscrowJson(root: Bytes32 | undefined): Readonly<Record<string, unknown>> {
  return Object.freeze({
    keyEscrow: root !== undefined,
    keyRegistryRoot: hex32(root ?? new Uint8Array(32), "keyRegistryRoot"),
  });
}

/** Mirrors Go `writeRegistryKey`, `null` for an absent key. */
function registryKeyJson(
  key: CustomRingRegistryKey | undefined,
): Readonly<Record<string, unknown>> | null {
  if (key === undefined) return null;
  if (typeof key.index !== "bigint" || key.index < 0n || key.index >= KEY_REGISTRY_CAPACITY)
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field: "key index" } });
  return Object.freeze({
    next: hex32(key.next, "key next"),
    ctHash: hex32(key.ctHash, "key ctHash"),
    index: u64Json(key.index, "key index"),
    path: sized(key.path, KEY_REGISTRY_HEIGHT, "key path").map((node) => hex32(node, "key path")),
  });
}

function registryIndexHex(index: bigint, field: string): string {
  if (typeof index !== "bigint" || index < 0n || index >= KEY_REGISTRY_CAPACITY)
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field } });
  return `0x${index.toString(16).padStart(64, "0")}`;
}

export function customRingCompressedPolicyProofRequest(
  input: CustomRingCompressedPolicyProofRequest,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    circuitType: "custom-ring-compressed-policy",
    transactionSalt: bytesHex(checkedBytes(input.transactionSalt, 16, "transactionSalt")),
    policy: customRingPolicyProofRequest(input.policy),
  });
}

function registryInsertionJson(
  input: CustomRingRegistryInsertion,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    registryOldRoot: hex32(input.registryOldRoot, "registryOldRoot"),
    registryNewRoot: hex32(input.registryNewRoot, "registryNewRoot"),
    member: hex32(input.member, "member"),
    newIndex: registryIndexHex(input.newIndex, "newIndex"),
    lowIndex: registryIndexHex(input.lowIndex, "lowIndex"),
    lowMember: hex32(input.lowMember, "lowMember"),
    lowNext: hex32(input.lowNext, "lowNext"),
    lowKey: hex32(input.lowKey, "lowKey"),
    lowProof: sized(input.lowProof, KEY_REGISTRY_HEIGHT, "lowProof").map((node) =>
      hex32(node, "lowProof"),
    ),
    newProof: sized(input.newProof, KEY_REGISTRY_HEIGHT, "newProof").map((node) =>
      hex32(node, "newProof"),
    ),
  });
}

/** Mirrors Rust `RegisterKeyProofRequest::body`, the zero high byte keeps the secret below the field order. */
export function customRingRegisterKeyProofRequest(
  input: CustomRingRegisterKeyProofRequest,
): Readonly<Record<string, unknown>> {
  const nullifierSecret = checkedBytes(input.nullifierSecret, 32, "nullifierSecret");
  if (nullifierSecret[0] !== 0) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  return Object.freeze({
    circuitType: "custom-ring-register-key",
    publicInputHash: hex32(input.publicInputHash, "publicInputHash"),
    ...registryInsertionJson(input),
    nullifierSecret: bytesHex(nullifierSecret),
    ephSk: hex32(input.ephemeralSecret, "ephSk"),
    auditorPk: auditorPkHex(input.auditorPublicKey),
  });
}

export function customRingDepositProofRequest(
  input: CustomRingDepositProofRequest,
): Readonly<Record<string, unknown>> {
  const columns = [input.ownerPkHashes, input.nullifierPks, input.blindings];
  if (
    !Number.isInteger(input.count) ||
    input.count < 1 ||
    input.count > RING_DEPOSIT_AUDIT_SLOTS ||
    !Array.isArray(input.keys) ||
    input.keys.length !== RING_DEPOSIT_AUDIT_SLOTS ||
    columns.some((column) => !Array.isArray(column) || column.length !== RING_DEPOSIT_AUDIT_SLOTS)
  )
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  try {
    P256PublicKey.fromUncompressed(input.auditorPublicKey);
    ViewingKey.fromBytes(input.ephemeralSecret).destroy();
  } catch {
    throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  for (const field of [input.publicInputHash, input.contextHash, ...columns.flat()]) {
    if (!isCanonicalField(field)) throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  for (let index = input.count; index < RING_DEPOSIT_AUDIT_SLOTS; index++) {
    if (
      columns.some((column) => column[index]?.some((byte) => byte !== 0)) ||
      input.keys[index] !== undefined
    )
      throw new ClientError("CLIENT_INVALID_PROOF_INPUTS");
  }
  return Object.freeze({
    circuitType: "custom-ring-deposit",
    publicInputHash: hex32(input.publicInputHash, "publicInputHash"),
    contextHash: hex32(input.contextHash, "contextHash"),
    count: input.count,
    ownerPkHashes: input.ownerPkHashes.map((field) => hex32(field, "ownerPkHash")),
    nullifierPks: input.nullifierPks.map((field) => hex32(field, "nullifierPk")),
    blindings: input.blindings.map((field) => hex32(field, "blinding")),
    keys: input.keys.map(registryKeyJson),
    ephSk: hex32(input.ephemeralSecret, "ephSk"),
    auditorPk: auditorPkHex(input.auditorPublicKey),
    ...keyEscrowJson(input.keyRegistryRoot),
  });
}

/** Rows past the count are zero, the server refuses other padding. */
function paddedVelocityRows(
  rows: readonly CustomRingVelocityRow[],
): readonly CustomRingVelocityRow[] {
  if (rows.length > RING_VELOCITY_SLOTS) {
    throw new ClientError("CLIENT_INVALID_LENGTH", {
      details: { field: "velocity", expected: RING_VELOCITY_SLOTS, actual: rows.length },
    });
  }
  return Object.freeze(
    Array.from(
      { length: RING_VELOCITY_SLOTS },
      (_, index) =>
        rows[index] ?? { asset: new Uint8Array(32) as Bytes32, cap: 0n, cosignAbove: 0n },
    ),
  );
}

function velocityRowJson(row: CustomRingVelocityRow): Readonly<Record<string, unknown>> {
  return Object.freeze({
    asset: hex32(row.asset, "velocity asset"),
    cap: u64FieldHex(row.cap, "velocity cap"),
    cosignAbove: u64FieldHex(row.cosignAbove, "velocity cosignAbove"),
  });
}

function spendRecordJson(
  record: CustomRingSpendRecordProofInput,
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    version: u64Json(record.version, "record version"),
    window: u64Json(record.window, "record window"),
    commitment: hex32(record.commitment, "record commitment"),
    salt: hex32(record.salt, "record salt"),
    assets: sized(record.assets, RING_VELOCITY_SLOTS, "record assets").map((asset) =>
      hex32(asset, "record assets"),
    ),
    spent: sized(record.spent, RING_VELOCITY_SLOTS, "record spent").map((spent) =>
      u64FieldHex(spent, "record spent"),
    ),
    nextSalt: hex32(record.nextSalt, "record nextSalt"),
  });
}

function openingJson(opening: CustomRingOpening): Readonly<Record<string, unknown>> {
  return Object.freeze({
    domain: hex32(opening.domain, "domain"),
    treeId: hex32(opening.treeId, "treeId"),
    ownerPkHash: hex32(opening.ownerPkHash, "ownerPkHash"),
    nullifierPk: hex32(opening.nullifierPk, "nullifierPk"),
    asset: hex32(opening.asset, "asset"),
    amount: hex32(opening.amount, "amount"),
    blinding: hex32(opening.blinding, "blinding"),
    dataHash: hex32(opening.dataHash, "dataHash"),
    ringDataHash: hex32(opening.ringDataHash, "ringDataHash"),
    ringProgramId: hex32(opening.ringProgramId, "ringProgramId"),
    ...(opening.key === undefined ? {} : { key: registryKeyJson(opening.key) }),
  });
}

/** The base circuit needs the already-combined owner hash used by the SPP commitment. */
function auditOpeningJson(opening: CustomRingOpening): Readonly<Record<string, unknown>> {
  const domain = bytesToBigInt(opening.domain);
  const ownerHash =
    domain === 0n || domain === BigInt(DUMMY_DOMAIN)
      ? new Uint8Array(32)
      : poseidon([opening.ownerPkHash, opening.nullifierPk]);
  return Object.freeze({
    domain: hex32(opening.domain, "domain"),
    treeId: hex32(opening.treeId, "treeId"),
    ownerHash: hex32(ownerHash, "ownerHash"),
    asset: hex32(opening.asset, "asset"),
    amount: hex32(opening.amount, "amount"),
    blinding: hex32(opening.blinding, "blinding"),
    dataHash: hex32(opening.dataHash, "dataHash"),
    ringDataHash: hex32(opening.ringDataHash, "ringDataHash"),
    ringProgramId: hex32(opening.ringProgramId, "ringProgramId"),
  });
}

function sourceJson(source: CustomRingSourceOwner): Readonly<Record<string, unknown>> {
  return Object.freeze({
    listId: u8(source.listId, "listId"),
    ownerHash: hex32(source.ownerHash, "ownerHash"),
  });
}

function answersJson(entry: CustomRingRuleAnswer): Readonly<Record<string, unknown>> {
  return Object.freeze({
    enabled: entry.enabled,
    treeSlot: u8(entry.treeSlot, "treeSlot"),
    mode: u8(entry.mode, "mode"),
    listId: u8(entry.listId, "listId"),
    state: u8(entry.state, "state"),
    absentBranch: u8(entry.absentBranch, "absentBranch"),
    member: hex32(entry.member, "member"),
    contentHash: hex32(entry.contentHash, "contentHash"),
    version: u64Json(entry.version, "version"),
    blinding: hex32(entry.blinding, "blinding"),
    low: hex32(entry.low, "low"),
    next: hex32(entry.next, "next"),
    nfPathElements: sized(entry.nullifierPath, RING_NULLIFIER_PATH_LENGTH, "nullifierPath").map(
      (element) => hex32(element, "nullifierPath"),
    ),
    nfPathIndex: u64Json(entry.nullifierPathIndex, "nullifierPathIndex"),
    statePathElements: sized(entry.statePath, RING_STATE_PATH_LENGTH, "statePath").map((element) =>
      hex32(element, "statePath"),
    ),
    statePathIndex: u64Json(entry.statePathIndex, "statePathIndex"),
  });
}

/** Rust `field_hex`, the fixed-width hex the prover requires. */
function hex32(bytes: Uint8Array, field: string): string {
  return bytesHex(checkedBytes(bytes, 32, field));
}

/** The uncompressed SEC1 auditor point the circuit witnesses, `0x04 || x || y`. */
function auditorPkHex(auditorPublicKey: Uint8Array): string {
  if (
    !(auditorPublicKey instanceof Uint8Array) ||
    auditorPublicKey.length !== UNCOMPRESSED_P256_LENGTH ||
    auditorPublicKey[0] !== 0x04
  ) {
    throw new ClientError("CLIENT_INVALID_P256_KEY");
  }
  return bytesHex(auditorPublicKey);
}

function u8(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xff) {
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field } });
  }
  return value;
}

/** Rust emits `u64` as a JSON number, the value must stay a safe integer. */
function u64Json(value: bigint, field: string): number {
  if (typeof value !== "bigint" || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field } });
  }
  return Number(value);
}

function u64FieldHex(value: bigint, field: string): string {
  if (typeof value !== "bigint" || value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new ClientError("CLIENT_INVALID_INTEGER", { details: { field } });
  }
  return `0x${value.toString(16).padStart(64, "0")}`;
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
function proverRequest(inputs: ProverInputs, secret: SecretEncoder): ProverRequestBody {
  const payload = inputs.payload;
  return Object.freeze({
    circuitType:
      inputs.circuit === "transferRingAuthority"
        ? "transfer-ring-authority"
        : inputs.circuit === "transferRing"
          ? "transfer-ring"
          : "transfer-confidential",
    nInputs: payload.inputs.length,
    nOutputs: payload.outputs.length,
    inputs: payload.inputs.map((input) => inputJson(input, secret)),
    outputs: payload.outputs.map(outputJson),
    treeSlots: payload.treeSlots.map(treeSlotJson),
    outputTreeId: hex(payload.outputTreeId),
    externalDataHash: hex(payload.externalDataHash),
    privateTxHash: hex(payload.privateTxHash),
    blindingSeed: hex(payload.blindingSeed),
    publicAssets: payload.publicAssets.map(hex),
    publicAmounts: payload.publicAmounts.map(hex),
    ringProgramId: hex(payload.ringProgramId),
    signerPkHashes: payload.signerPublicKeyHashes.map(hex),
    inputFlags: hex(payload.inputFlags),
    publishedOutputOwnerPkHashes: payload.publishedOutputOwnerPublicKeyHashes.map(hex),
    publicInputHash: hex(payload.publicInputHash),
  });
}

function inputJson(input: TransferInput, secret: SecretEncoder): Readonly<Record<string, unknown>> {
  return Object.freeze({
    utxo: utxoJson(input),
    isDummy: hex(input.isDummy),
    statePathElements: input.statePathElements.map(hex),
    statePathIndex: hex(input.statePathIndex),
    nullifierLowValue: hex(input.nullifierLowValue),
    nullifierNextValue: hex(input.nullifierNextValue),
    nullifierLowPathElements: input.nullifierLowPathElements.map(hex),
    nullifierLowPathIndex: hex(input.nullifierLowPathIndex),
    treeSlot: hex(input.treeSlot),
    nullifier: hex(input.nullifier),
    ownerPkHash: hex(input.ownerPublicKeyHash),
    nullifierSecret: secret(input.nullifierSecret),
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

function utxoJson(value: TransferInput | TransferOutput): Readonly<Record<string, unknown>> {
  const utxo = value.circuit;
  return Object.freeze({
    domain: hex(utxo.domain),
    owner: hex(utxo.owner),
    asset: hex(utxo.asset),
    amount: hex(utxo.amount),
    blinding: hex(utxo.blinding),
    dataHash: hex(utxo.dataHash),
    ringDataHash: hex(utxo.ringDataHash),
    ringProgramId: hex(utxo.ringProgramId),
  });
}

/** Inputs reach the prover only complete; a missing secret is a `ProofAuthority` that did not run. */
function requireSecret(secret: Field | undefined): Field {
  if (secret === undefined) throw new ClientError("CLIENT_MISSING_NULLIFIER_SECRET");
  return secret;
}

function hex(value: Field): string {
  return `0x${value.toString(16)}`;
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
  let body: unknown;
  try {
    body = await readBoundedJson(response, MAX_REASON_BYTES);
  } catch {
    return {};
  }
  if (!isObject(body)) return {};
  const parts = [body["code"], body["message"]].filter(
    (part): part is string => typeof part === "string" && part.length > 0,
  );
  return parts.length === 0 ? {} : { reason: parts.join(": ").slice(0, MAX_REASON_CHARS) };
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
