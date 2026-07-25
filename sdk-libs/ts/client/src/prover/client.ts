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
  TransferOutput,
} from "./types.js";

const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_ATTEMPTS = 3;
const RETRY_DELAY_MS = 2_000n;
const MAX_POLL_MS = 1_200_000;
const PROVE_MERGE = Symbol("proveMerge");
const PROVE_MERGE_ZONE = Symbol("proveMergeZone");

export class ProverClient {
  readonly #fetch: typeof globalThis.fetch;
  readonly #url: URL;

  constructor(input: Readonly<{ url: URL | string; fetch?: typeof globalThis.fetch }>) {
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
    url.pathname = `${url.pathname.replace(/\/+$/u, "")}/prove`;
    const fetchImplementation = input.fetch ?? globalThis.fetch;
    if (typeof fetchImplementation !== "function") {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "fetch" } });
    }
    this.#url = url;
    this.#fetch = fetchImplementation;
  }

  async prove(inputs: ProverInputs, context?: RequestContext): Promise<Proof> {
    return this.#send(
      JSON.stringify(proverRequest(inputs)),
      inputs.circuit === "transferP256",
      context,
    );
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
      let lastStatus: number | undefined;
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        if (attempt > 1) await sleep(RETRY_DELAY_MS, { signal: signal.signal });
        let response: Response;
        try {
          response = await this.#fetch(this.#url, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body,
            signal: signal.signal,
          });
        } catch {
          if (signal.signal.aborted) throw requestError("prove", signal);
          if (attempt < MAX_ATTEMPTS) continue;
          throw new ClientError("CLIENT_PROVER_REQUEST", {
            details: { method: "prove", attempts: attempt },
          });
        }
        lastStatus = response.status;
        if (!response.ok) {
          if (retryableStatus(response.status) && attempt < MAX_ATTEMPTS) continue;
          throw new ClientError("CLIENT_PROVER_HTTP", {
            details: { method: "prove", status: response.status, attempts: attempt },
          });
        }
        let value: unknown;
        try {
          value = await decodeResponse(response);
        } catch (error) {
          if (signal.signal.aborted) throw requestError("prove", signal);
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
      }
      throw new ClientError("CLIENT_PROVER_HTTP", {
        details: {
          method: "prove",
          ...(lastStatus === undefined ? {} : { status: lastStatus }),
          attempts: MAX_ATTEMPTS,
        },
      });
    } finally {
      signal.cleanup();
    }
  }

  async #poll(jobId: string, p256: boolean, signal: ComposedSignal): Promise<Proof> {
    if (!/^[A-Za-z0-9_-]{1,256}$/u.test(jobId)) {
      throw new ClientError("CLIENT_PROVER_JOB", { details: { method: "prove" } });
    }
    const url = new URL(this.#url);
    url.pathname = url.pathname.replace(/\/prove$/u, "/prove/status");
    url.searchParams.set("job_id", jobId);
    const started = Date.now();
    for (;;) {
      if (Date.now() - started >= MAX_POLL_MS) {
        throw new ClientError("CLIENT_PROVER_TIMEOUT", {
          details: { method: "proveStatus", jobId, timeoutMs: MAX_POLL_MS },
        });
      }
      await sleep(3_000n, { signal: signal.signal });
      let response: Response;
      try {
        response = await this.#fetch(url, { signal: signal.signal });
      } catch {
        if (signal.signal.aborted) throw requestError("prove", signal);
        continue;
      }
      if (!response.ok) {
        if (retryableStatus(response.status)) continue;
        throw new ClientError("CLIENT_PROVER_HTTP", {
          details: { method: "proveStatus", status: response.status },
        });
      }
      let value: unknown;
      try {
        value = await decodeResponse(response);
      } catch (error) {
        if (signal.signal.aborted) throw requestError("prove", signal);
        throw error;
      }
      const status = isObject(value) ? value["status"] : undefined;
      if (status === "pending" || status === "processing" || status === "queued") continue;
      if (status === "failed") {
        throw new ClientError("CLIENT_PROVER_SERVER", {
          details: { method: "proveStatus", status: "failed" },
        });
      }
      if (status === "completed") {
        const result = isObject(value) && isObject(value["result"]) ? value["result"] : value;
        return parseProof(result, p256);
      }
      continue;
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

export function proverRequest(inputs: ProverInputs): Readonly<Record<string, unknown>> {
  const payload = inputs.payload;
  const common = {
    circuitType:
      inputs.circuit === "transferP256" ? "transfer-p256-confidential" : "transfer-confidential",
    nInputs: payload.inputs.length,
    nOutputs: payload.outputs.length,
    inputs: payload.inputs.map(inputJson),
    outputs: payload.outputs.map(outputJson),
    externalDataHash: hex(payload.externalDataHash),
    privateTxHash: hex(payload.privateTxHash),
    publicSolAmount: hex(payload.publicSolAmount),
    publicSplAmount: hex(payload.publicSplAmount),
    publicSplAssetPubkey: hex(payload.publicSplAssetPublicKey),
    zoneProgramId: hex(payload.zoneProgramId),
    payerPubkeyHash: hex(payload.payerPublicKeyHash),
    publicInputHash: hex(payload.publicInputHash),
  };
  if (inputs.circuit === "transfer") return Object.freeze(common);
  return Object.freeze({
    ...common,
    p256PubX: hex(inputs.payload.p256PublicKeyX),
    p256PubY: hex(inputs.payload.p256PublicKeyY),
    p256SigR: hex(inputs.payload.p256SignatureR),
    p256SigS: hex(inputs.payload.p256SignatureS),
    p256MessageHashLow: hex(inputs.payload.p256MessageHashLow),
    p256MessageHashHigh: hex(inputs.payload.p256MessageHashHigh),
    p256SigningPkField: hex(inputs.payload.p256SigningPublicKeyField),
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

function retryableStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}
