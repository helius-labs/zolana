import { bytesToHex, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { TransportFailure, readBoundedBody, readBoundedJson } from "../../../services/transport.js";
import { ClientError } from "../../error.js";
import { requestError, type ComposedSignal } from "../../internal.js";
import {
  HEADER_ENC,
  HEADER_SEAL,
  HEADER_VERSION,
  RESPONSE_NONCE_SIZE,
  VERSION,
  sealRequest,
  type SealedRequest,
} from "./seal.js";
import { checkedTeePolicy, type TeePolicy } from "./policy.js";
import { verifyAttestation, type AttestedProver } from "./verify.js";

const NONCE_SIZE = 32;
const MAX_ATTESTATION_BYTES = 1024 * 1024;
const GCM_TAG_SIZE = 16;
const STATUS_SIZE = 2;

/** One prover HTTP call before it is sent. */
export type ProverCall = Readonly<{
  fetch: typeof globalThis.fetch;
  attestationUrl: URL;
  url: URL;
  method: "GET" | "POST";
  headers: Readonly<Record<string, string>>;
  body?: string;
  signal: ComposedSignal;
  maxResponseBytes: number;
}>;

/** A call as sent, and how its answer is read back. */
export type PreparedCall = Readonly<{
  init: RequestInit;
  open(response: Response): Promise<Response>;
}>;

/** Attestation state one prover client shares across its calls. */
export class TeeSession {
  readonly #policy: TeePolicy;
  #attested: Readonly<{ key: Uint8Array; at: number }> | undefined;

  constructor(policy: TeePolicy) {
    this.#policy = checkedTeePolicy(policy);
  }

  /** Attests the prover now against the policy and caches its key. */
  async attest(
    fetch: typeof globalThis.fetch,
    attestationUrl: URL,
    signal: ComposedSignal,
  ): Promise<AttestedProver> {
    const nonce = randomBytes(NONCE_SIZE);
    const url = new URL(attestationUrl);
    url.searchParams.set("nonce", bytesToHex(nonce));
    let response: Response;
    try {
      response = await fetch(url, { redirect: "error", signal: signal.signal });
    } catch {
      if (signal.signal.aborted) throw requestError("attest", signal);
      throw refused("unavailable");
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw refused("unavailable");
    }
    let evidence: unknown;
    try {
      evidence = await readBoundedJson(response, MAX_ATTESTATION_BYTES);
    } catch (error) {
      if (!(error instanceof TransportFailure)) throw error;
      throw refused("evidence");
    }
    const prover = verifyAttestation(evidence, this.#policy, nonce, Math.floor(Date.now() / 1000));
    this.#attested = Object.freeze({ key: prover.hpkePublicKey.slice(), at: Date.now() });
    return prover;
  }

  async #key(call: ProverCall): Promise<Uint8Array> {
    const cached = this.#attested;
    if (cached !== undefined && Date.now() - cached.at < this.#policy.maxAgeSecs * 1000) {
      return cached.key;
    }
    return (await this.attest(call.fetch, call.attestationUrl, call.signal)).hpkePublicKey;
  }

  /** Seals the call to the attested key, attesting first when no fresh key is cached. */
  async seal(call: ProverCall): Promise<PreparedCall> {
    const key = await this.#key(call);
    const plaintext = utf8ToBytes(call.body ?? "");
    let sealed;
    try {
      sealed = await sealRequest(
        key,
        call.method,
        `${call.url.pathname}${call.url.search}`,
        plaintext,
      );
    } finally {
      plaintext.fill(0);
    }
    const open = async (response: Response): Promise<Response> => {
      // An unsealed failure passes through so shedding and retries still
      // work, but an unsealed success is never trusted.
      if (response.headers.get(HEADER_VERSION) !== VERSION) {
        if (!response.ok) return response;
        await response.body?.cancel();
        throw sealError("unsealed");
      }
      let bytes: Uint8Array;
      try {
        bytes = await readBoundedBody(
          response,
          call.maxResponseBytes + RESPONSE_NONCE_SIZE + STATUS_SIZE + GCM_TAG_SIZE,
        );
      } catch (error) {
        if (!(error instanceof TransportFailure)) throw error;
        if (error.kind === "responseTooLarge")
          throw new ClientError("CLIENT_PROVER_RESPONSE_TOO_LARGE");
        throw sealError("response");
      }
      const opened = sealed.open(bytes);
      if (opened.status < 200 || opened.status > 599) throw sealError("status");
      const headers = new Headers(response.headers);
      headers.delete(HEADER_VERSION);
      headers.delete("content-length");
      headers.set("content-type", "application/json");
      const nullBody = opened.status === 204 || opened.status === 205 || opened.status === 304;
      return new Response(nullBody ? null : opened.body.slice(), {
        status: opened.status,
        headers,
      });
    };
    return Object.freeze({
      init: sealedInit(call, sealed),
      open,
    });
  }
}

/** A GET carries its sealed bytes in a header, fetch refuses a GET body. */
export function sealedInit(call: ProverCall, sealed: SealedRequest): RequestInit {
  const headers = { ...call.headers, [HEADER_VERSION]: VERSION, [HEADER_ENC]: sealed.enc };
  if (call.method === "GET") {
    return {
      method: call.method,
      headers: { ...headers, [HEADER_SEAL]: bytesToHex(sealed.body) },
      redirect: "error",
      signal: call.signal.signal,
    };
  }
  return {
    method: call.method,
    headers: { ...headers, "content-type": "application/octet-stream" },
    body: sealed.body.slice(),
    redirect: "error",
    signal: call.signal.signal,
  };
}

/** The plain call, or the sealed one when `session` requires a TEE. */
export async function prepareCall(
  session: TeeSession | undefined,
  call: ProverCall,
): Promise<PreparedCall> {
  if (session !== undefined) return session.seal(call);
  return Object.freeze({
    init: {
      method: call.method,
      headers:
        call.body === undefined
          ? call.headers
          : { ...call.headers, "content-type": "application/json" },
      ...(call.body === undefined ? {} : { body: call.body }),
      redirect: "error",
      signal: call.signal.signal,
    },
    open: (response: Response) => Promise.resolve(response),
  });
}

const refused = (check: string): ClientError =>
  new ClientError("CLIENT_PROVER_TEE_ATTESTATION", { details: { check } });
const sealError = (check: string): ClientError =>
  new ClientError("CLIENT_PROVER_TEE_SEAL", { details: { check } });
