import { bytesToHex, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { TransportFailure, readBoundedBody, readBoundedJson } from "../../../services/transport.js";
import { ClientError } from "../../error.js";
import { requestError, sleep, type ComposedSignal } from "../../internal.js";
import { MAX_ATTEMPTS, RETRY_DELAY_MS, attestationRetryDelayMs } from "../retry.js";
import {
  HEADER_ENC,
  HEADER_CIPHERTEXT,
  HEADER_VERSION,
  RESPONSE_NONCE_SIZE,
  VERSION,
  encryptRequest,
  type EncryptedRequest,
} from "./encryption.js";
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
  finish(response: Response): Promise<Response>;
}>;

/** An attestation in progress, and the signal of the call that started it. */
type Flight = Readonly<{ prover: Promise<AttestedProver>; signal: ComposedSignal }>;

/** Attestation state one prover client shares across its calls. */
export class TeeSession {
  readonly #policy: TeePolicy;
  #attested: Readonly<{ key: Uint8Array; at: number }> | undefined;
  // One attestation at a time, the server answers only a few quotes at once.
  #flight: Flight | undefined;

  constructor(policy: TeePolicy) {
    this.#policy = checkedTeePolicy(policy);
  }

  /**
   * Attests the prover now against the policy and caches its key. A call
   * joins an attestation already in flight, and starts its own when the
   * caller that started that one cancelled it.
   */
  async attest(
    fetch: typeof globalThis.fetch,
    attestationUrl: URL,
    signal: ComposedSignal,
  ): Promise<AttestedProver> {
    for (;;) {
      const flight = this.#flight ?? this.#launch(fetch, attestationUrl, signal);
      try {
        return await flight.prover;
      } catch (error) {
        const cancelledByOther =
          flight.signal !== signal && flight.signal.signal.aborted && !signal.signal.aborted;
        if (!cancelledByOther) throw error;
      }
    }
  }

  #launch(fetch: typeof globalThis.fetch, attestationUrl: URL, signal: ComposedSignal): Flight {
    const flight: Flight = {
      prover: this.#attestWithRetries(fetch, attestationUrl, signal),
      signal,
    };
    this.#flight = flight;
    const land = (): void => {
      if (this.#flight === flight) this.#flight = undefined;
    };
    void flight.prover.then(land, land);
    return flight;
  }

  /** Retries a transport failure and a busy or unavailable answer, each try with a fresh nonce. */
  async #attestWithRetries(
    fetch: typeof globalThis.fetch,
    attestationUrl: URL,
    signal: ComposedSignal,
  ): Promise<AttestedProver> {
    for (let attempt = 1; ; attempt++) {
      const nonce = randomBytes(NONCE_SIZE);
      const url = new URL(attestationUrl);
      url.searchParams.set("nonce", bytesToHex(nonce));
      let response: Response;
      try {
        response = await fetch(url, { redirect: "error", signal: signal.signal });
      } catch {
        if (signal.signal.aborted) throw requestError("attest", signal);
        if (attempt >= MAX_ATTEMPTS) throw refused("unavailable");
        await sleep(RETRY_DELAY_MS, { signal: signal.signal });
        continue;
      }
      if (!response.ok) {
        const delay =
          attempt < MAX_ATTEMPTS
            ? attestationRetryDelayMs(response.status, response.headers.get("retry-after"))
            : undefined;
        await response.body?.cancel();
        if (delay === undefined) throw refused("unavailable");
        await sleep(delay, { signal: signal.signal });
        continue;
      }
      return this.#accept(response, nonce);
    }
  }

  async #accept(response: Response, nonce: Uint8Array): Promise<AttestedProver> {
    let attestation: unknown;
    try {
      attestation = await readBoundedJson(response, MAX_ATTESTATION_BYTES);
    } catch (error) {
      if (!(error instanceof TransportFailure)) throw error;
      throw refused("malformed_attestation");
    }
    const prover = verifyAttestation(
      attestation,
      this.#policy,
      nonce,
      Math.floor(Date.now() / 1000),
    );
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

  /** Encrypts the call to the attested key, attesting first when no fresh key is cached. */
  async encrypt(call: ProverCall): Promise<PreparedCall> {
    const key = await this.#key(call);
    const plaintext = utf8ToBytes(call.body ?? "");
    let encrypted;
    try {
      encrypted = await encryptRequest(
        key,
        call.method,
        `${call.url.pathname}${call.url.search}`,
        plaintext,
      );
    } finally {
      plaintext.fill(0);
    }
    const finish = async (response: Response): Promise<Response> => {
      // An unencrypted failure passes through so shedding and retries still
      // work, but an unencrypted success is never trusted.
      if (response.headers.get(HEADER_VERSION) !== VERSION) {
        if (!response.ok) return response;
        await response.body?.cancel();
        throw encryptionError("unencrypted");
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
        throw encryptionError("response");
      }
      const decrypted = encrypted.decrypt(bytes);
      if (decrypted.status < 200 || decrypted.status > 599) throw encryptionError("status");
      const headers = new Headers(response.headers);
      headers.delete(HEADER_VERSION);
      headers.delete("content-length");
      headers.set("content-type", "application/json");
      const nullBody =
        decrypted.status === 204 || decrypted.status === 205 || decrypted.status === 304;
      return new Response(nullBody ? null : decrypted.body.slice(), {
        status: decrypted.status,
        headers,
      });
    };
    return Object.freeze({
      init: encryptedInit(call, encrypted),
      finish,
    });
  }
}

/** A GET carries its encrypted bytes in a header, fetch refuses a GET body. */
export function encryptedInit(call: ProverCall, encrypted: EncryptedRequest): RequestInit {
  const headers = { ...call.headers, [HEADER_VERSION]: VERSION, [HEADER_ENC]: encrypted.enc };
  if (call.method === "GET") {
    return {
      method: call.method,
      headers: { ...headers, [HEADER_CIPHERTEXT]: bytesToHex(encrypted.body) },
      redirect: "error",
      signal: call.signal.signal,
    };
  }
  return {
    method: call.method,
    headers: { ...headers, "content-type": "application/octet-stream" },
    body: encrypted.body.slice(),
    redirect: "error",
    signal: call.signal.signal,
  };
}

/** The plain call, or the encrypted one when `session` requires a TEE. */
export async function prepareCall(
  session: TeeSession | undefined,
  call: ProverCall,
): Promise<PreparedCall> {
  if (session !== undefined) return session.encrypt(call);
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
    finish: (response: Response) => Promise.resolve(response),
  });
}

const refused = (check: string): ClientError =>
  new ClientError("CLIENT_PROVER_TEE_ATTESTATION", { details: { check } });
const encryptionError = (check: string): ClientError =>
  new ClientError("CLIENT_PROVER_TEE_ENCRYPTION", { details: { check } });
