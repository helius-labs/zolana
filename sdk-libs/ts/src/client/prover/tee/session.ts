import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import {
  TransportFailure,
  readBoundedBody,
  readBoundedJson,
  setUrlQuery,
} from "../../../services/transport.js";
import { ClientError } from "../../error.js";
import {
  composeSignal,
  requestError,
  sleep,
  untilAborted,
  type ComposedSignal,
} from "../../internal.js";
import {
  ATTESTATION_TIMEOUT_MS,
  MAX_ATTEMPTS,
  RETRY_DELAY_MS,
  attestationRetryDelayMs,
} from "../retry.js";
import {
  HEADER_ENC,
  HEADER_KEY_ID,
  HEADER_CIPHERTEXT,
  HEADER_VERSION,
  RESPONSE_NONCE_SIZE,
  VERSION,
  encryptRequest,
  type EncryptedRequest,
} from "./encryption.js";
import {
  checkedProverTeePolicy,
  checkFleetTime,
  verifyFleetAttestation,
  type ProverTeePolicy,
} from "./fleet.js";
import { PLATFORMS, type TeePlatform } from "./registry.js";
import { verifyAttestation, type AttestedProver } from "./verify.js";
import { TeePolicySource, type ProverTee } from "./source.js";

const NONCE_SIZE = 32;
const MAX_ATTESTATION_BYTES = 1024 * 1024;
const GCM_TAG_SIZE = 16;
const STATUS_SIZE = 2;
const MAX_ERROR_BYTES = 4096;
/** The prover no longer holds the key the request was encrypted to. */
const KEY_LOST = "tee_decryption_failed";

/** One prover HTTP call before it is sent. */
export type ProverCall = Readonly<{
  fetch: typeof globalThis.fetch;
  attestationUrl: URL;
  url: URL;
  /** `url`'s path below the prover URL, what an encrypted call binds. */
  route: string;
  method: "GET" | "POST";
  headers: Readonly<Record<string, string>>;
  body?: string;
  signal: ComposedSignal;
  maxResponseBytes: number;
}>;

type PreparedCall = Readonly<{
  init: RequestInit;
  finish(response: Response): Promise<Response>;
}>;

type Flight = Readonly<{ prover: Promise<AttestedProver>; signal: ComposedSignal }>;

/** Attestation state one prover client shares across its calls. */
export class TeeSession {
  readonly #configuration: ProverTee;
  #attested:
    | Readonly<{
        key: Uint8Array;
        at: number;
        maxAgeSecs: number;
        platform: TeePlatform;
        fingerprint: string;
      }>
    | undefined;
  // One attestation at a time, the server answers only a few quotes at once.
  #flight: Flight | undefined;

  constructor(policy: ProverTee) {
    this.#configuration = TeePolicySource.isSource(policy)
      ? policy
      : checkedProverTeePolicy(policy);
  }

  /** Attests the prover now against the policy and caches its key. */
  async attest(
    fetch: typeof globalThis.fetch,
    attestationUrl: URL,
    signal: ComposedSignal,
  ): Promise<AttestedProver> {
    const pending = this.#resolvePolicy(signal);
    if (pending instanceof Promise) await pending;
    for (;;) {
      const flight = this.#flight ?? this.#launch(fetch, attestationUrl, signal);
      try {
        return copyAttestedProver(await untilAborted(flight.prover, signal));
      } catch (error) {
        // A flight its own caller cancelled restarts under this caller's signal.
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
    let delay: bigint | undefined;
    for (let attempt = 1; ; attempt++) {
      if (delay !== undefined) {
        try {
          await sleep(delay, { signal: signal.signal });
        } catch (error) {
          if (signal.signal.aborted) throw requestError("attest", signal);
          throw error;
        }
      }
      const pending = this.#resolvePolicy(signal);
      if (pending instanceof Promise) await pending;
      const nonce = randomBytes(NONCE_SIZE);
      const url = new URL(attestationUrl);
      setUrlQuery(url, "nonce", bytesToHex(nonce));
      const request = composeSignal(
        { signal: signal.signal, timeoutMs: ATTESTATION_TIMEOUT_MS },
        "attest",
      );
      try {
        let response: Response;
        try {
          response = await fetch(url, { redirect: "error", signal: request.signal });
        } catch {
          if (signal.signal.aborted) throw requestError("attest", signal);
          if (attempt >= MAX_ATTEMPTS) {
            throw request.timedOut() ? requestError("attest", request) : refused("unavailable");
          }
          delay = RETRY_DELAY_MS;
          continue;
        }
        if (!response.ok) {
          delay =
            attempt < MAX_ATTEMPTS
              ? attestationRetryDelayMs(
                  response.status,
                  response.headers.get("retry-after"),
                  Date.now(),
                )
              : undefined;
          await response.body?.cancel();
          if (delay === undefined) throw refused("unavailable");
          continue;
        }
        return await this.#accept(response, nonce, signal);
      } finally {
        request.cleanup();
      }
    }
  }

  async #accept(
    response: Response,
    nonce: Uint8Array,
    signal: ComposedSignal,
  ): Promise<AttestedProver> {
    let attestation: unknown;
    try {
      attestation = await readBoundedJson(response, MAX_ATTESTATION_BYTES);
    } catch (error) {
      if (!(error instanceof TransportFailure)) throw error;
      throw refused("malformed_attestation");
    }
    const pending = this.#resolvePolicy(signal);
    const approved = pending instanceof Promise ? await pending : pending;
    const nowSecs = Math.floor(Date.now() / 1000);
    const { prover, policy } =
      "kind" in approved
        ? verifyFleetAttestation(attestation, approved, nonce, nowSecs)
        : {
            prover: verifyAttestation(attestation, approved, nonce, nowSecs),
            policy: approved,
          };
    this.#attested = Object.freeze({
      key: prover.hpkePublicKey.slice(),
      at: Date.now(),
      maxAgeSecs: policy.maxAgeSecs,
      platform: prover.platform,
      fingerprint: JSON.stringify(policy),
    });
    return prover;
  }

  /** Resends once to a fresh attestation when a prover that draws its key per boot lost it. */
  async send(call: ProverCall): Promise<Response | undefined> {
    for (let resent = false; ; resent = true) {
      const { key, platform, fingerprint } = await this.#key(call);
      const keyPerBoot = PLATFORMS[platform].keyPerBoot;
      const prepared = await this.#encrypt(call, key);
      const pending = this.#resolvePolicy(call.signal);
      const current = pending instanceof Promise ? await pending : pending;
      if (!permits(current, key, fingerprint)) throw refused("policy_changed");
      const response = await fetched(call, prepared.init);
      if (response === undefined) return undefined;
      if (resent || !(await recipientUnavailable(response, keyPerBoot)))
        return prepared.finish(response);
      await response.body?.cancel();
      if (this.#attested !== undefined && equalBytes(this.#attested.key, key)) {
        this.#attested = undefined;
      }
    }
  }

  #resolvePolicy(signal: ComposedSignal): ProverTeePolicy | Promise<ProverTeePolicy> {
    const check = (policy: ProverTeePolicy): ProverTeePolicy => {
      if (signal.signal.aborted) throw requestError("attest", signal);
      if ("kind" in policy) checkFleetTime(policy, Math.floor(Date.now() / 1000));
      return policy;
    };
    if (TeePolicySource.isSource(this.#configuration)) {
      return this.#configuration
        .resolve({ signal: signal.signal })
        .then((policy) => check(checkedProverTeePolicy(policy)))
        .catch((error: unknown) => {
          if (signal.signal.aborted) throw requestError("attest", signal);
          throw error;
        });
    }
    return check(this.#configuration);
  }

  async #key(
    call: ProverCall,
  ): Promise<Readonly<{ key: Uint8Array; platform: TeePlatform; fingerprint: string }>> {
    const pending = this.#resolvePolicy(call.signal);
    const current = pending instanceof Promise ? await pending : pending;
    const cached = this.#attested;
    if (
      cached !== undefined &&
      Date.now() >= cached.at &&
      Date.now() - cached.at < cached.maxAgeSecs * 1000 &&
      permits(current, cached.key, cached.fingerprint)
    ) {
      return cached;
    }
    const prover = await this.attest(call.fetch, call.attestationUrl, call.signal);
    const updated = this.#resolvePolicy(call.signal);
    const approved = updated instanceof Promise ? await updated : updated;
    const accepted = this.#attested;
    if (
      accepted === undefined ||
      !equalBytes(accepted.key, prover.hpkePublicKey) ||
      !permits(approved, accepted.key, accepted.fingerprint)
    )
      throw refused("policy_changed");
    return accepted;
  }

  async #encrypt(call: ProverCall, key: Uint8Array): Promise<PreparedCall> {
    const plaintext = utf8ToBytes(call.body ?? "");
    let encrypted;
    try {
      encrypted = await encryptRequest(
        key,
        call.method,
        `${call.route}${call.url.search}`,
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

function selectedFingerprint(policy: ProverTeePolicy, key: Uint8Array): string | undefined {
  if (!("kind" in policy)) return JSON.stringify(policy);
  const hex = bytesToHex(key);
  const entry = policy.deployments.find((entry) => entry.policy.hpkePublicKey === hex);
  return entry === undefined ? undefined : JSON.stringify(entry.policy);
}

function permits(policy: ProverTeePolicy, key: Uint8Array, fingerprint: string): boolean {
  return selectedFingerprint(policy, key) === fingerprint;
}

function copyAttestedProver(prover: AttestedProver): AttestedProver {
  return Object.freeze({
    ...prover,
    hpkePublicKey: prover.hpkePublicKey.slice(),
    imageId: prover.imageId.slice(),
  });
}

/** A GET carries its encrypted bytes in a header, fetch refuses a GET body. */
export function encryptedInit(call: ProverCall, encrypted: EncryptedRequest): RequestInit {
  const headers = {
    ...call.headers,
    [HEADER_VERSION]: VERSION,
    [HEADER_ENC]: encrypted.enc,
    [HEADER_KEY_ID]: encrypted.recipientId,
  };
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

/** Undefined when fetch rejects. */
export async function sendCall(
  session: TeeSession | undefined,
  call: ProverCall,
): Promise<Response | undefined> {
  if (session !== undefined) return session.send(call);
  return fetched(call, {
    method: call.method,
    headers:
      call.body === undefined
        ? call.headers
        : { ...call.headers, "content-type": "application/json" },
    ...(call.body === undefined ? {} : { body: call.body }),
    redirect: "error",
    signal: call.signal.signal,
  });
}

async function fetched(call: ProverCall, init: RequestInit): Promise<Response | undefined> {
  try {
    return await call.fetch(call.url, init);
  } catch {
    return undefined;
  }
}

async function recipientUnavailable(response: Response, keyPerBoot: boolean): Promise<boolean> {
  if (response.headers.get(HEADER_VERSION) === VERSION) return false;
  if (response.status !== 503 && !(keyPerBoot && response.status === 400)) return false;
  let answer: unknown;
  try {
    answer = await readBoundedJson(response.clone(), MAX_ERROR_BYTES);
  } catch {
    return false;
  }
  return (
    typeof answer === "object" &&
    answer !== null &&
    "code" in answer &&
    ((response.status === 400 && keyPerBoot && answer.code === KEY_LOST) ||
      (response.status === 503 && answer.code === "tee_generation_unavailable"))
  );
}

const refused = (check: string): ClientError =>
  new ClientError("CLIENT_PROVER_TEE_ATTESTATION", { details: { check } });
const encryptionError = (check: string): ClientError =>
  new ClientError("CLIENT_PROVER_TEE_ENCRYPTION", { details: { check } });
