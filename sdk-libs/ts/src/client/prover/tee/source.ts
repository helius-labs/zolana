import type { RequestContext } from "../../../interface/types.js";
import { composeSignal, requestError, untilAborted, type ComposedSignal } from "../../internal.js";
import { ClientError } from "../../error.js";
import {
  checkFleetTime,
  identifier,
  teeFleetPolicyFromJson,
  type ProverTeePolicy,
  type TeeFleetPolicy,
} from "./fleet.js";
import { invalidPolicy, policyDecode, refused } from "./platform.js";

/** An application-authorized loader must authenticate its publisher before returning bytes. */
export interface TeePolicyDocument {
  readonly policy: unknown;
  /** Unix seconds, bounded by the authentication metadata's expiry. */
  readonly validUntil: number;
}

export interface TeePolicySourceConfig {
  readonly network: string;
  readonly load: (context: RequestContext) => Promise<TeePolicyDocument>;
  /** At most five minutes; default one minute. Expiry always takes precedence. */
  readonly refreshIntervalMs?: number;
}

export type ProverTee = ProverTeePolicy | TeePolicySource;

type Snapshot = Readonly<{ policy: TeeFleetPolicy; at: number }>;
type Flight = Readonly<{ policy: Promise<TeeFleetPolicy>; signal: ComposedSignal }>;

/** Resolves approved policies; the supplied loader owns publisher authentication and durable storage. */
export class TeePolicySource {
  readonly #network: string;
  readonly #load: TeePolicySourceConfig["load"];
  readonly #refreshIntervalMs: number;
  #snapshot: Snapshot | undefined;
  #flight: Flight | undefined;
  #revision = 0;
  #fingerprint: string | undefined;

  constructor(config: TeePolicySourceConfig) {
    policyDecode.record(config, "source");
    this.#network = identifier(config.network, "network");
    if (typeof config.load !== "function") throw invalidPolicy("source.load");
    this.#load = config.load;
    const interval = config.refreshIntervalMs ?? 60_000;
    if (!Number.isSafeInteger(interval) || interval <= 0 || interval > 300_000) {
      throw invalidPolicy("source.refreshIntervalMs");
    }
    this.#refreshIntervalMs = interval;
  }

  static isSource(value: unknown): value is TeePolicySource {
    return typeof value === "object" && value !== null && #load in value;
  }

  async resolve(context?: RequestContext): Promise<TeeFleetPolicy> {
    const request = composeSignal(
      { ...context, timeoutMs: context?.timeoutMs ?? 30_000 },
      "attest",
    );
    try {
      for (;;) {
        const cached = this.#snapshot;
        const now = Date.now();
        if (
          this.#flight === undefined &&
          cached !== undefined &&
          now >= cached.at &&
          now - cached.at < this.#refreshIntervalMs &&
          now < cached.policy.expiresAt * 1000
        ) {
          return cached.policy;
        }
        const flight = this.#flight ?? this.#launch(request);
        try {
          return await untilAborted(flight.policy, request);
        } catch (error) {
          if (
            flight.signal === request ||
            !flight.signal.signal.aborted ||
            request.signal.aborted
          ) {
            throw error;
          }
        }
      }
    } finally {
      request.cleanup();
    }
  }

  #launch(signal: ComposedSignal): Flight {
    const flight: Flight = {
      policy: untilAborted(this.#resolve(signal), signal),
      signal,
    };
    this.#flight = flight;
    const settle = (): void => {
      if (this.#flight === flight) this.#flight = undefined;
    };
    void flight.policy.then(settle, settle);
    return flight;
  }

  async #resolve(signal: ComposedSignal): Promise<TeeFleetPolicy> {
    let document: TeePolicyDocument;
    try {
      document = await this.#load({ signal: signal.signal });
    } catch (error) {
      if (signal.signal.aborted) throw requestError("attest", signal);
      if (error instanceof ClientError) throw error;
      throw refused("policy_unavailable");
    }
    if (signal.signal.aborted) throw requestError("attest", signal);
    if (
      typeof document !== "object" ||
      document === null ||
      !Number.isSafeInteger(document.validUntil) ||
      document.validUntil <= 0
    ) {
      throw refused("policy_metadata");
    }
    const policy = teeFleetPolicyFromJson(document.policy, this.#network);
    const fingerprint = JSON.stringify(policy);
    if (
      policy.revision < this.#revision ||
      (policy.revision === this.#revision && fingerprint !== this.#fingerprint)
    ) {
      throw refused("policy_rollback");
    }
    const approved = Object.freeze({
      ...policy,
      expiresAt: Math.min(policy.expiresAt, document.validUntil),
    });
    checkFleetTime(approved, Math.floor(Date.now() / 1000));
    this.#revision = policy.revision;
    this.#fingerprint = fingerprint;
    this.#snapshot = Object.freeze({ policy: approved, at: Date.now() });
    return approved;
  }
}
