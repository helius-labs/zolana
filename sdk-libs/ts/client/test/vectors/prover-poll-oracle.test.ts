import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ClientError } from "../../src/error.js";
import { ProverClient } from "../../src/prover/client.js";
import type { ProverInputs } from "../../src/prover/types.js";
import oracle from "../oracles/prover-poll-v1.json" with { type: "json" };

/// Replays `sdk-libs/client/src/prover/ts_poll_oracle.rs`, which drives the real
/// `poll_async` against a mock server and records what it did.
///
/// The previous evidence for this row was a set of TypeScript expectations that
/// a reader had matched to the arms of the Rust loop. That cannot fail when the
/// two disagree, because nothing in it comes from Rust. These cases carry Rust's
/// own response script, Rust's own request count, and the arm Rust stopped in.
///
/// Two observables are compared per case. The request count separates a retry
/// from a termination, which is the distinction the loop exists to make and the
/// one a reader is least likely to get right. The arm says where it stopped.
///
/// Rust reaches these seven outcomes through two error variants and tells them
/// apart by message text; TypeScript carries a code per outcome. The oracle
/// tags the Rust arm, and this table is the whole of the translation between
/// them, so a new arm on either side has nowhere to hide.
const RUST_ARM_TO_CODE: Readonly<Record<string, string>> = {
  failed: "CLIENT_PROVER_SERVER",
  httpStatus: "CLIENT_PROVER_HTTP",
  invalidJson: "CLIENT_PROVER_JSON",
  jobId: "CLIENT_PROVER_JOB",
  nullProof: "CLIENT_PROVER_SERVER",
  timeout: "CLIENT_PROVER_TIMEOUT",
  unparsableProof: "CLIENT_PROOF_PARSE",
};

interface OracleCase {
  readonly name: string;
  readonly jobId: string;
  readonly responses: readonly Readonly<{
    status?: number;
    body?: string;
    disconnect?: boolean;
  }>[];
  readonly statusRequests: number;
  readonly outcome: string;
  readonly arm?: string;
  readonly proof?: Readonly<{ a: string; b: string; c: string; hasCommitment: boolean }>;
}

/// Rust's budget is in seconds and TypeScript's in milliseconds. The loop
/// arithmetic is the same, so one Rust second is one TypeScript second here.
const INTERVAL_MS = oracle.config.pollIntervalSecs * 1_000;
const MAX_WAIT_MS = oracle.config.maxWaitSecs * 1_000;

interface Run {
  readonly prove: () => Promise<unknown>;
  statusRequests: () => number;
}

/// Serves Rust's script: the `/prove` answer carries the case's job handle, and
/// each subsequent request consumes the next recorded status response.
function replay(jobId: string, responses: OracleCase["responses"]): Run {
  let index = 0;
  let served = false;
  let statusRequests = 0;
  const fetch = ((): Promise<Response> => {
    if (!served) {
      served = true;
      return Promise.resolve(json(202, JSON.stringify({ job_id: jobId })));
    }
    statusRequests += 1;
    const reply = responses[index++];
    if (reply === undefined || reply.disconnect === true) {
      return Promise.reject(new Error("connection reset"));
    }
    return Promise.resolve(json(reply.status ?? 200, reply.body ?? ""));
  }) as typeof globalThis.fetch;

  const prover = new ProverClient({
    url: "http://127.0.0.1:3001",
    fetch,
    asyncPoll: { pollIntervalMs: INTERVAL_MS, maxWaitMs: MAX_WAIT_MS },
  });
  // `prove` reads only `circuit` before it sends, so an empty eddsa payload
  // reaches the poll loop without standing in for a real transfer.
  const inputs = {
    circuit: "transfer",
    payload: {
      inputs: [],
      outputs: [],
      externalDataHash: 0n,
      privateTxHash: 0n,
      publicSolAmount: 0n,
      publicSplAmount: 0n,
      publicSplAssetPublicKey: 0n,
      zoneProgramId: 0n,
      payerPublicKeyHash: 0n,
      publicInputHash: 0n,
    },
  } as unknown as ProverInputs;
  return { prove: () => prover.prove(inputs), statusRequests: () => statusRequests };
}

function json(status: number, body: string): Response {
  return new Response(body, { status, headers: { "content-type": "application/json" } });
}

async function settle(operation: Promise<unknown>): Promise<unknown> {
  const settled = operation.then((value: unknown) => value).catch((error: unknown) => error);
  await vi.runAllTimersAsync();
  return settled;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("prover status polling, against the arms Rust took", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  for (const rustCase of oracle.cases as readonly OracleCase[]) {
    it(`matches Rust for ${rustCase.name}`, async () => {
      const run = replay(rustCase.jobId, rustCase.responses);
      const result = await settle(run.prove());

      expect(run.statusRequests()).toBe(rustCase.statusRequests);

      if (rustCase.outcome === "proof") {
        expect(result).not.toBeInstanceOf(Error);
        const proof = result as Readonly<{ a: Uint8Array; b: Uint8Array; c: Uint8Array }>;
        expect(hex(proof.a)).toBe(rustCase.proof?.a);
        expect(hex(proof.b)).toBe(rustCase.proof?.b);
        expect(hex(proof.c)).toBe(rustCase.proof?.c);
        return;
      }
      expect(result).toBeInstanceOf(ClientError);
      expect((result as ClientError).code).toBe(RUST_ARM_TO_CODE[rustCase.arm ?? ""]);
    });
  }

  /// The handle is interpolated into the status query, so a character that can
  /// end the parameter rewrites the URL. Rust refuses before it makes any
  /// request, and the request count is what shows the refusal came first rather
  /// than after a round trip to a rewritten address.
  for (const rustCase of oracle.jobIds) {
    it(`matches Rust on the ${rustCase.name} job id`, async () => {
      const queued = { status: 200, body: JSON.stringify({ status: "queued" }) };
      const run = replay(rustCase.jobId, [queued, queued]);
      const result = await settle(run.prove());
      expect(result).toBeInstanceOf(ClientError);
      expect((result as ClientError).code).toBe(RUST_ARM_TO_CODE[rustCase.arm]);
      expect(run.statusRequests()).toBe(rustCase.statusRequests);
    });
  }
});
