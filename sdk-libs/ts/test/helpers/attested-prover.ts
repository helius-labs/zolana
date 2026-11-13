import { readFileSync } from "node:fs";

import { hexToBytes } from "@noble/hashes/utils.js";
import { vi } from "vitest";

import { ProverClient } from "../../src/client/prover/client.js";
import { teePolicyFromJson } from "../../src/client/prover/tee/policy.js";
import type { TeePolicy } from "../../src/client/prover/tee/registry.js";
import { wireDecoder } from "../../src/interface/decode.js";

const decode = wireDecoder((path) => new Error(`fixture ${path}`));
const testdata = (file: string): unknown =>
  JSON.parse(
    readFileSync(new URL(`../../../../prover/tee/testdata/${file}`, import.meta.url), "utf8"),
  );

// Bound once at load: a copy bound inside a call can capture an earlier
// test's spy under Bun and then recurse into itself.
const fill = globalThis.crypto.getRandomValues.bind(globalThis.crypto);

/** One prover call: its path and request headers. */
export type ProverRequest = Readonly<{ path: string; headers: Headers }>;

/**
 * A `ProverClient` against the recorded live AWS Nitro attestation, with the
 * attestation nonce and clock pinned to the capture. Every call other than
 * the attestation gets `answer`. `restore` undoes the pins.
 */
export function attestedProver(answer: (request: ProverRequest) => Response): Readonly<{
  prover: ProverClient;
  /** The policy and fetch the prover uses, for a `TeeSession` of its own. */
  tee: TeePolicy;
  fetch: typeof globalThis.fetch;
  requests: readonly ProverRequest[];
  restore(): void;
}> {
  const live = decode.record(testdata("nitro_live_attestation.json"), "live");
  const deployment = decode.record(
    decode.record(testdata("nitro_live_policy.json"), "policy")["deployment"],
    "deployment",
  );
  const nonce = hexToBytes(decode.string(live["nonce"], "nonce"));
  const at = Number(decode.integer(live["captured_at"], "captured_at"));
  const random = vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation((bytes) => {
    if (!(bytes instanceof Uint8Array) || bytes.length !== nonce.length) return fill(bytes);
    bytes.set(nonce);
    return bytes;
  });
  const now = vi.spyOn(Date, "now").mockReturnValue(at * 1000);
  const requests: ProverRequest[] = [];
  const tee = teePolicyFromJson(deployment);
  const fetch: typeof globalThis.fetch = (input, init) => {
    const request = {
      path: new URL(String(input)).pathname,
      headers: new Headers(init?.headers),
    };
    requests.push(request);
    return Promise.resolve(
      request.path === "/attestation" ? Response.json(live["attestation"]) : answer(request),
    );
  };
  const prover = new ProverClient({ url: "https://prover.invalid", tee, fetch });
  return {
    prover,
    tee,
    fetch,
    requests,
    restore: () => {
      random.mockRestore();
      now.mockRestore();
    },
  };
}
