import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { composeSignal } from "../src/client/internal.js";
import { TeeSession } from "../src/client/prover/tee/session.js";
import { PROVER_TEE_HEADERS } from "../src/index.js";
import { attestedProver } from "./helpers/attested-prover.js";

const contract = readFileSync(
  new URL("../../../prover/tee/WIRE_CONTRACT.md", import.meta.url),
  "utf8",
);

/** The backticked names on the one contract line that starts with `prefix`. */
function namesOnLine(prefix: string, after = ""): readonly string[] {
  const lines = contract.split("\n").filter((line) => line.startsWith(prefix));
  expect(lines).toHaveLength(1);
  const [line] = lines;
  const tail = (line ?? "").slice((line ?? "").indexOf(after) + after.length);
  return [...tail.matchAll(/`(Spr-[A-Za-z-]+)`/gu)].map((match) => match[1] ?? "");
}

describe("PROVER_TEE_HEADERS", () => {
  it("names the headers the wire contract tells a proxy to forward and expose", () => {
    expect([...PROVER_TEE_HEADERS.request]).toEqual(namesOnLine("It forwards"));
    expect([...PROVER_TEE_HEADERS.response]).toEqual(
      namesOnLine("For browsers it allows", "exposes"),
    );
  });

  it("is frozen", () => {
    expect(Object.isFrozen(PROVER_TEE_HEADERS)).toBe(true);
    expect(Object.isFrozen(PROVER_TEE_HEADERS.request)).toBe(true);
    expect(Object.isFrozen(PROVER_TEE_HEADERS.response)).toBe(true);
  });
});

describe("a prover refusing the encrypted envelope", () => {
  const refusal = (code: string) => () =>
    Response.json({ code, message: "server text private-witness-marker" }, { status: 400 });

  it("reports tee_required as the Spr-Tee header lost on the way, without resending", async () => {
    const { prover, requests, restore } = attestedProver(refusal("tee_required"));
    try {
      const error = await prover.health().then(
        () => undefined,
        (caught: unknown) => caught,
      );
      expect(error).toMatchObject({
        code: "CLIENT_PROVER_TEE_REJECTED",
        details: { reason: "tee_required", headers: "Spr-Tee" },
      });
      expect(JSON.stringify(error)).not.toContain("private-witness-marker");
      // The client did send the header; the prover never saw it.
      const sent = requests.filter((request) => request.path === "/health");
      expect(sent).toHaveLength(1);
      expect(sent[0]?.headers.get("Spr-Tee")).toBe("v1");
    } finally {
      restore();
    }
  });

  it.each([
    ["tee_version_unsupported", "Spr-Tee"],
    ["tee_request_malformed", "Spr-Tee-Enc, Spr-Tee-Ciphertext"],
  ])("reports %s on a GET as the headers %s", async (reason, headers) => {
    const { prover, requests, restore } = attestedProver(refusal(reason));
    try {
      await expect(prover.health()).rejects.toMatchObject({
        code: "CLIENT_PROVER_TEE_REJECTED",
        details: { reason, headers },
      });
      expect(requests.map((request) => request.path)).toEqual(["/attestation", "/health"]);
    } finally {
      restore();
    }
  });

  it.each([
    ["tee_request_malformed", 1],
    ["tee_decryption_failed", 2],
  ])("reports %s on a POST as Spr-Tee-Enc after %i sends", async (reason, sends) => {
    const { tee, fetch, requests, restore } = attestedProver(refusal(reason));
    const signal = composeSignal(undefined, "prove");
    try {
      const url = new URL("https://prover.invalid/prove/merge_8");
      await expect(
        new TeeSession(tee).send({
          fetch,
          attestationUrl: new URL("https://prover.invalid/attestation"),
          url,
          route: url.pathname,
          method: "POST",
          headers: {},
          body: "{}",
          signal,
          maxResponseBytes: 1024,
        }),
      ).rejects.toMatchObject({
        code: "CLIENT_PROVER_TEE_REJECTED",
        details: { reason, headers: "Spr-Tee-Enc" },
      });
      expect(requests.filter((request) => request.path === url.pathname)).toHaveLength(sends);
    } finally {
      signal.cleanup();
      restore();
    }
  });

  it("passes any other unencrypted refusal through", async () => {
    const { prover, restore } = attestedProver(refusal("unauthorized"));
    try {
      await expect(prover.health()).rejects.toMatchObject({
        code: "CLIENT_PROVER_HTTP",
        details: { status: 400 },
      });
    } finally {
      restore();
    }
  });
});
