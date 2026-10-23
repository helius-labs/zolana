import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { requestAad } from "../src/client/prover/tee/encryption.js";
import { wireDecoder } from "../src/interface/decode.js";
import { contract, routeOf, withoutCredentials } from "./reference-gateway.js";

const decode = wireDecoder((path) => new Error(`fixture ${path}`));
const vectors = decode.record(
  JSON.parse(
    readFileSync(new URL("../../../prover/tee/testdata/vectors.json", import.meta.url), "utf8"),
  ),
  "vectors",
);

// The live suite trusts this gateway to behave as docs/gateway.md says, so
// these pin it to the contract a hosted gateway is held to.
describe("the reference gateway", () => {
  it("forwards every AAD case as a target the prover authenticates unchanged", () => {
    const cases = decode.list(vectors["aad_cases"], "aad_cases");
    expect(cases.length).toBeGreaterThan(0);
    for (const entry of cases) {
      const c = decode.record(entry, "case");
      const method = decode.string(c["method"], "method");
      const { target } = withoutCredentials(decode.string(c["request_target"], "target"));
      expect(requestAad(method, target), target).toBe(decode.string(c["aad"], "aad"));
      const query = target.includes("?") ? target.slice(target.indexOf("?") + 1) : "";
      for (const pair of query.split("&")) {
        expect(new URLSearchParams(`?${pair}`).has(contract.credential), target).toBe(false);
      }
    }
  });

  it("takes the credential under any encoding of its name", () => {
    for (const name of ["api-key", "api%2Dkey", "%61pi-key", "%61%70%69%2D%6B%65%79"]) {
      expect(withoutCredentials(`/v1/zolana/prove/k?${name}=K&label=a%20b+c`)).toEqual({
        target: "/v1/zolana/prove/k?label=a%20b+c",
        credentials: ["K"],
      });
    }
  });

  it("routes each service's paths and nothing else", () => {
    for (const [method, path, origin] of [
      ["POST", "/v1/zolana/prove/transfer_confidential_2_2", "prover"],
      ["GET", "/v1/zolana/prove/transfer_confidential_2_2/status", "prover"],
      ["GET", "/v1/zolana/proving-keys", "prover"],
      ["GET", "/v1/zolana/tee/v1/attestation", "prover"],
      ["POST", "/v1/zolana/getUserRecords", "photon"],
      ["POST", "/v1/zolana/ring/ringDeposits", "ringRpc"],
    ] as const) {
      expect(routeOf(method, path)?.origin, path).toBe(origin);
    }
    for (const [method, path] of [
      ["POST", "/v1/zolana/prove/transfer_confidential_2_2/indexed"],
      ["POST", "/v1/zolana/prove/"],
      ["GET", "/v1/zolana/getUserRecords"],
      ["POST", "/prove/transfer_confidential_2_2"],
    ] as const) {
      expect(routeOf(method, path), path).toBeUndefined();
    }
  });
});
