import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { teePolicyFromJson } from "../src/client/prover/tee/policy.js";
import { wireDecoder } from "../src/interface/decode.js";

const decode = wireDecoder((path) => new Error(`fixture ${path}`));
const vectors = decode.record(
  JSON.parse(
    readFileSync(
      new URL("../../../prover/tee/testdata/policy_cases.json", import.meta.url),
      "utf8",
    ),
  ),
  "policy_cases.json",
);

describe("policy vectors", () => {
  it.each(decode.list(vectors["cases"], "cases").map((item) => decode.record(item, "case")))(
    "$name",
    (vector) => {
      for (const json of [vector["policy"], { deployment: vector["policy"] }]) {
        const parse = () => teePolicyFromJson(json);
        if (vector["expect"] === "accept") {
          expect(parse).not.toThrow();
        } else {
          expect(parse).toThrow(expect.objectContaining({ code: "CLIENT_INVALID_CONFIG" }));
        }
      }
    },
  );
});
