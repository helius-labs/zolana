import { readFileSync } from "node:fs";

import { teePolicyFromJson } from "../../src/client/prover/tee/policy.js";
export function readTeePolicy(path: URL) {
  const json: unknown = JSON.parse(readFileSync(path, "utf8"));
  return teePolicyFromJson(json);
}
