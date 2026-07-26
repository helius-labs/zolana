import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import oracleJson from "../oracles/prover-edge-cases-v1.json" with { type: "json" };
import { proverRequest } from "../../src/prover/client.js";
import { assemble } from "../../src/prover/index.js";
import {
  PROVER_EDGE_CASES,
  buildEdgeCase,
  type ProverEdgeCaseOracle,
} from "../helpers/prover-vectors.js";

/// The prover server routes on `circuitType`, so the set of strings the shipped
/// client can put in that field is the set of circuits it can reach. Rust
/// `prover::json` writes eight, and TypeScript now reaches seven of them: the
/// zone rails were built under the 2026-07-25 ruling that withdrew their
/// deferral (C13, C14, C18).
///
/// `address-append` stays out on a fact rather than a preference. It is the
/// forester's nullifier-tree rail, TypeScript ships no forester, and an SDK that
/// exported the builder would be exporting an instruction whose proof it cannot
/// generate. This test is the evidence for that disposition rather than an
/// assertion about it: it fails the moment a shipped source file can name it.
const REACHABLE = [
  "merge",
  "merge-zone",
  "transfer-confidential",
  "transfer-p256-confidential",
  "transfer-p256-zone",
  "transfer-zone",
  "transfer-zone-authority",
];

const UNREACHABLE = ["address-append"];

const SOURCE_ROOT = fileURLToPath(new URL("../../src", import.meta.url));
const oracle = oracleJson as ProverEdgeCaseOracle;

function sources(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sources(path);
    return entry.name.endsWith(".ts") ? [path] : [];
  });
}

function circuitTypeOf(caseIndex: number): unknown {
  const shape = PROVER_EDGE_CASES[caseIndex];
  if (!shape) throw new Error("missing edge case");
  const built = buildEdgeCase(oracle, shape);
  return proverRequest(assemble(built.proofInputs, built.spendProofs).proverInputs)["circuitType"];
}

describe("reachable prover circuit types", () => {
  it("emits the confidential circuit for each transfer rail", () => {
    expect(circuitTypeOf(0)).toBe("transfer-confidential");
    expect(circuitTypeOf(1)).toBe("transfer-p256-confidential");
  });

  it("names the forester circuit nowhere in the shipped source", () => {
    const files = sources(SOURCE_ROOT);
    const found = files.flatMap((path) => {
      const text = readFileSync(path, "utf8");
      // `transfer-zone` is a prefix of `transfer-zone-authority`, so match the
      // quoted literal rather than the bare substring.
      return UNREACHABLE.filter((circuit) => text.includes(`"${circuit}"`)).map(
        (circuit) => `${path}: ${circuit}`,
      );
    });
    expect(found).toEqual([]);
  });

  it("reaches exactly the seven circuits the SDK can prove", () => {
    const reachable = new Set(
      sources(SOURCE_ROOT).flatMap((path) => {
        const text = readFileSync(path, "utf8");
        return REACHABLE.filter((circuit) => text.includes(`"${circuit}"`));
      }),
    );
    expect([...reachable].sort()).toEqual(REACHABLE);
  });
});
