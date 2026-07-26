/// <reference types="node" />

/**
 * PKP-08 / P5: live prover G2 B points compress in pure TypeScript and match
 * Rust `alt_bn128_g2_compress_be` (gnark c1-first Fq2 layout).
 */

import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ProverClient } from "../../src/prover/client.js";
import { compressProof } from "../../src/prover/proof.js";
import type { Proof } from "../../src/prover/types.js";
import { proofWire, rustCompressProof } from "../helpers/groth16-verify-oracle.js";
import { ensureLocalProver, type OwnedProver } from "../helpers/p4-live-prover.js";
import { buildConfidentialWitness } from "../helpers/p4-witnesses.js";

const LIVE = process.env["ZOLANA_TEST_P5"] === "1" || process.env["ZOLANA_TEST_P4"] === "1";
const SAMPLES = 16;

interface Sample {
  readonly index: number;
  readonly tsCompress: boolean;
  readonly rustCompress: boolean;
  readonly matchesRust: boolean;
  readonly bHex: string;
}

describe.skipIf(!LIVE)("P5 live G2 compression characterisation", () => {
  let owned: OwnedProver | undefined;
  let client: ProverClient;

  beforeAll(async () => {
    owned = await ensureLocalProver();
    client = new ProverClient({ url: owned.url });
  }, 180_000);

  afterAll(async () => {
    await owned?.stop();
  });

  it(
    "compresses confidential eddsa 1x1 proofs in pure TypeScript matching Solana",
    async () => {
      const samples: Sample[] = [];
      for (let index = 0; index < SAMPLES; index++) {
        const assembled = buildConfidentialWitness("eddsa", { inputs: 1, outputs: 1 });
        const proof = await client.prove(assembled.proverInputs);
        samples.push(classify(index, proof));
      }

      const tsOk = samples.filter((sample) => sample.tsCompress).length;
      const rustOk = samples.filter((sample) => sample.rustCompress).length;
      const matched = samples.filter((sample) => sample.matchesRust).length;
      const report = {
        samples: SAMPLES,
        tsCompressOk: tsOk,
        rustCompressOk: rustOk,
        matchesRust: matched,
        rustFallbackNeeded: samples.filter((sample) => !sample.tsCompress && sample.rustCompress)
          .length,
        bothFail: samples.filter((sample) => !sample.tsCompress && !sample.rustCompress).length,
        firstReject: samples.find((sample) => !sample.tsCompress || !sample.matchesRust),
        all: samples.map((sample) => ({
          index: sample.index,
          tsCompress: sample.tsCompress,
          rustCompress: sample.rustCompress,
          matchesRust: sample.matchesRust,
        })),
      };
      const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../..");
      const out = path.join(workspace, "sdk-libs/ts/reports/g2-compression-live.json");
      writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
      expect(report, JSON.stringify(report.all.slice(0, 3))).toMatchObject({
        samples: SAMPLES,
        tsCompressOk: SAMPLES,
        rustCompressOk: SAMPLES,
        matchesRust: SAMPLES,
        rustFallbackNeeded: 0,
        bothFail: 0,
      });
    },
    900_000,
  );
});

function classify(index: number, proof: Proof): Sample {
  let tsCompress = false;
  let compressedB: Uint8Array | undefined;
  try {
    compressedB = compressProof(proof).b;
    tsCompress = true;
  } catch {
    compressedB = undefined;
  }

  let rustCompress = false;
  let matchesRust = false;
  try {
    const rust = rustCompressProof(proofWire(proof));
    rustCompress = true;
    if (compressedB !== undefined) {
      matchesRust = Buffer.from(compressedB).toString("hex") === rust.b;
    }
  } catch {
    // leave rustCompress / matchesRust false
  }

  return {
    index,
    tsCompress,
    rustCompress,
    matchesRust,
    bHex: Buffer.from(proof.b).toString("hex"),
  };
}
