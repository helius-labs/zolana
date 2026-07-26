/// <reference types="node" />

/**
 * PKP-08 / P5 characterisation: which live prover G2 B points take the Rust
 * `alt_bn128_g2_compress_be` fallback, and why TypeScript noble rejects them.
 *
 * Does not change production compression behaviour.
 */

import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { bn254 } from "@noble/curves/bn254.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { bytesToBigInt } from "../../src/internal.js";
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
  readonly nobleAssert: "ok" | "throw";
  readonly nobleMessage?: string;
  readonly onCurveFp2: boolean;
  readonly bHex: string;
}

describe.skipIf(!LIVE)("P5 live G2 compression characterisation", () => {
  let owned: OwnedProver;
  let client: ProverClient;

  beforeAll(async () => {
    owned = await ensureLocalProver();
    client = new ProverClient({ url: owned.url });
  }, 180_000);

  afterAll(async () => {
    await owned.stop();
  });

  it(
    "samples confidential eddsa 1x1 proofs and classifies B-point compression",
    async () => {
      const samples: Sample[] = [];
      for (let index = 0; index < SAMPLES; index++) {
        const assembled = buildConfidentialWitness("eddsa", { inputs: 1, outputs: 1 });
        const proof = await client.prove(assembled.proverInputs);
        samples.push(classify(index, proof));
      }

      const tsOk = samples.filter((sample) => sample.tsCompress).length;
      const rustOnly = samples.filter((sample) => !sample.tsCompress && sample.rustCompress).length;
      const bothFail = samples.filter((sample) => !sample.tsCompress && !sample.rustCompress).length;
      const report = {
        samples: SAMPLES,
        tsCompressOk: tsOk,
        rustFallbackNeeded: rustOnly,
        bothFail,
        nobleThrow: samples.filter((sample) => sample.nobleAssert === "throw").length,
        onCurveFp2: samples.filter((sample) => sample.onCurveFp2).length,
        firstReject: samples.find((sample) => !sample.tsCompress),
        all: samples.map((sample) => ({
          index: sample.index,
          tsCompress: sample.tsCompress,
          rustCompress: sample.rustCompress,
          nobleAssert: sample.nobleAssert,
          nobleMessage: sample.nobleMessage,
          onCurveFp2: sample.onCurveFp2,
        })),
      };
      const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../..");
      const out = path.join(
        workspace,
        "planning/typescript-sdk-port/row-updates/g2-compression-live.json",
      );
      writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
      // Surface the rates in the assertion message so CI logs keep them.
      expect(
        { tsCompressOk: tsOk, rustFallbackNeeded: rustOnly, bothFail, samples: SAMPLES },
        JSON.stringify(report.all.slice(0, 3)),
      ).toMatchObject({ samples: SAMPLES });
      expect(rustOnly + tsOk + bothFail).toBe(SAMPLES);
    },
    900_000,
  );
});

function classify(index: number, proof: Proof): Sample {
  const b = proof.b;
  const values = [0, 32, 64, 96].map((offset) => bytesToBigInt(b.subarray(offset, offset + 32)));
  const [x0, x1, y0, y1] = values;
  let nobleAssert: "ok" | "throw" = "ok";
  let nobleMessage: string | undefined;
  let onCurveFp2 = false;
  try {
    const point = bn254.G2.Point.fromAffine({
      x: { c0: x0!, c1: x1! },
      y: { c0: y0!, c1: y1! },
    });
    onCurveFp2 = true;
    try {
      point.assertValidity();
    } catch (error) {
      nobleAssert = "throw";
      nobleMessage = error instanceof Error ? error.message : String(error);
    }
  } catch (error) {
    onCurveFp2 = false;
    nobleAssert = "throw";
    nobleMessage = error instanceof Error ? error.message : String(error);
  }

  let tsCompress = false;
  try {
    compressProof(proof);
    tsCompress = true;
  } catch {
    tsCompress = false;
  }

  let rustCompress = false;
  try {
    rustCompressProof(proofWire(proof));
    rustCompress = true;
  } catch {
    rustCompress = false;
  }

  return {
    index,
    tsCompress,
    rustCompress,
    nobleAssert,
    ...(nobleMessage === undefined ? {} : { nobleMessage }),
    onCurveFp2,
    bHex: Buffer.from(b).toString("hex"),
  };
}
