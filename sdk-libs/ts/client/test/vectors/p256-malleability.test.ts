import type { Bytes32, Bytes64 } from "@zolana/interface";
import { SigningKey } from "@zolana/keypair";
import { describe, expect, it } from "vitest";

import proverFixtureJson from "../../../fixtures/client/prover-shapes-v1.json" with { type: "json" };
import { bigintToBytes } from "../../src/internal.js";
import { bytes, hex, type ProverShapesFixture } from "../helpers/prover-vectors.js";

const fixture = proverFixtureJson as ProverShapesFixture;

const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

// Rust never normalizes s and the circuit range-checks it against the curve
// order only, so the Rust-captured shapes below carry s above n/2. Every one of
// them must verify here, and TypeScript signing must reproduce its bytes.
const HIGH_S_SHAPES = ["4x3", "4x4", "5x3"];

function shapeName(shape: Readonly<{ inputs: string; outputs: string }>): string {
  return `${shape.inputs}x${shape.outputs}`;
}

describe("P256 signature malleability", () => {
  const rail = fixture.expected.rails.find((value) => value.rail === "p256");
  if (!rail) throw new Error("missing P256 fixture rail");
  const signing = SigningKey.fromBytes(bytes(fixture.inputs.p256SecretBytes) as Bytes32);

  const highS: string[] = [];
  for (const shape of rail.shapes) {
    const json = shape.proverJson;
    const digest = bigintToBytes(
      (BigInt(String(json.p256MessageHashHigh)) << 128n) | BigInt(String(json.p256MessageHashLow)),
    );
    const s = BigInt(String(json.p256SigS));
    if (s > P256_ORDER / 2n) highS.push(shapeName(shape.shape));
    const signature = new Uint8Array(64) as Bytes64;
    signature.set(bigintToBytes(BigInt(String(json.p256SigR))));
    signature.set(bigintToBytes(s), 32);

    it(`${shapeName(shape.shape)} verifies and reproduces the Rust signature`, () => {
      expect(signing.verify(digest, signature)).toBe(true);
      expect(hex(signing.sign(digest))).toBe(hex(signature));
    });
  }

  it("covers the shapes whose Rust signature is above n/2", () => {
    expect(highS).toEqual(HIGH_S_SHAPES);
  });
});
