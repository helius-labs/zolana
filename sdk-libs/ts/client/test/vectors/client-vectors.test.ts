import type { Bytes31 } from "@zolana/interface";
import { ProofInputUtxo } from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import proofInputFixture from "../../../fixtures/client/proof-input-v1.json" with { type: "json" };
import proofResultFixture from "../../../fixtures/client/proof-result-compression-v1.json" with { type: "json" };
import { ClientError } from "../../src/index.js";
import { compressedProof, parseProof } from "../../src/prover/proof.js";

function bytes(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/u.test(value)) throw new Error("invalid fixture hex");
  return Uint8Array.from(value.match(/.{2}/gu) ?? [], (byte) => Number.parseInt(byte, 16));
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("manifest-pinned P00 client vectors", () => {
  it("reproduces the frozen dummy-input nullifier", () => {
    const dummy = ProofInputUtxo.dummy(
      bytes(proofInputFixture.inputs.dummyBlindingBytes) as Bytes31,
    );

    expect(hex(dummy.nullifier())).toBe(proofInputFixture.expected.nullifierBytes);
    expect(dummy.isDummy()).toBe(true);
  });

  it("enforces the frozen wrong-rail commitment requirement", () => {
    try {
      parseProof(
        {
          ar: ["0x0", "0x0"],
          bs: [
            ["0x0", "0x0"],
            ["0x0", "0x0"],
          ],
          krs: ["0x0", "0x0"],
        },
        true,
      );
    } catch (error) {
      expect(error).toBeInstanceOf(ClientError);
      expect((error as ClientError).code).toBe("CLIENT_PROOF_RAIL_MISMATCH");
      expect(proofResultFixture.expected.error.code).toBe("ProofParse");
      return;
    }
    throw new Error("expected a P256 proof without a commitment to fail");
  });

  it("converts the frozen compressed P256 proof without changing bytes", () => {
    const proof = compressedProof({
      a: bytes(proofResultFixture.expected.aBytes),
      b: bytes(proofResultFixture.expected.bBytes),
      c: bytes(proofResultFixture.expected.cBytes),
      commitment: {
        commitment: bytes(proofResultFixture.expected.commitmentBytes),
        commitmentPok: bytes(proofResultFixture.expected.commitmentPokBytes),
      },
    }).toTransactProof();

    expect(proof.rail).toBe("p256");
    if (proof.rail !== "p256") throw new Error("expected P256 proof");
    expect(hex(proof.a)).toBe(proofResultFixture.expected.aBytes);
    expect(hex(proof.b)).toBe(proofResultFixture.expected.bBytes);
    expect(hex(proof.c)).toBe(proofResultFixture.expected.cBytes);
    expect(hex(proof.commitment)).toBe(proofResultFixture.expected.commitmentBytes);
    expect(hex(proof.commitmentPok)).toBe(proofResultFixture.expected.commitmentPokBytes);
  });
});
