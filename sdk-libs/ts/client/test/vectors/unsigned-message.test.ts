import { describe, expect, it } from "vitest";

import proverFixtureJson from "../../../fixtures/client/prover-shapes-v1.json" with { type: "json" };
import proofFixture from "../../../fixtures/client/proof-validity-v1.json" with { type: "json" };
import rpcFixture from "../../../fixtures/client/rpc-indexer-v1.json" with { type: "json" };
import { buildUnsignedTransaction } from "../../src/client.js";
import { encodeBase58 } from "../../src/internal.js";
import { assemble } from "../../src/prover/assembly.js";
import { compressProof, parseProof } from "../../src/prover/proof.js";
import { buildProofInputs, hex, type ProverShapesFixture } from "../helpers/prover-vectors.js";

const proverFixture = proverFixtureJson as ProverShapesFixture;

function transactProof() {
  const c = proofFixture.expected.vanilla.uncompressed.cBytes;
  const b = proofFixture.expected.vanilla.uncompressed.bBytes;
  const g1 = [`0x${c.slice(0, 64)}`, `0x${c.slice(64)}`];
  return compressProof(
    parseProof(
      {
        ar: g1,
        bs: [
          [`0x${b.slice(0, 64)}`, `0x${b.slice(64, 128)}`],
          [`0x${b.slice(128, 192)}`, `0x${b.slice(192)}`],
        ],
        krs: g1,
      },
      false,
    ),
  ).toTransactProof();
}

describe("frozen unsigned legacy messages", () => {
  const source = buildProofInputs(proverFixture, "eddsa", { inputs: 1, outputs: 2 });
  const data = assemble(source.proofInputs, source.spendProofs).withProof(transactProof());

  it.each([
    [undefined, rpcFixture.expected.legacyMessages.limitOnlyBytes],
    [7n, rpcFixture.expected.legacyMessages.limitAndPriceBytes],
  ] as const)("serializes the exact message with compute price %s", (price, expected) => {
    const transaction = buildUnsignedTransaction({
      computeUnitLimit: Number(rpcFixture.inputs.computeUnitLimit),
      ...(price === undefined ? {} : { computeUnitPriceMicroLamports: price }),
      feePayer: rpcFixture.inputs.feePayer as never,
      tree: rpcFixture.inputs.tree as never,
      recentBlockhash: encodeBase58(
        Uint8Array.from(rpcFixture.inputs.blockhashBytes.match(/.{2}/gu) ?? [], (byte) =>
          Number.parseInt(byte, 16),
        ),
      ),
      data,
    });

    expect(hex(transaction.messageBytes)).toBe(expected);
    expect(transaction.signatures).toEqual([undefined]);
  });
});
