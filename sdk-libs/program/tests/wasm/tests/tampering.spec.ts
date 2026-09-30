import { expect, test } from "./harness";
import { fixture, keyUrl } from "./fixtures";

test("a proof with A and C swapped in either form, or checked against another public hash, fails", async ({
  harness,
}) => {
  const data = fixture("escrow");
  const result = await harness.page.evaluate(
    async ({ url, data }) => {
      const { transaction } = await window.zkProgram.transaction(
        "escrow",
        data.inputs,
        data.sender,
        data.payer,
      );
      const proof = await window.zkProgram.prove("escrow", "arkworks", url, transaction.proofInputs);
      const swapped = { ...proof, proof: { a: proof.proof.c, b: proof.proof.b, c: proof.proof.a } };
      const compressedSwapped = {
        ...proof,
        compressedProof: {
          a: proof.compressedProof.c,
          b: proof.compressedProof.b,
          c: proof.compressedProof.a,
        },
      };
      const otherHash = {
        ...proof,
        publicHash: proof.publicHash.map((byte, index) => (index === 31 ? byte ^ 1 : byte)),
      };
      return {
        valid: await window.zkProgram.verify(data.verifyingKey, proof),
        swapped: await window.zkProgram.verify(data.verifyingKey, swapped),
        compressedSwapped: await window.zkProgram.verify(data.verifyingKey, compressedSwapped),
        otherHash: await window.zkProgram.verify(data.verifyingKey, otherHash),
      };
    },
    { url: keyUrl("escrow", "arkworks"), data },
  );

  expect(result).toEqual({
    valid: true,
    swapped: false,
    compressedSwapped: false,
    otherHash: false,
  });
});
