import { expect, test } from "./harness";
import { fixture, keyUrl } from "./fixtures";

test("proof inputs built on the main thread prove in a worker, twice with fresh randomness", async ({
  harness,
}) => {
  const data = fixture("escrow");
  const result = await harness.page.evaluate(
    async ({ url, data }) => {
      const { transaction } = await window.escrow.transaction(
        "escrow",
        data.inputs,
        data.sender,
        data.payer,
      );
      const first = await window.escrow.proveInWorker(
        "escrow",
        "arkworks",
        url,
        transaction.proofInputs,
      );
      const second = await window.escrow.proveInWorker(
        "escrow",
        "arkworks",
        url,
        transaction.proofInputs,
      );
      return {
        firstVerifies: await window.escrow.verify(data.verifyingKey, first),
        secondVerifies: await window.escrow.verify(data.verifyingKey, second),
        proofsDiffer: JSON.stringify(first.proof) !== JSON.stringify(second.proof),
        publicHashes: [first.publicHash, second.publicHash],
      };
    },
    { url: keyUrl("escrow", "arkworks"), data },
  );

  expect(result).toEqual({
    firstVerifies: true,
    secondVerifies: true,
    proofsDiffer: true,
    publicHashes: [data.transaction.publicHash, data.transaction.publicHash],
  });
});
