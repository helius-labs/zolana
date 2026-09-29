import { expect, test } from "./harness";
import { fixture, keyUrl } from "./fixtures";

test("dummyWalletUtxo fills unused escrow slots without changing the public hash", async ({
  harness,
}) => {
  const data = fixture("escrow");
  const result = await harness.page.evaluate(
    async ({ url, data }) => {
      const inputs = structuredClone(data.inputs) as {
        private: { tokenUtxosAssetA: unknown[] };
      };
      const dummy = window.escrow.dummyWalletUtxo(3);
      inputs.private.tokenUtxosAssetA = inputs.private.tokenUtxosAssetA.map((utxo, slot) =>
        slot < 2 ? utxo : window.escrow.dummyWalletUtxo(3),
      );
      const { transaction } = await window.escrow.transaction(
        "escrow",
        inputs,
        data.sender,
        data.payer,
      );
      const proof = await window.escrow.prove("escrow", "arkworks", url, transaction.proofInputs);
      return {
        dummyOwner: (dummy.utxo as { owner: number[] }).owner,
        dummyTreeId: dummy.treeId,
        publicHash: transaction.publicHash,
        verified: await window.escrow.verify(data.verifyingKey, proof),
      };
    },
    { url: keyUrl("escrow", "arkworks"), data },
  );

  expect(result).toEqual({
    dummyOwner: new Array(34).fill(0),
    dummyTreeId: 3,
    publicHash: data.transaction.publicHash,
    verified: true,
  });
});
