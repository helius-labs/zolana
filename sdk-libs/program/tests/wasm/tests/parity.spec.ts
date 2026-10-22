import { expect, test } from "./harness";
import { fixture, type Program } from "./fixtures";

const programs: Program[] = ["escrow", "withdraw"];

for (const program of programs) {
  test(`the ${program} transaction equals the native path field for field`, async ({
    harness,
  }) => {
    const data = fixture(program);
    const result = await harness.page.evaluate(
      ({ program, data }) =>
        window.zkProgram.transaction(program, data.inputs, data.sender, data.payer),
      { program, data },
    );
    const transaction = {
      finalizedTx: result.transaction.finalizedTx,
      publicHash: result.transaction.publicHash,
    };

    expect({
      transaction,
      proofInputsSha256: result.proofInputsSha256,
      encoding: result.encoding,
    }).toEqual({
      transaction: data.transaction,
      proofInputsSha256: data.proofInputsSha256,
      encoding: {
        proofInputs: "Uint8Array",
        publicHash: "Uint8Array",
        outputHash: "Uint8Array",
        outputAmount: "bigint",
        outputBlinding: "Uint8Array",
        inputLeafIndex: "bigint",
        inputAssetId: "bigint",
        inputOwner: "Uint8Array",
        resolvedOwnerTag: "Uint8Array",
        sender: "Uint8Array",
        payer: "string",
        outputTreeId: "number",
      },
    });
  });
}
