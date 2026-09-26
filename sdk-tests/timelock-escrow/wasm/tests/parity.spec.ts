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
        window.escrow.transaction(program, data.inputs, data.sender, data.payer),
      { program, data },
    );
    const { proofInputs: _proofInputs, ...transaction } = result.transaction;

    expect({
      transaction,
      proofInputsSha256: result.proofInputsSha256,
      amountType: result.amountType,
      proofInputsType: result.proofInputsType,
    }).toEqual({
      transaction: data.transaction,
      proofInputsSha256: data.proofInputsSha256,
      amountType: "bigint",
      proofInputsType: "Uint8Array",
    });
  });
}
