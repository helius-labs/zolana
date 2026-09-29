import { expect, test } from "./harness";
import { fixture, keyUrl, zkeyVerifyingKeyUrl, type KeyFormat, type Program } from "./fixtures";

const programs: Program[] = ["escrow", "withdraw"];
const formats: KeyFormat[] = ["arkworks", "zkey"];

for (const program of programs) {
  for (const format of formats) {
    test(`${program} proves in wasm and verifies with groth16-solana (${format} key)`, async ({
      harness,
    }) => {
      const data = fixture(program);
      const verifyingKey = format === "zkey" ? zkeyVerifyingKeyUrl(program) : data.verifyingKey;
      const result = await harness.page.evaluate(
        async ({ program, format, url, data, verifyingKey }) => {
          const { transaction } = await window.escrow.transaction(
            program,
            data.inputs,
            data.sender,
            data.payer,
          );
          const proof = await window.escrow.prove(program, format, url, transaction.proofInputs);
          return {
            verified: await window.escrow.verify(verifyingKey, proof),
            proofPublicHash: proof.publicHash,
            transactionPublicHash: transaction.publicHash,
          };
        },
        { program, format, url: keyUrl(program, format), data, verifyingKey },
      );

      expect(result).toEqual({
        verified: true,
        proofPublicHash: data.transaction.publicHash,
        transactionPublicHash: data.transaction.publicHash,
      });
    });
  }
}
