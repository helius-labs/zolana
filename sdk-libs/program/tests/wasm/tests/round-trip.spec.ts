import { test, expect } from "./harness";
import { fixture, keyUrl, type Program } from "./fixtures";
for (const program of ["escrow", "withdraw"] as Program[]) {
  test(`${program} preserves the native transaction and verifies its Xark proof`, async ({ harness }) => {
    const data = fixture(program);
    const result = await harness.page.evaluate(async ({ program, data, url }) => {
      const tx = await window.zkProgram.transaction(program, data.inputs, data.sender, data.payer);
      const proof = await window.zkProgram.prove(program, "streaming", url, tx.transaction.proofInputs);
      return { tx: tx.transaction, verified: await window.zkProgram.verify(program, proof) };
    }, { program, data, url: keyUrl(program, "streaming") });
    expect(result.tx).toEqual(data.transaction);
    expect(result.verified).toBe(true);
    expect(result.tx.finalizedTx.outputHashes).toEqual(data.encrypted.utxoHashes);
  });
}
