import { test, expect } from "./harness";
import { fixture, keyUrl } from "./fixtures";
test("the compiled circuit rejects public-hash, balance and ownership mutations", async ({ harness }) => {
  const data = fixture("escrow");
  const outcomes = await harness.page.evaluate(async ({ data, url }) => {
    const input = (await window.zkProgram.transaction("escrow", data.inputs, data.sender, data.payer)).transaction.proofInputs;
    const changedHash = structuredClone(input); changedHash.public_hash = (BigInt(changedHash.public_hash) + 1n).toString();
    const excessive = structuredClone(input); excessive.program.private.amount = 1001;
    const changedOwner = structuredClone(input); changedOwner.program.private.token_utxos_asset_a[1].owner.key.bytes[0] ^= 1;
    const out = [];
    for (const altered of [changedHash, excessive, changedOwner]) out.push(await window.zkProgram.attempt("prove", "escrow", "streaming", url, altered));
    return out;
  }, { data, url: keyUrl("escrow", "streaming") });
  for (const outcome of outcomes) expect(outcome).toHaveProperty("error");
});
