import { test, expect } from "./harness";
import { fixture, keyUrl } from "./fixtures";
test("the compiled circuit rejects public-hash, balance and ownership mutations", async ({ harness }) => {
  const data = fixture("escrow");
  const outcomes = await harness.page.evaluate(async ({ data, url }) => {
    const input = (await window.zkProgram.transaction("escrow", data.inputs, data.sender, data.payer)).transaction.proofInputs;
    const hash = input["public_hash"];
    const ownerField = "program.private.token_utxos_asset_a[1].owner.key.bytes[0]";
    const owner = input[ownerField];
    if (hash === undefined || owner === undefined) throw new Error("fixture is missing proof inputs");
    const changedHash = { ...input, public_hash: (BigInt(hash) + 1n).toString() };
    const excessive = { ...input, "program.private.amount": "1001" };
    const changedOwner = { ...input, [ownerField]: (BigInt(owner) ^ 1n).toString() };
    const out = [];
    for (const altered of [changedHash, excessive, changedOwner]) out.push(await window.zkProgram.attempt("prove", "escrow", "streaming", url, altered));
    return out;
  }, { data, url: keyUrl("escrow", "streaming") });
  for (const outcome of outcomes) {
    expect(outcome).toHaveProperty("error");
    expect(outcome.error?.message).toMatch(/constraint|solving witness|fail the check/);
  }
});
