import { test, expect } from "./harness";
import { fixture, keyUrl } from "./fixtures";
test("the compiled circuit rejects public-hash, balance and ownership mutations", async ({ harness }) => {
  const data = fixture("escrow");
  const outcomes = await harness.page.evaluate(async ({ data, url }) => {
    const input = (await window.zkProgram.transaction("escrow", data.inputs, data.sender, data.payer)).transaction.proofInputs;
    const changedHash = structuredClone(input); changedHash.public_hash = (BigInt(changedHash.public_hash) + 1n).toString();
    const excessive = structuredClone(input); excessive.program.private.amount = 1001;
    const changedOwner = structuredClone(input);
    const ownerKey = changedOwner.program.private.tokenUtxosAssetA[1].owner.key;
    ownerKey.bytes = `0x${(parseInt(ownerKey.bytes.slice(2, 4), 16) ^ 1).toString(16).padStart(2, "0")}${ownerKey.bytes.slice(4)}`;
    const out = [];
    for (const altered of [changedHash, excessive, changedOwner]) out.push(await window.zkProgram.attempt("prove", "escrow", "streaming", url, altered));
    return out;
  }, { data, url: keyUrl("escrow", "streaming") });
  for (const outcome of outcomes) {
    expect(outcome).toHaveProperty("error");
    expect(outcome.error?.message).toMatch(/constraint|solving witness|fail the check/);
  }
});
