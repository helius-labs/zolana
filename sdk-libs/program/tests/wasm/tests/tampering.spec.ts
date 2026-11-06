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

test("a proof with A and C swapped in either form, or checked against another public hash or circuit, fails", async ({ harness }) => {
  const data = fixture("escrow");
  const result = await harness.page.evaluate(async ({ data, url }) => {
    const api = window.zkProgram;
    const wasm = await import("/pkg/wasm_test_program.js");
    const { transaction } = await api.transaction("escrow", data.inputs, data.sender, data.payer);
    const proof = await api.prove("escrow", "streaming", url, transaction.proofInputs);
    // Compressed: A (32) || B (64) || C (32). On-chain: -A (64) || B (128) || C (64).
    const swap = (bytes: Uint8Array, point: number) => {
      const swapped = bytes.slice();
      swapped.set(bytes.subarray(bytes.length - point), 0);
      swapped.set(bytes.subarray(0, point), bytes.length - point);
      return swapped;
    };
    const compressed = new Uint8Array(proof.proof);
    const uncompressed = wasm.solanaProof(compressed);
    // The public inputs are a length-prefixed (u64) list of little-endian field elements:
    // flipping the low bit of the only element names another, still canonical, public hash.
    const otherInputs = new Uint8Array(proof.publicInputs);
    otherInputs[8] ^= 1;
    const otherHash = transaction.publicHash.map((byte, index) => (index === 31 ? byte ^ 1 : byte));
    const verify = (bytes: Uint8Array, publicInputs = proof.publicInputs) =>
      api.verify("escrow", { ...proof, proof: bytes, publicInputs });
    return {
      sizes: [compressed.length, uncompressed.length],
      valid: await verify(compressed),
      validUncompressed: await verify(uncompressed),
      swapped: await verify(swap(compressed, 32)),
      uncompressedSwapped: await verify(swap(uncompressed, 64)),
      otherHash: await verify(compressed, otherInputs),
      otherHashUncompressed: await verify(uncompressed, otherInputs),
      otherHashIndependent: await api.verifyIndependent("escrow", proof, otherHash),
      otherCircuit: await api.verify("withdraw", proof),
    };
  }, { data, url: keyUrl("escrow", "streaming") });

  expect(result).toEqual({
    sizes: [128, 256],
    valid: true,
    validUncompressed: true,
    swapped: false,
    uncompressedSwapped: false,
    otherHash: false,
    otherHashUncompressed: false,
    otherHashIndependent: false,
    otherCircuit: false,
  });
});
