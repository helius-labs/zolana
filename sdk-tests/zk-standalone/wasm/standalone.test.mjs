// Proves and verifies the standalone fixture's Withdrawal circuit through the
// wasm package `zolana zk compile` builds from a crate that depends on the zk
// DSL alone. Run by `just test-zk-wasm`, which builds the package and the test
// keys first.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const BUILD = new URL("../../../target/zk/zolana-zk-standalone-fixture/", import.meta.url);
const { default: init } = await import(new URL("wasm-node/node.mjs", BUILD));
const wasm = await init({ threads: 1 });
const fixture = JSON.parse(readFileSync(new URL("withdrawal.json", import.meta.url), "utf8"));

function prover() {
  const key = readFileSync(new URL("withdrawal.pk", BUILD));
  const digest = readFileSync(new URL("withdrawal.pk.sha256", BUILD), "utf8").trim().split(/\s+/)[0];
  return wasm.WithdrawalProver.fromKey(key, Uint8Array.from(Buffer.from(digest, "hex")));
}

const bytes = (values) => values.map((value) => Array.from(value));

test("a standalone circuit proves in wasm and its proof verifies", () => {
  const proofInputs = wasm.withdrawalProofInputs(fixture.inputs);
  const withdrawal = prover();
  try {
    const proof = withdrawal.prove(proofInputs);
    assert.deepEqual(bytes(proof.publicInputs), fixture.publicInputs);
    assert.equal(wasm.verifyProof(Uint8Array.from(fixture.verifyingKey), proof), true);
    const otherDestination = {
      ...proof,
      publicInputs: proof.publicInputs.map((input, index) =>
        index === 3 ? input.map((byte, at) => (at === 31 ? byte ^ 1 : byte)) : input,
      ),
    };
    assert.equal(wasm.verifyProof(Uint8Array.from(fixture.verifyingKey), otherDestination), false);
  } finally {
    withdrawal.free();
  }
});

test("proof inputs breaking the circuit's rule are refused", () => {
  const inputs = {
    ...fixture.inputs,
    public: { ...fixture.inputs.public, amount: fixture.inputs.public.amount + 1 },
  };
  assert.throws(() => wasm.withdrawalProofInputs(inputs), {
    name: "CircuitError.RuleBroken",
    message: "the note commits to the paid amount and destination",
  });
});
