// Standalone circuit proofs through Xark's stock Node WebAssembly runtime.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { test } from "node:test";

const BUILD = new URL("../../../target/zk/spr-zk-standalone-fixture/", import.meta.url);
const require = createRequire(import.meta.url);
const wasm = require(new URL("runtime/xark_wasm.js", BUILD).pathname);
const fixture = JSON.parse(readFileSync(new URL("withdrawal.json", import.meta.url), "utf8"));
const artifacts = (name) => readFileSync(new URL(name, BUILD));

function withProver(run) {
  const trustedKey = Buffer.from(fixture.verifyingKey);
  assert.deepEqual(artifacts("vk.bin"), trustedKey, "the built verifier must match the committed native fixture");
  const schema = new wasm.Schema(artifacts("schema.json").toString());
  const session = new wasm.ProvingSession(artifacts("circuit.xbc"), artifacts("pk.bin"), artifacts("sources.json").toString());
  const verifier = new wasm.VerifyingKey(trustedKey);
  try {
    run({ schema, session, verifier });
  } finally {
    verifier.free();
    session.free();
    schema.free();
  }
}

test("a standalone circuit proves in wasm and its proof verifies", () => {
  withProver(({ schema, session, verifier }) => {
    const inputs = schema.encodeInputs(JSON.stringify(fixture.inputs));
    const bundle = session.prove(inputs);
    try {
      const expected = fixture.publicInputs.map((bytes) => BigInt(`0x${Buffer.from(bytes).toString("hex")}`).toString());
      assert.deepEqual(wasm.decode_public_inputs(bundle.publicInputs), expected);
      assert.equal(verifier.verify(bundle.proof, bundle.publicInputs), true);
      const otherDestination = {
        public: { ...fixture.inputs.public, destination_lo: fixture.inputs.public.destination_lo ^ 1 },
      };
      const altered = schema.encodePublicInputs(JSON.stringify(otherDestination));
      assert.equal(verifier.verify(bundle.proof, altered), false);
    } finally {
      bundle.free();
    }
  });
});

test("proof inputs breaking the circuit's rule are refused", () => {
  withProver(({ schema, session }) => {
    for (const altered of [
      { ...fixture.inputs, public: { ...fixture.inputs.public, amount: (BigInt(fixture.inputs.public.amount) + 1n).toString() } },
      { ...fixture.inputs, private: { ...fixture.inputs.private, blinding: "100" } },
    ]) {
      assert.throws(() => session.prove(schema.encodeInputs(JSON.stringify(altered))), /constraint|fail the check|solving witness/);
    }
  });
});
