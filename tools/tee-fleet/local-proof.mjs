// One local CPU backend for the three independent synthetic attestation/HPKE origins.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { expectedProvingKey } from "../../sdk-libs/ts/dist/interface/proving-keys.js";

export async function localProofBackend() {
  const binary = process.env.ZOLANA_TEE_LOCAL_PROVER_BINARY;
  const directory = process.env.ZOLANA_TEE_PROVING_KEYS;
  assert.ok(binary && directory, "set the local prover binary and proving-key directory");
  const key = expectedProvingKey({ circuit: "transfer-confidential", nInputs: 2, nOutputs: 2 });
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(resolve(directory, key.name))) hash.update(chunk);
  assert.equal(hash.digest("hex"), key.sha256, "local proving key does not match the SDK pin");
  const port = async () => {
    const listener = createServer();
    await new Promise((done) => listener.listen(0, "127.0.0.1", done));
    const value = listener.address().port;
    await new Promise((done) => listener.close(done));
    return value;
  };
  const origin = `http://127.0.0.1:${await port()}`;
  const child = spawn(
    binary,
    [
      "start",
      "--prover-address",
      new URL(origin).host,
      "--metrics-address",
      `127.0.0.1:${await port()}`,
      "--keys-dir",
      directory,
      "--serve",
      "transfer_confidential_2_2",
      "--auto-download=false",
    ],
    {
      stdio: ["ignore", "ignore", "ignore"],
      env: { PATH: process.env.PATH, GOMAXPROCS: "2" },
    },
  );
  const exited = new Promise((done) => {
    child.once("exit", done);
    child.once("error", () => done(1));
  });
  const close = async () => {
    child.kill();
    const timer = setTimeout(() => child.kill("SIGKILL"), 5000);
    try {
      await exited;
    } finally {
      clearTimeout(timer);
    }
  };
  try {
    const deadline = Date.now() + 20_000;
    for (;;) {
      assert.equal(child.exitCode, null, "local prover exited during startup");
      try {
        if ((await fetch(`${origin}/health`, { signal: AbortSignal.timeout(1000) })).ok) break;
      } catch {}
      assert.ok(Date.now() < deadline, "local prover did not become ready");
      await new Promise((done) => setTimeout(done, 100));
    }
    const body = await readFile(
      new URL("../../prover/server/prover/request/testdata/transfer-2x2.json", import.meta.url),
      "utf8",
    );
    let generated = 0;
    return {
      body,
      close,
      generated: () => generated,
      async prove(plaintext) {
        const response = await fetch(`${origin}/prove/transfer_confidential_2_2`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-sync": "true" },
          body: plaintext,
          signal: AbortSignal.timeout(90_000),
        });
        assert.equal(response.status, 200, "local CPU proof failed");
        const result = await response.json();
        generated++;
        return result;
      },
    };
  } catch (error) {
    await close();
    throw error;
  }
}
