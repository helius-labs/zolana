// Child of the monorepo GK integration test; stdout is its local control channel.
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { fixtureAuthority, fixtureProver } from "./fixtures.mjs";
import { listen } from "./gateway.mjs";
import { sdkBundle } from "./sdk-bundle.mjs";
import { launchBrowser } from "./browser.mjs";
import { localProofBackend } from "./local-proof.mjs";

const replies = createInterface({ input: process.stdin });
const lines = replies[Symbol.asyncIterator]();
const receive = async () => {
  const value = await lines.next();
  assert.ok(!value.done, "GK test controller stopped");
  return JSON.parse(value.value);
};
const status = async () => {
  process.stdout.write("status\n");
  return receive();
};
const eventually = async (name, predicate) => {
  const deadline = Date.now() + 25_000;
  while (!(await predicate())) {
    assert.ok(Date.now() < deadline, `timed out: ${name}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
};
const servers = [];
const staging = await mkdtemp(new URL(".tmp-gk-sdk-", import.meta.url).pathname);
let browser;
let backend;
const proofs = [];
let native;
let nativeExit;
let nativeCommand;

try {
  backend = await localProofBackend();
  const authority = fixtureAuthority();
  const provers = await Promise.all(
    [0, 1, 2].map((i) =>
      fixtureProver(authority, i, {
        prefix: "/v1/fixture",
        credentialHeader: "x-origin-key",
        prove: backend.prove,
      }),
    ),
  );
  const ready = [true, true, true];
  const probes = [0, 0, 0];
  const origins = [];
  for (const [i, prover] of provers.entries()) {
    const label = "xyz"[i];
    prover.faults.apiKey = `fixture-credential-${label}`;
    const server = http.createServer((request, response) => {
      if (request.url === "/ready") {
        assert.equal(request.headers["x-origin-key"], prover.faults.apiKey);
        probes[i]++;
        response.writeHead(ready[i] ? 200 : 503);
        response.end();
      } else if (i === 0 && request.url.split("?")[0] === "/v1/fixture/attestation") {
        // Qualify SDK fallback through GK for an origin with only the legacy quote route.
        response.writeHead(404, { "content-type": "application/json" });
        response.end(JSON.stringify({ code: "not_found" }));
      } else void prover.handler(request, response);
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "::1", resolve);
    });
    servers.push({
      close: () =>
        new Promise((resolve) => {
          server.close(resolve);
          server.closeAllConnections();
        }),
    });
    origins.push({
      label,
      url: `http://[::1]:${server.address().port}`,
      recipient: prover.recipientId,
    });
  }
  process.stdout.write(`${JSON.stringify(origins)}\n`);
  assert.deepEqual(await receive(), { configured: true });
  await eventually("authenticated readiness probes", () => probes.every((count) => count > 0));
  await Promise.all([
    sdkBundle(authority, "node", join(staging, "node.mjs")),
    sdkBundle(authority, "browser", join(staging, "browser.mjs")),
  ]);
  const sdk = await import(pathToFileURL(join(staging, "node.mjs")).href);
  const policy = {
    schema_version: 1,
    network: "fixture",
    revision: 1,
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    deployments: provers.map((prover, i) => ({
      id: `fixture-${i}`,
      region: `region-${i}`,
      policy: prover.policy,
    })),
  };
  const full = { ...policy, revision: 2 };
  let current = { ...policy, deployments: [policy.deployments[0]] };
  const observed = [];
  const trackedFetch = (input, init) => {
    if (init?.method === "POST") {
      const headers = new Headers(init.headers);
      observed.push({ key: headers.get("zolana-tee-key-id"), enc: headers.get("zolana-tee-enc") });
    }
    return fetch(input, init);
  };
  const url = `${process.env.GK_TEST_URL}/v1/fixture?api-key=${process.env.GK_TEST_KEY}`;
  const client = new sdk.ProverClient({
    url,
    fetch: trackedFetch,
    tee: new sdk.TeePolicySource({
      network: "fixture",
      refreshIntervalMs: 1,
      load: async () => ({ policy: current, validUntil: current.expires_at }),
    }),
  });
  const key = sdk.expectedProvingKey({ circuit: "transfer-confidential", nInputs: 2, nOutputs: 2 });
  const send = async () => {
    const value = await client.send(backend.body, "sync", key, { timeoutMs: 120_000 });
    proofs.push(value);
    return value.status;
  };
  const initialUnits = (await status()).metering_units;
  assert.equal(await send(), "fixture-region-0");
  const assets = await listen(async (request, response) => {
    response.setHeader(
      "content-type",
      request.url === "/sdk.mjs" ? "application/javascript" : "text/html",
    );
    response.end(
      request.url === "/sdk.mjs"
        ? await readFile(join(staging, "browser.mjs"))
        : '<script type="module">import * as sdk from "/sdk.mjs"; window.sdk = sdk;</script>',
    );
  });
  servers.push(assets);
  browser = await launchBrowser();
  const page = await browser.newPage();
  await page.goto(assets.url);
  await page.waitForFunction(() => window.sdk);
  await page.evaluate(
    ({ url, policy, body }) => {
      const sdk = window.sdk;
      window.current = { ...policy, deployments: [policy.deployments[0]] };
      window.observed = [];
      const client = new sdk.ProverClient({
        url,
        tee: new sdk.TeePolicySource({
          network: "fixture",
          refreshIntervalMs: 1,
          load: async () => ({ policy: window.current, validUntil: window.current.expires_at }),
        }),
        fetch: (input, init) => {
          if (init?.method === "POST") {
            const headers = new Headers(init.headers);
            window.observed.push({
              key: headers.get("zolana-tee-key-id"),
              enc: headers.get("zolana-tee-enc"),
            });
          }
          return fetch(input, init);
        },
      });
      const key = sdk.expectedProvingKey({
        circuit: "transfer-confidential",
        nInputs: 2,
        nOutputs: 2,
      });
      window.proofs = [];
      window.send = async () => {
        const value = await client.send(body, "sync", key, { timeoutMs: 120_000 });
        window.proofs.push(value);
        return value.status;
      };
    },
    { url, policy, body: backend.body },
  );
  assert.equal(await page.evaluate(() => window.send()), "fixture-region-0");
  const rustBinary = process.env.ZOLANA_TEE_RUST_TEST_BINARY;
  assert.ok(rustBinary, "set ZOLANA_TEE_RUST_TEST_BINARY to the spr-client unit-test executable");
  native = spawn(
    rustBinary,
    [
      "--ignored",
      "--exact",
      "prover::client::gk_integration::gk_sdk_loopback",
      "--quiet",
      "--nocapture",
    ],
    { stdio: ["pipe", "pipe", "inherit"] },
  );
  nativeExit = new Promise((resolve, reject) => {
    native.once("exit", resolve);
    native.once("error", reject);
  });
  const nativeLines = createInterface({ input: native.stdout })[Symbol.asyncIterator]();
  nativeCommand = async (value) => {
    native.stdin.write(`${JSON.stringify(value)}\n`);
    for (;;) {
      const next = await nativeLines.next();
      assert.ok(!next.done, "Rust SDK test stopped");
      if (next.value.startsWith("{")) return JSON.parse(next.value);
    }
  };
  native.stdin.write(
    `${JSON.stringify({ url, root: [...authority.root], policy: current, body: backend.body })}\n`,
  );
  assert.equal((await nativeCommand({ action: "send" })).status, "fixture-region-0");
  assert.equal((await nativeCommand({ action: "verify", proof: proofs[0] })).verified, true);
  assert.equal(
    (await nativeCommand({ action: "verify", proof: await page.evaluate(() => window.proofs[0]) }))
      .verified,
    true,
  );
  const nativeEnc = provers[0].stats.requests.at(-1).enc;
  await nativeCommand({ action: "policy", policy: full });
  current = full;
  await page.evaluate((policy) => {
    window.current = { ...policy, revision: 2 };
  }, policy);
  ready[0] = false;
  await eventually("health supervisor disables the cached recipient", async () =>
    (await status()).disabled.includes("fixture-origin-x"),
  );
  const before = provers[0].stats.decrypted;
  const posts = observed.length;
  assert.notEqual(await send(), "fixture-region-0");
  assert.equal(observed.length, posts + 2);
  assert.equal(observed.at(-2).key, provers[0].recipientId);
  assert.notEqual(observed.at(-1).key, observed.at(-2).key);
  assert.notEqual(observed.at(-1).enc, observed.at(-2).enc);
  assert.notEqual(await page.evaluate(() => window.send()), "fixture-region-0");
  const browserPosts = await page.evaluate(() => window.observed);
  assert.equal(browserPosts.length, 3);
  assert.equal(browserPosts[1].key, provers[0].recipientId);
  assert.notEqual(browserPosts[2].key, browserPosts[1].key);
  assert.notEqual(browserPosts[2].enc, browserPosts[1].enc);
  assert.equal(provers[0].stats.decrypted, before, "disabled recipient received ciphertext");
  const nativeResult = await nativeCommand({ action: "send" });
  assert.equal(nativeResult.http_status, 200);
  assert.notEqual(nativeResult.status, "fixture-region-0");
  const nativeRegion = Number(nativeResult.status.at(-1));
  assert.notEqual(provers[nativeRegion].stats.requests.at(-1).enc, nativeEnc);
  assert.equal(provers[0].stats.decrypted, before, "disabled recipient received Rust ciphertext");
  for (const proof of [
    ...proofs.slice(1),
    ...(await page.evaluate(() => window.proofs.slice(1))),
  ]) {
    assert.equal((await nativeCommand({ action: "verify", proof })).verified, true);
    assert.equal(
      (await nativeCommand({ action: "verify", proof, wrong_statement: true })).verified,
      false,
    );
  }
  ready[0] = true;
  await eventually("automatic health recovery", async () => (await status()).disabled.length === 0);
  assert.equal(
    provers.reduce((sum, prover) => sum + prover.stats.attestations, 0),
    6,
  );
  // Each client performs two quotes and two successful encrypted requests.
  assert.equal((await status()).metering_units, initialUnits + 24);
  const counts = () => provers.reduce((sum, prover) => sum + prover.stats.decrypted, 0);
  provers.forEach((prover) => {
    prover.faults.dropResponse = true;
  });
  let count = counts();
  let attempts = observed.length;
  await assert.rejects(send(), {
    code: "CLIENT_PROVER_HTTP",
    details: { method: "prove", status: 500, attempts: 1 },
  });
  assert.equal(counts(), count + 1, "ambiguous Node POST was replayed");
  assert.equal(observed.length, attempts + 1);
  count = counts();
  attempts = browserPosts.length;
  await assert.rejects(page.evaluate(() => window.send()));
  assert.equal(counts(), count + 1, "ambiguous browser POST was replayed");
  assert.equal(await page.evaluate(() => window.observed.length), attempts + 1);
  assert.equal((await status()).metering_units, initialUnits + 24, "failed POSTs were billed");
  count = counts();
  const nativeFailure = await nativeCommand({ action: "send" });
  assert.equal(nativeFailure.http_status, 500);
  assert.equal(counts(), count + 1, "ambiguous Rust POST was replayed");
  assert.equal((await status()).metering_units, initialUnits + 24, "failed Rust POST was billed");
  assert.equal(backend.generated(), 9, "expected six successful and three lost-response proofs");
  assert.ok(provers.every((prover) => prover.stats.failed === 0));
  console.error(
    "passed: six verified Node/Rust/browser Groth16 proofs and three consumed lost-response proofs; HPKE through real GK auth, health-driven re-encryption, recovery and no POST replay",
  );
} finally {
  let nativeCode;
  if (native) {
    native.stdin.end();
    const timer = setTimeout(() => native.kill(), 10_000);
    try {
      nativeCode = await nativeExit.catch(() => 1);
    } finally {
      clearTimeout(timer);
    }
  }
  await browser?.close();
  await backend?.close();
  for (const server of servers.reverse()) await server.close();
  replies.close();
  process.stdin.pause();
  await rm(staging, { recursive: true, force: true });
  if (native) assert.equal(nativeCode, 0, "Rust SDK test failed");
}
