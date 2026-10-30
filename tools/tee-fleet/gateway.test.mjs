import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import { build } from "esbuild";
import { launchBrowser } from "./browser.mjs";
import { createMockGateway, createRecipientRouter, listen, recipientId } from "./gateway.mjs";
import { fixtureAuthority, fixtureProver } from "./fixtures.mjs";
import { policyFixture } from "./policy-fixture.mjs";

const root = new URL("../../", import.meta.url);
const dist = new URL("sdk-libs/ts/dist/", root);
const apiKey = "fixture-only-key";

async function sdkBundle(authority, platform, outfile) {
  await build({
    stdin: {
      contents: `
      export { tufTeePolicy } from ${JSON.stringify(new URL("client/prover/tee/tuf-browser.js", dist).pathname)};
      export { ZolanaClient } from ${JSON.stringify(new URL("client/index.js", dist).pathname)};
      export { ProverClient } from ${JSON.stringify(new URL("client/prover/client.js", dist).pathname)};
      export { teeFleetPolicyFromJson } from ${JSON.stringify(new URL("client/prover/tee/fleet.js", dist).pathname)};
      export { TeeSession } from ${JSON.stringify(new URL("client/prover/tee/session.js", dist).pathname)};
      export { composeSignal } from ${JSON.stringify(new URL("client/internal.js", dist).pathname)};
    `,
      resolveDir: root.pathname,
    },
    bundle: true,
    platform,
    format: "esm",
    outfile,
    ...(platform === "node"
      ? {
          banner: {
            js: 'import { createRequire } from "node:module"; const require = createRequire(import.meta.url);',
          },
        }
      : {}),
    plugins: [
      {
        name: "test-only-nitro-root",
        setup(context) {
          context.onLoad({ filter: /\/tee\/nitro\.js$/ }, async ({ path }) => {
            const source = await readFile(path, "utf8");
            const needle = "anchors: Object.freeze([AWS_NITRO_ROOT_G1])";
            assert.equal(
              source.split(needle).length,
              2,
              "test anchor patch must match exactly once",
            );
            return {
              contents: source.replace(
                needle,
                `anchors: Object.freeze([new Uint8Array(${JSON.stringify([...authority.root])})])`,
              ),
              loader: "js",
            };
          });
        },
      },
    ],
  });
}

test(
  "mock GK → recipient router → three independent encrypted provers",
  { timeout: 120_000 },
  async (t) => {
    const staging = await mkdtemp(new URL(".tmp-", import.meta.url).pathname);
    const servers = [];
    let browser;
    try {
      const authority = fixtureAuthority();
      const provers = await Promise.all([0, 1, 2].map((n) => fixtureProver(authority, n)));
      const deployments = [];
      for (let i = 0; i < provers.length; i++) {
        const server = await listen(provers[i].handler);
        servers.push(server);
        deployments.push({
          id: `generation-${i}`,
          region: ["eu-north-1", "us-east-1", "ap-southeast-1"][i],
          origin: server.url,
          recipientId: provers[i].recipientId,
        });
      }
      const router = createRecipientRouter({ deployments });
      const routerServer = await listen(router.handler);
      servers.push(routerServer);
      const browserBundle = join(staging, "browser.mjs");
      await Promise.all([
        sdkBundle(authority, "node", join(staging, "sdk.mjs")),
        sdkBundle(authority, "browser", browserBundle),
      ]);
      const sdk = await import(pathToFileURL(join(staging, "sdk.mjs")).href);
      let published;
      const assets = await listen(async (request, response) => {
        if (request.url.startsWith("/policy/")) {
          const data = published?.files[request.url.slice("/policy/".length)];
          response.writeHead(data === undefined ? 404 : 200, {
            "content-type": "application/json",
          });
          response.end(data);
        } else if (request.url === "/sdk.mjs") {
          response.writeHead(200, { "content-type": "application/javascript" });
          response.end(await readFile(browserBundle));
        } else {
          response.writeHead(200, { "content-type": "text/html" });
          response.end(
            '<!doctype html><script type="module">import * as sdk from "/sdk.mjs"; window.sdk = sdk;</script>',
          );
        }
      });
      servers.push(assets);
      const gateway = createMockGateway({
        apiKey,
        origin: routerServer.url,
        allowedOrigins: [assets.url],
      });
      const gatewayServer = await listen(gateway.handler);
      servers.push(gatewayServer);
      const url = `${gatewayServer.url}/v1/zolana?api-key=${apiKey}`;
      const fleetJson = {
        schema_version: 1,
        network: "test-fleet",
        revision: 1,
        expires_at: Math.floor(Date.now() / 1000) + 1800,
        deployments: provers.map((p, i) => ({
          id: deployments[i].id,
          region: deployments[i].region,
          policy: p.policy,
        })),
      };
      published = policyFixture(fleetJson);
      const fleet = sdk.teeFleetPolicyFromJson(fleetJson, "test-fleet");
      const clients = provers.map(() => new sdk.ProverClient({ url, tee: fleet }));

      await t.test("shared wire IDs match the committed vectors", async () => {
        const vectors = JSON.parse(
          await readFile(new URL("prover/tee/testdata/recipient_ids.json", root), "utf8"),
        );
        for (const vector of vectors.vectors)
          assert.equal(
            recipientId(Buffer.from(vector.hpke_public_key, "hex")),
            vector.recipient_id,
          );
      });
      await t.test(
        "each client attests a different region and cached requests stay with its recipient",
        async () => {
          for (let i = 0; i < clients.length; i++) {
            assert.equal((await clients[i].health()).status, `fixture-region-${i}`);
            assert.equal((await clients[i].health()).status, `fixture-region-${i}`);
          }
          assert.deepEqual(
            provers.map((p) => [p.stats.attestations, p.stats.decrypted, p.stats.failed]),
            [
              [1, 2, 0],
              [1, 2, 0],
              [1, 2, 0],
            ],
          );
        },
      );
      await t.test(
        "encrypted POST body and GET ciphertext survive both proxies and retain query bytes",
        async () => {
          const session = new sdk.TeeSession(fleet);
          const signal = sdk.composeSignal({ timeoutMs: 5000 }, "health");
          try {
            for (const method of ["POST", "GET"]) {
              const route =
                method === "POST" ? "/prove/transfer_2_2/indexed" : "/prove/transfer_2_2/status";
              const call = new URL(
                `${gatewayServer.url}/v1/zolana${route}?flag&tenant=a%20b&api%2Dkey=${apiKey}&v=%2f&v=%2F&literal=a?b`,
              );
              const response = await session.send({
                fetch,
                attestationUrl: new URL(
                  `${gatewayServer.url}/v1/zolana/tee/v1/attestation?api-key=${apiKey}`,
                ),
                url: call,
                route,
                method,
                headers: {
                  "X-Sync": "true",
                  Authorization: "must-not-forward",
                  "X-API-Key": "must-not-forward",
                },
                ...(method === "POST" ? { body: '{"private":"synthetic"}' } : {}),
                signal,
                maxResponseBytes: 4096,
              });
              assert.equal(response.status, 200);
              assert.equal((await response.json()).status, "fixture-region-0");
              assert.equal(
                provers[0].stats.requests.at(-1).query,
                "?flag&tenant=a%20b&v=%2f&v=%2F&literal=a?b",
              );
            }
          } finally {
            signal.cleanup();
          }
        },
      );
      await t.test(
        "generation loss triggers fresh attestation and encryption without forwarding stale ciphertext",
        async () => {
          const before = provers[0].stats.decrypted;
          router.setAvailable("generation-0", false);
          const status = (await clients[0].health()).status;
          assert.match(status, /^fixture-region-[12]$/u);
          assert.equal(provers[0].stats.decrypted, before);
          assert.equal(router.stats.unavailable, 1);
          assert.equal((await clients[0].health()).status, status);
          router.setAvailable("generation-0", true);
        },
      );
      await t.test("unknown key never falls back to round robin", async () => {
        const before = provers.map((p) => p.stats.decrypted);
        const response = await fetch(
          `${gatewayServer.url}/v1/zolana/prove/transfer_2_2?api-key=${apiKey}`,
          {
            method: "POST",
            headers: { "zolana-tee": "v1", "zolana-tee-key-id": "ff".repeat(32) },
            body: "opaque",
          },
        );
        assert.equal(response.status, 503);
        assert.deepEqual(await response.json(), { code: "tee_generation_unavailable" });
        assert.deepEqual(
          provers.map((p) => p.stats.decrypted),
          before,
        );
      });
      await t.test("missing routing header and stripped response marker fail closed", async () => {
        const before = router.stats.attestations;
        gateway.faults.dropRequest.add("zolana-tee-key-id");
        await assert.rejects(clients[1].health(), { code: "CLIENT_PROVER_HTTP" });
        assert.equal(router.stats.attestations, before);
        gateway.faults.dropRequest.clear();
        gateway.faults.dropResponse.add("zolana-tee");
        await assert.rejects(clients[1].health(), { code: "CLIENT_PROVER_TEE_ENCRYPTION" });
        gateway.faults.dropResponse.clear();
      });
      await t.test(
        "credentials, duplicate credentials, arbitrary routes and origins are refused",
        async () => {
          for (const query of [
            "api-key=wrong",
            `api-key=${apiKey}&api-key=${apiKey}`,
            `api-key=${apiKey}&api%2dkey=wrong`,
          ]) {
            const response = await fetch(`${gatewayServer.url}/v1/zolana/health?${query}`);
            assert.equal(response.status, 401);
          }
          assert.equal((await fetch(`${gatewayServer.url}/metrics?api-key=${apiKey}`)).status, 404);
          assert.equal(
            (
              await fetch(url.replace("?", "/health?"), {
                headers: { origin: "https://untrusted.invalid" },
              })
            ).status,
            403,
          );
        },
      );
      await t.test(
        "fresh nonce mismatch rejects evidence before any encrypted request",
        async () => {
          for (const p of provers) p.faults.wrongNonce = true;
          const before = provers.map((p) => p.stats.decrypted);
          await assert.rejects(new sdk.ProverClient({ url, tee: fleet }).health(), {
            code: "CLIENT_PROVER_TEE_ATTESTATION",
          });
          assert.deepEqual(
            provers.map((p) => p.stats.decrypted),
            before,
          );
          for (const p of provers) p.faults.wrongNonce = false;
        },
      );
      await t.test(
        "fleet outage stays within the caller deadline and never forwards ciphertext elsewhere",
        async () => {
          const before = provers.map((p) => p.stats.decrypted);
          for (const d of deployments) router.setAvailable(d.id, false);
          const started = Date.now();
          try {
            await assert.rejects(clients[2].health({ timeoutMs: 150 }), { code: "CLIENT_TIMEOUT" });
            assert.ok(Date.now() - started < 1500);
            assert.deepEqual(
              provers.map((p) => p.stats.decrypted),
              before,
            );
          } finally {
            for (const d of deployments) router.setAvailable(d.id, true);
          }
        },
      );
      await t.test(
        "cancellation propagates through both proxies without replaying the request",
        async () => {
          for (const p of provers) p.faults.delayMs = 2000;
          const before = provers.reduce((n, p) => n + p.stats.decrypted, 0);
          const controller = new AbortController();
          for (const p of provers) p.faults.afterDecryption = () => controller.abort();
          try {
            await assert.rejects(
              clients[1].health({ signal: controller.signal, timeoutMs: 5000 }),
              {
                code: "CLIENT_ABORTED",
              },
            );
            const cancelledBy = Date.now() + 5000;
            while (!provers.some((p) => p.stats.cancelled > 0) && Date.now() < cancelledBy) {
              await new Promise((resolve) => setTimeout(resolve, 10));
            }
            assert.equal(
              provers.reduce((n, p) => n + p.stats.decrypted, 0),
              before + 1,
            );
            assert.ok(provers.some((p) => p.stats.cancelled > 0));
          } finally {
            for (const p of provers) {
              p.faults.delayMs = 0;
              p.faults.afterDecryption = undefined;
            }
          }
        },
      );
      await t.test(
        "a real browser performs CORS preflights, verifies quotes and opens encrypted responses",
        async () => {
          browser = await launchBrowser();
          const page = await browser.newPage();
          const errors = [];
          page.on("pageerror", (error) => errors.push(error.message));
          await page.goto(assets.url);
          await page.waitForFunction(() => Boolean(window.sdk));
          const before = gateway.stats.preflights;
          const results = await page.evaluate(
            async ({ url, policyOptions }) => {
              const fleet = window.sdk.tufTeePolicy(policyOptions);
              const client = new window.sdk.ZolanaClient({
                solanaRpcUrl: "http://127.0.0.1:8899",
                indexerUrl: undefined,
                proverUrl: url,
                proverTee: fleet,
              });
              window.gatewayClient = client;
              return [(await client.proverHealth()).status, (await client.proverHealth()).status];
            },
            {
              url,
              policyOptions: {
                network: "test-fleet",
                rootJson: published.root,
                metadataUrl: `${assets.url}/policy/metadata/`,
                targetsUrl: `${assets.url}/policy/targets/`,
                databaseName: "gateway-test-policy",
              },
            },
          );
          assert.equal(results[0], results[1]);
          assert.match(results[0], /^fixture-region-[012]$/u);
          assert.ok(gateway.stats.preflights > before);
          const selectedRegion = Number(results[0].slice(-1));
          router.setAvailable(`generation-${selectedRegion}`, false);
          try {
            const next = await page.evaluate(
              async () => (await window.gatewayClient.proverHealth()).status,
            );
            assert.notEqual(next, results[0]);
            assert.match(next, /^fixture-region-[012]$/u);
          } finally {
            router.setAvailable(`generation-${selectedRegion}`, true);
          }
          assert.deepEqual(errors, []);
          await page.close();
        },
      );
    } finally {
      await browser?.close();
      for (const server of servers.reverse()) await server.close();
      await rm(staging, { recursive: true, force: true });
    }
  },
);
