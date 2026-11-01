import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { launchBrowser } from "./browser.mjs";
import { fixtureAuthority, fixtureProver } from "./fixtures.mjs";
import { createMockGateway, listen } from "./gateway.mjs";
import { gkRouter } from "./gk.mjs";
import { sdkBundle } from "./sdk-bundle.mjs";

test(
  "real GK routes three independently attested keys for Node and browser clients",
  { skip: !process.env.ZOLANA_TEE_GK_BINARY, timeout: 120_000 },
  async () => {
    const staging = await mkdtemp(new URL(".tmp-gk-", import.meta.url).pathname);
    const servers = [];
    let browser;
    try {
      const authority = fixtureAuthority();
      const provers = await Promise.all([0, 1, 2].map((i) => fixtureProver(authority, i)));
      const deployments = [];
      for (const [i, prover] of provers.entries()) {
        prover.faults.apiKey = `synthetic-origin-key-${i}`;
        const server = await listen(prover.handler);
        servers.push(server);
        deployments.push({
          id: `generation-${i}`,
          region: `region-${i}`,
          recipientId: prover.recipientId,
          origin: server.url,
          apiKey: prover.faults.apiKey,
        });
      }
      const router = await gkRouter({ deployments, binary: process.env.ZOLANA_TEE_GK_BINARY });
      servers.push({ close: router.close });
      await Promise.all([
        sdkBundle(authority, "node", join(staging, "node.mjs")),
        sdkBundle(authority, "browser", join(staging, "browser.mjs")),
      ]);
      const sdk = await import(pathToFileURL(join(staging, "node.mjs")).href);
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
      const gateway = createMockGateway({
        apiKey: "synthetic-caller-key",
        origin: router.origin,
        allowedOrigins: [assets.url],
      });
      const front = await listen(gateway.handler);
      servers.push(front);
      const url = `${front.url}/v1/zolana?api-key=synthetic-caller-key`;
      const policy = {
        schema_version: 1,
        network: "synthetic-fleet",
        revision: 1,
        expires_at: Math.floor(Date.now() / 1000) + 3600,
        deployments: deployments.map((entry, i) => ({
          id: entry.id,
          region: entry.region,
          policy: provers[i].policy,
        })),
      };
      browser = await launchBrowser();
      const page = await browser.newPage();
      await page.goto(assets.url);
      await page.waitForFunction(() => window.sdk);
      for (const [i, entry] of deployments.entries()) {
        // All regions are live. The SDK's approved-key hint must select this one.
        const one = { ...policy, deployments: [policy.deployments[i]] };
        const client = new sdk.ProverClient({
          url,
          tee: sdk.teeFleetPolicyFromJson(one, policy.network),
        });
        assert.equal((await client.health()).status, `fixture-region-${i}`);
        assert.equal((await client.health()).status, `fixture-region-${i}`);
        const status = await page.evaluate(
          async ({ url, policy }) => {
            window.prover = new window.sdk.ProverClient({
              url,
              tee: window.sdk.teeFleetPolicyFromJson(policy, policy.network),
            });
            return (await window.prover.health()).status;
          },
          { url, policy: one },
        );
        assert.equal(status, `fixture-region-${i}`);
        assert.equal(provers[i].stats.failed, 0);
        assert.equal(provers[i].stats.attestations, 2);
        const session = new sdk.TeeSession(sdk.teeFleetPolicyFromJson(one, policy.network));
        const signal = sdk.composeSignal({ timeoutMs: 5000 }, "prove");
        try {
          const result = await session.send({
            fetch,
            attestationUrl: new URL(
              `${front.url}/v1/zolana/attestation?api-key=synthetic-caller-key`,
            ),
            url: new URL(
              `${front.url}/v1/zolana/prove/sample?api-key=synthetic-caller-key&tenant=a%20b`,
            ),
            route: "/prove/sample",
            method: "POST",
            headers: { "X-Sync": "true" },
            body: '{"private":"synthetic"}',
            signal,
            maxResponseBytes: 4096,
          });
          assert.equal(result.status, 200);
          assert.equal((await result.json()).status, `fixture-region-${i}`);
          assert.equal(provers[i].stats.requests.at(-1).query, "?tenant=a%20b");
          assert.equal(provers[i].stats.requests.at(-1).method, "POST");
        } finally {
          signal.cleanup();
        }
        router.setDraining(entry.id, true);
        await router.sync();
        assert.equal((await client.health()).status, `fixture-region-${i}`);
        assert.equal(
          await page.evaluate(async () => (await window.prover.health()).status),
          `fixture-region-${i}`,
        );
        const fresh = new sdk.ProverClient({
          url,
          tee: sdk.teeFleetPolicyFromJson(one, policy.network),
        });
        await assert.rejects(fresh.attest({ timeoutMs: 100 }), { code: "CLIENT_TIMEOUT" });
        router.setDraining(entry.id, false);
        await router.sync();
      }
      const client = new sdk.ProverClient({
        url,
        tee: sdk.teeFleetPolicyFromJson(policy, policy.network),
      });
      const previous = (await client.health()).status;
      const index = Number(previous.at(-1));
      const before = provers[index].stats.decrypted;
      router.setAvailable(deployments[index].id, false);
      await router.sync();
      assert.notEqual((await client.health()).status, previous);
      assert.equal(provers[index].stats.decrypted, before);
      assert.ok((await router.readStats()).unavailable > 0);
      assert.ok(gateway.stats.preflights > 0);
    } finally {
      await browser?.close();
      for (const server of servers.reverse()) await server.close();
      await rm(staging, { recursive: true, force: true });
    }
  },
);
