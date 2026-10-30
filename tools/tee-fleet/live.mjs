// Run only against operator-owned PRI-285 test stacks. Never bypass vendor roots.
import assert from "node:assert/strict";
import { execFile, execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { createInterface } from "node:readline";
import { setTimeout as delay } from "node:timers/promises";
import { build } from "esbuild";
import { writeJson } from "./artifacts.mjs";
import { launchBrowser } from "./browser.mjs";
import { managedRouter } from "./managed.mjs";
import { createMockGateway, createRecipientRouter, listen, recipientId } from "./gateway.mjs";

const execute = promisify(execFile);
const verifier = process.env.ZOLANA_TEE_PROOF_VERIFIER;
const managedBinary = process.env.ZOLANA_TEE_ROUTER_BINARY;
const manifestPath = process.argv[2];
const output = process.argv[3];
if (!manifestPath || !output || !verifier)
  throw new Error(
    "usage: ZOLANA_TEE_PROOF_VERIFIER=<tee_policy_prove binary> node tools/tee-fleet/live.mjs <public-manifest.json> <output-directory>",
  );
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
if (
  manifest.network !== "pri285-tee-test" ||
  !Array.isArray(manifest.deployments) ||
  !manifest.deployments.length
)
  throw new Error("expected the isolated PRI-285 test fleet");
const rootJson = await readFile(resolve(dirname(manifestPath), manifest.rootFile), "utf8");
await mkdir(output, { recursive: true });
const staging = await mkdtemp(fileURLToPath(new URL(".tmp-live-", import.meta.url)));
const servers = [];
let browser;

function aws(region, ...args) {
  try {
    return JSON.parse(
      execFileSync("aws", ["--region", region, ...args, "--output", "json"], {
        encoding: "utf8",
        maxBuffer: 2 << 20,
        stdio: ["ignore", "pipe", "pipe"],
      }),
    );
  } catch {
    throw new Error("AWS read failed for the isolated test fleet");
  }
}

function backend(entry) {
  if (
    !["eu-central-1", "eu-north-1", "us-east-1", "ap-southeast-1"].includes(entry.region) ||
    !/^zolana-nitro-pri285-[a-z-]+$/u.test(entry.stackName)
  )
    throw new Error("unrecognized test deployment");
  const stack = aws(
    entry.region,
    "cloudformation",
    "describe-stacks",
    "--stack-name",
    entry.stackName,
  ).Stacks[0];
  if (!stack?.Tags?.some((tag) => tag.Key === "zolana-tool" && tag.Value === "nitro-deploy"))
    throw new Error("stack is not owned by the test deployment tool");
  const outputs = Object.fromEntries(
    stack.Outputs.map((item) => [item.OutputKey, item.OutputValue]),
  );
  if (
    !outputs.ApiKeySecret.startsWith(`arn:aws:secretsmanager:${entry.region}:558215002830:secret:`)
  )
    throw new Error("unexpected origin credential reference");
  const apiKey = managedBinary
    ? undefined
    : aws(entry.region, "secretsmanager", "get-secret-value", "--secret-id", outputs.ApiKeySecret)
        .SecretString;
  return {
    id: entry.id,
    region: entry.region,
    origin: outputs.Url,
    recipientId: entry.recipientId,
    apiKeyARN: outputs.ApiKeySecret,
    instanceId: outputs.InstanceId,
    apiKey,
  };
}

async function bundle(platform, outfile) {
  await build({
    entryPoints: [fileURLToPath(new URL("live-client.mjs", import.meta.url))],
    ...(platform === "browser"
      ? { alias: { "@heliuslabs/zolana/tee/node": "@heliuslabs/zolana/tee/browser" } }
      : {}),
    outfile,
    bundle: true,
    format: "esm",
    platform,
    ...(platform === "node"
      ? {
          banner: {
            js: 'import { createRequire } from "node:module"; const require = createRequire(import.meta.url);',
          },
        }
      : {}),
  });
}

async function saveProof(name, proof) {
  const path = join(output, `${name}.json`);
  await writeJson(path, proof);
  execFileSync(verifier, ["--verify", path], { stdio: ["ignore", "pipe", "pipe"] });
  return path;
}

try {
  const deployments = manifest.deployments.map(backend);
  let router;
  let origin;
  if (managedBinary) {
    router = await managedRouter({ deployments, binary: managedBinary, output });
    servers.push({ close: router.close });
    origin = router.origin;
  } else {
    const local = createRecipientRouter({ deployments });
    router = {
      ...local,
      sync: async () => {},
      restore: async () => {},
      readStats: async () => local.stats,
      failGeneration: async (id) => {
        for (const entry of deployments) local.setAvailable(entry.id, entry.id !== id);
      },
    };
    const server = await listen(router.handler);
    servers.push(server);
    origin = server.url;
  }
  const browserFile = join(staging, "browser.mjs");
  const nodeFile = join(staging, "node.mjs");
  await bundle("node", nodeFile);
  await bundle("browser", browserFile);
  const sdk = await import(pathToFileURL(nodeFile).href);
  const assets = await listen(async (request, response) => {
    response.writeHead(200, {
      "content-type": request.url === "/sdk.mjs" ? "application/javascript" : "text/html",
    });
    response.end(
      request.url === "/sdk.mjs"
        ? await readFile(browserFile)
        : '<!doctype html><script type="module">import * as sdk from "/sdk.mjs"; window.sdk = sdk;</script>',
    );
  });
  servers.push(assets);
  // Keep the client-facing test credential separate from regional origin keys.
  const apiKey = randomBytes(24).toString("hex");
  const front = createMockGateway({
    apiKey,
    origin,
    originApiKey: router.originApiKey,
    allowedOrigins: [assets.url],
  });
  const publicServer = await listen(front.handler);
  servers.push(publicServer);
  const proverUrl = `${publicServer.url}/v1/zolana?api-key=${apiKey}`;
  const policy = {
    network: manifest.network,
    rootJson,
    metadataUrl: manifest.metadataUrl,
    targetsUrl: manifest.targetsUrl,
    refreshIntervalMs: 1000,
  };
  const report = {
    network: manifest.network,
    managedRouter: router.metadata,
    node: [],
    rust: [],
    browser: [],
    failover: null,
    proofVerification: "committed on-chain Groth16 verifying key",
    vendorAnchors: "production AWS Nitro root",
  };
  const only = async (id) => {
    for (const entry of deployments) router.setAvailable(entry.id, entry.id === id);
    await router.sync();
  };
  const nativeArgs = [
    resolve(dirname(manifestPath), manifest.rootFile),
    manifest.network,
    manifest.metadataUrl,
    manifest.targetsUrl,
    resolve(output, "rust-cache"),
  ];
  const nativeProof = async (name) => {
    const path = resolve(output, `${name}.json`);
    try {
      await execute(verifier, nativeArgs, {
        env: { ...process.env, ZOLANA_PROVER_URL: proverUrl, ZOLANA_TEE_PROOF_OUTPUT: path },
        timeout: 240000,
        maxBuffer: 1 << 20,
      });
    } catch {
      throw new Error(`native Rust proof qualification failed for ${name}`);
    }
    await saveProof(name, JSON.parse(await readFile(path, "utf8")));
  };
  let nodeClient;
  for (const entry of deployments) {
    await only(entry.id);
    const client = await sdk.client({
      proverUrl,
      policy: { ...policy, cacheDirectory: resolve(output, "node-cache") },
    });
    nodeClient = client;
    const attestation = await client.attest();
    assert.equal(attestation.platform, "aws-nitro");
    assert.equal(recipientId(Buffer.from(attestation.key, "hex")), entry.recipientId);
    await saveProof(`node-${entry.id}`, await client.prove());
    await writeJson(join(output, `node-${entry.id}-attestation.json`), client.evidence());
    report.node.push({ id: entry.id, region: entry.region, ...client.observed, verified: true });
    await nativeProof(`rust-${entry.id}`);
    report.rust.push({ id: entry.id, region: entry.region, verified: true });
  }
  browser = await launchBrowser();
  const page = await browser.newPage();
  await page.goto(assets.url);
  await page.waitForFunction(() => Boolean(window.sdk));
  const browserClient = {
    attest: () => page.evaluate(() => window.liveClient.attest()),
    prove: () => page.evaluate(() => window.liveClient.prove()),
    policy: () => page.evaluate(() => window.liveClient.policy()),
    evidence: () => page.evaluate(() => window.liveClient.evidence()),
  };
  for (const entry of deployments) {
    await only(entry.id);
    const attestation = await page.evaluate(
      async (options) => {
        window.liveClient = await window.sdk.client(options);
        return await window.liveClient.attest();
      },
      { proverUrl, policy: { ...policy, databaseName: "pri285-live-qualification" } },
    );
    assert.equal(attestation.platform, "aws-nitro");
    assert.equal(recipientId(Buffer.from(attestation.key, "hex")), entry.recipientId);
    const proof = await browserClient.prove();
    await saveProof(`browser-${entry.id}`, proof);
    await writeJson(
      join(output, `browser-${entry.id}-attestation.json`),
      await browserClient.evidence(),
    );
    report.browser.push({ id: entry.id, region: entry.region, verified: true });
  }
  if (deployments.length > 1) {
    const previous = deployments.at(-1);
    const before = (await router.readStats()).forwarded[previous.id];
    await router.failGeneration(previous.id);
    const proof = await browserClient.prove();
    await saveProof("browser-failover", proof);
    await saveProof("node-failover", await nodeClient.prove());
    assert.equal((await router.readStats()).forwarded[previous.id], before);
    assert.ok((await router.readStats()).unavailable > 0);
    await only(previous.id);
    const rustProof = resolve(output, "rust-failover.json");
    let attested = false;
    let afterAttestation;
    await new Promise((resolveRun, rejectRun) => {
      const child = spawn(verifier, ["--pause-after-attestation", ...nativeArgs], {
        env: { ...process.env, ZOLANA_PROVER_URL: proverUrl, ZOLANA_TEE_PROOF_OUTPUT: rustProof },
        timeout: 240000,
        stdio: ["pipe", "pipe", "ignore"],
      });
      let pending = "";
      child.stdout.on("data", async (chunk) => {
        pending += chunk.toString();
        if (attested || !pending.includes("\n")) return;
        attested = true;
        try {
          const phase = JSON.parse(pending.slice(0, pending.indexOf("\n")));
          assert.equal(phase.phase, "attested");
          assert.equal(phase.recipientId, previous.recipientId);
          afterAttestation = (await router.readStats()).forwarded[previous.id];
          await router.failGeneration(previous.id);
          child.stdin.end("continue\n");
        } catch {
          child.kill();
          rejectRun(new Error("native Rust failover barrier failed"));
        }
      });
      child.once("error", () => rejectRun(new Error("native Rust failover process failed")));
      child.once("close", (code) =>
        code === 0 && attested
          ? resolveRun()
          : rejectRun(new Error("native Rust failover proof failed")),
      );
    });
    await saveProof("rust-failover", JSON.parse(await readFile(rustProof, "utf8")));
    assert.equal((await router.readStats()).forwarded[previous.id], afterAttestation);
    report.failover = {
      removed: previous.id,
      nodeVerified: true,
      browserVerified: true,
      rustVerified: true,
      staleRecipientForwarded: false,
    };
  }
  if (router.metadata?.realOutage) {
    await router.restore();
    const restored = deployments.at(-1);
    await only(restored.id);
    const attested = await nodeClient.attest();
    assert.equal(recipientId(Buffer.from(attested.key, "hex")), restored.recipientId);
    await saveProof("node-restored-generation", await nodeClient.prove());
    await writeJson(
      join(output, "node-restored-generation-attestation.json"),
      nodeClient.evidence(),
    );
    report.restoredGeneration = { id: restored.id, recipientUnchanged: true, proofVerified: true };
  }
  if (process.env.ZOLANA_TEE_CONTROL_PLANE_OUTAGE === "1") {
    assert.ok(managedBinary, "control-plane qualification requires the managed router");
    const affected = deployments.find((entry) => entry.region === "us-east-1");
    assert.ok(affected);
    await only(affected.id);
    const nodeQuote = await nodeClient.attest();
    const browserQuote = await browserClient.attest();
    for (const quote of [nodeQuote, browserQuote])
      assert.equal(recipientId(Buffer.from(quote.key, "hex")), affected.recipientId);
    await saveProof("node-before-control-plane", await nodeClient.prove());
    await saveProof("browser-before-control-plane", await browserClient.prove());
    await router.failControlPlane(affected.region);
    const before = (await router.readStats()).forwarded[affected.id];
    await saveProof("node-control-plane-failover", await nodeClient.prove());
    await saveProof("browser-control-plane-failover", await browserClient.prove());
    await nativeProof("rust-control-plane-failover");
    assert.equal((await router.readStats()).forwarded[affected.id], before);
    await router.restoreControlPlane();
    await only(affected.id);
    const restored = await nodeClient.attest();
    assert.equal(recipientId(Buffer.from(restored.key, "hex")), affected.recipientId);
    await saveProof("node-control-plane-restored", await nodeClient.prove());
    await writeJson(
      join(output, "node-control-plane-restored-attestation.json"),
      nodeClient.evidence(),
    );
    report.controlPlane = {
      affectedRegion: affected.region,
      nodeVerified: true,
      browserVerified: true,
      rustVerified: true,
      coldRouterRecovered: true,
      staleRecipientForwarded: false,
      restoredRecipientUnchanged: true,
    };
  }
  if (process.argv.includes("--lifecycle")) {
    report.lifecycle = [];
    const commands = createInterface({ input: process.stdin });
    let approvedPolicy = await nodeClient.policy();
    await writeJson(join(output, "qualification.json"), report);
    console.log(JSON.stringify({ phase: "ready", policy: approvedPolicy }));
    try {
      for await (const line of commands) {
        const command = JSON.parse(line);
        if (command.action === "finish") break;
        if (command.action === "policy") {
          assert.ok(Number.isSafeInteger(command.revision));
          assert.ok(Array.isArray(command.available) && command.available.length > 0);
          for (const id of command.available)
            assert.ok(deployments.some((entry) => entry.id === id));
          for (const entry of deployments)
            router.setAvailable(entry.id, command.available.includes(entry.id));
          for (const entry of deployments)
            router.setDraining(entry.id, entry.id === command.retired);
          await router.sync();
          const deadline = Date.now() + 30000;
          while ((await nodeClient.policy()).revision !== command.revision) {
            assert.ok(Date.now() < deadline, "published policy revision was not observed");
            await delay(250);
          }
          while ((await browserClient.policy()).revision !== command.revision) {
            assert.ok(
              Date.now() < deadline,
              "browser did not observe the published policy revision",
            );
            await delay(250);
          }
          approvedPolicy = await nodeClient.policy();
          const before = { ...(await router.readStats()).forwarded };
          await saveProof(`node-policy-${command.revision}`, await nodeClient.prove());
          await saveProof(`browser-policy-${command.revision}`, await browserClient.prove());
          await nativeProof(`rust-policy-${command.revision}`);
          if (command.retired) {
            assert.equal(
              (await router.readStats()).forwarded[command.retired],
              before[command.retired],
            );
          }
          report.lifecycle.push({
            action: "policy",
            revision: command.revision,
            verified: true,
            retiredRecipientForwarded: false,
          });
        } else if (command.action === "expiry") {
          // The operator triggers this after the actual signed CDN metadata expires.
          assert.ok(Date.now() >= approvedPolicy.expiresAt * 1000, "metadata has not expired yet");
          const response = await fetch(new URL("timestamp.json", manifest.metadataUrl), {
            signal: AbortSignal.timeout(30000),
            redirect: "error",
          });
          assert.equal(
            response.status,
            200,
            "CDN must remain available during expiry qualification",
          );
          const timestampBytes = await response.text();
          const timestamp = JSON.parse(timestampBytes);
          assert.ok(
            Date.parse(timestamp.signed.expires) <= Date.now(),
            "published timestamp has not expired",
          );
          await writeFile(join(output, "expired-timestamp.json"), timestampBytes);
          const before = JSON.stringify((await router.readStats()).forwarded);
          await assert.rejects(nodeClient.prove());
          await assert.rejects(browserClient.prove());
          await assert.rejects(nativeProof("expired"));
          assert.equal(
            JSON.stringify((await router.readStats()).forwarded),
            before,
            "expired policy forwarded a request",
          );
          report.lifecycle.push({
            action: "expiry",
            observedAt: new Date().toISOString(),
            nodeRejected: true,
            browserRejected: true,
            rustRejected: true,
            requestsForwarded: false,
          });
        } else throw new Error("unknown lifecycle command");
        await writeJson(join(output, "qualification.json"), report);
        console.log(JSON.stringify({ phase: "complete", action: command.action }));
      }
    } finally {
      commands.close();
    }
  }
  await writeJson(join(output, "qualification.json"), report);
  console.log(JSON.stringify(report, null, 2));
} finally {
  await browser?.close();
  for (const server of servers.reverse()) await server.close();
  await rm(staging, { recursive: true, force: true });
}
