// Run only against operator-owned PRI-285 test stacks. Never bypass vendor roots.
import assert from "node:assert/strict";
import { execFile, execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { createInterface } from "node:readline";
import { setTimeout as delay } from "node:timers/promises";
import { build } from "esbuild";
import { launchBrowser } from "./browser.mjs";
import { createMockGateway, createRecipientRouter, listen, recipientId } from "./gateway.mjs";

const repository = new URL("../../", import.meta.url).pathname;
const execute = promisify(execFile);
const dist = join(repository, "sdk-libs/ts/dist");
const verifier = process.env.ZOLANA_TEE_PROOF_VERIFIER;
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
const staging = await mkdtemp(new URL(".tmp-live-", import.meta.url).pathname);
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
  const apiKey = aws(
    entry.region,
    "secretsmanager",
    "get-secret-value",
    "--secret-id",
    outputs.ApiKeySecret,
  ).SecretString;
  return {
    id: entry.id,
    region: entry.region,
    origin: outputs.Url,
    recipientId: entry.recipientId,
    apiKey,
  };
}

async function bundle(platform, outfile) {
  const provider = platform === "node" ? "tuf-node.js" : "tuf-browser.js";
  await build({
    stdin: {
      contents: `
      import { createZolanaClient } from ${JSON.stringify(join(dist, "index.js"))};
      import { tufTeePolicy } from ${JSON.stringify(join(dist, "client/prover/tee", provider))};
      import { transferFixtureInputs, transferFixturePublicInputHash } from ${JSON.stringify(join(repository, "sdk-libs/ts/test/helpers/transfer-fixture.ts"))};
      import { bytesToHex } from "@noble/hashes/utils.js";
      export async function client(options) {
        const source = tufTeePolicy(options.policy);
        const observed = { encrypted: 0, attestations: 0 };
        const fetch = async (input, init) => {
          const url = new URL(input instanceof Request ? input.url : String(input));
          if (url.origin !== new URL(options.proverUrl).origin) throw new Error("unexpected fixture client endpoint");
          if (url.pathname.endsWith("/tee/v1/attestation")) observed.attestations++;
          else {
            const headers = new Headers(init?.headers);
            if (headers.get("Zolana-Tee") !== "v1" || !/^[0-9a-f]{64}$/.test(headers.get("Zolana-Tee-Key-Id") ?? "")) throw new Error("unencrypted fixture request");
            observed.encrypted++;
          }
          return globalThis.fetch(input, init);
        };
        const value = await createZolanaClient({ solanaRpcUrl: "http://127.0.0.1:8899", indexerUrl: undefined, proverUrl: options.proverUrl, proverTee: source, fetch });
        return {
          observed,
          async policy() { const p = await source.resolve({ timeoutMs: 30000 }); return { revision: p.revision, expiresAt: p.expiresAt, deployments: p.deployments.map(d => d.id) }; },
          async attest() { const p = await value.attestProver({ timeoutMs: 120000 }); return { platform: p.platform, key: bytesToHex(p.hpkePublicKey) }; },
          async prove() {
            await value.checkProverProvingKeys({ timeoutMs: 120000 });
            const p = await value.proofService.prove(transferFixtureInputs(), { timeoutMs: 180000 });
            return { a: bytesToHex(p.a), b: bytesToHex(p.b), c: bytesToHex(p.c), publicInputHash: transferFixturePublicInputHash() };
          }
        };
      }
    `,
      resolveDir: repository,
    },
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
  await writeFile(path, JSON.stringify(proof, null, 2) + "\n");
  execFileSync(verifier, ["--verify", path], { stdio: ["ignore", "pipe", "pipe"] });
  return path;
}

try {
  const deployments = manifest.deployments.map(backend);
  const router = createRecipientRouter({ deployments });
  const routerServer = await listen(router.handler);
  servers.push(routerServer);
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
    origin: routerServer.url,
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
    node: [],
    rust: [],
    browser: [],
    failover: null,
    proofVerification: "committed on-chain Groth16 verifying key",
    vendorAnchors: "production AWS Nitro root",
  };
  const only = (id) => {
    for (const entry of deployments) router.setAvailable(entry.id, entry.id === id);
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
    only(entry.id);
    const client = await sdk.client({
      proverUrl,
      policy: { ...policy, cacheDirectory: resolve(output, "node-cache") },
    });
    nodeClient = client;
    const attestation = await client.attest();
    assert.equal(attestation.platform, "aws-nitro");
    assert.equal(recipientId(Buffer.from(attestation.key, "hex")), entry.recipientId);
    await saveProof(`node-${entry.id}`, await client.prove());
    report.node.push({ id: entry.id, region: entry.region, ...client.observed, verified: true });
    await nativeProof(`rust-${entry.id}`);
    report.rust.push({ id: entry.id, region: entry.region, verified: true });
  }
  browser = await launchBrowser();
  const page = await browser.newPage();
  await page.goto(assets.url);
  await page.waitForFunction(() => Boolean(window.sdk));
  for (const entry of deployments) {
    only(entry.id);
    const attestation = await page.evaluate(
      async (options) => {
        window.liveClient = await window.sdk.client(options);
        return await window.liveClient.attest();
      },
      { proverUrl, policy: { ...policy, databaseName: "pri285-live-qualification" } },
    );
    assert.equal(attestation.platform, "aws-nitro");
    assert.equal(recipientId(Buffer.from(attestation.key, "hex")), entry.recipientId);
    const proof = await page.evaluate(async () => await window.liveClient.prove());
    await saveProof(`browser-${entry.id}`, proof);
    report.browser.push({ id: entry.id, region: entry.region, verified: true });
  }
  if (deployments.length > 1) {
    const previous = deployments.at(-1);
    const before = router.stats.forwarded[previous.id];
    for (const entry of deployments) router.setAvailable(entry.id, entry.id !== previous.id);
    const proof = await page.evaluate(async () => await window.liveClient.prove());
    await saveProof("browser-failover", proof);
    await saveProof("node-failover", await nodeClient.prove());
    assert.equal(router.stats.forwarded[previous.id], before);
    assert.ok(router.stats.unavailable > 0);
    only(previous.id);
    const rustProof = resolve(output, "rust-failover.json");
    let attested = false;
    let afterAttestation;
    await new Promise((resolveRun, rejectRun) => {
      const child = spawn(
        verifier,
        [
          "--pause-after-attestation",
          resolve(dirname(manifestPath), manifest.rootFile),
          manifest.network,
          manifest.metadataUrl,
          manifest.targetsUrl,
          resolve(output, "rust-cache"),
        ],
        {
          env: { ...process.env, ZOLANA_PROVER_URL: proverUrl, ZOLANA_TEE_PROOF_OUTPUT: rustProof },
          timeout: 240000,
          stdio: ["pipe", "pipe", "ignore"],
        },
      );
      let pending = "";
      child.stdout.on("data", (chunk) => {
        pending += chunk.toString();
        if (attested || !pending.includes("\n")) return;
        try {
          const phase = JSON.parse(pending.slice(0, pending.indexOf("\n")));
          assert.equal(phase.phase, "attested");
          assert.equal(phase.recipientId, previous.recipientId);
          afterAttestation = router.stats.forwarded[previous.id];
          for (const entry of deployments) router.setAvailable(entry.id, entry.id !== previous.id);
          attested = true;
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
    assert.equal(router.stats.forwarded[previous.id], afterAttestation);
    report.failover = {
      removed: previous.id,
      nodeVerified: true,
      browserVerified: true,
      rustVerified: true,
      staleRecipientForwarded: false,
    };
  }
  if (process.argv.includes("--lifecycle")) {
    report.lifecycle = [];
    const commands = createInterface({ input: process.stdin });
    let approvedPolicy = await nodeClient.policy();
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
          const deadline = Date.now() + 30000;
          while ((await nodeClient.policy()).revision !== command.revision) {
            assert.ok(Date.now() < deadline, "published policy revision was not observed");
            await delay(250);
          }
          approvedPolicy = await nodeClient.policy();
          const before = { ...router.stats.forwarded };
          await saveProof(`node-policy-${command.revision}`, await nodeClient.prove());
          await saveProof(
            `browser-policy-${command.revision}`,
            await page.evaluate(async () => await window.liveClient.prove()),
          );
          await nativeProof(`rust-policy-${command.revision}`);
          if (command.retired) {
            assert.equal(router.stats.forwarded[command.retired], before[command.retired]);
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
          const before = JSON.stringify(router.stats.forwarded);
          await assert.rejects(nodeClient.prove());
          assert.equal(
            await page.evaluate(async () => {
              try {
                await window.liveClient.prove();
                return false;
              } catch {
                return true;
              }
            }),
            true,
          );
          await assert.rejects(nativeProof("expired"));
          assert.equal(
            JSON.stringify(router.stats.forwarded),
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
        await writeFile(join(output, "qualification.json"), JSON.stringify(report, null, 2) + "\n");
        console.log(JSON.stringify({ phase: "complete", action: command.action }));
      }
    } finally {
      commands.close();
    }
  }
  await writeFile(join(output, "qualification.json"), JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify(report, null, 2));
} finally {
  await browser?.close();
  for (const server of servers.reverse()) await server.close();
  await rm(staging, { recursive: true, force: true });
}
