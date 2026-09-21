import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { test } from "node:test";
import { performance } from "node:perf_hooks";
import { Budget, matrix, sweep } from "./sweep.mjs";
import { TimedTransport, parseServerStages } from "./transport.mjs";

async function temporary(action) {
  const directory = await mkdtemp(join(tmpdir(), "prover-latency-"));
  try {
    await action(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function server(action, run) {
  const instance = createServer(action);
  await new Promise((resolve) => instance.listen(0, "127.0.0.1", resolve));
  try {
    await run(`http://127.0.0.1:${instance.address().port}`);
  } finally {
    instance.closeAllConnections();
    await new Promise((resolve) => instance.close(resolve));
  }
}

test("matrix has eight families and exactly thirty slots", () => {
  const entries = matrix();
  assert.equal(entries.length, 30);
  assert.equal(new Set(entries.map((row) => row.family)).size, 8);
  assert.equal(
    entries.filter((row) => row.deployment === "candidate" && row.source === "prover").length,
    12,
  );
});

test("deployment blocks do not reserve proof attempts", async () =>
  temporary(async (directory) => {
    const results = await sweep({
      directory,
      deployments: { baseline: "https://baseline.invalid", candidate: "https://candidate.invalid" },
      indexer: "https://indexer.invalid",
      fixtures: {
        "custom-ring-base": {
          shape: "audit",
          blockedDeployments: { baseline: "key_missing", candidate: "key_pending" },
          async prove() {
            throw new Error("Blocked proofs cannot run");
          },
          async verify() {
            return false;
          },
        },
      },
    });
    assert.equal(
      results.find((row) => row.family === "custom-ring-base" && row.deployment === "baseline")
        .reason,
      "key_missing",
    );
    assert.equal(
      results.find((row) => row.family === "custom-ring-base" && row.deployment === "candidate")
        .reason,
      "key_pending",
    );
    assert.equal(JSON.parse(await readFile(join(directory, "budget.json"), "utf8")).attempts, 0);
  }));

test("server stages accept only bounded finite intervals", () => {
  const valid = { name: "prove", start_ms: 10, duration_ms: 90, complete: true };
  assert.deepEqual(parseServerStages(JSON.stringify([valid])), [valid]);
  assert.deepEqual(parseServerStages(JSON.stringify([{ ...valid, witness: "private" }])), [valid]);
  assert.deepEqual(parseServerStages(JSON.stringify([{ ...valid, start_ms: -1 }])), []);
  assert.deepEqual(parseServerStages(JSON.stringify(Array(34).fill(valid))), []);
  assert.deepEqual(parseServerStages("bad JSON"), []);
});

test("budget serializes runs and persists claims before restart", async () =>
  temporary(async (directory) => {
    const budget = await Budget.acquire(directory);
    await assert.rejects(Budget.acquire(directory), { code: "EEXIST" });
    for (let index = 0; index < 30; index++) await budget.claim();
    assert.equal(JSON.parse(await readFile(join(directory, "budget.json"), "utf8")).attempts, 30);
    await assert.rejects(budget.claim(), /exhausted/);
    await budget.close();
    const reopened = await Budget.acquire(directory);
    await assert.rejects(reopened.claim(), /exhausted/);
    await reopened.close();
  }));

test("transport records overlapping calls and reuses connections", async () =>
  server(
    (request, response) => {
      setTimeout(() => {
        response.setHeader("Content-Type", "application/json");
        response.end('{"result":{}}');
      }, 25);
    },
    async (url) => {
      const transport = new TimedTransport();
      const rows = [];
      const origin = performance.now();
      const send = () => transport.request({ url, origin, record: (row) => rows.push(row) });
      try {
        await Promise.all([send(), send()]);
        await send();
        assert.ok(rows[1].startMs < rows[0].endMs);
        assert.equal(rows[2].reusedConnection, true);
        assert.ok(rows[0].phases.firstByteMs >= rows[0].phases.uploadFinishedMs);
        assert.equal(rows[0].responseBytes, 13);
      } finally {
        transport.close();
      }
    },
  ));

test("transport aborts a response body that stalls", async () =>
  server(
    (request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.write("{");
    },
    async (url) => {
      const transport = new TimedTransport();
      try {
        await assert.rejects(
          transport.request({
            url,
            origin: performance.now(),
            signal: AbortSignal.timeout(30),
            record() {},
          }),
        );
      } finally {
        transport.close();
      }
    },
  ));

test("broken response bodies retain completed timing intervals", async () =>
  server(
    (request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.write("{");
      setTimeout(() => response.destroy(), 10);
    },
    async (url) => {
      const transport = new TimedTransport();
      let row;
      try {
        await assert.rejects(
          transport.request({
            url,
            origin: performance.now(),
            record(value) {
              row = value;
            },
          }),
        );
        assert.ok(Number.isFinite(row.endMs));
        assert.ok(row.endMs >= row.startMs);
        assert.ok(row.durationMs >= 0);
        assert.equal(row.error, "transport_error");
      } finally {
        transport.close();
      }
    },
  ));

test("JSON RPC errors abort indexer retries before proof submission", async () =>
  temporary(async (directory) => {
    let calls = 0;
    await server(
      (request, response) => {
        calls++;
        response.end('{"jsonrpc":"2.0","error":{"code":-32000,"message":"private details"}}');
      },
      async (indexer) => {
        const results = await sweep({
          directory,
          deployments: { baseline: "https://prover.invalid", candidate: "https://prover.invalid" },
          indexer,
          fixtures: {
            "transfer-confidential": {
              shape: "2x3",
              async prove({ fetch }) {
                for (let attempt = 0; attempt < 3; attempt++) {
                  try {
                    return await fetch(indexer, {
                      method: "POST",
                      body: '{"method":"getMerkleProofs"}',
                    });
                  } catch {
                    if (attempt === 2) throw new Error("Retries exhausted");
                  }
                }
              },
              async verify() {
                throw new Error("No proof should arrive");
              },
            },
          },
        });
        assert.equal(calls, 1);
        assert.equal(results.length, 1);
        assert.equal(results[0].submitted, false);
        assert.equal(results[0].requests[0].rpcError, true);
        assert.doesNotMatch(
          await readFile(join(directory, "results.json"), "utf8"),
          /private details/,
        );
      },
    );
  }));

test("HTTP failure aborts retries and stops the sweep with one charged attempt", async () =>
  temporary(async (directory) => {
    let submissions = 0;
    await server(
      (request, response) => {
        submissions++;
        assert.equal(request.headers["x-sync"], "true");
        assert.equal(request.headers["x-async"], undefined);
        response.writeHead(429);
        response.end("{}");
      },
      async (url) => {
        const results = await sweep({
          directory,
          deployments: { baseline: url, candidate: url },
          indexer: url,
          fixtures: {
            "transfer-confidential": {
              shape: "2x3",
              async prove({ fetch, signal }) {
                for (let attempt = 0; attempt < 3; attempt++) {
                  try {
                    return await fetch(`${url}/prove`, {
                      method: "POST",
                      headers: { "x-async": "true" },
                      body: "{}",
                      signal,
                    });
                  } catch {
                    if (attempt === 2) throw new Error("Retries exhausted");
                  }
                }
              },
              async verify() {
                return true;
              },
            },
          },
        });
        assert.equal(submissions, 1);
        assert.equal(results.length, 1);
        const budget = JSON.parse(await readFile(join(directory, "budget.json"), "utf8"));
        assert.equal(budget.attempts, 1);
        assert.ok(budget.stopped);
        assert.match(await readFile(join(directory, "waterfall.html"), "utf8"), /request_aborted/);
      },
    );
  }));

test("verification failure prevents later proof submissions", async () =>
  temporary(async (directory) => {
    let submissions = 0;
    await server(
      (request, response) => {
        submissions++;
        response.end('{"proof":"example"}');
      },
      async (url) => {
        const results = await sweep({
          directory,
          deployments: { baseline: url, candidate: url },
          indexer: url,
          fixtures: {
            "transfer-confidential": {
              shape: "2x3",
              async prove({ fetch, signal }) {
                return (
                  await fetch(`${url}/prove`, {
                    method: "POST",
                    body: '{"private":"never persist"}',
                    signal,
                  })
                ).json();
              },
              async verify({ wire }) {
                assert.equal(wire[0].request.private, "never persist");
                return false;
              },
            },
          },
        });
        assert.equal(submissions, 1);
        assert.equal(results[0].status, "failed");
        assert.ok(results[0].proofReceivedMs > 0);
        assert.doesNotMatch(
          await readFile(join(directory, "results.json"), "utf8"),
          /never persist|example/,
        );
      },
    );
  }));

test("queued completion reaches the verifier without another proof attempt", async () =>
  temporary(async (directory) => {
    await server(
      (request, response) => {
        response.end(
          request.method === "POST"
            ? '{"jobId":"job"}'
            : '{"status":"completed","result":{"ar":["1","2"]}}',
        );
      },
      async (url) => {
        const results = await sweep({
          directory,
          deployments: { baseline: url, candidate: url },
          indexer: url,
          fixtures: {
            "transfer-confidential": {
              shape: "2x3",
              async prove({ fetch }) {
                await fetch(`${url}/prove`, { method: "POST", body: "{}" });
                return (await fetch(`${url}/prove/status?jobId=job`)).json();
              },
              async verify({ wire }) {
                assert.deepEqual(wire[0].response.ar, ["1", "2"]);
                return false;
              },
            },
          },
        });
        assert.equal(results[0].attempt, 1);
        assert.equal(results[0].requests.length, 2);
        assert.equal(results[0].requests[1].operation, "/prove/status");
      },
    );
  }));
