// Live origins behind loopback fault bridges; GK owns routing and health decisions.
import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import { createInterface } from "node:readline";
import { setTimeout as delay } from "node:timers/promises";

export async function integrationRouter({ deployments }) {
  assert.equal(deployments.length, 3);
  const input = createInterface({ input: process.stdin });
  const replies = input[Symbol.asyncIterator]();
  const receive = async () => {
    const next = await replies.next();
    assert.ok(!next.done, "GK integration controller stopped");
    return JSON.parse(next.value);
  };
  const command = async (value) => {
    process.stdout.write(`${typeof value === "string" ? value : JSON.stringify(value)}\n`);
    return receive();
  };
  const eventually = async (message, check) => {
    const deadline = Date.now() + 40_000;
    while (!(await check())) {
      assert.ok(Date.now() < deadline, message);
      await delay(100);
    }
  };
  const states = deployments.map((entry, index) => ({
    ...entry,
    label: "xyz"[index],
    available: true,
    draining: false,
    forwarded: 0,
    probes: 0,
    dropResponse: false,
    dropped: 0,
    billableUnits: 0,
    readinessStatus: undefined,
    requests: [],
  }));
  const servers = [];
  const close = async () => {
    input.close();
    process.stdin.pause();
    await Promise.all(
      servers.map(
        (server) =>
          new Promise((done) => {
            server.close(done);
            server.closeAllConnections();
          }),
      ),
    );
  };
  try {
    const endpoints = [];
    for (const state of states) {
      const target = new URL(state.origin);
      assert.equal(target.protocol, "https:");
      assert.ok(!target.username && !target.password && !target.search && !target.hash);
      const server = http.createServer((request, response) => {
        if (request.headers["x-origin-key"] !== `fixture-credential-${state.label}`) {
          response.writeHead(403).end();
          return;
        }
        const readiness = request.url === "/ready";
        let captured;
        if (readiness) {
          state.probes++;
          if (!state.available) {
            state.readinessStatus = 503;
            response.writeHead(503).end();
            return;
          }
        } else {
          assert.ok(request.url.startsWith("/v1/fixture/"));
          state.forwarded++;
          captured = {
            method: request.method,
            path: request.url.split("?")[0],
            nonce: new URL(request.url, "http://localhost").searchParams.get("nonce"),
            callerKeyForwarded: new URL(request.url, "http://localhost").searchParams.has(
              "api-key",
            ),
            key: request.headers["zolana-tee-key-id"],
            enc: request.headers["zolana-tee-enc"],
          };
          state.requests.push(captured);
        }
        const headers = { ...request.headers, host: target.host, "x-api-key": state.apiKey };
        delete headers["x-origin-key"];
        const drop = state.dropResponse && request.method === "POST";
        const upstream = https.request(
          target,
          {
            method: request.method,
            path: readiness ? "/ready" : request.url.replace(/^\/v1\/fixture\//u, "/v1/zolana/"),
            headers,
          },
          (incoming) => {
            if (readiness) state.readinessStatus = incoming.statusCode;
            if (captured) {
              captured.status = incoming.statusCode;
              if (incoming.statusCode >= 400) {
                let bytes = 0;
                incoming.on("data", (chunk) => {
                  bytes += chunk.length;
                  if (bytes <= 2048)
                    captured.error =
                      (captured.error ?? "") +
                      chunk.toString().replaceAll(state.apiKey, "[redacted]");
                });
              }
            }
            incoming.on("error", () => response.destroy());
            if (drop) {
              incoming.resume();
              incoming.on("end", () => {
                assert.equal(
                  incoming.statusCode,
                  200,
                  "expected a completed upstream response before dropping it",
                );
                state.dropped++;
                response.destroy();
              });
            } else {
              if (!readiness && incoming.statusCode >= 200 && incoming.statusCode < 300)
                state.billableUnits += Number(incoming.headers["x-helius-metering-units"] ?? 1);
              response.writeHead(incoming.statusCode, incoming.headers);
              incoming.pipe(response);
            }
          },
        );
        upstream.setTimeout(readiness ? 900 : 180_000, () => upstream.destroy());
        upstream.on("error", () => {
          if (readiness) state.readinessStatus = 0;
          if (captured) captured.status = 0;
          response.destroy();
        });
        response.on("close", () => upstream.destroy());
        request.on("error", () => upstream.destroy());
        request.pipe(upstream);
      });
      await new Promise((done, reject) => {
        server.once("error", reject);
        server.listen(0, "::1", done);
      });
      servers.push(server);
      endpoints.push({
        label: state.label,
        url: `http://[::1]:${server.address().port}`,
        recipient: state.recipientId,
      });
    }
    assert.deepEqual(await command(endpoints), { configured: true });
    const find = (id) => {
      const state = states.find((entry) => entry.id === id);
      assert.ok(state, "unknown staging recipient");
      return state;
    };
    let draining;
    const sync = async () => {
      const next = states.filter((entry) => entry.draining);
      assert.ok(next.length <= 1, "one draining recipient per test phase");
      const label = next[0]?.label ?? null;
      if (label !== draining) {
        assert.deepEqual(await command({ draining: label }), { updated: true });
        draining = label;
      }
      await eventually("health decisions did not converge", async () => {
        const status = await command("status");
        return states.every(
          (entry) =>
            entry.probes > 0 &&
            (!entry.available || entry.readinessStatus === 200) &&
            status.disabled.includes(`fixture-origin-${entry.label}`) === !entry.available,
        );
      });
      if (next.length) {
        await eventually("draining config was not applied", async () => {
          const response = await fetch(
            `${process.env.GK_TEST_URL}/v1/fixture/attestation?api-key=${process.env.GK_TEST_KEY}`,
            {
              headers: { "zolana-tee-accept": next[0].recipientId },
              signal: AbortSignal.timeout(5000),
            },
          );
          await response.arrayBuffer();
          return response.status === 503;
        });
      }
    };
    await sync();
    return {
      origin: process.env.GK_TEST_URL,
      metadata: {
        implementation: "heimdall-proxy",
        control: "local config watcher, health checker, supervisor and admin",
        productionAuth: true,
        productionHealthController: true,
        deployed: false,
        originCredentials: "memory-only live fault bridges",
      },
      sync,
      setAvailable: (id, value) => {
        find(id).available = value;
      },
      setDraining: (id, value) => {
        find(id).draining = value;
      },
      setDropResponse: (value) => {
        states.forEach((entry) => {
          entry.dropResponse = value;
        });
      },
      failGeneration: async (id) => {
        states.forEach((entry) => {
          entry.available = entry.id !== id;
        });
        await sync();
      },
      readStats: async () => ({
        forwarded: Object.fromEntries(states.map((entry) => [entry.id, entry.forwarded])),
        probes: Object.fromEntries(states.map((entry) => [entry.id, entry.probes])),
        readinessStatus: Object.fromEntries(
          states.map((entry) => [entry.id, entry.readinessStatus]),
        ),
        requests: Object.fromEntries(
          states.map((entry) => [entry.id, structuredClone(entry.requests)]),
        ),
        dropped: states.reduce((count, entry) => count + entry.dropped, 0),
        billableUnits: states.reduce((count, entry) => count + entry.billableUnits, 0),
        meteringUnits: (await command("status")).metering_units,
      }),
      close,
    };
  } catch (error) {
    await close();
    throw error;
  }
}
