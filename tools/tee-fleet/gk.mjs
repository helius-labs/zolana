// Loopback driver for Heimdall's real REST frontend. Credentials stay on stdin.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import https from "node:https";
import { createInterface } from "node:readline";
import { listen } from "./gateway.mjs";

export async function gkRouter({ deployments, binary }) {
  const counters = {
    attestations: 0,
    unavailable: 0,
    forwarded: Object.fromEntries(deployments.map((entry) => [entry.id, 0])),
  };
  const proxies = [];
  let child;
  const close = async () => {
    child?.stdin.end();
    child?.kill();
    await Promise.all(proxies.map((proxy) => proxy.close()));
  };
  try {
    const origins = [];
    for (const entry of deployments) {
      const target = new URL(entry.origin);
      assert.ok(
        target.protocol === "https:" ||
          (target.protocol === "http:" && target.hostname === "127.0.0.1"),
      );
      const proxy = await listen((request, response) => {
        counters.forwarded[entry.id]++;
        if (request.url.split("?")[0].endsWith("/attestation")) counters.attestations++;
        const upstream = (target.protocol === "https:" ? https : http).request(
          target,
          {
            method: request.method,
            path: request.url,
            headers: { ...request.headers, host: target.host },
          },
          (incoming) => {
            response.writeHead(incoming.statusCode, incoming.headers);
            incoming.pipe(response);
            incoming.on("error", () => response.destroy());
          },
        );
        upstream.on("error", () => response.destroy());
        response.on("close", () => upstream.destroy());
        request.on("error", () => upstream.destroy());
        request.pipe(upstream);
      });
      proxies.push(proxy);
      origins.push({
        name: entry.id,
        url: proxy.url,
        recipient_id: entry.recipientId,
        headers: entry.apiKey === undefined ? [] : [["x-api-key", entry.apiKey]],
        draining: false,
        enabled: true,
      });
    }
    child = spawn(binary, [], { stdio: ["pipe", "pipe", "pipe"] });
    // Never surface native diagnostics: origin setup errors may contain credentials.
    child.stderr.resume();
    const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
    const receive = async () => {
      const next = await lines.next();
      assert.ok(!next.done, "GK qualification process stopped");
      return JSON.parse(next.value);
    };
    child.on("error", () => child.stdout.destroy());
    const send = (value) => child.stdin.write(`${JSON.stringify(value)}\n`);
    const routes = [
      ["GET", "/attestation", 184],
      ["GET", "/proving-keys", 185],
      ["GET", "/health", 162],
      ["GET", "/prove/{key}/status", 162],
      ["POST", "/prove/{key}", 161],
      ["POST", "/prove/{key}/indexed", 161],
    ].map(([verb, path, method]) => ({ verb, path: `/v1/zolana${path}`, method }));
    send({ origins, routes });
    const started = await receive();
    assert.match(started.url, /^http:\/\/127\.0\.0\.1:\d+$/u);
    const sync = async () => {
      send(origins);
      const reply = await receive();
      assert.equal(reply.updated, true);
      counters.unavailable = reply.unavailable;
    };
    const set = (id, field, value) => {
      const entry = origins.find((entry) => entry.name === id);
      assert.ok(entry && typeof value === "boolean", "invalid generation update");
      entry[field] = value;
    };
    return {
      origin: started.url,
      metadata: {
        implementation: "heimdall-proxy",
        control: "loopback qualification stdin",
        productionAuth: false,
        productionHealthController: false,
      },
      sync,
      readStats: async () => {
        await sync();
        return structuredClone(counters);
      },
      failGeneration: async (id) => {
        origins.forEach((entry) => {
          entry.enabled = entry.name !== id;
        });
        await sync();
      },
      setAvailable: (id, value) => set(id, "enabled", value),
      setDraining: (id, value) => set(id, "draining", value),
      close,
    };
  } catch (error) {
    await close();
    throw error;
  }
}
