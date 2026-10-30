// Loopback qualification fixture. CONNECT carries end-to-end TLS unchanged.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { connect } from "node:net";

export async function connectionFaultProxy(targets) {
  const routes = new Map();
  for (const { authority, region } of targets) {
    assert.match(authority, /^[a-z0-9.-]+:[0-9]{1,5}$/u);
    assert.match(region, /^[a-z0-9-]+$/u);
    assert.ok(!routes.has(authority));
    const [host, port] = authority.split(":");
    assert.ok(Number(port) > 0 && Number(port) <= 65535);
    routes.set(authority, { host, port: Number(port), region });
  }
  const blocked = new Set();
  const tunnels = new Set();
  const clients = new Set();
  const events = [];
  const statistics = Object.fromEntries([...new Set(targets.map((target) => target.region))].map((region) => [region, { opened: 0, refused: 0 }]));
  const server = createServer((_, response) => response.writeHead(405).end());
  server.on("connection", (socket) => {
    clients.add(socket);
    socket.on("error", () => {});
    socket.once("close", () => clients.delete(socket));
  });
  server.on("connect", (request, client, head) => {
    const target = routes.get(request.url);
    const refuse = (status) => client.end(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
    if (!target) return refuse("403 Forbidden");
    if (blocked.has(target.region) || tunnels.size >= 32) {
      statistics[target.region].refused++;
      return refuse("503 Service Unavailable");
    }
    const upstream = connect({ host: target.host, port: target.port });
    const tunnel = { client, upstream, region: target.region };
    tunnels.add(tunnel);
    const close = () => {
      tunnels.delete(tunnel);
      client.destroy();
      upstream.destroy();
    };
    client.once("error", close);
    upstream.once("error", close);
    client.once("close", close);
    upstream.once("close", close);
    upstream.setTimeout(3000, close);
    upstream.once("connect", () => {
      statistics[target.region].opened++;
      upstream.setTimeout(0);
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      client.pipe(upstream);
      upstream.pipe(client);
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    events,
    statistics,
    fail(region) {
      assert.ok([...routes.values()].some((target) => target.region === region));
      blocked.add(region);
      let closed = 0;
      for (const tunnel of tunnels) {
        if (tunnel.region !== region) continue;
        tunnel.client.destroy();
        tunnel.upstream.destroy();
        closed++;
      }
      events.push({ action: "disconnect-region", region, closed, at: new Date().toISOString() });
    },
    restore() {
      blocked.clear();
      events.push({ action: "restore-connections", at: new Date().toISOString() });
    },
    async close() {
      for (const socket of clients) socket.destroy();
      for (const { upstream } of tunnels) upstream.destroy();
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    },
  };
}
