import assert from "node:assert/strict";
import { once } from "node:events";
import { request } from "node:http";
import { createServer } from "node:net";
import test from "node:test";
import { connectionFaultProxy } from "./connection-fault.mjs";

test("regional connection fault closes existing tunnels, rejects new ones and leaves other regions usable", async () => {
  const upstreams = [];
  const sockets = [];
  let proxy;
  try {
    for (let n = 0; n < 2; n++) {
      const server = createServer((socket) => socket.pipe(socket));
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
      upstreams.push(server);
    }
    const targets = upstreams.map((server, n) => ({ authority: `127.0.0.1:${server.address().port}`, region: n ? "eu-test" : "us-test" }));
    proxy = await connectionFaultProxy(targets);
    const tunnel = (authority) => new Promise((resolve, reject) => {
      const req = request(proxy.url, { method: "CONNECT", path: authority });
      req.once("error", reject);
      req.once("connect", (response, socket, head) => {
        sockets.push(socket);
        socket.on("error", () => {});
        assert.equal(head.length, 0);
        resolve({ status: response.statusCode, socket });
      });
      req.end();
    });
    const us = await tunnel(targets[0].authority);
    const eu = await tunnel(targets[1].authority);
    assert.equal(us.status, 200);
    assert.equal(eu.status, 200);
    const payload = Buffer.from([0, 255, 1, 254, 7]);
    const echo = async (socket) => {
      const data = once(socket, "data");
      socket.write(payload);
      assert.deepEqual((await data)[0], payload);
    };
    await echo(us.socket);
    const closed = once(us.socket, "close");
    proxy.fail("us-test");
    us.socket.resume();
    await closed;
    assert.equal(proxy.events[0].closed, 1);
    assert.equal((await tunnel(targets[0].authority)).status, 503);
    assert.equal(proxy.statistics["us-test"].refused, 1);
    await echo(eu.socket);
    assert.equal((await tunnel("unlisted.example:443")).status, 403);
    proxy.restore();
    const restored = await tunnel(targets[0].authority);
    assert.equal(restored.status, 200);
    await echo(restored.socket);
    // SDK clients may keep several idle TLS pools. The fault fixture must not
    // inject admission failures into a region that was never disconnected.
    for (let n = 0; n < 40; n++) {
      assert.equal((await tunnel(targets[1].authority)).status, 200);
    }
    assert.equal(proxy.statistics["eu-test"].refused, 0);
  } finally {
    for (const socket of sockets) socket.destroy();
    await proxy?.close();
    for (const server of upstreams) await new Promise((resolve) => server.close(resolve));
  }
});
