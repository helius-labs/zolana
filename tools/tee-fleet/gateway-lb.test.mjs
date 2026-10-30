import assert from "node:assert/strict";
import test from "node:test";
import { createMockGateway, listen } from "./gateway.mjs";

test("mock GK balances independent router replicas without leaking caller credentials or replaying a body", async () => {
  const origins = [];
  const calls = [[], []];
  let drop = false;
  const clientKey = "test-caller-only-key";
  const originKey = "test-router-ingress-key";
  const body = Buffer.from([0, 255, 1, 9]);
  try {
    for (let index = 0; index < 2; index++) {
      origins.push(
        await listen(async (request, response) => {
          const chunks = [];
          for await (const chunk of request) chunks.push(chunk);
          calls[index].push({
            headers: request.headers,
            uri: request.url,
            body: Buffer.concat(chunks),
          });
          if (drop && index === 0) {
            request.socket.destroy();
            return;
          }
          response.writeHead(200, {
            "content-type": "application/octet-stream",
            "zolana-tee": "v1",
          });
          response.end(body);
        }),
      );
    }
    const gateway = createMockGateway({
      apiKey: clientKey,
      originApiKey: originKey,
      origin: origins.map((origin) => origin.url),
    });
    const front = await listen(gateway.handler);
    origins.push(front);
    const send = () =>
      fetch(`${front.url}/v1/zolana/prove/key?api-key=${clientKey}&tenant=a%20b&v=%2f&v=%2F`, {
        method: "POST",
        body,
        headers: {
          "zolana-tee": "v1",
          "x-api-key": "do-not-forward",
          authorization: "do-not-forward",
        },
      });
    for (let n = 0; n < 4; n++) {
      const response = await send();
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("zolana-tee"), "v1");
      assert.deepEqual(Buffer.from(await response.arrayBuffer()), body);
    }
    assert.deepEqual(
      calls.map((items) => items.length),
      [2, 2],
    );
    for (const request of calls.flat()) {
      assert.equal(request.headers["x-api-key"], originKey);
      assert.equal(request.headers.authorization, undefined);
      assert.equal(request.uri, "/v1/zolana/prove/key?tenant=a%20b&v=%2f&v=%2F");
      assert.deepEqual(request.body, body);
    }
    drop = true;
    const response = await send();
    assert.equal(response.status, 502);
    await response.body?.cancel();
    assert.deepEqual(
      calls.map((items) => items.length),
      [3, 2],
    );
  } finally {
    for (const origin of origins.reverse()) await origin.close();
  }
});
