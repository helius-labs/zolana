import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";
import { launchBrowser } from "./browser.mjs";
import { listen } from "./gateway.mjs";

const root = new URL("../../", import.meta.url);
const vector = JSON.parse(
  await readFile(new URL("test-vectors/tee_tuf_repository.json", root), "utf8"),
);

test(
  "browser signed policy: reference TUF engine, real IndexedDB and Web Locks",
  { timeout: 120_000 },
  async (t) => {
    const staging = await mkdtemp(new URL(".tmp-", import.meta.url).pathname);
    const servers = [];
    let browser;
    try {
      const bundle = join(staging, "policy.mjs");
      const built = await build({
        entryPoints: [new URL("sdk-libs/ts/dist/client/prover/tee/tuf-browser.js", root).pathname],
        outfile: bundle,
        bundle: true,
        format: "esm",
        platform: "browser",
        metafile: true,
      });
      assert.ok(Object.values(built.metafile.outputs).every((o) => o.imports.length === 0));
      assert.ok(
        !Object.keys(built.metafile.inputs).some((input) =>
          /tuf-node|node_modules\/tuf-js\/dist\/updater/u.test(input),
        ),
      );
      let selected = "v1";
      let fault;
      const requests = [];
      const held = new Set();
      const repository = await listen((request, response) => {
        requests.push(request.url);
        assert.equal(request.headers.cookie, undefined);
        assert.equal(request.headers.authorization, undefined);
        assert.equal(request.headers.referer, undefined);
        response.setHeader("access-control-allow-origin", "*");
        const path = request.url.slice(1);
        if (
          (fault === "holdTimestamp" && path === "metadata/timestamp.json") ||
          (fault === "holdSnapshot" && path.endsWith(".snapshot.json"))
        ) {
          held.add(response);
          response.once("close", () => held.delete(response));
          return;
        }
        if (path.endsWith(".root.json")) {
          if (fault === "root500") {
            response.writeHead(500);
            response.end();
            return;
          }
          if (fault === "redirect") {
            response.writeHead(302, { location: "/metadata/1.root.json" });
            response.end();
            return;
          }
          if (fault === "oversized") {
            response.writeHead(200, { "content-type": "application/json" });
            response.end(" ".repeat(512_001));
            return;
          }
        }
        const data = vector.repositories[selected][path];
        if (data === undefined) {
          response.writeHead(404);
          response.end();
          return;
        }
        response.writeHead(200, {
          "content-type": fault === "badType" ? "text/plain" : "application/json",
        });
        response.end(fault === "badTarget" && path.startsWith("targets/") ? `${data}x` : data);
      });
      servers.push(repository);
      const assets = await listen(async (request, response) => {
        if (request.url === "/policy.mjs") {
          response.writeHead(200, { "content-type": "application/javascript" });
          response.end(await readFile(bundle));
        } else {
          response.writeHead(200, { "content-type": "text/html" });
          response.end(
            '<!doctype html><script type="module">import * as policy from "/policy.mjs"; window.policy = policy;</script>',
          );
        }
      });
      servers.push(assets);
      browser = await launchBrowser();
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(assets.url);
      await page.waitForFunction(() => Boolean(window.policy));
      const options = {
        network: vector.network,
        rootJson: vector.bootstrap_root,
        metadataUrl: `${repository.url}/metadata/`,
        targetsUrl: `${repository.url}/targets/`,
      };
      const resolve = (databaseName) =>
        page.evaluate(
          async (options) => {
            try {
              const value = await window.policy.tufTeePolicy(options).resolve();
              return {
                revision: value.revision,
                expiresAt: value.expiresAt,
                deployments: value.deployments.length,
              };
            } catch (error) {
              return { error: error.code, details: error.details };
            }
          },
          { ...options, databaseName },
        );
      const refused = (value) => assert.equal(value.error, "CLIENT_PROVER_TEE_ATTESTATION");
      let index = 0;
      const fresh = () => `policy-test-${index++}`;
      const waitUntil = async (predicate) => {
        const deadline = Date.now() + 5000;
        while (!predicate() && Date.now() < deadline)
          await new Promise((resolve) => setTimeout(resolve, 10));
        assert.ok(predicate());
      };

      for (const name of ["v1", "v2", "rotated", "fractional"]) {
        await t.test(`accepts the shared Rust/Node repository ${name}`, async () => {
          selected = name;
          const result = await resolve(fresh());
          assert.equal(result.revision, name === "v2" || name === "rotated" ? 2 : 1);
          assert.equal(result.deployments, 3);
          if (name === "fractional") assert.equal(result.expiresAt, vector.fractional_valid_until);
        });
      }
      for (const name of [
        "bad_signature",
        "hash_mismatch",
        "weak_hash",
        "expired",
        "rotation_old_only",
        "rotation_new_only",
      ]) {
        await t.test(`rejects the shared adversarial repository ${name}`, async () => {
          selected = name;
          refused(await resolve(fresh()));
        });
      }
      await t.test(
        "revision and metadata floors survive a page reload and a new source",
        async () => {
          const db = fresh();
          selected = "v2";
          assert.equal((await resolve(db)).revision, 2);
          await page.reload();
          await page.waitForFunction(() => Boolean(window.policy));
          selected = "rollback";
          refused(await resolve(db));
          selected = "v1";
          refused(await resolve(db));
        },
      );
      await t.test("same-revision policy substitution is rejected after restart", async () => {
        const db = fresh();
        selected = "v1";
        assert.equal((await resolve(db)).revision, 1);
        selected = "substitution";
        refused(await resolve(db));
      });
      await t.test(
        "root rotation persists and never bootstraps from an old root again",
        async () => {
          const db = fresh();
          selected = "v1";
          assert.equal((await resolve(db)).revision, 1);
          selected = "rotated";
          assert.equal((await resolve(db)).revision, 2);
          selected = "v1";
          refused(await resolve(db));
        },
      );
      await t.test("accepted metadata floors survive a later target failure", async () => {
        const db = fresh();
        selected = "v1";
        assert.equal((await resolve(db)).revision, 1);
        selected = "v2";
        fault = "badTarget";
        refused(await resolve(db));
        fault = undefined;
        selected = "v1";
        refused(await resolve(db));
      });
      for (const mode of ["root500", "redirect", "oversized", "badType"]) {
        await t.test(`fails closed before timestamp on ${mode}`, async () => {
          selected = "rotated";
          fault = mode;
          requests.length = 0;
          refused(await resolve(fresh()));
          assert.deepEqual(requests, ["/metadata/2.root.json"]);
          fault = undefined;
        });
      }
      await t.test("corrupt cache or deleted state is refused before network", async () => {
        for (const action of ["corrupt", "delete"]) {
          const db = fresh();
          selected = "v1";
          assert.equal((await resolve(db)).revision, 1);
          await page.evaluate(
            async ({ db, action }) => {
              await new Promise((resolve, reject) => {
                const open = indexedDB.open(db, 1);
                open.onsuccess = () => {
                  const database = open.result;
                  const tx = database.transaction("repositories", "readwrite");
                  const cursor = tx.objectStore("repositories").openCursor();
                  cursor.onsuccess = () => {
                    if (!cursor.result) throw new Error("missing test row");
                    if (action === "delete") cursor.result.delete();
                    else cursor.result.update({ ...cursor.result.value, checksum: "wrong" });
                  };
                  tx.oncomplete = () => {
                    database.close();
                    resolve();
                  };
                  tx.onabort = reject;
                };
                open.onerror = reject;
              });
            },
            { db, action },
          );
          requests.length = 0;
          refused(await resolve(db));
          assert.deepEqual(requests, []);
        }
      });
      await t.test(
        "a cancelled refresh preserves accepted floors before releasing its lock",
        async () => {
          const db = fresh();
          selected = "v1";
          assert.equal((await resolve(db)).revision, 1);
          selected = "v2";
          fault = "holdSnapshot";
          requests.length = 0;
          await page.evaluate(
            (options) => {
              window.abort = new AbortController();
              window.result = window.policy
                .tufTeePolicy(options)
                .resolve({ signal: window.abort.signal })
                .then(
                  () => "unexpected success",
                  (e) => e.code,
                );
            },
            { ...options, databaseName: db },
          );
          await waitUntil(() => requests.includes("/metadata/2.snapshot.json"));
          assert.equal(
            await page.evaluate(async () => {
              window.abort.abort();
              return await window.result;
            }),
            "CLIENT_ABORTED",
          );
          fault = undefined;
          selected = "v1";
          refused(await resolve(db));
          await waitUntil(() => held.size === 0);
        },
      );
      await t.test(
        "two tabs serialize refreshes; cancelling a lock waiter sends no request",
        async () => {
          const db = fresh();
          selected = "v1";
          fault = "holdTimestamp";
          requests.length = 0;
          await page.evaluate(
            (options) => {
              window.abort = new AbortController();
              window.result = window.policy
                .tufTeePolicy(options)
                .resolve({ signal: window.abort.signal })
                .then(
                  () => "unexpected success",
                  (e) => e.code,
                );
            },
            { ...options, databaseName: db },
          );
          await waitUntil(() => requests.includes("/metadata/timestamp.json"));
          const second = await context.newPage();
          await second.goto(assets.url);
          await second.waitForFunction(() => Boolean(window.policy));
          const before = requests.length;
          const result = await second.evaluate(
            async (options) => {
              try {
                await window.policy.tufTeePolicy(options).resolve({ timeoutMs: 100 });
                return "unexpected success";
              } catch (e) {
                return e.code;
              }
            },
            { ...options, databaseName: db },
          );
          assert.equal(result, "CLIENT_TIMEOUT");
          assert.equal(requests.length, before);
          assert.equal(
            await page.evaluate(async () => {
              window.abort.abort();
              return await window.result;
            }),
            "CLIENT_ABORTED",
          );
          fault = undefined;
          assert.equal((await resolve(db)).revision, 1);
          await second.close();
        },
      );
      await t.test("effective metadata expiry rejects an already cached source", async () => {
        const db = fresh();
        selected = "fractional";
        await page.clock.setFixedTime(new Date((vector.fractional_valid_until - 1) * 1000));
        try {
          assert.equal(
            await page.evaluate(
              async (options) => {
                window.expiring = window.policy.tufTeePolicy(options);
                return (await window.expiring.resolve()).revision;
              },
              { ...options, databaseName: db },
            ),
            1,
          );
          await page.clock.setFixedTime(new Date(vector.fractional_valid_until * 1000));
          const result = await page.evaluate(async () => {
            try {
              await window.expiring.resolve();
              return "unexpected success";
            } catch (error) {
              return error.code;
            }
          });
          assert.equal(result, "CLIENT_PROVER_TEE_ATTESTATION");
        } finally {
          await page.clock.setFixedTime(new Date());
        }
      });
      for (const feature of ["indexedDB", "locks"]) {
        await t.test(`missing ${feature} fails without an in-memory fallback`, async () => {
          const tab = await context.newPage();
          await tab.goto(assets.url);
          await tab.waitForFunction(() => Boolean(window.policy));
          const before = requests.length;
          const result = await tab.evaluate(
            async ({ options, feature }) => {
              if (feature === "indexedDB")
                Object.defineProperty(window, "indexedDB", { value: undefined });
              else Object.defineProperty(navigator, "locks", { value: undefined });
              try {
                await window.policy.tufTeePolicy(options).resolve();
                return "unexpected success";
              } catch (error) {
                return error.code;
              }
            },
            { options: { ...options, databaseName: fresh() }, feature },
          );
          assert.equal(result, "CLIENT_PROVER_TEE_ATTESTATION");
          assert.equal(requests.length, before);
          await tab.close();
        });
      }
      await context.close();
    } finally {
      await browser?.close();
      for (const server of servers.reverse()) await server.close();
      await rm(staging, { recursive: true, force: true });
    }
  },
);
