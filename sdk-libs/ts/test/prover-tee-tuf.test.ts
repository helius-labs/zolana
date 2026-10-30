import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import vector from "../../../test-vectors/tee_fleet_policy.json" with { type: "json" };
import { tufTeePolicy } from "../src/client/prover/tee/tuf-node.js";
import { TeePolicySource } from "../src/client/prover/tee/source.js";
import { wireDecoder } from "../src/interface/decode.js";
import { tufRepository } from "./helpers/tuf-repository.js";

const decode = wireDecoder((path) => new Error(`fixture ${path}`));
const denied = expect.objectContaining({ code: "CLIENT_PROVER_TEE_ATTESTATION" });
let directory: string;

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), "zolana-tuf-test-"));
});
afterEach(async () => {
  vi.restoreAllMocks();
  await rm(directory, { recursive: true, force: true });
});

function setup(initial = tufRepository()) {
  let repository = initial;
  const requests: string[] = [];
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = new URL(String(input));
    requests.push(url.pathname);
    expect(init?.redirect).toBe("error");
    expect(init?.credentials).toBe("omit");
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    const bytes = repository.files.get(url.pathname);
    return bytes === undefined
      ? new Response(null, { status: 404 })
      : new Response(new Uint8Array(bytes));
  };
  return {
    requests,
    setRepository(next: typeof repository) {
      repository = next;
    },
    source(overrides: Partial<Parameters<typeof tufTeePolicy>[0]> = {}): TeePolicySource {
      return tufTeePolicy({
        network: "fixture",
        rootJson: initial.rootJson,
        metadataUrl: "https://policies.example/metadata/",
        targetsUrl: "https://policies.example/targets/",
        cacheDirectory: directory,
        fetch,
        ...overrides,
      });
    },
  };
}

describe("Node TUF fleet policy provider", () => {
  it.each(["metadata", "target"])(
    "rejects duplicate JSON fields in authenticated %s without committing a fleet floor",
    async (kind) => {
      const repo = tufRepository(
        kind === "target"
          ? {
              policyJson: JSON.stringify({ ...vector.policy, revision: 1 }).replace(
                '"revision":1',
                '"revision":0,"revision":1',
              ),
            }
          : {},
      );
      if (kind === "metadata") {
        const path = "/metadata/timestamp.json";
        const bytes = repo.files.get(path);
        if (bytes === undefined) throw new Error("missing fixture timestamp");
        repo.files.set(
          path,
          Buffer.from(bytes.toString("utf8").replace('"version":1', '"version":0,"version":1')),
        );
      }
      const test = setup(repo);
      await expect(test.source().resolve()).rejects.toThrow(denied);
      const namespace = (await readdir(directory))[0];
      if (namespace === undefined) throw new Error("missing cache");
      expect(await readdir(join(directory, namespace))).not.toContain("fleet-floor.json");
      if (kind === "metadata") expect(test.requests).not.toContain(repo.targetUrl);
    },
  );

  it("requires strong target digests even if a publisher signs an empty or weak hash set", async () => {
    let revision = 1;
    for (const algorithm of ["none", "md5"] as const) {
      await expect(
        setup(tufRepository({ targetHashAlgorithm: algorithm, revision: revision++ }))
          .source()
          .resolve(),
      ).rejects.toThrow(denied);
    }
    expect(
      (
        await setup(tufRepository({ targetHashAlgorithm: "sha512", revision }))
          .source()
          .resolve()
      ).revision,
    ).toBe(revision);
  });
  it("authenticates a static repository and caps policy validity by signed metadata expiry", async () => {
    const repo = tufRepository();
    const test = setup(repo);
    const source = test.source();
    const policy = await source.resolve();
    expect(policy.revision).toBe(1);
    expect(policy.deployments).toHaveLength(3);
    expect(policy.expiresAt).toBe(repo.timestampExpires);
    expect(test.requests).toContain(repo.targetUrl);
    const count = test.requests.length;
    expect(await source.resolve()).toBe(policy);
    expect(test.requests).toHaveLength(count);
    const fractional = tufRepository({
      revision: 2,
      timestampExpires: repo.timestampExpires + 0.5,
    });
    test.setRepository(fractional);
    expect((await test.source().resolve()).expiresAt).toBe(Math.floor(fractional.timestampExpires));
  });

  it("retains timestamp and fleet revision floors across provider restarts", async () => {
    const test = setup();
    expect((await test.source().resolve()).revision).toBe(1);
    test.setRepository(tufRepository({ revision: 2 }));
    expect((await test.source().resolve()).revision).toBe(2);
    test.setRepository(tufRepository());
    await expect(test.source().resolve()).rejects.toThrow(denied);
    test.setRepository(tufRepository({ revision: 1, metadataVersion: 3 }));
    await expect(test.source().resolve()).rejects.toThrow(denied);
  });

  it("refuses changed policy bytes under the same fleet revision", async () => {
    const test = setup();
    await test.source().resolve();
    test.setRepository(
      tufRepository({
        metadataVersion: 2,
        policy: { ...vector.policy, expires_at: vector.policy.expires_at + 1 },
      }),
    );
    await expect(test.source().resolve()).rejects.toThrow(denied);
  });

  it("verifies a root rotation against the previous root and the new root", async () => {
    const test = setup();
    await test.source().resolve();
    test.setRepository(tufRepository({ revision: 2, rotatedRoot: true }));
    expect((await test.source().resolve()).revision).toBe(2);
    expect(test.requests).toContain("/metadata/2.root.json");
    expect(test.requests).toContain("/metadata/3.root.json");
    test.setRepository(tufRepository({ revision: 3 }));
    await expect(test.source().resolve()).rejects.toThrow(denied);
  });

  it("requires both old-root approval and new-root self-signatures during rotation", async () => {
    for (const keep of [0, 1]) {
      const repo = tufRepository({ rotatedRoot: true, revision: 2 });
      const bytes = repo.files.get("/metadata/2.root.json");
      if (bytes === undefined) throw new Error("missing rotated root");
      const parsed: unknown = JSON.parse(bytes.toString("utf8"));
      const metadata = decode.record(parsed, "root");
      const signatures = decode.list(metadata["signatures"], "signatures");
      metadata["signatures"] = [signatures[keep]];
      repo.files.set("/metadata/2.root.json", Buffer.from(JSON.stringify(metadata)));
      await expect(setup(repo).source().resolve()).rejects.toThrow(denied);
    }
  });

  it("rejects tampered target bytes even when the signed metadata is valid", async () => {
    const repo = tufRepository();
    repo.files.set(repo.targetUrl, Buffer.from(JSON.stringify({ ...vector.policy, revision: 9 })));
    await expect(setup(repo).source().resolve()).rejects.toThrow(denied);
  });

  it("rejects invalid metadata signatures", async () => {
    const repo = tufRepository();
    const path = "/metadata/timestamp.json";
    const bytes = repo.files.get(path);
    if (bytes === undefined) throw new Error("missing fixture");
    const json: unknown = JSON.parse(bytes.toString("utf8"));
    const record = decode.record(json, "metadata");
    const signature = decode.record(
      decode.list(record["signatures"], "signatures")[0],
      "signature",
    );
    signature["sig"] = "00".repeat(64);
    repo.files.set(path, Buffer.from(JSON.stringify(record)));
    await expect(setup(repo).source().resolve()).rejects.toThrow(denied);
  });

  it("rejects expired timestamp metadata and signed policies for another network", async () => {
    const expired = setup(tufRepository({ timestampExpires: Math.floor(Date.now() / 1000) - 1 }));
    await expect(expired.source().resolve()).rejects.toThrow(denied);
    const wrongNetwork = setup(tufRepository({ policy: { ...vector.policy, network: "devnet" } }));
    await expect(wrongNetwork.source().resolve()).rejects.toThrow(denied);
  });

  it("fails closed on corrupted persistent metadata instead of restarting from the bootstrap root", async () => {
    const test = setup();
    await test.source().resolve();
    const namespace = (await readdir(directory))[0];
    if (namespace === undefined) throw new Error("missing cache");
    await writeFile(join(directory, namespace, "timestamp.json"), "{");
    const count = test.requests.length;
    await expect(test.source().resolve()).rejects.toThrow(denied);
    expect(test.requests).toHaveLength(count);
  });

  it("does not reset trusted roots when a populated cache loses root.json", async () => {
    const test = setup();
    await test.source().resolve();
    const namespace = (await readdir(directory))[0];
    if (namespace === undefined) throw new Error("missing cache");
    await rm(join(directory, namespace, "root.json"));
    const count = test.requests.length;
    await expect(test.source().resolve()).rejects.toThrow(denied);
    expect(test.requests).toHaveLength(count);
  });

  it("rejects unsafe URLs and returns sanitized errors without repository-controlled text", async () => {
    const test = setup();
    for (const metadataUrl of [
      "http://remote.example/",
      "https://policies.example/?api-key=secret",
      "https://user:secret@policies.example/",
    ]) {
      expect(() => test.source({ metadataUrl })).toThrow(
        expect.objectContaining({ code: "CLIENT_INVALID_CONFIG" }),
      );
    }
    const source = test.source({
      fetch: async () => {
        throw new Error("server-controlled secret");
      },
    });
    await expect(source.resolve()).rejects.toThrow(denied);
    await expect(source.resolve()).rejects.not.toThrow(/secret|policies\.example/u);
  });

  it("serializes competing writers and propagates cancellation while waiting for the cache lock", async () => {
    const test = setup();
    await test.source().resolve();
    const namespace = (await readdir(directory))[0];
    if (namespace === undefined) throw new Error("missing cache");
    const lock = join(directory, namespace, "lock");
    await writeFile(lock, "");
    await expect(test.source().resolve({ timeoutMs: 30 })).rejects.toThrow(
      expect.objectContaining({ code: "CLIENT_TIMEOUT" }),
    );
    expect(await readFile(lock, "utf8")).toBe("");
  });

  it("allows separate providers to safely share the persistent cache", async () => {
    const test = setup();
    const policies = await Promise.all([test.source().resolve(), test.source().resolve()]);
    expect(policies.map((policy) => policy.revision)).toEqual([1, 1]);
    const namespace = (await readdir(directory))[0];
    if (namespace === undefined) throw new Error("missing cache");
    expect(await readdir(join(directory, namespace))).not.toContain("lock");
  });

  it("verifies metadata and target bytes over real HTTP from a static local repository", async () => {
    const repo = tufRepository();
    const server = createServer((request, response) => {
      const bytes = repo.files.get(request.url ?? "");
      response.writeHead(bytes === undefined ? 404 : 200, { "Content-Type": "application/json" });
      response.end(bytes);
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("missing local port");
      const source = tufTeePolicy({
        network: "fixture",
        rootJson: repo.rootJson,
        metadataUrl: `http://127.0.0.1:${address.port}/metadata/`,
        targetsUrl: `http://127.0.0.1:${address.port}/targets/`,
        cacheDirectory: directory,
      });
      expect((await source.resolve()).revision).toBe(1);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
